package codescan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// This file is the bounded cross-language symbol layer. It reuses the lexical
// token/statement IR and existing declaration parsing; it is not a type system,
// import resolver or call graph. A "same_file" call means only that the exact
// simple name occurs as a declaration in the same file. External calls remain
// unresolved instead of being treated as resolved.

var typeDeclarationKeywords = map[string]string{
	"class": "class", "interface": "interface", "struct": "struct",
	"enum": "enum", "record": "record", "trait": "trait", "type": "type",
}

var functionDeclarationKeywords = map[string]bool{
	"function": true, "func": true, "def": true,
}

func scanSymbolIndex(statements []statement, relations map[int]scopeRelation, spec languageSpec, file, fileSHA string) ([]Symbol, []Call, []Unresolved) {
	symbols := make([]Symbol, 0, 64)
	scopeSymbol := map[int]int{}
	byShort := map[string]bool{}
	for index, stmt := range statements {
		typeBody := scopeIsTypeBody(stmt.scope, scopeSymbol, symbols)
		name, kind, params, ok := declarationSymbol(stmt, spec.Name, typeBody)
		if !ok || name == "" {
			continue
		}
		container := nearestTypeContainer(stmt.scope, relations, scopeSymbol, symbols)
		if container == "" && spec.Name == "go" {
			container = goReceiverType(stmt.tokens)
		}
		if kind == "function" && container != "" {
			kind = "method"
		}
		qualified := name
		if container != "" {
			qualified = container + "." + name
		}
		item := Symbol{
			ID:            fmt.Sprintf("%s:%s:%d:%s:%s:%d", spec.Name, file, stmt.line, kind, name, index),
			Language:      spec.Name,
			Kind:          kind,
			Name:          name,
			QualifiedName: qualified,
			Container:     container,
			File:          file,
			SHA256:        fileSHA,
			Line:          stmt.line,
			Parameters:    make([]SymbolParameter, 0, len(params)),
		}
		for _, param := range params {
			item.Parameters = append(item.Parameters, SymbolParameter{Name: param})
		}
		if bodyScope, ok := directChildScope(index, statements, relations, stmt.scope); ok {
			item.EndLine = endLineForScope(bodyScope, stmt.line, statements, relations)
			scopeSymbol[bodyScope] = len(symbols)
		}
		symbols = append(symbols, item)
		byShort[normalizeName(spec.Name, name)] = true
	}

	calls := make([]Call, 0, 128)
	unresolved := make([]Unresolved, 0, 64)
	receiverTypes := inferReceiverTypes(statements)
	for _, stmt := range statements {
		if stmt.declaration || startsWithAnnotation(stmt.tokens) {
			continue
		}
		caller := nearestCaller(stmt.scope, relations, scopeSymbol, symbols)
		for _, call := range stmt.calls {
			target := call.full
			if target == "" {
				target = call.short
			}
			status := "external_or_unresolved"
			if byShort[normalizeName(spec.Name, call.short)] {
				status = "same_file"
			}
			receiver := ""
			if call.full != "" && call.short != "" && strings.HasSuffix(call.full, "."+call.short) {
				receiver = strings.TrimSuffix(call.full, "."+call.short)
			}
			callLine := call.line
			if callLine == 0 {
				callLine = stmt.line
			}
			calls = append(calls, Call{
				Language:     spec.Name,
				Caller:       caller,
				Callee:       target,
				Name:         call.short,
				Receiver:     receiver,
				ReceiverType: receiverTypeFor(receiver, receiverTypes, caller),
				File:         file,
				SHA256:       fileSHA,
				Line:         callLine,
				Arguments:    len(call.args),
				Status:       status,
			})
			if status == "external_or_unresolved" {
				unresolved = append(unresolved, Unresolved{
					Language: spec.Name,
					Caller:   caller,
					Expr:     target,
					Reason:   "no_same_file_symbol",
					File:     file,
					SHA256:   fileSHA,
					Line:     callLine,
				})
			}
		}
	}
	return symbols, calls, unresolved
}

func scanVariableIndex(statements []statement, spec languageSpec, file, fileSHA string) ([]Variable, []StringConstant, bool, bool) {
	variables := make([]Variable, 0, 64)
	stringsOut := make([]StringConstant, 0, 64)
	for _, stmt := range statements {
		if stmt.assign != nil && simpleAssignmentTarget(stmt.assign.target) && simpleAssignmentLHS(stmt.assign.lhs) {
			name := strings.TrimPrefix(stmt.assign.target, "$")
			kind := "variable"
			if isConstantAssignment(name, stmt.assign.lhs) {
				kind = "constant"
			}
			variables = append(variables, Variable{
				Language: spec.Name, Name: name, Kind: kind,
				File: file, SHA256: fileSHA, Line: stmt.assign.line,
			})
		}
		for _, tok := range stmt.tokens {
			if tok.kind != tokString || tok.text == "" {
				continue
			}
			sum := sha256.Sum256([]byte(tok.text))
			stringsOut = append(stringsOut, StringConstant{
				Language: spec.Name, Hash: hex.EncodeToString(sum[:]),
				File: file, SHA256: fileSHA, Line: tok.line, Length: len([]rune(tok.text)),
			})
		}
	}
	return variables, stringsOut, len(variables) > MaxVariables, len(stringsOut) > MaxStringConstants
}

func simpleAssignmentTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, ".[]()+-*/?:") {
		return false
	}
	if strings.HasPrefix(target, "$") {
		target = target[1:]
	}
	if target == "" {
		return false
	}
	for _, r := range target {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func simpleAssignmentLHS(lhs []token) bool {
	for _, tok := range lhs {
		switch tok.text {
		case ".", "->", "::", "?.", "?->", "[", "]":
			return false
		}
	}
	return true
}

func isConstantAssignment(target string, lhs []token) bool {
	for _, tok := range lhs {
		switch strings.ToLower(tok.text) {
		case "const", "final", "static", "readonly":
			return true
		}
	}
	name := strings.TrimPrefix(target, "$")
	return name != "" && strings.ToUpper(name) == name && strings.ToLower(name) != name
}

// resolveCrossFileCalls consumes the completed per-file index. A call is
// upgraded only when a unique project-wide function/method declaration matches
// its simple or qualified name; ambiguity remains explicit.
func resolveCrossFileCalls(report *Report) {
	byLanguage := map[string]map[string][]Symbol{}
	for _, symbol := range report.Symbols {
		if symbol.Kind != "function" && symbol.Kind != "method" {
			continue
		}
		if byLanguage[symbol.Language] == nil {
			byLanguage[symbol.Language] = map[string][]Symbol{}
		}
		keys := []string{normalizeSelectorName(symbol.Language, symbol.Name)}
		if qualified := normalizeSelectorName(symbol.Language, symbol.QualifiedName); qualified != "" && qualified != keys[0] {
			keys = append(keys, qualified)
		}
		for _, key := range keys {
			byLanguage[symbol.Language][key] = append(byLanguage[symbol.Language][key], symbol)
		}
	}
	resolved := 0
	for index := range report.Calls {
		call := &report.Calls[index]
		if call.Status != "external_or_unresolved" {
			continue
		}
		candidates := byLanguage[call.Language][normalizeSelectorName(call.Language, call.Name)]
		if len(candidates) == 0 && call.Callee != "" && call.ReceiverType == "" {
			candidates = byLanguage[call.Language][normalizeSelectorName(call.Language, call.Callee)]
		}
		if len(candidates) > 1 && call.ReceiverType != "" {
			candidates = symbolsInContainer(candidates, call.ReceiverType)
		}
		switch {
		case len(candidates) == 1:
			call.Status = "same_project"
			call.ResolvedFile = candidates[0].File
			call.ResolvedSymbol = candidates[0].QualifiedName
			if call.ResolvedSymbol == "" {
				call.ResolvedSymbol = candidates[0].Name
			}
			resolved++
		case len(candidates) > 1:
			call.Status = "ambiguous_symbol"
		}
	}
	if resolved > 0 {
		filtered := make([]Unresolved, 0, len(report.Unresolved))
		for _, item := range report.Unresolved {
			matched := false
			for _, call := range report.Calls {
				if call.File == item.File && call.Line == item.Line && call.Name == item.Expr && call.Status == "same_project" {
					matched = true
					break
				}
			}
			if !matched {
				filtered = append(filtered, item)
			}
		}
		report.Unresolved = filtered
	}
}

// receiverTypeFor is deliberately file-scoped: it recognizes `$this`, a bare
// class name and `$var = new Type`; other receivers stay untyped and ambiguous.
func receiverTypeFor(receiver string, types map[string]string, caller string) string {
	receiver = strings.TrimSpace(receiver)
	switch strings.ToLower(receiver) {
	case "$this", "self", "static":
		return containerFromQualified(caller, ".")
	}
	if strings.HasPrefix(receiver, "$") {
		return types[receiver]
	}
	if receiver == "" || strings.ContainsAny(receiver, "()[]") {
		return ""
	}
	return lastTypeName(receiver)
}

func inferReceiverTypes(statements []statement) map[string]string {
	types := map[string]string{}
	for _, stmt := range statements {
		if stmt.assign == nil || !simpleAssignmentTarget(stmt.assign.target) {
			continue
		}
		typeName := newTypeFromTokens(stmt.assign.rhs)
		if typeName == "" {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(stmt.assign.target), "$")
		if name == "" {
			continue
		}
		types["$"+name] = typeName
		types[name] = typeName
	}
	return types
}

func newTypeFromTokens(tokens []token) string {
	candidate := ""
	expect := false
	for _, tok := range tokens {
		if strings.EqualFold(tok.text, "new") {
			expect = true
			candidate = ""
			continue
		}
		if !expect {
			continue
		}
		if tok.text == `\` || tok.text == "." {
			continue
		}
		if isTypeNameText(tok.text) {
			candidate = tok.text
			continue
		}
		if candidate != "" {
			break
		}
	}
	return candidate
}

func isTypeNameText(text string) bool {
	if text == "" {
		return false
	}
	for _, char := range text {
		if !(char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func symbolsInContainer(symbols []Symbol, typeName string) []Symbol {
	want := strings.ToLower(lastTypeName(typeName))
	if want == "" {
		return symbols
	}
	out := make([]Symbol, 0, len(symbols))
	for _, symbol := range symbols {
		container := symbol.Container
		if container == "" {
			container = containerFromQualified(symbol.QualifiedName, ".")
		}
		if strings.ToLower(lastTypeName(container)) == want {
			out = append(out, symbol)
		}
	}
	return out
}

func containerFromQualified(value, separator string) string {
	index := strings.LastIndex(value, separator)
	if index <= 0 {
		return ""
	}
	return value[:index]
}

func lastTypeName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, `\`, ".")
	if index := strings.LastIndex(value, "."); index >= 0 {
		value = value[index+1:]
	}
	return value
}

func declarationSymbol(stmt statement, language string, typeBody bool) (string, string, []string, bool) {
	if name, kind, ok := typeDeclaration(stmt.tokens); ok {
		return name, kind, nil, true
	}
	if !stmt.declaration && !hasFunctionKeyword(stmt.tokens) {
		if !typeBody || !looksLikeMethodDeclaration(stmt.tokens) {
			return "", "", nil, false
		}
	}
	name, params, ok := functionDeclaration(stmt.tokens, language)
	if !ok || name == "" {
		return "", "", nil, false
	}
	return name, "function", params, true
}

func looksLikeMethodDeclaration(tokens []token) bool {
	open := -1
	for i, tok := range tokens {
		if tok.kind == tokSymbol && tok.text == "=" {
			return false
		}
		if tok.kind == tokSymbol && tok.text == "(" {
			open = i
			break
		}
	}
	if open <= 0 {
		return false
	}
	switch strings.ToLower(tokens[0].text) {
	case "return", "if", "for", "while", "switch", "catch", "new", "await", "throw":
		return false
	}
	return true
}

func scopeIsTypeBody(scope int, scopeSymbol map[int]int, symbols []Symbol) bool {
	index, ok := scopeSymbol[scope]
	return ok && index < len(symbols) && isTypeSymbol(symbols[index])
}

func typeDeclaration(tokens []token) (string, string, bool) {
	for i, tok := range tokens {
		if tok.kind != tokIdent {
			continue
		}
		kind, ok := typeDeclarationKeywords[strings.ToLower(tok.text)]
		if !ok {
			continue
		}
		for j := i + 1; j < len(tokens) && j <= i+3; j++ {
			if tokens[j].kind != tokIdent {
				continue
			}
			name := tokens[j].text
			if name == "" || strings.EqualFold(name, "of") {
				continue
			}
			if kind == "type" {
				for k := j + 1; k < len(tokens) && k <= j+3; k++ {
					if tokens[k].kind == tokIdent {
						switch strings.ToLower(tokens[k].text) {
						case "struct", "interface":
							kind = strings.ToLower(tokens[k].text)
						}
						break
					}
				}
			}
			return name, kind, true
		}
		return "", "", false
	}
	return "", "", false
}

func hasFunctionKeyword(tokens []token) bool {
	for i, tok := range tokens {
		if tok.kind != tokIdent {
			continue
		}
		if functionDeclarationKeywords[strings.ToLower(tok.text)] {
			return true
		}
		if i > 8 {
			break
		}
	}
	return false
}

func startsWithAnnotation(tokens []token) bool {
	return len(tokens) > 0 && strings.HasPrefix(tokens[0].text, "@")
}

func directChildScope(index int, statements []statement, relations map[int]scopeRelation, parent int) (int, bool) {
	for j := index + 1; j < len(statements); j++ {
		candidate := statements[j].scope
		if candidate == parent {
			return 0, false
		}
		if relations[candidate].parent == parent {
			return candidate, true
		}
	}
	return 0, false
}

func endLineForScope(scope, fallback int, statements []statement, relations map[int]scopeRelation) int {
	end := fallback
	for _, stmt := range statements {
		if scopeInside(stmt.scope, scope, relations) && stmt.line > end {
			end = stmt.line
		}
	}
	return end
}

func nearestTypeContainer(scope int, relations map[int]scopeRelation, scopeSymbol map[int]int, symbols []Symbol) string {
	for depth := 0; depth < 32; depth++ {
		if index, ok := scopeSymbol[scope]; ok && index < len(symbols) && isTypeSymbol(symbols[index]) {
			name := symbols[index].QualifiedName
			if name == "" {
				name = symbols[index].Name
			}
			return name
		}
		relation, ok := relations[scope]
		if !ok || relation.parent < 0 {
			break
		}
		scope = relation.parent
	}
	return ""
}

func nearestCaller(scope int, relations map[int]scopeRelation, scopeSymbol map[int]int, symbols []Symbol) string {
	for depth := 0; depth < 32; depth++ {
		if index, ok := scopeSymbol[scope]; ok && index < len(symbols) {
			if symbols[index].Kind == "function" || symbols[index].Kind == "method" {
				name := symbols[index].QualifiedName
				if name == "" {
					name = symbols[index].Name
				}
				return name
			}
		}
		relation, ok := relations[scope]
		if !ok || relation.parent < 0 {
			break
		}
		scope = relation.parent
	}
	return "<file>"
}

func isTypeSymbol(item Symbol) bool {
	switch item.Kind {
	case "class", "interface", "struct", "enum", "record", "trait", "type":
		return true
	default:
		return false
	}
}

// goReceiverType extracts the receiver type from `func (u *User) Name(...)`.
// It is container evidence only; it does not create a type-resolved method set.
func goReceiverType(tokens []token) string {
	if len(tokens) < 4 || tokens[0].text != "func" || tokens[1].text != "(" {
		return ""
	}
	close := matchingParen(tokens, 1)
	if close < 0 {
		return ""
	}
	name := ""
	for i := 2; i < close; i++ {
		if tokens[i].kind != tokIdent {
			continue
		}
		switch strings.ToLower(tokens[i].text) {
		case "chan", "func", "map", "interface", "struct":
			continue
		default:
			name = tokens[i].text
		}
	}
	return name
}
