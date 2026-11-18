package dataflow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/scanner"
	"unicode/utf8"

	"trident/internal/javasrc"
	"trident/internal/project"
)

type javaToken struct {
	Text string
	Line int
	Tok  rune
}

type fileModel struct {
	Path     string
	SHA256   string
	Package  string
	Imports  map[string]string
	Wildcard []string
	Tokens   []javaToken
	Comments []javaToken
	Classes  []*classModel
	Nested   int
	// Notes discloses syntax the lexer had to neutralise. The only current
	// value is text_block_content_not_analyzed: the block is replaced by an
	// empty literal so the rest of the file stays analysable.
	Notes []string
}

type classModel struct {
	Name           string
	Symbol         string
	Kind           string
	Parents        []string
	Bases          []*classModel
	MissingParents []string
	File           *fileModel
	Fields         map[string]string
	Methods        []*methodModel
	Line           int
	EndLine        int
}

type methodModel struct {
	Name       string
	ReturnType string
	TypeParams []string
	Params     []paramModel
	BodyStart  int
	BodyEnd    int
	Line       int
	EndLine    int
	Class      *classModel
	File       *fileModel
}

type paramModel struct {
	Name    string
	Type    string
	Line    int
	Varargs bool
}

type projectModel struct {
	files       map[string]*fileModel
	classes     map[string]*classModel
	methods     map[string][]*methodModel
	simple      map[string][]*classModel
	imported    map[string]*classModel
	order       []*classModel
	methodCount int
	astHints    map[string]astCallHint
}

func parseProject(ctx context.Context, snapshot *project.Snapshot) ([]*fileModel, int, []string, error) {
	var javaFiles []string
	for _, entry := range snapshot.Manifest().Entries {
		if strings.HasSuffix(entry.Path, ".java") {
			javaFiles = append(javaFiles, entry.Path)
		}
	}
	sort.Strings(javaFiles)
	if len(javaFiles) > MaxJavaFiles {
		return nil, 0, nil, fmt.Errorf("%w: Java file count exceeds %d", ErrLimit, MaxJavaFiles)
	}
	files := make([]*fileModel, 0, len(javaFiles))
	rejected := 0
	var problems []string
	for _, file := range javaFiles {
		if err := ctx.Err(); err != nil {
			return nil, 0, nil, err
		}
		data, err := snapshot.ReadFile(ctx, file)
		if err != nil {
			return nil, 0, nil, err
		}
		parsed, err := parseJavaFile(file, manifestSHA(snapshot, file), data)
		if err != nil {
			rejected++
			problems = append(problems, "rejected_java:"+file+":"+errorReason(err))
			continue
		}
		files = append(files, parsed)
		for _, note := range parsed.Notes {
			problems = append(problems, note+":"+file)
		}
	}
	sort.Strings(problems)
	return files, rejected, dedupe(problems), nil
}

func manifestSHA(snapshot *project.Snapshot, file string) string {
	for _, entry := range snapshot.Manifest().Entries {
		if entry.Path == file {
			return entry.SHA256
		}
	}
	return ""
}

func errorReason(err error) string {
	if errors.Is(err, ErrLimit) {
		return "limit"
	}
	return "unsupported_or_malformed"
}

func parseJavaFile(file, sha256 string, data []byte) (*fileModel, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty Java source", ErrUnsupported)
	}
	if len(data) > MaxJavaBytes {
		return nil, fmt.Errorf("%w: Java source exceeds %d bytes", ErrLimit, MaxJavaBytes)
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("%w: non-UTF-8 or NUL byte", ErrUnsupported)
	}
	code, textBlocks, ok := javasrc.Strip(data)
	if !ok {
		return nil, fmt.Errorf("%w: unterminated Java text block", ErrUnsupported)
	}
	// tokenize on the rewritten source keeps every token line identical to the
	// original file because each block is replaced by a literal with the same
	// newline count.
	tokenSource, comments, err := tokenize(code)
	if err != nil {
		return nil, err
	}
	model := &fileModel{Path: file, SHA256: sha256, Tokens: tokenSource, Comments: comments, Imports: map[string]string{}}
	if textBlocks > 0 {
		model.Notes = append(model.Notes, javasrc.TextBlockNote)
	}
	model.parsePackage()
	model.parseImports()
	model.parseClasses()
	return model, nil
}

func tokenize(data []byte) ([]javaToken, []javaToken, error) {
	var s scanner.Scanner
	s.Init(bytes.NewReader(data))
	s.Mode = scanner.ScanIdents | scanner.ScanFloats | scanner.ScanChars | scanner.ScanStrings | scanner.ScanRawStrings | scanner.ScanComments
	var lexical string
	s.Error = func(_ *scanner.Scanner, msg string) {
		if lexical == "" {
			lexical = msg
		}
	}
	var code, comments []javaToken
	count := 0
	for {
		tok := s.Scan()
		if tok == scanner.EOF {
			break
		}
		count++
		if count > MaxJavaTokens {
			return nil, nil, fmt.Errorf("%w: Java token count", ErrLimit)
		}
		token := javaToken{Text: s.TokenText(), Line: s.Position.Line, Tok: tok}
		if tok == scanner.Comment {
			comments = append(comments, token)
		} else {
			code = append(code, token)
		}
	}
	if lexical != "" {
		return nil, nil, fmt.Errorf("%w: Java lexical error", ErrUnsupported)
	}
	return code, comments, nil
}

func (f *fileModel) parsePackage() {
	for i := 0; i < len(f.Tokens); i++ {
		if f.Tokens[i].Text == "{" {
			return
		}
		if f.Tokens[i].Text != "package" {
			continue
		}
		var name strings.Builder
		for j := i + 1; j < len(f.Tokens) && f.Tokens[j].Text != ";"; j++ {
			name.WriteString(f.Tokens[j].Text)
		}
		f.Package = name.String()
		return
	}
}

func (f *fileModel) parseImports() {
	for i := 0; i < len(f.Tokens); i++ {
		if f.Tokens[i].Text == "{" {
			return
		}
		if f.Tokens[i].Text != "import" {
			continue
		}
		j := i + 1
		if j < len(f.Tokens) && f.Tokens[j].Text == "static" {
			continue
		}
		var name strings.Builder
		wildcard := false
		for ; j < len(f.Tokens) && f.Tokens[j].Text != ";"; j++ {
			if f.Tokens[j].Text == "*" {
				wildcard = true
				continue
			}
			name.WriteString(f.Tokens[j].Text)
		}
		importName := name.String()
		if importName == "" {
			continue
		}
		if wildcard {
			f.Wildcard = append(f.Wildcard, importName)
			continue
		}
		parts := strings.Split(importName, ".")
		f.Imports[parts[len(parts)-1]] = importName
	}
}

func (f *fileModel) parseClasses() {
	for i := 0; i < len(f.Tokens); {
		if f.Tokens[i].Text == "@" && i+1 < len(f.Tokens) && f.Tokens[i+1].Text == "interface" {
			open := findNext(f.Tokens, i+2, "{")
			if open < 0 {
				return
			}
			close := matchDelimiter(f.Tokens, open, "{", "}")
			if close < 0 {
				return
			}
			i = close + 1
			continue
		}
		if f.Tokens[i].Text == "@" {
			i = skipAnnotation(f.Tokens, i, len(f.Tokens))
			continue
		}
		if !isTypeKeyword(f.Tokens[i].Text) || i+1 >= len(f.Tokens) || f.Tokens[i+1].Tok != scanner.Ident {
			i++
			continue
		}
		name := f.Tokens[i+1].Text
		open := findNext(f.Tokens, i+2, "{")
		if open < 0 {
			return
		}
		close := matchDelimiter(f.Tokens, open, "{", "}")
		if close < 0 {
			return
		}
		f.Classes = append(f.Classes, f.parseClass(name, f.Tokens[i].Text, i, open, close))
		i = close + 1
	}
}

func (f *fileModel) parseClass(name, kind string, headerStart, bodyOpen, bodyClose int) *classModel {
	class := &classModel{
		Name:    name,
		Symbol:  qualify(f.Package, name),
		Kind:    kind,
		Parents: parseParents(f.Tokens[headerStart+2 : bodyOpen]),
		File:    f,
		Fields:  map[string]string{},
		Line:    f.Tokens[bodyOpen].Line,
		EndLine: f.Tokens[bodyClose].Line,
	}
	for i := bodyOpen + 1; i < bodyClose; {
		// Skip annotations and modifiers before a member.
		for i < bodyClose {
			if f.Tokens[i].Text == "@" {
				i = skipAnnotation(f.Tokens, i, bodyClose)
				continue
			}
			if isModifier(f.Tokens[i].Text) {
				i++
				continue
			}
			break
		}
		if i >= bodyClose {
			break
		}
		if isTypeKeyword(f.Tokens[i].Text) {
			open := findNext(f.Tokens, i+1, "{")
			if open >= 0 && open < bodyClose {
				close := matchDelimiter(f.Tokens, open, "{", "}")
				if close >= 0 && close <= bodyClose {
					f.Nested++
					i = close + 1
					continue
				}
			}
			i = skipMember(f.Tokens, i, bodyClose)
			continue
		}
		// Locate a method-like '(' before the first top-level field delimiter.
		j := i
		for j < bodyClose {
			switch f.Tokens[j].Text {
			case "(":
				goto method
			case "=", ";", "{", "}":
				goto field
			}
			j++
		}
	method:
		if j < bodyClose && f.Tokens[j].Text == "(" && j-1 >= i && f.Tokens[j-1].Tok == scanner.Ident {
			nameIndex := j - 1
			paramsEnd := matchDelimiter(f.Tokens, j, "(", ")")
			if paramsEnd < 0 || paramsEnd >= bodyClose {
				i = skipMember(f.Tokens, i, bodyClose)
				continue
			}
			k := paramsEnd + 1
			for k < bodyClose && f.Tokens[k].Text != "{" && f.Tokens[k].Text != ";" {
				k++
			}
			if k >= bodyClose {
				i = bodyClose
				continue
			}
			methodName := f.Tokens[nameIndex].Text
			bodyStart, bodyEnd := -1, -1
			if f.Tokens[k].Text == "{" {
				bodyStart = k
				bodyEnd = matchDelimiter(f.Tokens, k, "{", "}")
				if bodyEnd < 0 || bodyEnd > bodyClose {
					i = bodyClose
					continue
				}
			}
			if methodName != class.Name {
				class.Methods = append(class.Methods, &methodModel{
					Name:       methodName,
					ReturnType: methodReturnType(f.Tokens, i, nameIndex),
					TypeParams: methodTypeParams(f.Tokens, i, nameIndex),
					Params:     parseParams(f.Tokens[j+1 : paramsEnd]),
					BodyStart:  bodyStart,
					BodyEnd:    bodyEnd,
					Line:       f.Tokens[nameIndex].Line,
					EndLine:    tokenLine(f.Tokens, bodyEnd, f.Tokens[nameIndex].Line),
					Class:      class,
					File:       f,
				})
			}
			if bodyEnd >= 0 {
				i = bodyEnd + 1
			} else {
				i = k + 1
			}
			continue
		}
	field:
		// Field or initializer: capture a simple name -> type mapping.
		if j < bodyClose && (f.Tokens[j].Text == "=" || f.Tokens[j].Text == ";") {
			field := f.Tokens[i:j]
			if name, fieldType := fieldNameType(field); name != "" && fieldType != "" {
				class.Fields[name] = fieldType
			}
			if f.Tokens[j].Text == "=" {
				i = skipToSemicolon(f.Tokens, j+1, bodyClose)
			} else {
				i = j + 1
			}
			continue
		}
		i = skipMember(f.Tokens, i, bodyClose)
	}
	return class
}

func parseParents(tokens []javaToken) []string {
	var parents []string
	depth := 0
	expect := false
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token.Text == "@" {
			i = skipAnnotation(tokens, i, len(tokens)) - 1
			continue
		}
		switch token.Text {
		case "<":
			depth++
			continue
		case ">":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth > 0 {
			continue
		}
		switch token.Text {
		case "extends", "implements":
			expect = true
			continue
		case "permits":
			expect = false
			continue
		case ",":
			continue
		case ".":
			if expect {
				continue // qualified parent names keep the last simple name
			}
		}
		if expect && token.Tok == scanner.Ident && !isModifier(token.Text) {
			if len(parents) > 0 && i >= 1 && tokens[i-1].Text == "." {
				parents[len(parents)-1] = token.Text
			} else {
				parents = append(parents, token.Text)
			}
			continue
		}
		expect = false
	}
	return parents
}

func methodReturnType(tokens []javaToken, start, nameIndex int) string {
	i := start
	if i < nameIndex && tokens[i].Text == "<" {
		close := matchDelimiter(tokens, i, "<", ">")
		if close <= i || close >= nameIndex {
			return ""
		}
		i = close + 1
	}
	for ; i < nameIndex; i++ {
		if tokens[i].Tok != scanner.Ident || isModifier(tokens[i].Text) {
			continue
		}
		return tokens[i].Text
	}
	return ""
}

func methodTypeParams(tokens []javaToken, start, nameIndex int) []string {
	if start >= nameIndex || tokens[start].Text != "<" {
		return nil
	}
	close := matchDelimiter(tokens, start, "<", ">")
	if close <= start || close >= nameIndex {
		return nil
	}
	var params []string
	expectName := false
	depth := 0
	for i := start; i <= close; i++ {
		switch tokens[i].Text {
		case "<":
			depth++
			if depth == 1 {
				expectName = true
			}
			continue
		case ">":
			depth--
			continue
		case ",":
			if depth == 1 {
				expectName = true
			}
			continue
		case "extends", "super":
			if depth == 1 {
				expectName = false
			}
			continue
		}
		if depth == 1 && expectName && tokens[i].Tok == scanner.Ident && !isModifier(tokens[i].Text) {
			params = append(params, tokens[i].Text)
			expectName = false
		}
	}
	return params
}

func hasVarargs(tokens []javaToken, nameIndex int) bool {
	if nameIndex >= 1 && tokens[nameIndex-1].Text == "..." {
		return true
	}
	return nameIndex >= 3 && tokens[nameIndex-1].Text == "." &&
		tokens[nameIndex-2].Text == "." && tokens[nameIndex-3].Text == "."
}

func parseParams(tokens []javaToken) []paramModel {
	segments := splitTopLevel(tokens)
	params := make([]paramModel, 0, len(segments))
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		clean := stripAnnotations(segment)
		clean = removeText(clean, "final")
		if len(clean) < 2 {
			continue
		}
		nameIndex := -1
		for i := len(clean) - 1; i >= 0; i-- {
			if clean[i].Tok == scanner.Ident {
				nameIndex = i
				break
			}
		}
		if nameIndex <= 0 {
			continue
		}
		typeName := ""
		typeIndex := -1
		for i := 0; i < nameIndex; i++ {
			if clean[i].Tok == scanner.Ident && !isModifier(clean[i].Text) {
				typeName = clean[i].Text
				typeIndex = i
				break
			}
		}
		if typeName == "" {
			continue
		}
		for i := typeIndex + 1; i < nameIndex; i++ {
			if clean[i].Text == "<" || clean[i].Text == "," {
				break
			}
			if clean[i].Text == "[" {
				typeName += "[]"
			}
		}
		params = append(params, paramModel{
			Name:    clean[nameIndex].Text,
			Type:    typeName,
			Line:    clean[nameIndex].Line,
			Varargs: hasVarargs(clean, nameIndex),
		})
	}
	return params
}

func fieldNameType(tokens []javaToken) (string, string) {
	clean := make([]javaToken, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Text == "@" {
			i = skipAnnotation(tokens, i, len(tokens)) - 1
			continue
		}
		clean = append(clean, tokens[i])
	}
	if len(clean) < 2 {
		return "", ""
	}
	nameIndex := -1
	for i := len(clean) - 1; i >= 0; i-- {
		if clean[i].Tok == scanner.Ident {
			nameIndex = i
			break
		}
	}
	if nameIndex <= 0 {
		return "", ""
	}
	fieldType := ""
	typeIndex := -1
	for i := 0; i < nameIndex; i++ {
		if clean[i].Tok == scanner.Ident && !isModifier(clean[i].Text) {
			fieldType = clean[i].Text
			typeIndex = i
			break
		}
	}
	if fieldType == "" {
		return "", ""
	}
	for i := typeIndex + 1; i < nameIndex; i++ {
		if clean[i].Text == "<" || clean[i].Text == "," {
			break
		}
		if clean[i].Text == "[" {
			fieldType += "[]"
		}
	}
	return clean[nameIndex].Text, fieldType
}

func newProjectModel(files []*fileModel) *projectModel {
	p := &projectModel{
		files:    map[string]*fileModel{},
		classes:  map[string]*classModel{},
		methods:  map[string][]*methodModel{},
		simple:   map[string][]*classModel{},
		imported: map[string]*classModel{},
	}
	for _, file := range files {
		p.files[file.Path] = file
		for _, class := range file.Classes {
			p.classes[class.Symbol] = class
			p.methods[class.Symbol] = append([]*methodModel{}, class.Methods...)
			p.simple[class.Name] = append(p.simple[class.Name], class)
			p.order = append(p.order, class)
			p.methodCount += len(class.Methods)
		}
	}
	imported := map[string][]*classModel{}
	for _, file := range files {
		for _, qualified := range file.Imports {
			if class := p.classes[qualified]; class != nil {
				imported[file.Path+"\x00"+class.Name] = append(imported[file.Path+"\x00"+class.Name], class)
			}
		}
	}
	for _, file := range files {
		for simple := range file.Imports {
			candidates := imported[file.Path+"\x00"+simple]
			if len(candidates) != 1 {
				continue
			}
			if existing, ok := p.imported[simple]; ok && existing != candidates[0] {
				// Two files import different classes with the same simple name;
				// a file-agnostic fallback would guess, so drop it.
				delete(p.imported, simple)
				continue
			}
			p.imported[simple] = candidates[0]
		}
	}
	sort.Slice(p.order, func(i, j int) bool { return p.order[i].Symbol < p.order[j].Symbol })
	for _, class := range p.order {
		for _, parent := range class.Parents {
			base := p.resolveClass(parent, class.File.Package)
			if base != nil && base != class {
				class.Bases = append(class.Bases, base)
			} else {
				class.MissingParents = append(class.MissingParents, parent)
			}
		}
	}
	return p
}

// classLineage lists a class followed by its transitive bases in stable order.
func classLineage(class *classModel) []*classModel {
	var lineage []*classModel
	seen := map[string]bool{}
	var walk func(*classModel)
	walk = func(current *classModel) {
		if current == nil || seen[current.Symbol] {
			return
		}
		seen[current.Symbol] = true
		lineage = append(lineage, current)
		for _, base := range current.Bases {
			walk(base)
		}
	}
	walk(class)
	return lineage
}

func fieldOwner(class *classModel, name string) *classModel {
	for _, current := range classLineage(class) {
		if _, ok := current.Fields[name]; ok {
			return current
		}
	}
	return nil
}

// methodCandidates collects same-name, same-arity methods from the class and
// its transitive bases, preserving subclass-first order.
func (p *projectModel) methodCandidates(class *classModel, methodName string, arity int) []*methodModel {
	var candidates []*methodModel
	seen := map[string]bool{}
	seenSignatures := map[string]bool{}
	var walk func(*classModel)
	walk = func(current *classModel) {
		if current == nil || seen[current.Symbol] {
			return
		}
		seen[current.Symbol] = true
		for _, method := range current.Methods {
			if method.Name != methodName || !acceptsArity(method.Params, arity) {
				continue
			}
			key := signatureKey(method.Params)
			if seenSignatures[key] {
				continue // subclass override of the same signature wins
			}
			seenSignatures[key] = true
			candidates = append(candidates, method)
		}
		for _, base := range current.Bases {
			walk(base)
		}
	}
	walk(class)
	return candidates
}

// resolveMethodCall resolves a call through inheritance and overloads using
// simple argument types. Unknown argument types never disqualify a candidate;
// a remaining tie is reported as ambiguous.
func (p *projectModel) resolveMethodCall(typeName, currentPackage, methodName string, argTypes []string) (*methodModel, int, string) {
	class := p.resolveClass(typeName, currentPackage)
	if class == nil {
		return nil, 0, ""
	}
	candidates := p.methodCandidates(class, methodName, len(argTypes))
	if len(candidates) == 0 {
		return nil, 0, ""
	}
	if len(candidates) == 1 {
		return candidates[0], 1, ""
	}
	type scored struct {
		method *methodModel
		exact  int
	}
	var compatible []scored
	for _, candidate := range candidates {
		exact, ok := p.matchArguments(argTypes, candidate.Params, currentPackage)
		if ok {
			compatible = append(compatible, scored{method: candidate, exact: exact})
		}
	}
	if len(compatible) == 0 {
		return nil, len(candidates), "overload"
	}
	bestExact := -1
	var best []*methodModel
	for _, item := range compatible {
		switch {
		case item.exact > bestExact:
			bestExact = item.exact
			best = []*methodModel{item.method}
		case item.exact == bestExact:
			best = append(best, item.method)
		}
	}
	if len(best) == 1 {
		return best[0], 1, ""
	}
	return nil, len(best), "overload"
}

func acceptsArity(params []paramModel, arity int) bool {
	if len(params) > 0 && params[len(params)-1].Varargs {
		return arity >= len(params)-1
	}
	return len(params) == arity
}

// matchArguments scores simple argument types against parameters, including
// varargs tails, lambdas, type variables and project/JDK assignability.
func (p *projectModel) matchArguments(argTypes []string, params []paramModel, currentPackage string) (int, bool) {
	variadic := len(params) > 0 && params[len(params)-1].Varargs
	fixed := len(params)
	if variadic {
		fixed = len(params) - 1
		if len(argTypes) < fixed {
			return 0, false
		}
	} else if len(argTypes) != len(params) {
		return 0, false
	}
	exact := 0
	for i, argType := range argTypes {
		paramType := params[len(params)-1].Type
		if i < fixed {
			paramType = params[i].Type
		}
		switch {
		case argType == "":
			// Unknown argument type cannot disqualify a candidate.
		case argType == paramType:
			exact++
		case p.typeCompatible(argType, paramType, currentPackage):
		default:
			return 0, false
		}
	}
	return exact, true
}

func (p *projectModel) typeCompatible(argType, paramType, currentPackage string) bool {
	if argType == "" || argType == paramType {
		return true
	}
	if argType == "lambda" {
		return p.isFunctionalInterface(paramType, currentPackage)
	}
	if argType == "null" {
		return !isPrimitiveType(paramType)
	}
	if isTypeVariable(paramType) || paramType == "Object" {
		return true
	}
	if jdkAssignable(argType, paramType) {
		return true
	}
	if argClass := p.resolveClass(argType, currentPackage); argClass != nil {
		if paramClass := p.resolveClass(paramType, currentPackage); paramClass != nil && classExtends(argClass, paramClass) {
			return true
		}
	}
	switch argType {
	case "int":
		return paramType == "long" || paramType == "double" || paramType == "float" ||
			paramType == "Integer" || paramType == "Number"
	case "long":
		return paramType == "double" || paramType == "float" || paramType == "Long" || paramType == "Number"
	case "float":
		return paramType == "double" || paramType == "Float" || paramType == "Number"
	case "double":
		return paramType == "Double" || paramType == "Number"
	case "char":
		return paramType == "int" || paramType == "long" || paramType == "double" || paramType == "float" ||
			paramType == "Character" || paramType == "Number"
	case "boolean":
		return paramType == "Boolean"
	case "String":
		return paramType == "CharSequence" || paramType == "Comparable"
	}
	return false
}

func isTypeVariable(name string) bool {
	return len(name) == 1 && name[0] >= 'A' && name[0] <= 'Z'
}

// jdkAssignable covers common JDK collection/CharSequence hierarchies without
// a classpath. Generic type arguments are erased and not modeled.
func jdkAssignable(argType, paramType string) bool {
	switch paramType {
	case "Iterable":
		return argType == "Collection" || argType == "List" || argType == "Set" ||
			argType == "ArrayList" || argType == "LinkedList" || argType == "HashSet" || argType == "TreeSet"
	case "Collection":
		return argType == "List" || argType == "Set" ||
			argType == "ArrayList" || argType == "LinkedList" || argType == "HashSet" || argType == "TreeSet"
	case "List":
		return argType == "ArrayList" || argType == "LinkedList" || argType == "List"
	case "Set":
		return argType == "HashSet" || argType == "TreeSet" || argType == "LinkedHashSet" || argType == "Set"
	case "Map":
		return argType == "HashMap" || argType == "TreeMap" || argType == "LinkedHashMap" || argType == "Map"
	case "CharSequence":
		return argType == "String" || argType == "StringBuilder" || argType == "StringBuffer"
	}
	return false
}

func (p *projectModel) isFunctionalInterface(typeName, currentPackage string) bool {
	switch typeName {
	case "Function", "BiFunction", "Consumer", "BiConsumer", "Supplier", "Predicate",
		"BiPredicate", "Runnable", "Callable", "Comparator", "UnaryOperator", "BinaryOperator":
		return true
	}
	class := p.resolveClass(typeName, currentPackage)
	return class != nil && class.Kind == "interface" && len(class.Methods) == 1
}

// substituteReturnType replaces a method-level type variable with the matching
// known argument type. Generic class parameters and bounds stay unmodeled.
func (p *projectModel) substituteReturnType(method *methodModel, argTypes []string) string {
	returnType := method.ReturnType
	if returnType == "" || returnType == "void" {
		return ""
	}
	if !isTypeVariable(returnType) {
		return returnType
	}
	declared := false
	for _, name := range method.TypeParams {
		if name == returnType {
			declared = true
			break
		}
	}
	if !declared {
		return returnType
	}
	for i, parameter := range method.Params {
		if parameter.Type != returnType || i >= len(argTypes) {
			continue
		}
		if argTypes[i] != "" {
			return argTypes[i]
		}
	}
	return ""
}

func isPrimitiveType(name string) bool {
	switch name {
	case "boolean", "byte", "short", "int", "long", "char", "float", "double":
		return true
	}
	return false
}

// dispatchMethod returns the unique concrete implementation of a bodyless
// interface/abstract method, or the number of ambiguous candidates.
func (p *projectModel) dispatchMethod(method *methodModel) (*methodModel, int) {
	if method == nil {
		return nil, 0
	}
	signature := make([]string, len(method.Params))
	for i, parameter := range method.Params {
		signature[i] = parameter.Type
	}
	var candidates []*methodModel
	seen := map[string]bool{}
	for _, class := range p.order {
		if class == method.Class || !classExtends(class, method.Class) {
			continue
		}
		for _, override := range class.Methods {
			if override.Name != method.Name || len(override.Params) != len(method.Params) || override.BodyStart < 0 {
				continue
			}
			if _, ok := p.matchArguments(signature, override.Params, method.Class.File.Package); !ok {
				continue
			}
			key := override.Class.Symbol + "." + override.Name + ":" + signatureKey(override.Params)
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, override)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], 1
	}
	return nil, len(candidates)
}

func signatureKey(params []paramModel) string {
	parts := make([]string, len(params))
	for i, parameter := range params {
		parts[i] = parameter.Type
	}
	return strings.Join(parts, ",")
}

func classHasMissingParents(class *classModel) bool {
	for _, current := range classLineage(class) {
		if len(current.MissingParents) > 0 {
			return true
		}
	}
	return false
}

func (p *projectModel) hasUnresolvedParent(typeName, currentPackage string) bool {
	return classHasMissingParents(p.resolveClass(typeName, currentPackage))
}

func classExtends(class, base *classModel) bool {
	if class == nil || base == nil {
		return false
	}
	for _, current := range classLineage(class) {
		if current == base {
			return true
		}
	}
	return false
}

func (p *projectModel) class(symbol string) *classModel {
	return p.classes[symbol]
}

func (c *classModel) method(name string, arity int) *methodModel {
	var found *methodModel
	for _, method := range c.Methods {
		if method.Name == name && len(method.Params) == arity {
			if found != nil {
				return nil // ambiguous overload for this bounded slice
			}
			found = method
		}
	}
	if found == nil && arity < 0 {
		for _, method := range c.Methods {
			if method.Name == name {
				if found != nil {
					return nil
				}
				found = method
			}
		}
	}
	return found
}

func (p *projectModel) resolveClass(typeName, currentPackage string) *classModel {
	if typeName == "" {
		return nil
	}
	if currentPackage != "" {
		if class := p.classes[currentPackage+"."+typeName]; class != nil {
			return class
		}
	}
	if class := p.imported[typeName]; class != nil {
		return class
	}
	candidates := p.simple[typeName]
	if len(candidates) == 1 {
		return candidates[0]
	}
	return nil
}

// resolveCallWithTypes resolves a call through inheritance, overloads and, for
// a bodyless interface/abstract method, to a unique concrete implementation.
// The reason is "overload" or "dispatch" when candidates remain ambiguous.
func (p *projectModel) resolveCallWithTypes(typeName, currentPackage, methodName string, argTypes []string) (*methodModel, int, string) {
	method, ambiguous, reason := p.resolveMethodCall(typeName, currentPackage, methodName, argTypes)
	if method == nil {
		return nil, ambiguous, reason
	}
	if method.BodyStart >= 0 {
		return method, 1, ""
	}
	dispatched, count := p.dispatchMethod(method)
	if dispatched != nil {
		return dispatched, count, ""
	}
	if count > 1 {
		return nil, count, "dispatch"
	}
	return nil, 0, ""
}

func skipAnnotation(tokens []javaToken, i, end int) int {
	if i >= end || tokens[i].Text != "@" || i+1 >= end || tokens[i+1].Tok != scanner.Ident {
		return i + 1
	}
	i += 2
	for i+1 < end && tokens[i].Text == "." && tokens[i+1].Tok == scanner.Ident {
		i += 2
	}
	if i < end && tokens[i].Text == "(" {
		if close := matchDelimiter(tokens, i, "(", ")"); close >= 0 {
			return close + 1
		}
		return end
	}
	return i
}

func stripAnnotations(tokens []javaToken) []javaToken {
	out := make([]javaToken, 0, len(tokens))
	for i := 0; i < len(tokens); {
		if tokens[i].Text == "@" {
			i = skipAnnotation(tokens, i, len(tokens))
			continue
		}
		out = append(out, tokens[i])
		i++
	}
	return out
}

func removeText(tokens []javaToken, text string) []javaToken {
	out := tokens[:0]
	for _, token := range tokens {
		if token.Text != text {
			out = append(out, token)
		}
	}
	return out
}

func splitTopLevel(tokens []javaToken) [][]javaToken {
	var segments [][]javaToken
	if len(tokens) == 0 {
		return segments
	}
	start := 0
	depth := 0
	for i, token := range tokens {
		switch token.Text {
		case "(", "[", "{", "<":
			depth++
		case ")", "]", "}", ">":
			if depth > 0 {
				depth--
			}
		}
		if token.Text == "," && depth == 0 {
			segments = append(segments, tokens[start:i])
			start = i + 1
		}
	}
	segments = append(segments, tokens[start:])
	return segments
}

func matchDelimiter(tokens []javaToken, start int, open, close string) int {
	if start < 0 || start >= len(tokens) || tokens[start].Text != open {
		return -1
	}
	depth := 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].Text {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func findNext(tokens []javaToken, start int, text string) int {
	for i := start; i < len(tokens); i++ {
		if tokens[i].Text == text {
			return i
		}
	}
	return -1
}

func skipMember(tokens []javaToken, start, end int) int {
	for i := start; i < end; i++ {
		switch tokens[i].Text {
		case ";":
			return i + 1
		case "{":
			close := matchDelimiter(tokens, i, "{", "}")
			if close < 0 || close >= end {
				return end
			}
			return close + 1
		case "}":
			return i + 1
		}
	}
	return end
}

func skipToSemicolon(tokens []javaToken, start, end int) int {
	depth := 0
	for i := start; i < end; i++ {
		switch tokens[i].Text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			if depth > 0 {
				depth--
			}
		}
		if tokens[i].Text == ";" && depth == 0 {
			return i + 1
		}
	}
	return end
}

func isTypeKeyword(text string) bool {
	switch text {
	case "class", "interface", "enum", "record":
		return true
	}
	return false
}

func isModifier(text string) bool {
	switch text {
	case "public", "protected", "private", "abstract", "static", "final", "strictfp", "sealed", "transient", "volatile", "synchronized", "native", "default":
		return true
	}
	return false
}

func tokenLine(tokens []javaToken, index, fallback int) int {
	if index >= 0 && index < len(tokens) {
		return tokens[index].Line
	}
	return fallback
}

func qualify(pkg, name string) string {
	if pkg == "" {
		return name
	}
	return pkg + "." + name
}
