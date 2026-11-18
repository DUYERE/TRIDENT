package codescan

import (
	"fmt"
	"strings"
)

// statement is one IR statement. scope is an integer id; parent relations are
// kept separately so nested blocks inherit taint at block entry.
type statement struct {
	line        int
	tokens      []token
	scope       int
	occurs      []chainInfo
	calls       []callInfo
	assign      *assignInfo
	head        string
	declaration bool // method/function signature header, not executable code
}

var declarationHeads = map[string]bool{
	"public": true, "private": true, "protected": true, "static": true,
	"final": true, "abstract": true, "virtual": true, "override": true,
	"async": true, "func": true, "def": true, "function": true,
	"class": true, "interface": true, "struct": true, "type": true,
	"export": true, "module": true,
}

type scopeRelation struct {
	parent int
	depth  int
}

type chainInfo struct {
	segs       []string
	full       string
	short      string
	start      int
	end        int
	kind       string
	line       int
	annotated  bool // leading @ (Java/C# annotation, Razor or PHP suppression)
	fromString bool // derived from an interpolated string expression; source-only
}

type callInfo struct {
	full  string
	short string
	args  [][]token
	open  int
	close int
	line  int
}

type assignInfo struct {
	target string
	full   string
	op     string
	rhs    []token
	lhs    []token
	line   int
}

// splitStatements converts the token stream into statements and scope ids.
// Brace languages scope by {} blocks; Python is file-scoped (documented as a
// limitation) because indentation-based scoping is not modeled.
func splitStatements(tokens []token, spec languageSpec, max int) ([]statement, map[int]scopeRelation, error) {
	out := make([]statement, 0, 64)
	relations := map[int]scopeRelation{0: {parent: -1, depth: 0}}
	stack := []int{0}
	nextScope := 1
	cur := make([]token, 0, 16)
	curLine := 0
	parenDepth := 0
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		if len(out) >= max {
			return fmt.Errorf("%w: statement limit %d", ErrLimit, max)
		}
		copied := append([]token(nil), cur...)
		stmt := statement{line: curLine, tokens: copied, scope: stack[len(stack)-1]}
		prepareStatement(&stmt, spec)
		out = append(out, stmt)
		cur = cur[:0]
		return nil
	}
	for _, tok := range tokens {
		if tok.kind == tokNewline {
			// A newline ends a statement unless the previous line is an open
			// expression (unclosed call/array or a trailing operator). This is
			// required for Go/JS, which have no mandatory semicolons.
			if len(cur) > 0 && parenDepth == 0 && !endsWithContinuation(cur) {
				if err := flush(); err != nil {
					return nil, nil, err
				}
			}
			continue
		}
		if tok.kind == tokSymbol {
			switch tok.text {
			case "(", "[":
				parenDepth++
			case ")", "]":
				if parenDepth > 0 {
					parenDepth--
				}
			case "{":
				if spec.Braces {
					if err := flush(); err != nil {
						return nil, nil, err
					}
					parenDepth = 0
					id := nextScope
					nextScope++
					relations[id] = scopeRelation{parent: stack[len(stack)-1], depth: len(stack)}
					stack = append(stack, id)
					continue
				}
			case "}":
				if spec.Braces {
					if err := flush(); err != nil {
						return nil, nil, err
					}
					parenDepth = 0
					if len(stack) > 1 {
						stack = stack[:len(stack)-1]
					}
					continue
				}
			case ";":
				if err := flush(); err != nil {
					return nil, nil, err
				}
				parenDepth = 0
				continue
			}
		}
		if len(cur) == 0 {
			curLine = tok.line
		}
		cur = append(cur, tok)
	}
	if err := flush(); err != nil {
		return nil, nil, err
	}
	return out, relations, nil
}

func prepareStatement(stmt *statement, spec languageSpec) {
	tokens := stmt.tokens
	if len(tokens) == 0 {
		return
	}
	if tokens[0].kind == tokIdent {
		stmt.head = tokens[0].text
	}
	stmt.occurs = dropFromStringChains(chainsIn(tokens, spec))
	stmt.calls = callsIn(tokens, spec, stmt.occurs)
	stmt.assign = assignmentIn(tokens, spec, stmt.occurs)
	head := strings.TrimPrefix(strings.ToLower(stmt.head), "@")
	stmt.declaration = declarationHeads[head] && stmt.assign == nil
}

// dropFromStringChains removes chains derived from interpolated string
// expressions. String text is runtime data, not code: it may feed taint
// sources or sanitizers inside expression evaluation, but it must never
// declare sinks, routes, calls or annotation parameter bindings.
func dropFromStringChains(chains []chainInfo) []chainInfo {
	out := chains[:0]
	for _, chain := range chains {
		if !chain.fromString {
			out = append(out, chain)
		}
	}
	return out
}

var continuationSymbols = map[string]bool{
	"+": true, "-": true, "*": true, "/": true, "%": true, ".": true, ",": true,
	"=": true, "&&": true, "||": true, "??": true, "?": true, "->": true, "::": true,
	"?.": true, "?->": true, "=>": true, "+=": true, "-=": true, "*=": true, ".=": true,
	":=": true, "==": true, "!=": true, "===": true, "!==": true, "<": true, ">": true,
	"<=": true, ">=": true, "&": true, "|": true, "^": true, "!": true, "~": true,
	"(": true, "[": true, "{": true,
}

func endsWithContinuation(tokens []token) bool {
	return len(tokens) > 0 && tokens[len(tokens)-1].kind == tokSymbol && continuationSymbols[tokens[len(tokens)-1].text]
}

func isMemberOp(text string) bool {
	return text == "." || text == "->" || text == "::" || text == "?." || text == "?->"
}

func chainsIn(tokens []token, spec languageSpec) []chainInfo {
	out := make([]chainInfo, 0, len(tokens))
	for i, tok := range tokens {
		if tok.kind != tokIdent {
			continue
		}
		// '@' is an annotation/decorator or PHP suppression prefix, not part of
		// a symbol name. Normalizing it here keeps rules identical across C#,
		// Java, Razor views and PHP without a language-specific matcher.
		name := tok.text
		leadingAt := len(name) > 1 && name[0] == '@'
		if leadingAt {
			name = name[1:]
		}
		segs := []string{name}
		start := i
		last := i // chain end must stay on the symbol itself, not the leftmost receiver
		cursor := i
		for cursor-2 >= 0 && len(segs) < MaxChainSegments && isMemberOp(tokens[cursor-1].text) && tokens[cursor-2].kind == tokIdent {
			previous := tokens[cursor-2].text
			if len(previous) > 1 && previous[0] == '@' {
				previous = previous[1:]
			}
			segs = append([]string{previous}, segs...)
			start = cursor - 2
			cursor -= 2
		}
		next := ""
		if last+1 < len(tokens) {
			next = tokens[last+1].text
		}
		kind := "identifier"
		switch {
		case next == "(":
			kind = "call"
		case next == "[", isMemberOp(next):
			kind = "access"
		}
		out = append(out, chainInfo{
			segs: segs, full: strings.Join(segs, "."), short: segs[len(segs)-1],
			start: start, end: last, kind: kind, line: tok.line, annotated: leadingAt,
			fromString: tok.fromString,
		})
	}
	return out
}

func callsIn(tokens []token, spec languageSpec, occurs []chainInfo) []callInfo {
	out := make([]callInfo, 0, 8)
	for _, chain := range occurs {
		if chain.kind != "call" {
			continue
		}
		open := chain.end + 1
		if open >= len(tokens) || tokens[open].text != "(" {
			continue
		}
		close := matchingParen(tokens, open)
		if close < 0 {
			continue
		}
		out = append(out, callInfo{
			full: chain.full, short: chain.short,
			args: splitArgs(tokens[open+1 : close]), open: open, close: close, line: chain.line,
		})
	}
	return out
}

func matchingParen(tokens []token, open int) int {
	depth := 0
	for i := open; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func splitArgs(tokens []token) [][]token {
	args := make([][]token, 0, 4)
	depth := 0
	start := 0
	for i, tok := range tokens {
		switch tok.text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			if depth > 0 {
				depth--
			}
		case ",":
			if depth == 0 {
				args = append(args, append([]token(nil), tokens[start:i]...))
				start = i + 1
			}
		}
	}
	if start < len(tokens) {
		args = append(args, append([]token(nil), tokens[start:]...))
	}
	if len(args) == 0 {
		args = append(args, []token{})
	}
	return args
}

var declarationStopWords = map[string]bool{
	"throws": true, "implements": true, "extends": true, "where": true,
}

var nonAssignmentHeads = map[string]bool{
	"if": true, "while": true, "for": true, "foreach": true, "switch": true,
	"return": true, "echo": true, "print": true, "case": true, "elif": true,
	"else": true, "throw": true, "yield": true, "assert": true,
}

func assignmentIn(tokens []token, spec languageSpec, occurs []chainInfo) *assignInfo {
	opIndex := -1
	op := ""
	for i, tok := range tokens {
		if tok.kind != tokSymbol {
			continue
		}
		switch tok.text {
		case "=", ".=", "+=", ":=":
			opIndex, op = i, tok.text
		}
		if opIndex >= 0 {
			break
		}
	}
	if opIndex <= 0 {
		return nil
	}
	lhs := tokens[:opIndex]
	rhs := tokens[opIndex+1:]
	if len(rhs) == 0 {
		return nil
	}
	for _, tok := range lhs {
		if tok.kind == tokIdent && nonAssignmentHeads[strings.ToLower(tok.text)] {
			return nil
		}
		if tok.kind == tokSymbol && tok.text == "(" {
			return nil
		}
	}
	// Type annotations (`: string`) and declaration keywords must not become
	// the assignment target. Member assignments keep their full chain so
	// `cmd.CommandText = tainted` can be matched by assign sinks.
	lhsEnd := opIndex
	for i, tok := range lhs {
		if tok.kind == tokSymbol && tok.text == ":" {
			lhsEnd = i
			break
		}
	}
	hasMember := false
	hasComma := false
	for _, tok := range lhs[:lhsEnd] {
		if tok.kind == tokSymbol && isMemberOp(tok.text) {
			hasMember = true
		}
		if tok.kind == tokSymbol && tok.text == "," {
			hasComma = true
		}
	}
	var target, full string
	for _, chain := range occurs {
		if chain.end < lhsEnd && chain.end >= 0 {
			target, full = chain.short, chain.full
		}
	}
	if !hasMember && len(lhs) > 0 {
		idents := make([]int, 0, 4)
		for i := 0; i < lhsEnd; i++ {
			if lhs[i].kind == tokIdent {
				idents = append(idents, i)
			}
		}
		pick := -1
		if strings.ToLower(lhs[0].text) == "var" && len(idents) >= 2 {
			pick = idents[1]
		} else if hasComma && len(idents) >= 1 {
			pick = idents[0]
		}
		if pick >= 0 {
			target = lhs[pick].text
			full = target
			for _, chain := range occurs {
				if chain.end == pick {
					full = chain.full
				}
			}
		}
	}
	if target == "" {
		return nil
	}
	return &assignInfo{target: target, full: full, op: op, rhs: rhs, lhs: lhs, line: tokens[opIndex].line}
}

func splitSelector(selector string) []string {
	normalized := strings.NewReplacer("->", ".", "::", ".", "?.", ".", "?->", ".").Replace(selector)
	parts := strings.Split(normalized, ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// selectorMatches checks a pattern selector against a call/access chain.
// Selectors may be short names (suffix match), qualified names (suffix match)
// or prefixes (for property reads such as req.query.name). '*' matches one
// segment. Matching is case-insensitive for PHP.
func selectorMatches(selector string, chain chainInfo, language string) bool {
	want := splitSelector(selector)
	if len(want) == 0 || len(want) > MaxChainSegments {
		return false
	}
	have := make([]string, len(chain.segs))
	for i, seg := range chain.segs {
		have[i] = normalizeSelectorName(language, seg)
	}
	for i, seg := range want {
		want[i] = normalizeSelectorName(language, seg)
	}
	if len(want) <= len(have) {
		if segmentMatch(want, have[len(have)-len(want):]) || segmentMatch(want, have[:len(want)]) {
			return true
		}
	}
	return false
}

func segmentMatch(want, have []string) bool {
	if len(want) != len(have) {
		return false
	}
	for i := range want {
		if want[i] != "*" && want[i] != have[i] {
			return false
		}
	}
	return true
}

// normalizeSelectorName keeps PHP's case folding and also matches a namespaced
// class by its short name (e.g. \think\Route against the selector Route::rule).
func normalizeSelectorName(language, name string) string {
	name = normalizeName(language, name)
	if language == "php" {
		if index := strings.LastIndex(name, "\\"); index >= 0 {
			return name[index+1:]
		}
	}
	return name
}

func patternMatches(pattern PatternSpec, chain chainInfo, language string) bool {
	switch pattern.Kind {
	case "any", "identifier":
	case "call":
		if chain.kind != "call" {
			return false
		}
	case "access":
		if chain.kind != "access" && chain.kind != "identifier" {
			return false
		}
	default:
		return false
	}
	for _, name := range pattern.Names {
		if selectorMatches(name, chain, language) {
			return true
		}
	}
	return false
}

func chainHasName(chain chainInfo, names []string, language string) bool {
	for _, name := range names {
		if selectorMatches(name, chain, language) {
			return true
		}
	}
	return false
}
