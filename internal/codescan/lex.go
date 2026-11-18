package codescan

import (
	"fmt"
	"strings"
	"unicode"
)

type tokenKind uint8

const (
	tokIdent tokenKind = iota
	tokString
	tokNumber
	tokSymbol
	tokNewline
)

// token is the language-independent IR unit. Comments never produce tokens;
// string literals produce exactly one token so annotation and route paths can
// still be read without mistaking string contents for code. Tokens derived
// from interpolated expressions (fromString) may act as taint sources or
// sanitizers only: string text is data, not executed code, so it must never
// produce sinks, routes, calls or parameter bindings.
type token struct {
	text       string
	kind       tokenKind
	line       int
	fromString bool
}

var multiSymbols = []string{"?->", "===", "!==", "<<<", "->", "::", "=>", "==", "!=", "<=", ">=", ".=", "+=", "-=", "*=", "??", "?.", "&&", "||", "++", "--", "<<", ">>", ":="}

func lex(src []byte, spec languageSpec, max int) ([]token, error) {
	runes := []rune(string(src))
	tokens := make([]token, 0, len(runes)/4+1)
	line := 1
	at := func(i int, value string) bool {
		needle := []rune(value)
		if i+len(needle) > len(runes) {
			return false
		}
		for j, r := range needle {
			if runes[i+j] != r {
				return false
			}
		}
		return true
	}
	appendToken := func(text string, kind tokenKind, tokenLine int) error {
		if len(tokens) >= max {
			return fmt.Errorf("%w: token limit %d", ErrLimit, max)
		}
		tokens = append(tokens, token{text: text, kind: kind, line: tokenLine})
		return nil
	}
	appendTokenMarked := func(text string, kind tokenKind, tokenLine int, fromString bool) error {
		if len(tokens) >= max {
			return fmt.Errorf("%w: token limit %d", ErrLimit, max)
		}
		tokens = append(tokens, token{text: text, kind: kind, line: tokenLine, fromString: fromString})
		return nil
	}

	for i := 0; i < len(runes); {
		r := runes[i]
		if r == '\n' {
			if err := appendToken("\n", tokNewline, line); err != nil {
				return nil, err
			}
			line++
			i++
			continue
		}
		if r == '\r' || (r != '\n' && unicode.IsSpace(r)) {
			i++
			continue
		}

		// Comments first: code-shaped text inside them must never be analyzed.
		comment := false
		for _, prefix := range spec.LineComments {
			if at(i, prefix) {
				for i < len(runes) && runes[i] != '\n' {
					i++
				}
				comment = true
				break
			}
		}
		if comment {
			continue
		}
		for _, pair := range spec.BlockComments {
			if !at(i, pair[0]) {
				continue
			}
			startLine := line
			i += len([]rune(pair[0]))
			closed := false
			for i < len(runes) {
				if at(i, pair[1]) {
					i += len([]rune(pair[1]))
					closed = true
					break
				}
				if runes[i] == '\n' {
					line++
				}
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated block comment at line %d", ErrLimit, startLine)
			}
			comment = true
			break
		}
		if comment {
			continue
		}

		// PHP open/close tags and heredoc/nowdoc are pre-token boundaries.
		if spec.Name == "php" {
			tag := false
			for _, marker := range spec.SkipTags {
				if at(i, marker) {
					i += len([]rune(marker))
					tag = true
					break
				}
			}
			if tag {
				continue
			}
			if at(i, "<<<") {
				j := i + 3
				for j < len(runes) && (runes[j] == ' ' || runes[j] == '\t') {
					j++
				}
				quote := rune(0)
				if j < len(runes) && (runes[j] == '\'' || runes[j] == '"') {
					quote = runes[j]
					j++
				}
				labelStart := j
				for j < len(runes) && isIdentRune(runes[j]) {
					j++
				}
				label := string(runes[labelStart:j])
				if quote != 0 && j < len(runes) && runes[j] == quote {
					j++
				}
				if label != "" {
					end := -1
					for k := j; k < len(runes); k++ {
						if runes[k] == '\n' {
							line++
						}
						if runes[k] == '\n' || k == j {
							start := k
							if runes[start] == '\n' {
								start++
							}
							trimmed := strings.TrimSpace(string(runes[start:minInt(start+len(label)+4, len(runes))]))
							if trimmed == label || strings.HasPrefix(trimmed, label+";") || strings.HasPrefix(trimmed, label+",") {
								end = minInt(start+len(label)+4, len(runes))
								break
							}
						}
					}
					if end < 0 {
						return nil, fmt.Errorf("%w: unterminated heredoc at line %d", ErrLimit, line)
					}
					i = end
					if err := appendToken("", tokString, line); err != nil {
						return nil, err
					}
					continue
				}
			}
		}

		// C# verbatim / interpolated strings.
		if spec.VerbatimPrefix != "" && at(i, spec.VerbatimPrefix+"\"") {
			startLine := line
			i += len([]rune(spec.VerbatimPrefix)) + 1
			var content []rune
			closed := false
			for i < len(runes) {
				if runes[i] == '"' {
					if i+1 < len(runes) && runes[i+1] == '"' {
						content = append(content, '"')
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				if runes[i] == '\n' {
					line++
				}
				content = append(content, runes[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated verbatim string at line %d", ErrLimit, startLine)
			}
			if err := appendInterpolatedOrString(string(content), spec, false, startLine, appendToken, appendTokenMarked); err != nil {
				return nil, err
			}
			continue
		}
		csharpInterpolated := false
		if spec.Name == "csharp" && at(i, "$\"") {
			i++
			csharpInterpolated = true
			// fall through to the ordinary double-quoted string handler
		}
		// Python f-string prefixes: a bare f/F identifier immediately followed
		// by a quote is the interpolation marker. r-strings and combined
		// prefixes stay opaque (documented limitation).
		pythonInterpolated := spec.Interpolation == "brace" && spec.Name == "python" &&
			len(tokens) > 0 && tokens[len(tokens)-1].kind == tokIdent &&
			(tokens[len(tokens)-1].text == "f" || tokens[len(tokens)-1].text == "F")

		// Triple-quoted (Python) and ordinary string literals.
		quoted := false
		for _, delimiter := range spec.TripleDelimiters {
			if !at(i, delimiter) {
				continue
			}
			startLine := line
			i += len([]rune(delimiter))
			var content []rune
			closed := false
			for i < len(runes) {
				if at(i, delimiter) {
					i += len([]rune(delimiter))
					closed = true
					break
				}
				if runes[i] == '\n' {
					line++
				}
				content = append(content, runes[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated triple string at line %d", ErrLimit, startLine)
			}
			if err := appendInterpolatedOrString(string(content), spec, pythonInterpolated, startLine, appendToken, appendTokenMarked); err != nil {
				return nil, err
			}
			quoted = true
			break
		}
		if quoted {
			continue
		}
		for _, delimiter := range spec.StringDelimiters {
			// Compare the rune at the current index, not the cached loop start:
			// the C# interpolated-prefix branch has already advanced i past '$'.
			if string(runes[i]) != delimiter {
				continue
			}
			startLine := line
			quote := runes[i]
			i++
			var content []rune
			closed := false
			for i < len(runes) {
				current := runes[i]
				if current == '\\' && i+1 < len(runes) {
					content = append(content, current, runes[i+1])
					i += 2
					continue
				}
				if current == quote {
					i++
					closed = true
					break
				}
				if current == '\n' {
					line++
				}
				content = append(content, current)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: unterminated string at line %d", ErrLimit, startLine)
			}
			interp := csharpInterpolated || pythonInterpolated
			switch spec.Interpolation {
			case "php_dollar":
				interp = interp || (spec.Name == "php" && quote == '"')
			case "dollar_brace":
				interp = interp || ((spec.Name == "javascript" || spec.Name == "typescript") && quote == '`')
			}
			if err := appendInterpolatedOrString(string(content), spec, interp, startLine, appendToken, appendTokenMarked); err != nil {
				return nil, err
			}
			quoted = true
			break
		}
		if quoted {
			continue
		}

		// Identifiers include PHP variables/namespaces and C# verbatim names.
		if isIdentStart(r) {
			startLine := line
			start := i
			i++
			for i < len(runes) && isIdentRune(runes[i]) {
				i++
			}
			if err := appendToken(string(runes[start:i]), tokIdent, startLine); err != nil {
				return nil, err
			}
			continue
		}
		if r >= '0' && r <= '9' {
			start := i
			for i < len(runes) && ((runes[i] >= '0' && runes[i] <= '9') || runes[i] == '.' || runes[i] == '_') {
				i++
			}
			if err := appendToken(string(runes[start:i]), tokNumber, line); err != nil {
				return nil, err
			}
			continue
		}

		symbol := string(r)
		for _, candidate := range multiSymbols {
			if at(i, candidate) {
				symbol = candidate
				break
			}
		}
		i += len([]rune(symbol))
		if err := appendToken(symbol, tokSymbol, line); err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

func isIdentStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '$' || r == '@' || r == '\\' || r >= 0x80
}

func isIdentRune(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Interpolation-aware string emission
// ---------------------------------------------------------------------------

// appendInterpolatedOrString emits one opaque string token, or — when the
// literal is an interpolated string in this language — the literal text
// segments plus re-tokenized interpolation expressions marked fromString.
func appendInterpolatedOrString(content string, spec languageSpec, interpolated bool, line int, plain func(string, tokenKind, int) error, marked func(string, tokenKind, int, bool) error) error {
	if !interpolated || spec.Interpolation == "" {
		return plain(content, tokString, line)
	}
	tokens, err := expandInterpolation(content, spec, line, MaxTokensPerFile)
	if err != nil {
		return err
	}
	for _, tok := range tokens {
		if err := marked(tok.text, tok.kind, tok.line, tok.fromString); err != nil {
			return err
		}
	}
	return nil
}

// expandInterpolation splits an interpolated literal into text segments
// (tokString, opaque) and expression fragments (re-tokenized with the same
// language spec, marked fromString). Escapes are treated as text; doubled
// braces are escaped literal braces in brace modes.
func expandInterpolation(content string, spec languageSpec, line, max int) ([]token, error) {
	runes := []rune(content)
	out := make([]token, 0, 8)
	add := func(text string, kind tokenKind) error {
		if len(out) >= max {
			return fmt.Errorf("%w: token limit %d", ErrLimit, max)
		}
		out = append(out, token{text: text, kind: kind, line: line, fromString: true})
		return nil
	}
	appendInner := func(inner []token) error {
		if len(out)+len(inner) > max {
			return fmt.Errorf("%w: token limit %d", ErrLimit, max)
		}
		for i := range inner {
			inner[i].line = line
			inner[i].fromString = true
		}
		out = append(out, inner...)
		return nil
	}
	subLex := func(expr string) ([]token, error) {
		inner, err := lex([]byte(expr), spec, max)
		if err != nil {
			// An expression the sub-lexer cannot tokenize stays opaque text:
			// string content is data, and a weird expression must never fail
			// the whole file analysis.
			return nil, nil
		}
		return inner, nil
	}
	flushText := func(start, end int) error {
		if end > start {
			return add(string(runes[start:end]), tokString)
		}
		return nil
	}
	isWordRune := func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
	}
	memberLenAt := func(i int) int {
		for _, op := range []string{"->", "::", "?->"} {
			if i+len(op) <= len(runes) && string(runes[i:i+len(op)]) == op &&
				i+len(op) < len(runes) && isWordRune(runes[i+len(op)]) {
				return len(op)
			}
		}
		return 0
	}
	i, start := 0, 0
	for i < len(runes) {
		c := runes[i]
		if c == '\\' && i+1 < len(runes) && spec.Interpolation != "brace" {
			// Escape pair stays literal text in php_dollar/dollar_brace modes.
			i += 2
			continue
		}
		if spec.Interpolation == "brace" {
			// Python/C#: {expr} interpolates; doubled braces are literals.
			if (c == '{' || c == '}') && i+1 < len(runes) && runes[i+1] == c {
				if err := flushText(start, i); err != nil {
					return nil, err
				}
				if err := add(string(c), tokString); err != nil {
					return nil, err
				}
				i += 2
				start = i
				continue
			}
			if c == '{' {
				close := matchDelim(runes, i, '{', '}')
				if close < 0 {
					i++
					continue
				}
				if err := flushText(start, i); err != nil {
					return nil, err
				}
				inner, err := subLex(string(runes[i+1 : close]))
				if err != nil {
					return nil, err
				}
				if err := appendInner(inner); err != nil {
					return nil, err
				}
				i = close + 1
				start = i
				continue
			}
			i++
			continue
		}
		if spec.Interpolation == "dollar_brace" && c == '$' && i+1 < len(runes) && runes[i+1] == '{' {
			close := matchDelim(runes, i+1, '{', '}')
			if close < 0 {
				i++
				continue
			}
			if err := flushText(start, i); err != nil {
				return nil, err
			}
			inner, err := subLex(string(runes[i+2 : close]))
			if err != nil {
				return nil, err
			}
			if err := appendInner(inner); err != nil {
				return nil, err
			}
			i = close + 1
			start = i
			continue
		}
		if spec.Interpolation == "php_dollar" && c == '{' && i+1 < len(runes) && runes[i+1] == '$' {
			close := matchDelim(runes, i, '{', '}')
			if close < 0 {
				i++
				continue
			}
			if err := flushText(start, i); err != nil {
				return nil, err
			}
			inner, err := subLex(string(runes[i+1 : close]))
			if err != nil {
				return nil, err
			}
			if err := appendInner(inner); err != nil {
				return nil, err
			}
			i = close + 1
			start = i
			continue
		}
		if spec.Interpolation == "php_dollar" && c == '$' && i+1 < len(runes) && isWordRune(runes[i+1]) {
			if err := flushText(start, i); err != nil {
				return nil, err
			}
			j := i + 1
			for j < len(runes) && isWordRune(runes[j]) {
				j++
			}
			if err := add(string(runes[i:j]), tokIdent); err != nil {
				return nil, err
			}
			i = j
			for {
				opLen := memberLenAt(i)
				if opLen == 0 {
					break
				}
				opEnd := i + opLen
				k := opEnd
				for k < len(runes) && isWordRune(runes[k]) {
					k++
				}
				if k == opEnd {
					break
				}
				if err := add(string(runes[i:opEnd]), tokSymbol); err != nil {
					return nil, err
				}
				if err := add(string(runes[opEnd:k]), tokIdent); err != nil {
					return nil, err
				}
				i = k
			}
			if i < len(runes) && runes[i] == '[' {
				close := matchDelim(runes, i, '[', ']')
				if close > 0 {
					if err := add("[", tokSymbol); err != nil {
						return nil, err
					}
					inner, err := subLex(string(runes[i+1 : close]))
					if err != nil {
						return nil, err
					}
					if err := appendInner(inner); err != nil {
						return nil, err
					}
					if err := add("]", tokSymbol); err != nil {
						return nil, err
					}
					i = close + 1
				}
			}
			start = i
			continue
		}
		i++
	}
	if err := flushText(start, len(runes)); err != nil {
		return nil, err
	}
	return out, nil
}

// matchDelim returns the index of the delimiter matching the one at open, or
// -1 when unbalanced. Delimiters are single runes (braces or brackets).
func matchDelim(runes []rune, open int, openRune, closeRune rune) int {
	depth := 0
	for i := open; i < len(runes); i++ {
		switch runes[i] {
		case openRune:
			depth++
		case closeRune:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
