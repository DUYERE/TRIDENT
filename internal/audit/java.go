package audit

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/scanner"
	"unicode/utf8"
)

type javaToken struct {
	Text string
	Line int
	Tok  rune
}

type annotationArg struct {
	Key    string
	Tokens []javaToken
}

type annotation struct {
	Name string
	Line int
	Args []annotationArg
}

type javaParser struct {
	file        string
	sha256      string
	pkg         string
	code        []javaToken
	comments    []javaToken
	Controllers []Controller
	Endpoints   []Endpoint
	Problems    []string
	Nested      int
}

type classInfo struct {
	Name           string
	Symbol         string
	Line           int
	EndLine        int
	Annotations    []string
	Controller     bool
	BasePaths      []string
	BasePathStatus string
}

type parsedJava struct {
	Controllers   []Controller
	Endpoints     []Endpoint
	Problems      []string
	NestedClasses int
}

const (
	MaxJavaAnnotationArgs = 64
	MaxJavaParameters     = 64
)

var mappingAnnotations = map[string]bool{
	"RequestMapping": true,
	"GetMapping":     true,
	"PostMapping":    true,
	"PutMapping":     true,
	"DeleteMapping":  true,
	"PatchMapping":   true,
}

var bindingAnnotations = map[string]bool{
	"RequestParam":     true,
	"PathVariable":     true,
	"RequestBody":      true,
	"RequestHeader":    true,
	"CookieValue":      true,
	"ModelAttribute":   true,
	"RequestPart":      true,
	"SessionAttribute": true,
}

var httpMappingMethods = map[string][]string{
	"GetMapping":    {"GET"},
	"PostMapping":   {"POST"},
	"PutMapping":    {"PUT"},
	"DeleteMapping": {"DELETE"},
	"PatchMapping":  {"PATCH"},
}

func parseJavaFile(file, sha256 string, data []byte) (parsedJava, error) {
	if len(data) == 0 {
		return parsedJava{}, fmt.Errorf("%w: empty Java source", ErrUnsupported)
	}
	if len(data) > MaxJavaFileBytes {
		return parsedJava{}, fmt.Errorf("%w: Java source exceeds %d bytes", ErrLimit, MaxJavaFileBytes)
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return parsedJava{}, fmt.Errorf("%w: non-UTF-8 or NUL byte", ErrUnsupported)
	}
	// Java text blocks would need their own lexer state; refuse rather than
	// risk treating block content as code.
	if bytes.Contains(data, []byte(`"""`)) {
		return parsedJava{}, fmt.Errorf("%w: Java text blocks are unsupported", ErrUnsupported)
	}
	code, comments, err := tokenizeJava(data)
	if err != nil {
		return parsedJava{}, err
	}
	parser := &javaParser{file: file, sha256: sha256, code: code, comments: comments}
	parser.parsePackage()
	parser.parseTopLevel()
	return parsedJava{Controllers: parser.Controllers, Endpoints: parser.Endpoints, Problems: parser.Problems, NestedClasses: parser.Nested}, nil
}

func tokenizeJava(data []byte) ([]javaToken, []javaToken, error) {
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

func (p *javaParser) problem(code string) {
	p.Problems = append(p.Problems, code)
}

func (p *javaParser) parsePackage() {
	for i := 0; i < len(p.code); i++ {
		if p.code[i].Text == "{" {
			return
		}
		if p.code[i].Text != "package" {
			continue
		}
		var name strings.Builder
		for j := i + 1; j < len(p.code) && p.code[j].Text != ";"; j++ {
			name.WriteString(p.code[j].Text)
		}
		p.pkg = name.String()
		return
	}
}

func (p *javaParser) parseTopLevel() {
	var pending []annotation
	for i := 0; i < len(p.code); {
		token := p.code[i]
		if token.Text == "@" && i+1 < len(p.code) && p.code[i+1].Text == "interface" {
			// Annotation type declarations are not controllers; skip their body.
			open := findNext(p.code, i+2, "{")
			if open < 0 {
				return
			}
			close := matchDelimiter(p.code, open, "{", "}")
			if close < 0 {
				p.problem("unterminated_annotation_type")
				return
			}
			p.problem("annotation_type_declaration_skipped")
			i = close + 1
			continue
		}
		if token.Text == "@" {
			ann, next, ok := parseAnnotation(p.code, i)
			if !ok {
				i++
				continue
			}
			pending = append(pending, ann)
			i = next
			continue
		}
		if isTypeKeyword(token.Text) && i+1 < len(p.code) && p.code[i+1].Tok == scanner.Ident {
			name := p.code[i+1].Text
			open := findNext(p.code, i+2, "{")
			if open < 0 {
				p.problem("unterminated_class:" + name)
				return
			}
			close := matchDelimiter(p.code, open, "{", "}")
			if close < 0 {
				p.problem("unterminated_class:" + name)
				return
			}
			p.parseClass(name, token.Line, p.code[close].Line, open, close, pending)
			pending = nil
			i = close + 1
			continue
		}
		switch token.Text {
		case ";", "}":
			pending = nil
		}
		i++
	}
}

func (p *javaParser) parseClass(name string, line, endLine, bodyOpen, bodyClose int, annotations []annotation) {
	class := classInfo{
		Name:           name,
		Symbol:         qualify(p.pkg, name),
		Line:           line,
		EndLine:        endLine,
		Annotations:    annotationNames(annotations),
		BasePaths:      []string{},
		BasePathStatus: "absent",
	}
	for _, ann := range annotations {
		switch ann.Name {
		case "Controller", "RestController":
			class.Controller = true
		}
	}
	var requestMappings int
	for _, ann := range annotations {
		if ann.Name != "RequestMapping" {
			continue
		}
		requestMappings++
		if requestMappings > 1 {
			p.problem("multiple_class_mappings:" + class.Symbol)
			continue
		}
		paths, status := annotationPaths(ann)
		class.BasePaths = paths
		class.BasePathStatus = status
	}
	if class.Controller {
		if len(p.Controllers) >= MaxControllers {
			p.problem("controller_limit")
			return
		}
		p.Controllers = append(p.Controllers, Controller{
			File:           p.file,
			Package:        p.pkg,
			Class:          name,
			Symbol:         class.Symbol,
			SHA256:         p.sha256,
			Annotations:    append([]string{}, class.Annotations...),
			BasePaths:      append([]string{}, class.BasePaths...),
			BasePathStatus: class.BasePathStatus,
			StartLine:      class.Line,
			EndLine:        class.EndLine,
		})
	}
	p.parseMembers(class, bodyOpen+1, bodyClose)
}

func (p *javaParser) parseMembers(class classInfo, start, end int) bool {
	mappingFound := false
	for i := start; i < end; {
		var annotations []annotation
		for {
			if i < end && p.code[i].Text == "@" {
				ann, next, ok := parseAnnotation(p.code, i)
				if !ok {
					break
				}
				annotations = append(annotations, ann)
				i = next
				continue
			}
			if i < end && isModifier(p.code[i].Text) {
				i++
				continue
			}
			break
		}
		if i >= end {
			break
		}
		if p.code[i].Text == "@" && i+1 < end && p.code[i+1].Text == "interface" {
			open := findNext(p.code, i+2, "{")
			if open >= 0 && open < end {
				close := matchDelimiter(p.code, open, "{", "}")
				if close >= 0 && close <= end {
					p.Nested++
					p.problem("annotation_type_declaration_skipped:" + class.Symbol)
					i = close + 1
					continue
				}
			}
			i = skipMember(p.code, i, end)
			continue
		}
		if isTypeKeyword(p.code[i].Text) {
			open := findNext(p.code, i+1, "{")
			if open >= 0 && open < end {
				close := matchDelimiter(p.code, open, "{", "}")
				if close >= 0 && close <= end {
					p.Nested++
					p.problem("nested_class_skipped:" + class.Symbol)
					i = close + 1
					continue
				}
			}
			i = skipMember(p.code, i, end)
			continue
		}
		// The first top-level '(' before '=', ';', '}' or '{' can only belong
		// to a method-like member; field initializers are skipped at '='.
		j := i
		for j < end {
			switch p.code[j].Text {
			case "(":
				goto found
			case "=", ";", "{", "}":
				j = end
				goto found
			}
			j++
		}
	found:
		if j >= end || p.code[j].Text != "(" {
			i = skipMember(p.code, i, end)
			continue
		}
		nameIndex := j - 1
		if nameIndex < i || p.code[nameIndex].Tok != scanner.Ident || isControlKeyword(p.code[nameIndex].Text) {
			i = skipMember(p.code, i, end)
			continue
		}
		paramsEnd := matchDelimiter(p.code, j, "(", ")")
		if paramsEnd < 0 || paramsEnd >= end {
			p.problem("unterminated_method:" + class.Symbol)
			break
		}
		k := paramsEnd + 1
		for k < end && p.code[k].Text != "{" && p.code[k].Text != ";" {
			k++
		}
		if k >= end {
			p.problem("unterminated_member:" + class.Symbol)
			break
		}
		methodName := p.code[nameIndex].Text
		bodyClose := k
		if p.code[k].Text == "{" {
			bodyClose = matchDelimiter(p.code, k, "{", "}")
			if bodyClose < 0 || bodyClose > end {
				p.problem("unterminated_method_body:" + class.Symbol)
				break
			}
		}
		if methodName != class.Name {
			if p.handleMethod(class, annotations, nameIndex, j, paramsEnd, methodName, p.code[bodyClose].Line) {
				mappingFound = true
			}
		}
		if p.code[k].Text == "{" {
			i = bodyClose + 1
		} else {
			i = k + 1
		}
	}
	return mappingFound
}

func (p *javaParser) handleMethod(class classInfo, annotations []annotation, nameIndex, paramOpen, paramClose int, methodName string, endLine int) bool {
	var mappings []annotation
	for _, ann := range annotations {
		if mappingAnnotations[ann.Name] {
			mappings = append(mappings, ann)
		}
	}
	if len(mappings) == 0 {
		return false
	}
	if !class.Controller {
		p.problem("controller_marker_missing:" + class.Symbol)
		return true
	}
	parameters, err := parseParameters(p.code[paramOpen+1 : paramClose])
	if err != nil {
		p.problem("parameter_limit:" + class.Symbol + "." + methodName)
		return true
	}
	methodLine := p.code[nameIndex].Line
	startLine := methodLine
	if len(annotations) > 0 {
		startLine = annotations[0].Line
	}
	anchor, anchorLine := p.anchor(methodLine, endLine)
	for _, mapping := range mappings {
		methodPaths, methodStatus := annotationPaths(mapping)
		httpMethods, methodState := annotationHTTPMethods(mapping)
		basePaths := class.BasePaths
		baseStatus := class.BasePathStatus
		if baseStatus == "absent" {
			basePaths = []string{""}
		}
		if methodStatus == "absent" {
			methodPaths = []string{""}
		}
		if baseStatus == "unresolved" || methodStatus == "unresolved" {
			reason := "non_literal_path"
			if baseStatus == "unresolved" {
				reason = "unresolved_base_path"
			}
			p.appendEndpoint(class, mapping, "", "", "", httpMethods, methodState, parameters, methodName, startLine, endLine, methodLine, "unresolved", reason, anchor, anchorLine)
			continue
		}
		for _, base := range basePaths {
			for _, relative := range methodPaths {
				path := joinRoute(base, relative)
				p.appendEndpoint(class, mapping, path, base, relative, httpMethods, methodState, parameters, methodName, startLine, endLine, methodLine, "resolved", "", anchor, anchorLine)
			}
		}
	}
	return true
}

func (p *javaParser) appendEndpoint(class classInfo, mapping annotation, path, base, relative string, httpMethods []string, methodState string, parameters []Parameter, methodName string, startLine, endLine, methodLine int, pathStatus, reason, anchor string, anchorLine int) {
	if len(p.Endpoints) >= MaxEndpoints {
		p.problem("endpoint_limit")
		return
	}
	p.Endpoints = append(p.Endpoints, Endpoint{
		Path:         path,
		BasePath:     base,
		RelativePath: relative,
		HTTPMethods:  append([]string{}, httpMethods...),
		MethodStatus: methodState,
		File:         p.file,
		Package:      p.pkg,
		Class:        class.Name,
		Method:       methodName,
		Symbol:       class.Symbol + "." + methodName,
		SHA256:       p.sha256,
		Annotation:   mapping.Name,
		StartLine:    startLine,
		EndLine:      endLine,
		MethodLine:   methodLine,
		Parameters:   parameters,
		PathStatus:   pathStatus,
		PathReason:   reason,
		Anchor:       anchor,
		AnchorLine:   anchorLine,
	})
}

func (p *javaParser) anchor(startLine, endLine int) (string, int) {
	for _, comment := range p.comments {
		if comment.Line < startLine || comment.Line > endLine {
			continue
		}
		index := strings.Index(comment.Text, "fixture:")
		if index < 0 {
			continue
		}
		value := comment.Text[index:]
		stop := strings.IndexFunc(value, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';' || r == ',' || r == '*' || r == '/'
		})
		if stop >= 0 {
			value = value[:stop]
		}
		return value, comment.Line
	}
	return "", 0
}

func parseParameters(tokens []javaToken) ([]Parameter, error) {
	segments := splitAtTopLevel(tokens, ",")
	if len(segments) > MaxJavaParameters {
		return nil, ErrLimit
	}
	parameters := []Parameter{}
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		annotations := annotationsIn(segment)
		clean := stripAnnotations(segment)
		clean = removeTokens(clean, "final")
		if len(clean) == 0 {
			continue
		}
		nameIndex := -1
		for i := len(clean) - 1; i >= 0; i-- {
			if clean[i].Tok == scanner.Ident {
				nameIndex = i
				break
			}
		}
		if nameIndex < 0 {
			continue
		}
		parameter := Parameter{
			Name:     clean[nameIndex].Text,
			Type:     joinType(clean[:nameIndex]),
			Bindings: []string{},
			Required: "unspecified",
			Line:     clean[nameIndex].Line,
		}
		for _, ann := range annotations {
			if !bindingAnnotations[ann.Name] {
				continue
			}
			parameter.Bindings = append(parameter.Bindings, ann.Name)
			parameter.Line = ann.Line
			if name := firstString(ann, "name", "value"); name != "" {
				parameter.BindingName = name
			}
			if required := boolArg(ann, "required"); required != "" {
				parameter.Required = required
			}
		}
		parameters = append(parameters, parameter)
	}
	return parameters, nil
}

func annotationsIn(tokens []javaToken) []annotation {
	annotations := []annotation{}
	for i := 0; i < len(tokens); {
		if tokens[i].Text != "@" {
			i++
			continue
		}
		ann, next, ok := parseAnnotation(tokens, i)
		if !ok {
			i++
			continue
		}
		annotations = append(annotations, ann)
		i = next
	}
	return annotations
}

func stripAnnotations(tokens []javaToken) []javaToken {
	out := make([]javaToken, 0, len(tokens))
	for i := 0; i < len(tokens); {
		if tokens[i].Text == "@" {
			if _, next, ok := parseAnnotation(tokens, i); ok {
				i = next
				continue
			}
		}
		out = append(out, tokens[i])
		i++
	}
	return out
}

func removeTokens(tokens []javaToken, text string) []javaToken {
	out := tokens[:0]
	for _, token := range tokens {
		if token.Text != text {
			out = append(out, token)
		}
	}
	return out
}

func parseAnnotation(tokens []javaToken, at int) (annotation, int, bool) {
	if at >= len(tokens) || tokens[at].Text != "@" || at+1 >= len(tokens) {
		return annotation{}, at, false
	}
	if tokens[at+1].Tok != scanner.Ident {
		return annotation{}, at, false
	}
	index := at + 1
	name := tokens[index].Text
	index++
	for index+1 < len(tokens) && tokens[index].Text == "." && tokens[index+1].Tok == scanner.Ident {
		name = tokens[index+1].Text
		index += 2
	}
	ann := annotation{Name: name, Line: tokens[at].Line}
	if index < len(tokens) && tokens[index].Text == "(" {
		close := matchDelimiter(tokens, index, "(", ")")
		if close < 0 {
			return ann, len(tokens), false
		}
		ann.Args = splitAnnotationArgs(tokens[index+1 : close])
		index = close + 1
	}
	return ann, index, true
}

func splitAnnotationArgs(tokens []javaToken) []annotationArg {
	segments := splitAtTopLevel(tokens, ",")
	args := make([]annotationArg, 0, len(segments))
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		if len(args) >= MaxJavaAnnotationArgs {
			break
		}
		if len(segment) >= 2 && segment[0].Tok == scanner.Ident && segment[1].Text == "=" {
			args = append(args, annotationArg{Key: segment[0].Text, Tokens: segment[2:]})
		} else {
			args = append(args, annotationArg{Tokens: segment})
		}
	}
	return args
}

func annotationPaths(ann annotation) ([]string, string) {
	var selected []annotationArg
	for _, arg := range ann.Args {
		if arg.Key == "" || arg.Key == "value" || arg.Key == "path" {
			selected = append(selected, arg)
		}
	}
	if len(selected) == 0 {
		return nil, "absent"
	}
	var paths []string
	for _, arg := range selected {
		values, literal, present := stringValues(arg.Tokens)
		if !literal {
			return nil, "unresolved"
		}
		if present {
			paths = append(paths, values...)
		}
	}
	if len(paths) == 0 {
		return nil, "absent"
	}
	return paths, "resolved"
}

func annotationHTTPMethods(ann annotation) ([]string, string) {
	if methods, ok := httpMappingMethods[ann.Name]; ok {
		return append([]string{}, methods...), "specified"
	}
	if ann.Name != "RequestMapping" {
		return []string{}, "unspecified"
	}
	var methods []string
	for _, arg := range ann.Args {
		if arg.Key != "method" {
			continue
		}
		for i := 0; i+1 < len(arg.Tokens); i++ {
			if arg.Tokens[i].Text == "." && arg.Tokens[i+1].Tok == scanner.Ident {
				method := arg.Tokens[i+1].Text
				switch method {
				case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE":
					methods = append(methods, method)
				}
			}
		}
	}
	if len(methods) == 0 {
		return []string{}, "unspecified"
	}
	sort.Strings(methods)
	return dedupeStrings(methods), "specified"
}

func stringValues(tokens []javaToken) ([]string, bool, bool) {
	var values []string
	present := false
	for _, token := range tokens {
		switch {
		case token.Tok == scanner.String:
			value, err := unquoteJava(token.Text)
			if err != nil {
				return nil, false, present
			}
			values = append(values, value)
			present = true
		case token.Text == "{" || token.Text == "}" || token.Text == "," || token.Text == "[" || token.Text == "]":
			continue
		default:
			return nil, false, present
		}
	}
	return values, true, present
}

func firstString(ann annotation, keys ...string) string {
	for _, arg := range ann.Args {
		matches := arg.Key == ""
		for _, key := range keys {
			if arg.Key == key {
				matches = true
			}
		}
		if !matches {
			continue
		}
		if values, literal, present := stringValues(arg.Tokens); literal && present && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func boolArg(ann annotation, key string) string {
	for _, arg := range ann.Args {
		if arg.Key != key || len(arg.Tokens) != 1 || arg.Tokens[0].Tok != scanner.Ident {
			continue
		}
		switch arg.Tokens[0].Text {
		case "true":
			return "true"
		case "false":
			return "false"
		}
	}
	return ""
}

func joinRoute(base, relative string) string {
	if base == "" {
		base = "/"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	if relative == "" {
		return trimTrailing(base)
	}
	if !strings.HasPrefix(relative, "/") {
		relative = "/" + relative
	}
	joined := strings.TrimSuffix(base, "/") + relative
	for strings.Contains(joined, "//") {
		joined = strings.ReplaceAll(joined, "//", "/")
	}
	return trimTrailing(joined)
}

func trimTrailing(value string) string {
	if len(value) > 1 && strings.HasSuffix(value, "/") {
		return strings.TrimSuffix(value, "/")
	}
	return value
}

func joinType(tokens []javaToken) string {
	var out strings.Builder
	for i, token := range tokens {
		if i > 0 && tokens[i-1].Tok == scanner.Ident && token.Tok == scanner.Ident {
			out.WriteByte(' ')
		}
		out.WriteString(token.Text)
	}
	return out.String()
}

func unquoteJava(text string) (string, error) {
	if len(text) < 2 || text[0] != '"' || text[len(text)-1] != '"' {
		return "", ErrUnsupported
	}
	body := text[1 : len(text)-1]
	var out strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			out.WriteByte(body[i])
			continue
		}
		i++
		if i >= len(body) {
			return "", ErrUnsupported
		}
		switch body[i] {
		case 'b':
			out.WriteByte('\b')
		case 't':
			out.WriteByte('\t')
		case 'n':
			out.WriteByte('\n')
		case 'f':
			out.WriteByte('\f')
		case 'r':
			out.WriteByte('\r')
		case '"', '\'', '\\':
			out.WriteByte(body[i])
		case 'u':
			if i+4 >= len(body) {
				return "", ErrUnsupported
			}
			value := 0
			for j := 0; j < 4; j++ {
				digit, ok := hexDigit(body[i+1+j])
				if !ok {
					return "", ErrUnsupported
				}
				value = value*16 + digit
			}
			if value >= 0xD800 && value <= 0xDFFF {
				return "", ErrUnsupported
			}
			out.WriteRune(rune(value))
			i += 4
		default:
			return "", ErrUnsupported
		}
	}
	value := out.String()
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", ErrUnsupported
	}
	return value, nil
}

func hexDigit(value byte) (int, bool) {
	switch {
	case value >= '0' && value <= '9':
		return int(value - '0'), true
	case value >= 'a' && value <= 'f':
		return int(value-'a') + 10, true
	case value >= 'A' && value <= 'F':
		return int(value-'A') + 10, true
	}
	return 0, false
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

func splitAtTopLevel(tokens []javaToken, separator string) [][]javaToken {
	var segments [][]javaToken
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
		if token.Text == separator && depth == 0 {
			segments = append(segments, tokens[start:i])
			start = i + 1
		}
	}
	segments = append(segments, tokens[start:])
	return segments
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

func findNext(tokens []javaToken, start int, text string) int {
	for i := start; i < len(tokens); i++ {
		if tokens[i].Text == text {
			return i
		}
		if tokens[i].Text == ";" {
			return -1
		}
	}
	return -1
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
	case "public", "protected", "private", "abstract", "static", "final", "strictfp", "sealed", "non", "transient", "volatile", "synchronized", "native", "default":
		return true
	}
	return false
}

func isControlKeyword(text string) bool {
	switch text {
	case "if", "for", "while", "switch", "catch", "try", "return", "new", "throw", "assert", "do", "else", "case", "synchronized":
		return true
	}
	return false
}

func annotationNames(annotations []annotation) []string {
	names := make([]string, 0, len(annotations))
	for _, ann := range annotations {
		names = append(names, ann.Name)
	}
	sort.Strings(names)
	return names
}

func qualify(pkg, name string) string {
	if pkg == "" {
		return name
	}
	return pkg + "." + name
}

func dedupeStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
