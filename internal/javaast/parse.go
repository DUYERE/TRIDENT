package javaast

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/scanner"
	"unicode/utf8"

	"trident/internal/javasrc"
)

// The parser accepts a deliberately restricted Java subset: declarations,
// annotations, fields, methods, local variables and call expressions. It does
// not implement the full JLS; unsupported statements are recorded as boundaries
// instead of being guessed.
const (
	MaxFiles   = 2000
	MaxBytes   = 2 << 20
	MaxTypes   = 10_000
	MaxMethods = 50_000
	MaxCalls   = 100_000
	MaxDepth   = 8
)

var ErrUnsupported = errors.New("unsupported Java source")

type token struct {
	text string
	line int
}

type Import struct {
	Name   string `json:"name"`
	Static bool   `json:"static,omitempty"`
	Line   int    `json:"line"`
}

type Annotation struct {
	Name    string          `json:"name"`
	Line    int             `json:"line"`
	RawArgs []string        `json:"-"`
	Args    []AnnotationArg `json:"args,omitempty"`
}

type AnnotationArg struct {
	Name  string `json:"name"`
	Value Value  `json:"value"`
}

// Value is a folded annotation value. Kind is string, number, bool, name,
// array or expr; expr means constant folding failed and the raw text is kept.
type Value struct {
	Kind     string  `json:"kind"`
	Text     string  `json:"text"`
	Elements []Value `json:"elements,omitempty"`
}

type Field struct {
	Name           string
	TypeRaw        string
	Type           string
	Modifiers      []string
	Annotations    []Annotation
	Constant       string
	HasInitializer bool
	InitStart      int
	InitEnd        int
	Line           int
}

type Param struct {
	Name        string
	TypeRaw     string
	Type        string
	Varargs     bool
	Annotations []Annotation
	Line        int
}

type Method struct {
	Name        string
	ReturnRaw   string
	ReturnType  string
	Constructor bool
	TypeParams  []string
	Params      []Param
	Modifiers   []string
	Annotations []Annotation
	Line        int
	BodyStart   int
	BodyEnd     int
	Class       *Type
}

type Type struct {
	Name          string
	FQN           string
	Kind          string
	Modifiers     []string
	Annotations   []Annotation
	TypeParams    []string
	ExtendsRaw    string
	ImplementsRaw []string
	Extends       string
	Implements    []string
	Fields        []*Field
	Methods       []*Method
	Nested        []*Type
	Line          int
	Parent        *Type
	Unit          *Unit
}

type Unit struct {
	Path       string
	SHA256     string
	Package    string
	Imports    []Import
	Types      []*Type
	Tokens     []token
	ParseError string
	Boundaries []string
	constants  map[string]string
}

type parser struct {
	tokens []token
	pos    int
	unit   *Unit
}

// ParseFile parses one Java source file. A structural error rejects that file
// only; the caller keeps analyzing the rest of the snapshot.
func ParseFile(path, sha256 string, data []byte) (*Unit, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty source", ErrUnsupported)
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%w: source exceeds %d bytes", ErrUnsupported, MaxBytes)
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("%w: non-UTF-8 or NUL byte", ErrUnsupported)
	}
	code, textBlocks, ok := javasrc.Strip(data)
	if !ok {
		return nil, fmt.Errorf("%w: unterminated Java text block", ErrUnsupported)
	}
	tokens, err := tokenize(code)
	if err != nil {
		return nil, err
	}
	if err := checkBalanced(tokens); err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens, unit: &Unit{Path: path, SHA256: sha256, Tokens: tokens, constants: map[string]string{}}}
	if err := p.parseUnit(); err != nil {
		return nil, err
	}
	if textBlocks > 0 {
		p.unit.Boundaries = append(p.unit.Boundaries, javasrc.TextBlockNote)
	}
	return p.unit, nil
}

func tokenize(data []byte) ([]token, error) {
	var s scanner.Scanner
	s.Init(bytes.NewReader(data))
	s.Mode = scanner.ScanIdents | scanner.ScanFloats | scanner.ScanChars |
		scanner.ScanStrings | scanner.ScanRawStrings | scanner.ScanComments
	var failure string
	s.Error = func(_ *scanner.Scanner, msg string) {
		if failure == "" {
			failure = msg
		}
	}
	var tokens []token
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		if tok == scanner.Comment {
			continue
		}
		tokens = append(tokens, token{text: s.TokenText(), line: s.Position.Line})
	}
	if failure != "" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, failure)
	}
	return tokens, nil
}

func checkBalanced(tokens []token) error {
	stack := make([]string, 0, 64)
	for _, item := range tokens {
		switch item.text {
		case "(", "{", "[":
			stack = append(stack, item.text)
		case ")", "}", "]":
			if len(stack) == 0 || !matches(stack[len(stack)-1], item.text) {
				return fmt.Errorf("%w: unbalanced %q at line %d", ErrUnsupported, item.text, item.line)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("%w: unclosed %q", ErrUnsupported, stack[len(stack)-1])
	}
	return nil
}

func matches(open, close string) bool {
	return (open == "(" && close == ")") || (open == "{" && close == "}") || (open == "[" && close == "]")
}

func (p *parser) eof() bool { return p.pos >= len(p.tokens) }

func (p *parser) peek() string {
	if p.eof() {
		return ""
	}
	return p.tokens[p.pos].text
}

func (p *parser) peekAt(offset int) string {
	if p.pos+offset >= len(p.tokens) || p.pos+offset < 0 {
		return ""
	}
	return p.tokens[p.pos+offset].text
}

func (p *parser) next() token {
	if p.eof() {
		return token{}
	}
	item := p.tokens[p.pos]
	p.pos++
	return item
}

func (p *parser) accept(text string) bool {
	if p.peek() == text {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expect(text string) error {
	if !p.accept(text) {
		line := 0
		got := "<eof>"
		if !p.eof() {
			line = p.tokens[p.pos].line
			got = p.tokens[p.pos].text
		}
		return fmt.Errorf("%w: expected %q near line %d (got %q)", ErrUnsupported, text, line, got)
	}
	return nil
}

func (p *parser) parseUnit() error {
	for !p.eof() {
		switch p.peek() {
		case "package":
			p.next()
			name := p.parseQualifiedName()
			if name == "" || p.expect(";") != nil {
				return fmt.Errorf("%w: malformed package declaration", ErrUnsupported)
			}
			p.unit.Package = name
		case "import":
			p.next()
			item := Import{Line: p.tokens[p.pos-1].line}
			if p.accept("static") {
				item.Static = true
			}
			item.Name = p.parseQualifiedName()
			if item.Name == "" || p.expect(";") != nil {
				return fmt.Errorf("%w: malformed import", ErrUnsupported)
			}
			p.unit.Imports = append(p.unit.Imports, item)
		default:
			if err := p.parseType(nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *parser) parseQualifiedName() string {
	first := p.acceptIdentifier()
	if first == "" {
		return ""
	}
	parts := []string{first}
	for p.accept(".") {
		if p.accept("*") {
			parts = append(parts, "*")
			break
		}
		next := p.acceptIdentifier()
		if next == "" {
			break
		}
		parts = append(parts, next)
	}
	return strings.Join(parts, ".")
}

func (p *parser) acceptIdentifier() string {
	if p.eof() {
		return ""
	}
	text := p.peek()
	if !isIdentifier(text) || isKeyword(text) {
		return ""
	}
	p.pos++
	return text
}

func (p *parser) parseType(parent *Type) error {
	annotations := p.parseAnnotations()
	modifiers := p.parseModifiers()
	kind := p.peek()
	if kind != "class" && kind != "interface" && kind != "enum" && kind != "record" && kind != "@" {
		return fmt.Errorf("%w: expected type declaration near line %d", ErrUnsupported, p.line())
	}
	if kind == "@" {
		p.next()
		if p.peek() != "interface" {
			return fmt.Errorf("%w: malformed annotation type", ErrUnsupported)
		}
		kind = "@interface"
	}
	p.next()
	name := p.acceptIdentifier()
	if name == "" {
		return fmt.Errorf("%w: missing type name near line %d", ErrUnsupported, p.line())
	}
	decl := &Type{
		Name: name, Kind: kind, Modifiers: modifiers, Annotations: annotations,
		Line: p.line(), Parent: parent, Unit: p.unit,
	}
	if len(p.unit.Types) >= MaxTypes {
		return fmt.Errorf("%w: type limit", ErrUnsupported)
	}
	if parent != nil {
		decl.FQN = parent.FQN + "." + name
		parent.Nested = append(parent.Nested, decl)
	} else {
		if p.unit.Package != "" {
			decl.FQN = p.unit.Package + "." + name
		} else {
			decl.FQN = name
		}
		p.unit.Types = append(p.unit.Types, decl)
	}
	if p.peek() == "<" {
		decl.TypeParams = p.parseTypeParams()
	}
	if kind == "record" && p.accept("(") {
		params, err := p.parseParams()
		if err != nil {
			return err
		}
		for _, param := range params {
			decl.Fields = append(decl.Fields, &Field{
				Name: param.Name, TypeRaw: param.TypeRaw, Modifiers: []string{"private", "final"},
				Line: param.Line,
			})
		}
	}
	for !p.eof() && p.peek() != "{" {
		switch p.peek() {
		case "extends":
			p.next()
			if decl.ExtendsRaw == "" {
				decl.ExtendsRaw = p.parseTypeRefAt()
			}
			for p.accept(",") {
				value := p.parseTypeRefAt()
				if kind == "interface" {
					decl.ImplementsRaw = append(decl.ImplementsRaw, value)
				} else if decl.ExtendsRaw == "" {
					decl.ExtendsRaw = value
				}
			}
		case "implements", "permits":
			p.next()
			for {
				value := p.parseTypeRefAt()
				if value == "" {
					return fmt.Errorf("%w: malformed implements clause", ErrUnsupported)
				}
				decl.ImplementsRaw = append(decl.ImplementsRaw, value)
				if !p.accept(",") {
					break
				}
			}
		default:
			p.next()
		}
	}
	if err := p.expect("{"); err != nil {
		return err
	}
	phaseEnum := kind == "enum"
	for !p.eof() && p.peek() != "}" {
		if p.accept(";") {
			phaseEnum = false
			continue
		}
		if phaseEnum {
			if p.peek() == "}" {
				break
			}
			if isIdentifier(p.peek()) && !isKeyword(p.peek()) {
				line := p.line()
				constant := p.next().text
				if p.accept("(") {
					p.skipBalanced("(", ")")
				}
				if p.peek() == "{" {
					p.skipBalanced("{", "}")
				}
				decl.Fields = append(decl.Fields, &Field{
					Name: constant, TypeRaw: name, Constant: constant,
					Modifiers: []string{"public", "static", "final"}, Line: line,
				})
				p.accept(",")
				continue
			}
			phaseEnum = false
		}
		if err := p.parseMember(decl); err != nil {
			return err
		}
	}
	return p.expect("}")
}

func (p *parser) parseMember(decl *Type) error {
	if p.accept(";") {
		return nil
	}
	annotations := p.parseAnnotations()
	modifiers := p.parseModifiers()
	if p.peek() == "{" {
		p.skipBalanced("{", "}")
		decl.Unit.Boundaries = append(decl.Unit.Boundaries, "initializer_block")
		return nil
	}
	if p.peek() == "class" || p.peek() == "interface" || p.peek() == "enum" || p.peek() == "record" || p.peek() == "@" {
		return p.parseTypeWithPrefix(decl, annotations, modifiers)
	}
	typeParams := []string{}
	if p.peek() == "<" {
		typeParams = p.parseTypeParams()
	}
	// Constructor: name directly followed by "(".
	if p.peek() == decl.Name && p.peekAt(1) == "(" {
		nameToken := p.next()
		p.next()
		params, err := p.parseParams()
		if err != nil {
			return err
		}
		method := &Method{
			Name: nameToken.text, Constructor: true, Params: params,
			Modifiers: modifiers, Annotations: annotations, Line: nameToken.line, Class: decl,
			TypeParams: typeParams,
		}
		return p.parseMethodBody(method, decl)
	}
	returnType := p.parseTypeRefAt()
	if returnType == "" {
		// Unknown member: skip conservatively to the next ";" or "}".
		for !p.eof() && p.peek() != ";" && p.peek() != "}" {
			p.next()
		}
		p.accept(";")
		decl.Unit.Boundaries = append(decl.Unit.Boundaries, "unsupported_member")
		return nil
	}
	if p.peek() == "(" {
		// A missing member name is not valid Java. Skip the parameter list and
		// body conservatively instead of inventing a constructor.
		if err := p.skipBalanced("(", ")"); err != nil {
			return err
		}
		if p.peek() == "{" {
			if err := p.skipBalanced("{", "}"); err != nil {
				return err
			}
		} else {
			for !p.eof() && p.peek() != ";" {
				p.next()
			}
			p.accept(";")
		}
		decl.Unit.Boundaries = append(decl.Unit.Boundaries, "unsupported_member")
		return nil
	}
	name := p.acceptIdentifier()
	if name == "" {
		// Unsupported member; skip to member end.
		for !p.eof() && p.peek() != ";" && p.peek() != "}" {
			p.next()
		}
		p.accept(";")
		decl.Unit.Boundaries = append(decl.Unit.Boundaries, "unsupported_member")
		return nil
	}
	nameLine := p.tokens[p.pos-1].line
	if p.peek() == "(" {
		p.next()
		params, err := p.parseParams()
		if err != nil {
			return err
		}
		method := &Method{
			Name: name, ReturnRaw: returnType, Params: params,
			Modifiers: modifiers, Annotations: annotations, Line: nameLine, Class: decl,
			TypeParams: typeParams,
		}
		return p.parseMethodBody(method, decl)
	}
	// Field declaration(s).
	field := &Field{
		Name: name, TypeRaw: returnType, Modifiers: modifiers, Annotations: annotations,
		Line: nameLine,
	}
	if p.accept("=") {
		field.HasInitializer = true
		field.InitStart = p.pos
		field.InitEnd = p.captureUntilTopLevel(",", ";")
	}
	decl.Fields = append(decl.Fields, field)
	for p.accept(",") {
		nextName := p.acceptIdentifier()
		if nextName == "" {
			return fmt.Errorf("%w: malformed field declaration", ErrUnsupported)
		}
		extra := &Field{Name: nextName, TypeRaw: returnType, Modifiers: modifiers, Line: p.tokens[p.pos-1].line}
		if p.accept("=") {
			extra.HasInitializer = true
			extra.InitStart = p.pos
			extra.InitEnd = p.captureUntilTopLevel(",", ";")
		}
		decl.Fields = append(decl.Fields, extra)
	}
	return p.expect(";")
}

func (p *parser) parseTypeWithPrefix(decl *Type, annotations []Annotation, modifiers []string) error {
	// Reuse parseType by injecting the already-consumed prefix through a
	// dedicated path: parse the remainder and merge the prefix.
	if err := p.parseType(decl); err != nil {
		return err
	}
	nested := decl.Nested[len(decl.Nested)-1]
	nested.Annotations = append(annotations, nested.Annotations...)
	nested.Modifiers = append(modifiers, nested.Modifiers...)
	return nil
}

func (p *parser) parseMethodBody(method *Method, decl *Type) error {
	if method.Line == 0 {
		method.Line = p.line()
	}
	if p.peek() == "throws" {
		p.next()
		for !p.eof() && p.peek() != "{" && p.peek() != ";" {
			p.next()
		}
	}
	if p.peek() == "default" {
		// Annotation element default value: consume the value (which may be an
		// array literal) up to the member's terminating semicolon.
		p.next()
		depth := 0
		for !p.eof() {
			text := p.peek()
			if depth == 0 && text == ";" {
				break
			}
			switch text {
			case "(", "{", "[":
				depth++
			case ")", "}", "]":
				if depth > 0 {
					depth--
				}
			}
			p.next()
		}
		p.accept(";")
		decl.Methods = append(decl.Methods, method)
		return nil
	}
	if p.accept(";") {
		decl.Methods = append(decl.Methods, method)
		return nil
	}
	if p.peek() != "{" {
		return fmt.Errorf("%w: expected method body near line %d", ErrUnsupported, p.line())
	}
	start := p.pos
	if err := p.skipBalanced("{", "}"); err != nil {
		return err
	}
	method.BodyStart, method.BodyEnd = start, p.pos-1
	decl.Methods = append(decl.Methods, method)
	if len(decl.Methods) > MaxMethods {
		return fmt.Errorf("%w: method limit", ErrUnsupported)
	}
	return nil
}

func (p *parser) parseAnnotations() []Annotation {
	var annotations []Annotation
	for p.peek() == "@" {
		line := p.line()
		p.next()
		if p.peek() == "interface" {
			p.pos--
			break
		}
		name := p.parseQualifiedName()
		if name == "" {
			break
		}
		annotation := Annotation{Name: name, Line: line}
		if p.accept("(") {
			annotation.RawArgs = p.captureArguments(")")
		}
		annotations = append(annotations, annotation)
	}
	return annotations
}

func (p *parser) parseModifiers() []string {
	var modifiers []string
	for {
		switch p.peek() {
		case "public", "protected", "private", "static", "final", "abstract", "native",
			"synchronized", "transient", "volatile", "strictfp", "default", "sealed", "non-sealed":
			modifiers = append(modifiers, p.next().text)
		default:
			return modifiers
		}
	}
}

func (p *parser) parseTypeParams() []string {
	var names []string
	if !p.accept("<") {
		return names
	}
	depth := 1
	for !p.eof() && depth > 0 {
		switch p.peek() {
		case "<":
			depth++
			p.next()
		case ">":
			depth--
			p.next()
		default:
			if depth == 1 && isIdentifier(p.peek()) && !isKeyword(p.peek()) {
				name := p.next().text
				if p.peek() == "extends" || p.peek() == "," || p.peek() == ">" {
					names = append(names, name)
					continue
				}
			}
			p.next()
		}
	}
	return names
}

func (p *parser) parseParams() ([]Param, error) {
	var params []Param
	if p.peek() == ")" {
		p.next()
		return params, nil
	}
	for !p.eof() {
		param := Param{Line: p.line()}
		param.Annotations = p.parseAnnotations()
		for p.peek() == "final" {
			p.next()
		}
		param.TypeRaw = p.parseTypeRefAt()
		if param.TypeRaw == "" {
			return nil, fmt.Errorf("%w: malformed parameter near line %d", ErrUnsupported, p.line())
		}
		if strings.HasSuffix(param.TypeRaw, "...") {
			param.Varargs = true
			param.TypeRaw = strings.TrimSuffix(param.TypeRaw, "...") + "[]"
		}
		param.Name = p.acceptIdentifier()
		if param.Name == "" {
			return nil, fmt.Errorf("%w: missing parameter name", ErrUnsupported)
		}
		params = append(params, param)
		if p.accept(")") {
			return params, nil
		}
		if err := p.expect(","); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: unterminated parameter list", ErrUnsupported)
}

// parseTypeRefAt parses a type reference starting at pos and returns its erased
// spelling (generic arguments removed, arrays kept).
func (p *parser) parseTypeRefAt() string {
	name, consumed := parseTypeAt(p.tokens, p.pos)
	if consumed <= p.pos {
		return ""
	}
	p.pos = consumed
	return name
}

func parseTypeAt(tokens []token, start int) (string, int) {
	if start >= len(tokens) {
		return "", start
	}
	index := start
	first := tokens[index].text
	if !isIdentifier(first) || isKeyword(first) && !isPrimitive(first) {
		return "", start
	}
	var parts []string
	parts = append(parts, first)
	index++
	for index < len(tokens) && tokens[index].text == "<" {
		index = skipAngles(tokens, index)
	}
	for index < len(tokens) && tokens[index].text == "." {
		if index+1 >= len(tokens) || !isIdentifier(tokens[index+1].text) {
			break
		}
		parts = append(parts, tokens[index+1].text)
		index += 2
		for index < len(tokens) && tokens[index].text == "<" {
			index = skipAngles(tokens, index)
		}
	}
	name := strings.Join(parts, ".")
	for index < len(tokens) && tokens[index].text == "[" {
		if index+1 < len(tokens) && tokens[index+1].text == "]" {
			name += "[]"
			index += 2
			continue
		}
		break
	}
	if index+2 < len(tokens) && tokens[index].text == "." && tokens[index+1].text == "." && tokens[index+2].text == "." {
		name += "..."
		index += 3
	}
	return name, index
}

// skipAngles returns the index just past a balanced <...> group. Unbalanced
// input (for example the comparison operator in "a < b") consumes only the
// opening token: callers loop until the index stops pointing at "<", so a
// non-advancing return value would hang the scanner.
func skipAngles(tokens []token, start int) int {
	if start >= len(tokens) || tokens[start].text != "<" {
		return start
	}
	depth := 0
	for index := start; index < len(tokens); index++ {
		switch tokens[index].text {
		case "<":
			depth++
		case ">":
			depth--
			if depth == 0 {
				return index + 1
			}
		}
	}
	return start + 1
}

func (p *parser) captureArguments(close string) []string {
	var args []string
	var current []string
	depth := 0
	for !p.eof() {
		text := p.peek()
		if depth == 0 && text == close {
			p.next()
			if len(current) > 0 || len(args) > 0 {
				args = append(args, strings.Join(current, " "))
			}
			return args
		}
		switch text {
		case "(", "{", "[":
			depth++
		case ")", "}", "]":
			depth--
		case ",":
			if depth == 0 {
				args = append(args, strings.Join(current, " "))
				current = nil
				p.next()
				continue
			}
		}
		current = append(current, p.next().text)
	}
	return args
}

func (p *parser) captureUntilTopLevel(stops ...string) int {
	stop := map[string]bool{}
	for _, item := range stops {
		stop[item] = true
	}
	depth := 0
	for !p.eof() {
		text := p.peek()
		if depth == 0 && stop[text] {
			return p.pos
		}
		switch text {
		case "(", "{", "[":
			depth++
		case ")", "}", "]":
			if depth > 0 {
				depth--
			}
		}
		p.next()
	}
	return p.pos
}

func (p *parser) skipBalanced(open, close string) error {
	if !p.accept(open) {
		return fmt.Errorf("%w: expected %q", ErrUnsupported, open)
	}
	depth := 1
	for !p.eof() {
		switch p.next().text {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: unclosed %q", ErrUnsupported, open)
}

func (p *parser) line() int {
	if p.eof() {
		if len(p.tokens) == 0 {
			return 0
		}
		return p.tokens[len(p.tokens)-1].line
	}
	return p.tokens[p.pos].line
}

func isPrimitive(text string) bool {
	switch text {
	case "byte", "short", "int", "long", "float", "double", "boolean", "char", "void", "var":
		return true
	}
	return false
}

func isIdentifier(text string) bool {
	if text == "" {
		return false
	}
	for index, r := range text {
		if index == 0 {
			if !(r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return false
			}
			continue
		}
		if !(r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func isKeyword(text string) bool {
	switch text {
	case "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
		"continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
		"for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
		"new", "package", "private", "protected", "public", "return", "short", "static", "strictfp",
		"super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void",
		"volatile", "while", "record", "sealed", "permits", "yield", "var", "null", "true", "false":
		return true
	}
	return false
}

func unquote(text string) (string, bool) {
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		if value, err := strconv.Unquote(text); err == nil {
			return value, true
		}
		// Java and Go escapes are close enough for the supported subset; fall
		// back to stripping the quotes when Unquote rejects a legal Java escape.
		return text[1 : len(text)-1], true
	}
	return "", false
}
