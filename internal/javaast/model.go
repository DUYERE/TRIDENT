package javaast

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"trident/internal/project"
)

// Package javaast builds a deterministic semantic model of a restricted Java
// subset: declarations, erased type names, field/method symbols, constant and
// annotation folding, and a bounded method-level call graph. It never compiles,
// resolves or runs Java, and unresolved constructs are reported as boundaries.
const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.3+r1-java-semantic-model-v1"
	AnalysisKind  = "java_semantic_model_v1"

	MaxConstants   = 20_000
	MaxFoldDepth   = 16
	MaxRawArgBytes = 4 << 10
)

var ErrLimit = errors.New("java semantic model limit")

// Call status values. "external" calls are counted but never emitted.
const (
	CallResolved   = "resolved"
	CallAmbiguous  = "ambiguous"
	CallUnresolved = "unresolved"
)

type Model struct {
	SchemaVersion int        `json:"schema_version"`
	ToolVersion   string     `json:"tool_version"`
	SnapshotHash  string     `json:"snapshot_hash"`
	AnalysisKind  string     `json:"analysis_kind"`
	Partial       bool       `json:"partial"`
	Files         []FileInfo `json:"files"`
	Types         []TypeInfo `json:"types"`
	Calls         []CallEdge `json:"calls"`
	Coverage      Coverage   `json:"coverage"`
	Limitations   []string   `json:"limitations"`
}

type FileInfo struct {
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256"`
	Package    string   `json:"package,omitempty"`
	Imports    []Import `json:"imports,omitempty"`
	Types      []string `json:"types,omitempty"`
	Boundaries []string `json:"boundaries,omitempty"`
	ParseError string   `json:"parse_error,omitempty"`
}

type TypeInfo struct {
	FQN           string       `json:"fqn"`
	Name          string       `json:"name"`
	Kind          string       `json:"kind"`
	File          string       `json:"file"`
	Line          int          `json:"line"`
	Modifiers     []string     `json:"modifiers,omitempty"`
	Annotations   []Annotation `json:"annotations,omitempty"`
	ExtendsRaw    string       `json:"extends_raw,omitempty"`
	Extends       string       `json:"extends,omitempty"`
	ImplementsRaw []string     `json:"implements_raw,omitempty"`
	Implements    []string     `json:"implements,omitempty"`
	Nested        []string     `json:"nested,omitempty"`
	Fields        []FieldInfo  `json:"fields,omitempty"`
	Methods       []MethodInfo `json:"methods,omitempty"`
}

type FieldInfo struct {
	Name        string       `json:"name"`
	TypeRaw     string       `json:"type_raw"`
	Type        string       `json:"type,omitempty"`
	Modifiers   []string     `json:"modifiers,omitempty"`
	Annotations []Annotation `json:"annotations,omitempty"`
	Constant    string       `json:"constant,omitempty"`
	Line        int          `json:"line"`
}

type MethodInfo struct {
	Name        string       `json:"name"`
	Symbol      string       `json:"symbol"`
	ReturnRaw   string       `json:"return_raw,omitempty"`
	ReturnType  string       `json:"return_type,omitempty"`
	Constructor bool         `json:"constructor,omitempty"`
	TypeParams  []string     `json:"type_params,omitempty"`
	Params      []ParamInfo  `json:"params,omitempty"`
	Modifiers   []string     `json:"modifiers,omitempty"`
	Annotations []Annotation `json:"annotations,omitempty"`
	Line        int          `json:"line"`
	EndLine     int          `json:"end_line,omitempty"`
	HasBody     bool         `json:"has_body"`
}

type ParamInfo struct {
	Name        string       `json:"name"`
	TypeRaw     string       `json:"type_raw"`
	Type        string       `json:"type,omitempty"`
	Varargs     bool         `json:"varargs,omitempty"`
	Annotations []Annotation `json:"annotations,omitempty"`
	Line        int          `json:"line"`
}

type CallEdge struct {
	Caller       string   `json:"caller"`
	File         string   `json:"file"`
	SHA256       string   `json:"sha256"`
	Line         int      `json:"line"`
	Receiver     string   `json:"receiver,omitempty"`
	API          string   `json:"api"`
	Args         []string `json:"args,omitempty"`
	ArgTypes     []string `json:"arg_types,omitempty"`
	Target       string   `json:"target,omitempty"`
	TargetFile   string   `json:"target_file,omitempty"`
	TargetSHA256 string   `json:"target_sha256,omitempty"`
	Status       string   `json:"status"`
	Reason       string   `json:"reason,omitempty"`
}

type Coverage struct {
	FilesScanned       int    `json:"files_scanned"`
	FilesRejected      int    `json:"files_rejected"`
	TypesIndexed       int    `json:"types_indexed"`
	MethodsIndexed     int    `json:"methods_indexed"`
	FieldsIndexed      int    `json:"fields_indexed"`
	ConstantsFolded    int    `json:"constants_folded"`
	AnnotationsIndexed int    `json:"annotations_indexed"`
	CallsObserved      int    `json:"calls_observed"`
	CallsResolved      int    `json:"calls_resolved"`
	CallsAmbiguous     int    `json:"calls_ambiguous"`
	CallsUnresolved    int    `json:"calls_unresolved"`
	ExternalCalls      int    `json:"external_calls"`
	InterfaceDispatch  int    `json:"interface_dispatches"`
	RuntimeStatus      string `json:"runtime_status"`
}

type RejectedFile struct {
	Path   string
	SHA256 string
	Reason string
}

// ScanResult is the parser output shared with analyzers that only need AST
// availability and declaration counts.
type ScanResult struct {
	Units    []*Unit
	Rejected []RejectedFile
}

// ScanSnapshot parses every .java file in the pinned snapshot with the
// restricted subset parser. A malformed file is rejected alone and reported;
// the rest of the snapshot is still analyzed.
func ScanSnapshot(ctx context.Context, snapshot *project.Snapshot) (ScanResult, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return ScanResult{}, fmt.Errorf("%w: pinned snapshot required", ErrLimit)
	}
	hashes := map[string]string{}
	var paths []string
	for _, entry := range snapshot.Manifest().Entries {
		if strings.HasSuffix(entry.Path, ".java") {
			paths = append(paths, entry.Path)
		}
		hashes[entry.Path] = entry.SHA256
	}
	sort.Strings(paths)
	if len(paths) > MaxFiles {
		return ScanResult{}, fmt.Errorf("%w: Java file count exceeds %d", ErrLimit, MaxFiles)
	}
	result := ScanResult{}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return ScanResult{}, err
		}
		data, err := snapshot.ReadFile(ctx, path)
		if err != nil {
			return ScanResult{}, err
		}
		unit, parseErr := ParseFile(path, hashes[path], data)
		if parseErr != nil {
			result.Rejected = append(result.Rejected, RejectedFile{
				Path: path, SHA256: hashes[path], Reason: parseErr.Error(),
			})
			continue
		}
		result.Units = append(result.Units, unit)
	}
	return result, nil
}

// DeclarationCounts returns the number of indexed types and methods in a scan
// result without building the full call graph.
func DeclarationCounts(result ScanResult) (types, methods int) {
	for _, unit := range result.Units {
		for _, decl := range flattenTypes(unit) {
			types++
			methods += len(decl.Methods)
		}
	}
	return types, methods
}

// Analyze builds the semantic model for a pinned snapshot.
func Analyze(ctx context.Context, snapshot *project.Snapshot) (Model, error) {
	scan, err := ScanSnapshot(ctx, snapshot)
	if err != nil {
		return Model{}, err
	}
	ix := newIndex(scan.Units)
	ix.walkCalls()

	report := Model{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  AnalysisKind,
		Files:         []FileInfo{},
		Types:         []TypeInfo{},
		Calls:         ix.sortedCalls(),
	}
	rejected := map[string]RejectedFile{}
	for _, item := range scan.Rejected {
		rejected[item.Path] = item
	}
	paths := make([]string, 0, len(scan.Units)+len(scan.Rejected))
	for _, unit := range scan.Units {
		paths = append(paths, unit.Path)
	}
	for path := range rejected {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if item, ok := rejected[path]; ok {
			report.Files = append(report.Files, FileInfo{
				Path: item.Path, SHA256: item.SHA256, ParseError: item.Reason,
				Boundaries: []string{"rejected_java_file"},
			})
			continue
		}
		unit := ix.unitByPath[path]
		info := FileInfo{
			Path: unit.Path, SHA256: unit.SHA256, Package: unit.Package,
			Imports: append([]Import(nil), unit.Imports...),
		}
		for _, decl := range flattenTypes(unit) {
			info.Types = append(info.Types, decl.FQN)
		}
		info.Boundaries = ix.fileBoundaries(unit)
		report.Files = append(report.Files, info)
	}
	for _, decl := range ix.sortedTypes() {
		report.Types = append(report.Types, ix.typeInfo(decl))
	}
	// Constants and annotations are folded while building the output, so the
	// coverage counters are snapshotted only after this point.
	report.Partial = len(scan.Rejected) > 0 || ix.partial
	report.Limitations = ix.limitations()
	report.Coverage = Coverage{
		FilesScanned:       len(scan.Units) + len(scan.Rejected),
		FilesRejected:      len(scan.Rejected),
		TypesIndexed:       ix.typeCount,
		MethodsIndexed:     ix.methodCount,
		FieldsIndexed:      ix.fieldCount,
		ConstantsFolded:    ix.constantsFolded,
		AnnotationsIndexed: ix.annotationCount,
		CallsObserved:      ix.callsObserved,
		CallsResolved:      ix.callsResolved,
		CallsAmbiguous:     ix.callsAmbiguous,
		CallsUnresolved:    ix.callsUnresolved,
		ExternalCalls:      ix.externalCalls,
		InterfaceDispatch:  ix.dispatches,
		RuntimeStatus:      "not_run",
	}
	return report, nil
}

type index struct {
	units       []*Unit
	unitByPath  map[string]*Unit
	unitTypes   map[*Unit][]*Type
	all         []*Type
	byFQN       map[string]*Type
	bySimple    map[string][]*Type
	folded      map[*Field]Value
	folding     map[*Field]bool
	boundaries  map[string]map[string]bool
	calls       []CallEdge
	callKeys    map[string]bool
	partial     bool
	typeCount   int
	methodCount int
	fieldCount  int

	constantsFolded  int
	annotationCount  int
	callsObserved    int
	callsResolved    int
	callsAmbiguous   int
	callsUnresolved  int
	externalCalls    int
	dispatches       int
	staticImportSeen bool
}

func newIndex(units []*Unit) *index {
	ix := &index{
		units:      units,
		unitByPath: map[string]*Unit{},
		unitTypes:  map[*Unit][]*Type{},
		byFQN:      map[string]*Type{},
		bySimple:   map[string][]*Type{},
		folded:     map[*Field]Value{},
		folding:    map[*Field]bool{},
		boundaries: map[string]map[string]bool{},
		callKeys:   map[string]bool{},
	}
	for _, unit := range units {
		ix.unitByPath[unit.Path] = unit
		for _, imp := range unit.Imports {
			if imp.Static {
				ix.staticImportSeen = true
			}
		}
		decls := flattenTypes(unit)
		ix.unitTypes[unit] = decls
		for _, decl := range decls {
			ix.all = append(ix.all, decl)
			ix.byFQN[decl.FQN] = decl
			ix.bySimple[decl.Name] = append(ix.bySimple[decl.Name], decl)
			ix.typeCount++
			ix.fieldCount += len(decl.Fields)
			ix.methodCount += len(decl.Methods)
		}
	}
	for _, decl := range ix.all {
		if decl.ExtendsRaw != "" {
			decl.Extends = ix.resolveType(decl.Unit, decl.Parent, decl.ExtendsRaw)
		}
		decl.Implements = nil
		for _, raw := range decl.ImplementsRaw {
			if fqn := ix.resolveType(decl.Unit, decl.Parent, raw); fqn != "" {
				decl.Implements = append(decl.Implements, fqn)
			}
		}
	}
	return ix
}

func flattenTypes(unit *Unit) []*Type {
	var out []*Type
	var walk func(*Type)
	walk = func(decl *Type) {
		out = append(out, decl)
		for _, nested := range decl.Nested {
			walk(nested)
		}
	}
	for _, decl := range unit.Types {
		walk(decl)
	}
	return out
}

func (ix *index) sortedTypes() []*Type {
	out := append([]*Type(nil), ix.all...)
	sort.Slice(out, func(i, j int) bool { return out[i].FQN < out[j].FQN })
	return out
}

func (ix *index) fileBoundaries(unit *Unit) []string {
	set := map[string]bool{}
	for _, item := range unit.Boundaries {
		set[item] = true
	}
	for item := range ix.boundaries[unit.Path] {
		set[item] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func (ix *index) limitations() []string {
	items := []string{
		"java_subset_parser: restricted Java subset only; text blocks, complex lambdas, anonymous classes, method references and dynamic constructs are boundaries, not parsed",
		"java_declarations_only: declarations, erased signatures, constants, annotations and direct call expressions; control flow, aliases, points-to and taint dataflow are not modeled",
		"constant_folding_bounded: only literals, static final fields, string concatenation, integer addition, class literals and enum constants are folded",
		"reflection_not_resolved",
		"dynamic_proxy_and_aop_not_resolved",
		"external_types_not_resolved: JDK and library types are named but their method bodies are not analyzed",
		"classpath_not_resolved",
		"runtime_status_not_run",
	}
	if ix.staticImportSeen {
		items = append(items, "static_import_constants_not_folded")
	}
	if ix.partial {
		items = append(items, "partial_parse_or_limit")
	}
	sort.Strings(items)
	return items
}

// resolveType returns an erased, project- or import-qualified spelling for a
// source type reference, or "" when it cannot be resolved.
func (ix *index) resolveType(unit *Unit, enclosing *Type, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	suffix := ""
	for strings.HasSuffix(raw, "[]") {
		suffix += "[]"
		raw = strings.TrimSuffix(raw, "[]")
	}
	if raw == "" {
		return ""
	}
	if isPrimitive(raw) {
		return raw + suffix
	}
	if raw == "var" {
		return ""
	}
	if enclosing != nil && isTypeParam(enclosing, raw) {
		return raw + suffix
	}
	parts := strings.Split(raw, ".")
	if len(parts) == 1 {
		return ix.resolveSimple(unit, enclosing, raw) + suffix
	}
	if _, ok := ix.byFQN[raw]; ok {
		return raw + suffix
	}
	head := ix.resolveSimple(unit, enclosing, parts[0])
	if head == "" {
		return ""
	}
	candidate := head
	for _, part := range parts[1:] {
		candidate += "." + part
		if _, ok := ix.byFQN[candidate]; !ok {
			return candidate + suffix
		}
	}
	return candidate + suffix
}

func isTypeParam(decl *Type, name string) bool {
	for _, item := range decl.TypeParams {
		if item == name {
			return true
		}
	}
	for current := decl; current != nil; current = current.Parent {
		for _, item := range current.TypeParams {
			if item == name {
				return true
			}
		}
	}
	return false
}

func (ix *index) resolveSimple(unit *Unit, enclosing *Type, name string) string {
	for current := enclosing; current != nil; current = current.Parent {
		if current.Name == name {
			return current.FQN
		}
		for _, nested := range current.Nested {
			if nested.Name == name {
				return nested.FQN
			}
		}
	}
	for _, decl := range ix.unitTypes[unit] {
		if decl.Name == name {
			return decl.FQN
		}
	}
	for _, imp := range unit.Imports {
		if imp.Static || strings.HasSuffix(imp.Name, ".*") {
			continue
		}
		if strings.HasSuffix(imp.Name, "."+name) {
			return imp.Name
		}
	}
	if unit.Package != "" {
		if _, ok := ix.byFQN[unit.Package+"."+name]; ok {
			return unit.Package + "." + name
		}
	}
	if javaLangTypes[name] {
		return "java.lang." + name
	}
	for _, imp := range unit.Imports {
		if imp.Static || !strings.HasSuffix(imp.Name, ".*") {
			continue
		}
		fqn := strings.TrimSuffix(imp.Name, ".*") + "." + name
		if _, ok := ix.byFQN[fqn]; ok {
			return fqn
		}
	}
	if list := ix.bySimple[name]; len(list) == 1 {
		return list[0].FQN
	}
	return ""
}

var javaLangTypes = map[string]bool{
	"Object": true, "String": true, "CharSequence": true, "StringBuilder": true, "StringBuffer": true,
	"Integer": true, "Long": true, "Short": true, "Byte": true, "Double": true, "Float": true,
	"Boolean": true, "Character": true, "Number": true, "Math": true, "System": true, "Void": true,
	"Class": true, "Enum": true, "Iterable": true, "Comparable": true, "Thread": true, "Runnable": true,
	"Exception": true, "RuntimeException": true, "IllegalArgumentException": true,
	"IllegalStateException": true, "Throwable": true, "Error": true, "Override": true,
	"Deprecated": true, "SuppressWarnings": true, "FunctionalInterface": true,
}

// typeInfo converts one parsed declaration into the stable output shape,
// resolving erased types and folding annotations once.
func (ix *index) typeInfo(decl *Type) TypeInfo {
	info := TypeInfo{
		FQN: decl.FQN, Name: decl.Name, Kind: decl.Kind, File: decl.Unit.Path, Line: decl.Line,
		Modifiers:   append([]string(nil), decl.Modifiers...),
		Annotations: ix.foldAnnotations(decl.Unit, decl, decl.Annotations),
		ExtendsRaw:  decl.ExtendsRaw, Extends: decl.Extends,
		ImplementsRaw: append([]string(nil), decl.ImplementsRaw...),
		Implements:    append([]string(nil), decl.Implements...),
	}
	for _, nested := range decl.Nested {
		info.Nested = append(info.Nested, nested.FQN)
	}
	for _, field := range decl.Fields {
		item := FieldInfo{
			Name: field.Name, TypeRaw: field.TypeRaw,
			Type:        ix.resolveType(decl.Unit, decl, field.TypeRaw),
			Modifiers:   append([]string(nil), field.Modifiers...),
			Annotations: ix.foldAnnotations(decl.Unit, decl, field.Annotations),
			Constant:    field.Constant, Line: field.Line,
		}
		info.Fields = append(info.Fields, item)
	}
	for _, method := range decl.Methods {
		info.Methods = append(info.Methods, ix.methodInfo(decl, method))
	}
	return info
}

func (ix *index) methodInfo(decl *Type, method *Method) MethodInfo {
	info := MethodInfo{
		Name: method.Name, Symbol: ix.methodSymbol(method),
		ReturnRaw: method.ReturnRaw, Constructor: method.Constructor,
		TypeParams:  append([]string(nil), method.TypeParams...),
		Modifiers:   append([]string(nil), method.Modifiers...),
		Annotations: ix.foldAnnotations(decl.Unit, decl, method.Annotations),
		Line:        method.Line, HasBody: method.BodyStart > 0 && method.BodyEnd > method.BodyStart,
	}
	if method.ReturnRaw != "" {
		info.ReturnType = ix.resolveType(decl.Unit, decl, method.ReturnRaw)
	}
	for _, param := range method.Params {
		info.Params = append(info.Params, ParamInfo{
			Name: param.Name, TypeRaw: param.TypeRaw,
			Type:        ix.resolveType(decl.Unit, decl, param.TypeRaw),
			Varargs:     param.Varargs,
			Annotations: ix.foldAnnotations(decl.Unit, decl, param.Annotations),
			Line:        param.Line,
		})
	}
	if unit := decl.Unit; unit != nil && method.BodyEnd > 0 && method.BodyEnd < len(unit.Tokens) {
		info.EndLine = unit.Tokens[method.BodyEnd].line
	}
	return info
}

func (ix *index) methodSymbol(method *Method) string {
	name := method.Name
	if method.Constructor {
		name = "<init>"
	}
	var params []string
	for _, param := range method.Params {
		params = append(params, ix.resolveType(method.Class.Unit, method.Class, param.TypeRaw))
	}
	return method.Class.FQN + "#" + name + "(" + strings.Join(params, ",") + ")"
}

// foldAnnotations returns the annotation list with literal/constant arguments
// folded. Raw token text is never emitted.
func (ix *index) foldAnnotations(unit *Unit, enclosing *Type, annotations []Annotation) []Annotation {
	if len(annotations) == 0 {
		return nil
	}
	out := make([]Annotation, 0, len(annotations))
	for _, item := range annotations {
		ix.annotationCount++
		folded := Annotation{Name: item.Name, Line: item.Line}
		for _, raw := range item.RawArgs {
			folded.Args = append(folded.Args, ix.foldAnnotationArg(unit, enclosing, raw))
		}
		out = append(out, folded)
	}
	return out
}

func (ix *index) foldAnnotationArg(unit *Unit, enclosing *Type, raw string) AnnotationArg {
	arg := AnnotationArg{Name: "value", Value: Value{Kind: "expr", Text: strings.TrimSpace(raw)}}
	if len(raw) > MaxRawArgBytes {
		return arg
	}
	tokens, err := tokenize([]byte(raw))
	if err != nil || len(tokens) == 0 {
		return arg
	}
	if len(tokens) >= 2 && isIdentifier(tokens[0].text) && tokens[1].text == "=" {
		arg.Name = tokens[0].text
		tokens = tokens[2:]
	}
	arg.Value = ix.foldTokens(unit, enclosing, tokens)
	return arg
}

func (ix *index) foldTokens(unit *Unit, enclosing *Type, tokens []token) Value {
	if len(tokens) == 0 {
		return Value{Kind: "expr", Text: ""}
	}
	if tokens[0].text == "(" {
		if close := matchDelim(tokens, 0, "(", ")"); close == len(tokens)-1 {
			return ix.foldTokens(unit, enclosing, tokens[1:len(tokens)-1])
		}
		if raw, next := parseTypeAt(tokens, 1); raw != "" && next < len(tokens) && tokens[next].text == ")" && next < len(tokens)-1 {
			return ix.foldTokens(unit, enclosing, tokens[next+1:])
		}
	}
	if len(tokens) == 2 && tokens[0].text == "-" && isNumber(tokens[1].text) {
		return Value{Kind: "number", Text: "-" + tokens[1].text}
	}
	if tokens[0].text == "{" {
		if close := matchDelim(tokens, 0, "{", "}"); close == len(tokens)-1 {
			value := Value{Kind: "array"}
			for _, part := range splitTopLevel(tokens[1:len(tokens)-1], ",") {
				if len(part) == 0 {
					continue
				}
				value.Elements = append(value.Elements, ix.foldTokens(unit, enclosing, part))
			}
			return value
		}
	}
	if parts := splitTopLevel(tokens, "+"); len(parts) > 1 {
		values := make([]Value, 0, len(parts))
		for _, part := range parts {
			values = append(values, ix.foldTokens(unit, enclosing, part))
		}
		if folded, ok := concatValues(values); ok {
			return folded
		}
	}
	if len(tokens) == 1 {
		return ix.foldAtom(unit, enclosing, tokens[0])
	}
	if isNameChain(tokens) {
		return ix.foldNameChain(unit, enclosing, tokens)
	}
	return Value{Kind: "expr", Text: joinTokens(tokens)}
}

func (ix *index) foldAtom(unit *Unit, enclosing *Type, item token) Value {
	if text, ok := unquote(item.text); ok {
		return Value{Kind: "string", Text: text}
	}
	if len(item.text) >= 2 && item.text[0] == '\'' && item.text[len(item.text)-1] == '\'' {
		return Value{Kind: "char", Text: item.text[1 : len(item.text)-1]}
	}
	if isNumber(item.text) {
		return Value{Kind: "number", Text: item.text}
	}
	switch item.text {
	case "true", "false":
		return Value{Kind: "bool", Text: item.text}
	case "null":
		return Value{Kind: "name", Text: "null"}
	}
	if isIdentifier(item.text) && !isKeyword(item.text) {
		if value, ok := ix.constantByName(unit, enclosing, item.text); ok {
			return value
		}
		return Value{Kind: "name", Text: item.text}
	}
	return Value{Kind: "expr", Text: item.text}
}

func (ix *index) foldNameChain(unit *Unit, enclosing *Type, tokens []token) Value {
	raw := joinNameChain(tokens)
	parts := make([]string, 0, len(tokens)/2+1)
	for index := 0; index < len(tokens); index += 2 {
		parts = append(parts, tokens[index].text)
	}
	if len(tokens) >= 2 && tokens[len(tokens)-1].text == "class" {
		if fqn := ix.resolveType(unit, enclosing, strings.Join(parts[:len(parts)-1], ".")); fqn != "" {
			return Value{Kind: "name", Text: fqn}
		}
		return Value{Kind: "name", Text: raw}
	}
	head := ix.resolveType(unit, enclosing, parts[0])
	if head == "" {
		return Value{Kind: "name", Text: raw}
	}
	if len(parts) == 1 {
		return Value{Kind: "name", Text: head}
	}
	decl, ok := ix.byFQN[head]
	if !ok {
		return Value{Kind: "name", Text: head + "." + strings.Join(parts[1:], ".")}
	}
	if len(parts) == 2 {
		if owner, field := ix.findField(decl, parts[1]); field != nil {
			if owner.Kind == "enum" && field.Constant != "" {
				return Value{Kind: "name", Text: owner.FQN + "." + field.Constant}
			}
			if value, ok := ix.fieldValue(owner, field, 0); ok {
				return value
			}
		}
	}
	candidate := head
	for _, part := range parts[1:] {
		candidate += "." + part
	}
	if _, ok := ix.byFQN[candidate]; ok {
		return Value{Kind: "name", Text: candidate}
	}
	return Value{Kind: "name", Text: candidate}
}

func (ix *index) constantByName(unit *Unit, enclosing *Type, name string) (Value, bool) {
	for current := enclosing; current != nil; current = current.Parent {
		if owner, field := ix.findField(current, name); field != nil {
			if value, ok := ix.fieldValue(owner, field, 0); ok {
				return value, true
			}
		}
	}
	for _, imp := range unit.Imports {
		if !imp.Static {
			continue
		}
		dot := strings.LastIndex(imp.Name, ".")
		if dot < 0 || imp.Name[dot+1:] != name {
			continue
		}
		owner := imp.Name[:dot]
		decl, ok := ix.byFQN[owner]
		if !ok {
			continue
		}
		if owner, field := ix.findField(decl, name); field != nil {
			if value, ok := ix.fieldValue(owner, field, 0); ok {
				return value, true
			}
		}
	}
	return Value{}, false
}

func (ix *index) fieldValue(decl *Type, field *Field, depth int) (Value, bool) {
	if cached, ok := ix.folded[field]; ok {
		return cached, true
	}
	if ix.folding[field] || depth > MaxFoldDepth || len(ix.folded) >= MaxConstants {
		return Value{}, false
	}
	if !field.HasInitializer || field.InitStart < 0 || field.InitEnd <= field.InitStart {
		return Value{}, false
	}
	if !isConstantField(field) {
		return Value{}, false
	}
	unit := decl.Unit
	if unit == nil || field.InitEnd > len(unit.Tokens) {
		return Value{}, false
	}
	ix.folding[field] = true
	value := ix.foldTokens(unit, decl, unit.Tokens[field.InitStart:field.InitEnd])
	delete(ix.folding, field)
	if value.Kind == "expr" {
		return Value{}, false
	}
	ix.folded[field] = value
	ix.constantsFolded++
	return value, true
}

func isConstantField(field *Field) bool {
	if field.Constant != "" {
		return true
	}
	for _, modifier := range field.Modifiers {
		if modifier == "final" {
			return true
		}
	}
	return false
}

func (ix *index) findField(decl *Type, name string) (*Type, *Field) {
	seen := map[string]bool{}
	for current := decl; current != nil; {
		if seen[current.FQN] {
			break
		}
		seen[current.FQN] = true
		for _, field := range current.Fields {
			if field.Name == name {
				return current, field
			}
		}
		if current.Extends == "" {
			break
		}
		parent, ok := ix.byFQN[current.Extends]
		if !ok {
			break
		}
		current = parent
	}
	return nil, nil
}

func concatValues(values []Value) (Value, bool) {
	text := false
	numeric := true
	var sum int
	for _, value := range values {
		switch value.Kind {
		case "string", "char":
			text = true
			numeric = false
		case "number":
			number, err := strconv.Atoi(value.Text)
			if err != nil {
				numeric = false
				continue
			}
			sum += number
		case "bool", "name":
			numeric = false
		default:
			return Value{}, false
		}
	}
	if text {
		var builder strings.Builder
		for _, value := range values {
			builder.WriteString(value.Text)
		}
		return Value{Kind: "string", Text: builder.String()}, true
	}
	if numeric {
		return Value{Kind: "number", Text: strconv.Itoa(sum)}, true
	}
	return Value{}, false
}

// walkCalls resolves every direct call in method bodies through the indexed
// hierarchy. Unresolved receivers, ambiguous overloads and interface dispatch
// are recorded explicitly instead of being guessed.
func (ix *index) walkCalls() {
	for _, unit := range ix.units {
		for _, decl := range flattenTypes(unit) {
			for _, method := range decl.Methods {
				if method.BodyStart <= 0 || method.BodyEnd <= method.BodyStart {
					continue
				}
				ix.scanBody(decl, method)
			}
		}
	}
}

func (ix *index) scanBody(decl *Type, method *Method) {
	unit := decl.Unit
	tokens := unit.Tokens
	locals := map[string]string{}
	for _, param := range method.Params {
		locals[param.Name] = ix.resolveType(unit, decl, param.TypeRaw)
	}
	for position := method.BodyStart + 1; position < method.BodyEnd && position < len(tokens); {
		text := tokens[position].text
		if text == "-" && position+1 < method.BodyEnd && tokens[position+1].text == ">" {
			ix.addBoundary(unit, "lambda_not_resolved")
			position += 2
			continue
		}
		if text == ":" && position+1 < method.BodyEnd && tokens[position+1].text == ":" {
			ix.addBoundary(unit, "method_reference_not_resolved")
			position += 2
			continue
		}
		if text == "new" {
			if raw, next := parseTypeAt(tokens, position+1); raw != "" && next < method.BodyEnd && tokens[next].text == "(" {
				ix.recordConstructor(decl, method, locals, raw, tokens, next)
				position = next
				continue
			}
		}
		if text == "this" || text == "super" {
			if position+3 < method.BodyEnd && tokens[position+1].text == "." &&
				isCandidate(tokens[position+2].text) && tokens[position+3].text == "(" {
				ix.recordCall(decl, method, locals, text, tokens[position+2].text, tokens, position+3)
			}
			position++
			continue
		}
		if !isCandidate(text) {
			position++
			continue
		}
		// Local variable declaration: Type name (=|;|,|)|:|[ ]).
		if raw, next := parseTypeAt(tokens, position); raw != "" && next > position &&
			next < method.BodyEnd && isCandidate(tokens[next].text) {
			terminator := next + 1
			if terminator < method.BodyEnd {
				switch tokens[terminator].text {
				case "=", ";", ",", ")", ":":
					locals[tokens[next].text] = ix.resolveType(unit, decl, raw)
					position = terminator + 1
					continue
				case "[":
					if terminator+1 < method.BodyEnd && tokens[terminator+1].text == "]" {
						locals[tokens[next].text] = ix.resolveType(unit, decl, raw)
						position = terminator + 2
						continue
					}
				}
			}
		}
		if position+1 < method.BodyEnd && tokens[position+1].text == "(" && tokens[position-1].text != "." {
			ix.recordCall(decl, method, locals, "", text, tokens, position+1)
			position++
			continue
		}
		if position+2 < method.BodyEnd && tokens[position+1].text == "." &&
			isCandidate(tokens[position+2].text) {
			receiver := text
			name := tokens[position+2].text
			if position+3 < method.BodyEnd && tokens[position+3].text == "(" {
				ix.recordCall(decl, method, locals, receiver, name, tokens, position+3)
			} else if position+3 < method.BodyEnd && tokens[position+3].text == ":" &&
				position+4 < method.BodyEnd && tokens[position+4].text == ":" {
				ix.addBoundary(unit, "method_reference_not_resolved")
			}
			position++
			continue
		}
		if position > 0 && tokens[position-1].text == "." && position+1 < method.BodyEnd && tokens[position+1].text == "(" {
			before := ""
			if position >= 2 {
				before = tokens[position-2].text
			}
			if before == ")" || before == "]" || before == "" {
				ix.recordEdge(decl, method, "", text, nil, nil, "", CallUnresolved, "receiver_expression_not_resolved")
			}
			position++
			continue
		}
		position++
	}
}

func (ix *index) recordConstructor(decl *Type, method *Method, locals map[string]string, raw string, tokens []token, open int) {
	close := matchDelim(tokens, open, "(", ")")
	if close < 0 {
		return
	}
	argTokens := splitTopLevel(tokens[open+1:close], ",")
	args, argTypes := ix.arguments(decl, locals, argTokens)
	target := ix.resolveType(decl.Unit, decl, raw)
	if target == "" || !ix.isProjectType(target) {
		ix.externalCalls++
		return
	}
	declType := ix.byFQN[target]
	symbol, found, status := ix.resolveConstructor(declType, argTypes)
	if found {
		ix.recordEdge(decl, method, "", declType.Name, args, argTypes, symbol, status, "")
		return
	}
	ix.recordEdge(decl, method, "", declType.Name, args, argTypes, "", CallUnresolved, "no_matching_constructor")
}

func (ix *index) resolveConstructor(decl *Type, argTypes []string) (string, bool, string) {
	var candidates []*Method
	for _, method := range decl.Methods {
		if method.Constructor {
			candidates = append(candidates, method)
		}
	}
	if len(candidates) == 0 {
		if len(argTypes) == 0 && decl.Kind != "interface" && decl.Kind != "enum" {
			return decl.FQN + "#<init>()", true, CallResolved
		}
		return "", false, CallUnresolved
	}
	best, status := ix.selectCandidate(candidates, argTypes)
	if best == nil {
		return "", false, status
	}
	return ix.methodSymbol(best), true, status
}

func (ix *index) recordCall(decl *Type, method *Method, locals map[string]string, receiver, name string, tokens []token, open int) {
	close := matchDelim(tokens, open, "(", ")")
	if close < 0 {
		return
	}
	argTokens := splitTopLevel(tokens[open+1:close], ",")
	args, argTypes := ix.arguments(decl, locals, argTokens)
	line := tokens[open].line

	recvType, kind := ix.receiverType(decl, locals, receiver)
	if kind == "unresolved" {
		if reflectionAPIs[name] {
			ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallUnresolved, "reflection_not_resolved", line)
			ix.addBoundary(decl.Unit, "reflection_not_resolved")
			return
		}
		ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallUnresolved, "unresolved_receiver", line)
		return
	}
	if recvType == "" || !ix.isProjectType(recvType) {
		if reflectionAPIs[name] {
			ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallUnresolved, "reflection_not_resolved", line)
			ix.addBoundary(decl.Unit, "reflection_not_resolved")
			return
		}
		ix.externalCalls++
		return
	}
	declType := ix.byFQN[recvType]
	candidates := ix.methodCandidates(declType, name)
	if len(candidates) == 0 && receiver == "" {
		// An inner class may call an instance method of an enclosing class.
		for outer := decl.Parent; outer != nil; outer = outer.Parent {
			if found := ix.methodCandidates(outer, name); len(found) > 0 {
				declType = outer
				candidates = found
				break
			}
		}
	}
	if len(candidates) == 0 {
		if ix.hasUnresolvedParent(declType) {
			ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallUnresolved, "parent_outside_snapshot", line)
			return
		}
		ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallUnresolved, "no_matching_method", line)
		return
	}
	best, status := ix.selectCandidate(candidates, argTypes)
	if best == nil {
		if status == CallAmbiguous {
			ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallAmbiguous, "ambiguous_overload", line)
		} else {
			ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallUnresolved, "no_matching_arity_or_types", line)
		}
		return
	}
	if status == CallAmbiguous {
		ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallAmbiguous, "ambiguous_overload", line)
		return
	}
	if best.BodyStart > 0 {
		ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, ix.methodSymbol(best), CallResolved, "", line)
		return
	}
	// Bodyless interface/abstract method: dispatch only when exactly one
	// concrete implementation exists in the snapshot.
	impls := ix.concreteImplementations(declType.FQN, best)
	if len(impls) == 1 {
		ix.dispatches++
		ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, ix.methodSymbol(impls[0]), CallResolved, "interface_dispatch", line)
		return
	}
	if len(impls) > 1 {
		ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallAmbiguous, "ambiguous_dispatch", line)
		return
	}
	ix.recordEdgeAt(decl, method, receiver, name, args, argTypes, "", CallUnresolved, "no_concrete_implementation", line)
}

func (ix *index) arguments(decl *Type, locals map[string]string, parts [][]token) ([]string, []string) {
	args := make([]string, 0, len(parts))
	types := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		args = append(args, truncate(joinTokens(part), 200))
		types = append(types, ix.inferType(decl, locals, part))
	}
	return args, types
}

func (ix *index) inferType(decl *Type, locals map[string]string, tokens []token) string {
	if len(tokens) == 0 {
		return ""
	}
	if tokens[0].text == "(" {
		if close := matchDelim(tokens, 0, "(", ")"); close == len(tokens)-1 {
			return ix.inferType(decl, locals, tokens[1:len(tokens)-1])
		}
		if raw, next := parseTypeAt(tokens, 1); raw != "" && next < len(tokens) && tokens[next].text == ")" && next < len(tokens)-1 {
			if resolved := ix.resolveType(decl.Unit, decl, raw); resolved != "" {
				return resolved
			}
			return ix.inferType(decl, locals, tokens[next+1:])
		}
	}
	if tokens[0].text == "new" {
		if raw, _ := parseTypeAt(tokens, 1); raw != "" {
			return ix.resolveType(decl.Unit, decl, raw)
		}
	}
	if len(tokens) == 1 {
		item := tokens[0].text
		if _, ok := unquote(item); ok {
			return "java.lang.String"
		}
		if len(item) >= 2 && item[0] == '\'' && item[len(item)-1] == '\'' {
			return "char"
		}
		if isNumber(item) {
			return numberType(item)
		}
		switch item {
		case "true", "false":
			return "boolean"
		case "null":
			return "null"
		}
		if isCandidate(item) {
			if resolved, ok := locals[item]; ok {
				return resolved
			}
			if _, field := ix.findField(decl, item); field != nil {
				return ix.resolveType(decl.Unit, decl, field.TypeRaw)
			}
		}
	}
	if parts := splitTopLevel(tokens, "+"); len(parts) > 1 {
		for _, part := range parts {
			if len(part) == 1 {
				if _, ok := unquote(part[0].text); ok {
					return "java.lang.String"
				}
			}
		}
	}
	return ""
}

func (ix *index) receiverType(decl *Type, locals map[string]string, receiver string) (string, string) {
	switch receiver {
	case "", "this":
		return decl.FQN, "this"
	case "super":
		if decl.Extends == "" {
			return "", "unresolved"
		}
		return decl.Extends, "super"
	}
	if resolved, ok := locals[receiver]; ok {
		if resolved == "" {
			return "", "unresolved"
		}
		return resolved, "local"
	}
	if _, field := ix.findField(decl, receiver); field != nil {
		resolved := ix.resolveType(decl.Unit, decl, field.TypeRaw)
		if resolved == "" {
			return "", "unresolved"
		}
		return resolved, "field"
	}
	if resolved := ix.resolveType(decl.Unit, decl, receiver); resolved != "" {
		return resolved, "type"
	}
	return "", "unresolved"
}

func (ix *index) methodCandidates(decl *Type, name string) []*Method {
	var out []*Method
	seen := map[string]bool{}
	var walk func(*Type)
	walk = func(current *Type) {
		if current == nil || seen[current.FQN] {
			return
		}
		seen[current.FQN] = true
		for _, method := range current.Methods {
			if !method.Constructor && method.Name == name {
				out = append(out, method)
			}
		}
		if current.Extends != "" {
			walk(ix.byFQN[current.Extends])
		}
		for _, parent := range current.Implements {
			walk(ix.byFQN[parent])
		}
	}
	walk(decl)
	return out
}

func (ix *index) hasUnresolvedParent(decl *Type) bool {
	for _, item := range append([]string{decl.ExtendsRaw}, decl.ImplementsRaw...) {
		if item != "" && ix.resolveType(decl.Unit, decl.Parent, item) == "" {
			return true
		}
	}
	return false
}

// selectCandidate picks the unique best overload. Unknown argument types are
// compatible at the lowest score; a tie stays ambiguous.
func (ix *index) selectCandidate(candidates []*Method, argTypes []string) (*Method, string) {
	bestScore := -1
	var best []*Method
	for _, method := range candidates {
		score, ok := ix.score(method, argTypes)
		if !ok {
			continue
		}
		switch {
		case score > bestScore:
			bestScore = score
			best = []*Method{method}
		case score == bestScore:
			best = append(best, method)
		}
	}
	if len(best) == 1 {
		return best[0], CallResolved
	}
	if len(best) > 1 {
		return nil, CallAmbiguous
	}
	return nil, CallUnresolved
}

func (ix *index) score(method *Method, argTypes []string) (int, bool) {
	params := method.Params
	if len(params) == 0 {
		if len(argTypes) == 0 {
			return 1, true
		}
		return 0, false
	}
	varargs := params[len(params)-1].Varargs
	if !varargs && len(argTypes) != len(params) {
		return 0, false
	}
	if varargs && len(argTypes) < len(params)-1 {
		return 0, false
	}
	total := 0
	for index, arg := range argTypes {
		raw := params[len(params)-1].TypeRaw
		if index < len(params) {
			raw = params[index].TypeRaw
		}
		if varargs && index >= len(params)-1 {
			raw = strings.TrimSuffix(strings.TrimSuffix(raw, "[]"), "...")
		}
		param := ix.resolveType(method.Class.Unit, method.Class, raw)
		score, ok := ix.matchType(arg, param, raw)
		if !ok {
			return 0, false
		}
		total += score
	}
	if varargs {
		total--
	}
	return total, true
}

func (ix *index) matchType(arg, param, rawParam string) (int, bool) {
	if arg == "" {
		return 1, true
	}
	if param == "" {
		if arg == rawParam || arg == "java.lang."+rawParam {
			return 2, true
		}
		return 1, true
	}
	if arg == param {
		return 4, true
	}
	if arg == "null" {
		if isPrimitive(param) {
			return 0, false
		}
		return 1, true
	}
	if param == "java.lang.Object" {
		return 1, true
	}
	if widening[arg][param] {
		return 2, true
	}
	if ix.isSubtype(arg, param) {
		return 3, true
	}
	if isPrimitive(arg) && isPrimitive(param) {
		return 0, false
	}
	if isPrimitive(arg) != isPrimitive(param) {
		if !isPrimitive(arg) {
			return 0, false
		}
		if wrapper[arg] == param {
			return 2, true
		}
	}
	return 0, false
}

func (ix *index) isSubtype(child, parent string) bool {
	if child == parent {
		return true
	}
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(name string) bool {
		if name == "" || seen[name] {
			return false
		}
		seen[name] = true
		if name == parent {
			return true
		}
		decl, ok := ix.byFQN[name]
		if !ok {
			return false
		}
		if decl.Extends != "" && walk(decl.Extends) {
			return true
		}
		for _, item := range decl.Implements {
			if walk(item) {
				return true
			}
		}
		// Interfaces declared through the single extends clause.
		if decl.ExtendsRaw != "" {
			resolved := ix.resolveType(decl.Unit, decl.Parent, decl.ExtendsRaw)
			if resolved != "" && resolved != decl.Extends && walk(resolved) {
				return true
			}
		}
		return false
	}
	return walk(child)
}

func (ix *index) concreteImplementations(parent string, method *Method) []*Method {
	var out []*Method
	for _, decl := range ix.all {
		if decl.Kind == "interface" || decl.Kind == "@interface" || decl.Kind == "enum" || decl.FQN == parent {
			continue
		}
		if !ix.isSubtype(decl.FQN, parent) {
			continue
		}
		for _, candidate := range decl.Methods {
			if candidate.Constructor || candidate.Name != method.Name || candidate.BodyStart <= 0 {
				continue
			}
			if sameSignature(ix, candidate, method) {
				out = append(out, candidate)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return ix.methodSymbol(out[i]) < ix.methodSymbol(out[j]) })
	return out
}

func sameSignature(ix *index, left, right *Method) bool {
	if len(left.Params) != len(right.Params) {
		return false
	}
	for index := range left.Params {
		lt := ix.resolveType(left.Class.Unit, left.Class, left.Params[index].TypeRaw)
		rt := ix.resolveType(right.Class.Unit, right.Class, right.Params[index].TypeRaw)
		if lt != rt {
			return false
		}
	}
	return true
}

func (ix *index) isProjectType(fqn string) bool {
	if fqn == "" {
		return false
	}
	_, ok := ix.byFQN[fqn]
	return ok
}

func (ix *index) recordEdge(decl *Type, method *Method, receiver, api string, args, argTypes []string, target, status, reason string) {
	ix.recordEdgeAt(decl, method, receiver, api, args, argTypes, target, status, reason, method.Line)
}

func (ix *index) recordEdgeAt(decl *Type, method *Method, receiver, api string, args, argTypes []string, target, status, reason string, line int) {
	if line <= 0 {
		return
	}
	if ix.callsObserved >= MaxCalls {
		ix.partial = true
		return
	}
	caller := ix.methodSymbol(method)
	key := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s", decl.Unit.Path, line, caller, receiver, api, target, status)
	if ix.callKeys[key] {
		return
	}
	ix.callKeys[key] = true
	edge := CallEdge{
		Caller: caller, File: decl.Unit.Path, SHA256: decl.Unit.SHA256, Line: line,
		Receiver: receiver, API: api, Args: args, ArgTypes: argTypes, Status: status, Reason: reason,
	}
	if target != "" {
		edge.Target = target
		if hash, file, ok := ix.symbolLocation(target); ok {
			edge.TargetFile = file
			edge.TargetSHA256 = hash
		}
	}
	ix.calls = append(ix.calls, edge)
	ix.callsObserved++
	switch status {
	case CallResolved:
		ix.callsResolved++
	case CallAmbiguous:
		ix.callsAmbiguous++
	case CallUnresolved:
		ix.callsUnresolved++
	}
}

func (ix *index) symbolLocation(symbol string) (string, string, bool) {
	hash := strings.Index(symbol, "#")
	if hash <= 0 {
		return "", "", false
	}
	decl, ok := ix.byFQN[symbol[:hash]]
	if !ok {
		return "", "", false
	}
	return decl.Unit.SHA256, decl.Unit.Path, true
}

func (ix *index) sortedCalls() []CallEdge {
	out := append([]CallEdge{}, ix.calls...)
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.API != right.API {
			return left.API < right.API
		}
		if left.Caller != right.Caller {
			return left.Caller < right.Caller
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		return left.Status < right.Status
	})
	return out
}

func (ix *index) addBoundary(unit *Unit, reason string) {
	if unit == nil {
		return
	}
	set := ix.boundaries[unit.Path]
	if set == nil {
		set = map[string]bool{}
		ix.boundaries[unit.Path] = set
	}
	set[reason] = true
}

var reflectionAPIs = map[string]bool{
	"forName": true, "getMethod": true, "getDeclaredMethod": true, "getMethods": true,
	"getDeclaredMethods": true, "getConstructor": true, "getDeclaredConstructor": true,
	"newInstance": true, "invoke": true, "newProxyInstance": true,
}

var widening = map[string]map[string]bool{
	"byte":  {"short": true, "int": true, "long": true, "float": true, "double": true},
	"short": {"int": true, "long": true, "float": true, "double": true},
	"char":  {"int": true, "long": true, "float": true, "double": true},
	"int":   {"long": true, "float": true, "double": true},
	"long":  {"float": true, "double": true},
	"float": {"double": true},
}

var wrapper = map[string]string{
	"int": "java.lang.Integer", "long": "java.lang.Long", "short": "java.lang.Short",
	"byte": "java.lang.Byte", "double": "java.lang.Double", "float": "java.lang.Float",
	"boolean": "java.lang.Boolean", "char": "java.lang.Character",
}

func isCandidate(text string) bool {
	return isIdentifier(text) && !isKeyword(text)
}

func isNumber(text string) bool {
	if text == "" {
		return false
	}
	first := text[0]
	if first >= '0' && first <= '9' {
		return true
	}
	return first == '.' && len(text) > 1 && text[1] >= '0' && text[1] <= '9'
}

func numberType(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.HasSuffix(lower, "l"):
		return "long"
	case strings.HasSuffix(lower, "f"):
		return "float"
	case strings.HasSuffix(lower, "d"), strings.ContainsAny(lower, ".e"):
		return "double"
	}
	return "int"
}

func isNameChain(tokens []token) bool {
	if len(tokens) == 0 || len(tokens)%2 == 0 {
		return false
	}
	for index, item := range tokens {
		if index%2 == 0 {
			if !isCandidate(item.text) {
				return false
			}
		} else if item.text != "." {
			return false
		}
	}
	return true
}

func joinNameChain(tokens []token) string {
	var builder strings.Builder
	for _, item := range tokens {
		if item.text == "." {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteString(".")
		}
		builder.WriteString(item.text)
	}
	return builder.String()
}

func joinTokens(tokens []token) string {
	parts := make([]string, 0, len(tokens))
	for _, item := range tokens {
		parts = append(parts, item.text)
	}
	return strings.Join(parts, " ")
}

func matchDelim(tokens []token, start int, open, close string) int {
	if start >= len(tokens) || tokens[start].text != open {
		return -1
	}
	depth := 0
	for index := start; index < len(tokens); index++ {
		switch tokens[index].text {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func splitTopLevel(tokens []token, separator string) [][]token {
	var parts [][]token
	var current []token
	depth := 0
	for _, item := range tokens {
		switch item.text {
		case "(", "{", "[":
			depth++
		case ")", "}", "]":
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && item.text == separator {
			parts = append(parts, current)
			current = nil
			continue
		}
		current = append(current, item)
	}
	parts = append(parts, current)
	for len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit]
}
