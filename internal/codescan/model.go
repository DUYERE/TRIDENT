// Package codescan implements a bounded, deterministic, multi-language code
// audit engine over a pinned read-only snapshot.
//
// Design: each language front end is only a tokenizer configuration; all
// language front ends emit the same token/statement IR, and one rule engine
// evaluates source -> propagator -> sanitizer -> sink paths against that IR.
// This mirrors the "unified IR + per-language front end" idea of open-source
// CPG tools and the declarative source/sink/sanitizer rule shape of taint-mode
// SAST rules, while staying pure Go, offline and deterministic.
//
// It never compiles, runs or imports the audited code, never resolves a type
// system, never follows cross-file/inter-procedural flows, never accesses the
// network and never upgrades static evidence to runtime exploitability.
package codescan

import (
	"errors"
	"sort"
	"strings"
)

const (
	SchemaVersion  = 1
	ToolVersion    = "0.2.0-p0.6+r1-multi-language-code-audit-v2"
	AnalysisKind   = "multi_language_code_audit_v2"
	RuleSetVersion = "trident-core-rules-2026-11-15-v2"

	MaxFiles             = 4000
	MaxFileBytes         = 2 << 20
	MaxTokensPerFile     = 200_000
	MaxStatementsPerFile = 20_000
	MaxFindings          = 10_000
	MaxFlowSteps         = 32
	MaxSymbols           = 2_000
	MaxCalls             = 4_000
	MaxUnresolved        = 2_000
	MaxVariables         = 10_000
	MaxStringConstants   = 5_000
	MaxRuleBytes         = 64 << 10
	MaxRules             = 256
	MaxPatternNames      = 64
	MaxChainSegments     = 6
)

var (
	ErrLimit       = errors.New("code audit analysis limit")
	ErrRule        = errors.New("code audit rule rejected")
	ErrUnsupported = errors.New("unsupported language")
)

// Options selects languages and optional caller-supplied rules. An empty
// Languages slice means every supported language present in the snapshot.
type Options struct {
	Languages []string
	RulePath  string
	Extra     []RuleSpec
}

// RuleSpec is the serialized, language-agnostic rule shape. Sources,
// sanitizers and sinks are declarative patterns (never regular expressions or
// executable code), following the taint-rule convention.
type RuleSpec struct {
	ID         string        `json:"id"`
	Languages  []string      `json:"languages"`
	Category   string        `json:"category"`
	CWE        string        `json:"cwe"`
	Severity   string        `json:"severity"`
	Confidence string        `json:"confidence"`
	Title      string        `json:"title"`
	Message    string        `json:"message"`
	Sources    []PatternSpec `json:"sources"`
	Sinks      []PatternSpec `json:"sinks"`
	Sanitizers []PatternSpec `json:"sanitizers,omitempty"`
	SafeCalls  []string      `json:"safe_calls,omitempty"`
}

// RuleFile is the caller-supplied rule catalog. Unknown fields, oversized
// files, duplicate IDs and invalid selectors fail closed.
type RuleFile struct {
	SchemaVersion  int        `json:"schema_version"`
	RuleSetVersion string     `json:"ruleset_version,omitempty"`
	Rules          []RuleSpec `json:"rules"`
}

// PatternSpec matches a normalized call/access chain. Kind is one of
// call, access, identifier, assign or any.
type PatternSpec struct {
	Kind     string   `json:"kind"`
	Names    []string `json:"names"`
	ArgIndex int      `json:"arg_index,omitempty"`
}

// Report is the deterministic top-level output of `trident audit code`.
type Report struct {
	SchemaVersion   int               `json:"schema_version"`
	ToolVersion     string            `json:"tool_version"`
	SnapshotHash    string            `json:"snapshot_hash"`
	AnalysisKind    string            `json:"analysis_kind"`
	RuleSetVersion  string            `json:"ruleset_version"`
	Partial         bool              `json:"partial"`
	FilePartial     bool              `json:"file_partial"`
	SymbolPartial   bool              `json:"symbol_partial"`
	FindingPartial  bool              `json:"finding_partial"`
	Languages       []LanguageSummary `json:"languages"`
	Files           []FileSummary     `json:"files"`
	Routes          []Route           `json:"routes"`
	Symbols         []Symbol          `json:"symbols"`
	Calls           []Call            `json:"calls"`
	Unresolved      []Unresolved      `json:"unresolved"`
	Variables       []Variable        `json:"variables"`
	StringConstants []StringConstant  `json:"string_constants"`
	Findings        []Finding         `json:"findings"`
	Coverage        Coverage          `json:"coverage"`
	Limitations     []string          `json:"limitations"`
}

// LanguageSummary reports observed files and rules for one language.
type LanguageSummary struct {
	Language      string   `json:"language"`
	Extensions    []string `json:"extensions"`
	FilesScanned  int      `json:"files_scanned"`
	FilesRejected int      `json:"files_rejected"`
	RulesActive   int      `json:"rules_active"`
	Findings      int      `json:"findings"`
	Routes        int      `json:"routes"`
	Symbols       int      `json:"symbols"`
	Calls         int      `json:"calls"`
	CallsResolved int      `json:"calls_resolved"`
	Unresolved    int      `json:"unresolved"`
	Variables     int      `json:"variables"`
	Strings       int      `json:"string_constants"`
	Status        string   `json:"status"` // scanned | no_source_files | skipped_by_filter
}

// FileSummary is one audited source file. Source text is never stored.
type FileSummary struct {
	File       string `json:"file"`
	Language   string `json:"language"`
	Scope      string `json:"scope,omitempty"` // project | vendor | generated
	SHA256     string `json:"sha256"`
	Bytes      int    `json:"bytes"`
	Tokens     int    `json:"tokens"`
	Statements int    `json:"statements"`
	Status     string `json:"status"` // scanned | rejected
	Reason     string `json:"reason,omitempty"`
}

// Route is a declarative HTTP entry point observed in source. Declaration is
// not deployment and is not proof of reachability.
type Route struct {
	Language    string   `json:"language"`
	Path        string   `json:"path"`
	Target      string   `json:"target,omitempty"`
	PathStatus  string   `json:"path_status,omitempty"` // declared | dynamic_unresolved | convention_candidate
	Reason      string   `json:"reason,omitempty"`
	Source      string   `json:"source,omitempty"` // declaration | database | convention
	HTTPMethods []string `json:"http_methods"`
	Symbol      string   `json:"symbol"`
	File        string   `json:"file"`
	SHA256      string   `json:"sha256"`
	Line        int      `json:"line"`
	Kind        string   `json:"kind"`
}

// SymbolParameter is the lexical name of one declared parameter. Types are
// deliberately absent: the current IR does not resolve a type system.
type SymbolParameter struct {
	Name string `json:"name"`
}

// Symbol is a lexical declaration, not a type-resolved entity. ID is stable for
// one file/index and is only an evidence key, not a language semantic identity.
type Symbol struct {
	ID            string            `json:"id"`
	Language      string            `json:"language"`
	Kind          string            `json:"kind"` // function | method | class | interface | struct | enum | record | trait | type
	Name          string            `json:"name"`
	QualifiedName string            `json:"qualified_name"`
	Container     string            `json:"container,omitempty"`
	File          string            `json:"file"`
	SHA256        string            `json:"sha256"`
	Line          int               `json:"line"`
	EndLine       int               `json:"end_line,omitempty"`
	Parameters    []SymbolParameter `json:"parameters,omitempty"`
}

// Call is one observed call site. Status is same_file when the exact simple
// name has a same-file declaration, same_project when a unique project-wide
// declaration matches, ambiguous_symbol when several match, and
// external_or_unresolved otherwise. Receiver/type dispatch is not resolved.
type Call struct {
	Language       string `json:"language"`
	Caller         string `json:"caller"`
	Callee         string `json:"callee"`
	Name           string `json:"name"`
	Receiver       string `json:"receiver,omitempty"`
	ReceiverType   string `json:"receiver_type,omitempty"`
	File           string `json:"file"`
	SHA256         string `json:"sha256"`
	Line           int    `json:"line"`
	Arguments      int    `json:"arguments,omitempty"`
	Status         string `json:"status"`
	ResolvedFile   string `json:"resolved_file,omitempty"`
	ResolvedSymbol string `json:"resolved_symbol,omitempty"`
}

// Variable is a lexical assignment target, not a type-resolved variable.
type Variable struct {
	Language string `json:"language"`
	Name     string `json:"name"`
	Kind     string `json:"kind"` // variable | constant
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Line     int    `json:"line"`
}

// StringConstant is a hashed string literal. The original text is deliberately
// never emitted; callers can correlate the hash without leaking secrets.
type StringConstant struct {
	Language string `json:"language"`
	Hash     string `json:"sha256"`
	File     string `json:"file"`
	SHA256   string `json:"file_sha256"`
	Line     int    `json:"line"`
	Length   int    `json:"length"`
}

// Unresolved is a call whose name could not be resolved to a unique project
// declaration. It is an evidence gap, not a vulnerability conclusion.
type Unresolved struct {
	Language string `json:"language"`
	Caller   string `json:"caller,omitempty"`
	Expr     string `json:"expr"`
	Reason   string `json:"reason"`
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Line     int    `json:"line"`
}

// Finding is one bounded source-to-sink observation. Every finding carries a
// source, a sink and the propagation steps between them, all pinned to file
// SHA-256 and line numbers.
type Finding struct {
	ID            string     `json:"id"`
	RuleID        string     `json:"rule_id"`
	Language      string     `json:"language"`
	Category      string     `json:"category"`
	CWE           string     `json:"cwe"`
	Severity      string     `json:"severity"`
	Confidence    string     `json:"confidence"`
	Status        string     `json:"status"`
	RuntimeStatus string     `json:"runtime_status"`
	Title         string     `json:"title"`
	Message       string     `json:"message"`
	File          string     `json:"file"`
	SHA256        string     `json:"sha256"`
	StartLine     int        `json:"start_line"`
	EndLine       int        `json:"end_line"`
	Source        *Ref       `json:"source,omitempty"`
	Sink          *Ref       `json:"sink"`
	Sanitizer     *Ref       `json:"sanitizer,omitempty"`
	Flow          []FlowStep `json:"flow"`
	Evidence      []Ref      `json:"evidence"`
	Limitations   []string   `json:"limitations"`
}

// Ref is a source-, sink- or evidence-level code location.
type Ref struct {
	Kind   string `json:"kind"`
	Symbol string `json:"symbol"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Line   int    `json:"line"`
	Detail string `json:"detail,omitempty"`
}

// FlowStep is one propagation step in the bounded intra-scope taint path.
type FlowStep struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Line   int    `json:"line"`
}

// Coverage is a deterministic aggregate; no maps are emitted so byte-level
// output stability does not depend on map iteration or JSON key ordering.
type Coverage struct {
	FilesScanned      int     `json:"files_scanned"`
	FilesRejected     int     `json:"files_rejected"`
	TokensScanned     int     `json:"tokens_scanned"`
	StatementsScanned int     `json:"statements_scanned"`
	RulesLoaded       int     `json:"rules_loaded"`
	RulesActive       int     `json:"rules_active"`
	RoutesFound       int     `json:"routes_found"`
	SymbolsFound      int     `json:"symbols_found"`
	CallsFound        int     `json:"calls_found"`
	CallsResolved     int     `json:"calls_resolved"`
	UnresolvedFound   int     `json:"unresolved_found"`
	VariablesFound    int     `json:"variables_found"`
	StringConstants   int     `json:"string_constants_found"`
	Findings          int     `json:"findings"`
	ByLanguage        []Count `json:"by_language"`
	ByCategory        []Count `json:"by_category"`
	RuntimeStatus     string  `json:"runtime_status"`
	AnalysisScope     string  `json:"analysis_scope"`
}

// Count is a sorted (key, value) pair used for deterministic aggregates.
type Count struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}

// RuleSummary is a bounded description of one built-in rule for read-only
// consumers such as the Agent list_rules tool. It exposes metadata and pattern
// counts only, never the pattern bodies themselves.
type RuleSummary struct {
	ID         string   `json:"id"`
	Languages  []string `json:"languages"`
	Category   string   `json:"category"`
	CWE        string   `json:"cwe"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Title      string   `json:"title"`
	Sources    int      `json:"sources"`
	Sinks      int      `json:"sinks"`
	Sanitizers int      `json:"sanitizers"`
	SafeCalls  int      `json:"safe_calls"`
}

// RuleSummaries describes the built-in rule set, sorted by ID for
// deterministic output. Caller-supplied rule files are not included.
func RuleSummaries() []RuleSummary {
	out := make([]RuleSummary, 0, 64)
	for _, r := range builtinRules() {
		out = append(out, RuleSummary{
			ID: r.ID, Languages: append([]string(nil), r.Languages...),
			Category: r.Category, CWE: r.CWE, Severity: r.Severity,
			Confidence: r.Confidence, Title: r.Title,
			Sources: len(r.Sources), Sinks: len(r.Sinks),
			Sanitizers: len(r.Sanitizers), SafeCalls: len(r.SafeCalls),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func countsFrom(values map[string]int) []Count {
	out := make([]Count, 0, len(values))
	for key, value := range values {
		out = append(out, Count{Key: key, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func dedupeSorted(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value != "" && (len(out) == 0 || out[len(out)-1] != value) {
			out = append(out, value)
		}
	}
	return out
}

// normalizeName makes PHP function/identifier matching case-insensitive, as
// PHP itself does, while other languages keep exact case.
func normalizeName(language, name string) string {
	if language == "php" {
		return strings.ToLower(name)
	}
	return name
}
