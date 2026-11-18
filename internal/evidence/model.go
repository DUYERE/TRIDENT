// Package evidence defines the shared, provider-neutral representation used by
// capability surfaces (Web, CLI and Agent). It deliberately holds evidence,
// not analyzer-specific structs, so a Java annotation route and a PHP route
// declaration can be rendered and compared without pretending they have the
// same semantics.
package evidence

const (
	// SchemaVersion is the JSON schema version for Report.
	SchemaVersion = 1

	// KindAnnotationRoute is a framework-annotated Java endpoint with a
	// controller method and optional authorization decision.
	KindAnnotationRoute = "annotation_route"
	// KindRouteDeclaration is a route declaration observed by codescan in any
	// supported language. It is not proof of deployment.
	KindRouteDeclaration = "route_declaration"
	// KindApplicationEntry is a known application entry file candidate. It has
	// no authoritative URL.
	KindApplicationEntry = "application_entry"
	// KindRequestScript is a web script observed reading request data directly
	// (currently PHP superglobals/php://input). It is a file-level candidate,
	// not a deployed route.
	KindRequestScript = "request_script"
)

// Parameter is one endpoint parameter binding. It intentionally mirrors the
// stable fields the Java audit already exposes, without importing that package.
type Parameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type,omitempty"`
	Bindings    []string `json:"bindings,omitempty"`
	BindingName string   `json:"binding_name,omitempty"`
	Required    string   `json:"required,omitempty"`
	Line        int      `json:"line,omitempty"`
}

// Authz is the authorization evidence attached to an entry when a provider can
// resolve it. A nil Authz means "not evaluated for this entry", never "public".
type Authz struct {
	Decision        string   `json:"decision"`
	Requirement     string   `json:"requirement,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	MatchedControls []string `json:"matched_controls,omitempty"`
	RuntimeStatus   string   `json:"runtime_status"`
}

// Entry is one normalized piece of entry evidence.
type Entry struct {
	ID          string      `json:"id"`
	Language    string      `json:"language"`
	Framework   string      `json:"framework,omitempty"`
	Kind        string      `json:"kind"`
	Source      string      `json:"source"`
	HTTPMethods []string    `json:"http_methods,omitempty"`
	Path        string      `json:"path,omitempty"`
	PathStatus  string      `json:"path_status,omitempty"`
	Target      string      `json:"target,omitempty"`
	Symbol      string      `json:"symbol,omitempty"`
	Class       string      `json:"class,omitempty"`
	Method      string      `json:"method,omitempty"`
	File        string      `json:"file"`
	SHA256      string      `json:"sha256,omitempty"`
	StartLine   int         `json:"start_line"`
	EndLine     int         `json:"end_line,omitempty"`
	MethodLine  int         `json:"method_line,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty"`
	Authz       *Authz      `json:"authz,omitempty"`
	Confidence  string      `json:"confidence,omitempty"`
	Reason      string      `json:"reason,omitempty"`
}

// LanguageCoverage reports what one provider actually inspected for one
// language. It is the guard against treating an empty result as "no entry".
type LanguageCoverage struct {
	Source        string `json:"source"`
	Capability    string `json:"capability"`
	Language      string `json:"language"`
	FilesScanned  int    `json:"files_scanned"`
	FilesRejected int    `json:"files_rejected"`
	Entries       int    `json:"entries"`
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
}

// Report is the capability output consumed by surfaces.
type Report struct {
	SchemaVersion int                `json:"schema_version"`
	Capability    string             `json:"capability"`
	Providers     []string           `json:"providers"`
	Entries       []Entry            `json:"entries"`
	Coverage      []LanguageCoverage `json:"coverage"`
	Partial       bool               `json:"partial"`
	Limitations   []string           `json:"limitations"`
}
