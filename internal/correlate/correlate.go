// Package correlate links the read-only static finding report with an
// explicitly authorized runtime HTTP report.
//
// It only compares declared routes and methods with observed request results.
// It never rewrites either input, never upgrades a static finding, and never
// treats a matching response as an exploitation proof.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p1.2+r1-static-runtime-correlation-v1"
	AnalysisKind  = "static_runtime_correlation_v1"

	FindingsAnalysisKind = "unified_finding_evidence_v1"
	RuntimeAnalysisKind  = "http_runtime_assertions_v1"

	MaxInputBytes     = 16 << 20
	MaxFindings       = 20_000
	MaxRuntimeResults = 10_000
	MaxEvidenceIDs    = 16
	MaxRuntimeRefs    = 64
)

// Match values. correlated means exactly one observed runtime result matches the
// declared route and method; ambiguous means more than one; not_correlated means
// none or no route was declared.
const (
	MatchCorrelated    = "correlated"
	MatchNotCorrelated = "not_correlated"
	MatchAmbiguous     = "ambiguous"
)

// Input is one caller-supplied report file. Path is recorded for evidence only;
// the bytes are never written back.
type Input struct {
	Path string
	Data []byte
}

type Report struct {
	SchemaVersion int           `json:"schema_version"`
	ToolVersion   string        `json:"tool_version"`
	AnalysisKind  string        `json:"analysis_kind"`
	RuntimeStatus string        `json:"runtime_status"`
	Findings      Source        `json:"findings_source"`
	Runtime       RuntimeSource `json:"runtime_source"`
	Results       []Correlation `json:"results"`
	Unmatched     []RuntimeRef  `json:"unmatched_runtime"`
	Coverage      Coverage      `json:"coverage"`
	Limitations   []string      `json:"limitations"`
}

type Source struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	SchemaVersion int    `json:"schema_version"`
	AnalysisKind  string `json:"analysis_kind"`
}

type RuntimeSource struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	SchemaVersion int    `json:"schema_version"`
	AnalysisKind  string `json:"analysis_kind"`
	PlanName      string `json:"plan_name"`
	Origin        string `json:"origin"`
	Status        string `json:"status"`
	RuntimeStatus string `json:"runtime_status"`
}

// Endpoint is the static side of the correlation: annotation-level route
// evidence as recorded by `trident audit findings`.
type Endpoint struct {
	Path      string   `json:"path"`
	Methods   []string `json:"http_methods"`
	File      string   `json:"file,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
	StartLine int      `json:"start_line,omitempty"`
	EndLine   int      `json:"end_line,omitempty"`
}

// RuntimeRef is the runtime side of the correlation: one observed request from
// the approved runtime report. Only redacted fields are copied.
type RuntimeRef struct {
	ID             string `json:"id"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Status         string `json:"status"`
	ObservedStatus int    `json:"observed_status,omitempty"`
	Location       string `json:"location,omitempty"`
	BodySHA256     string `json:"body_sha256,omitempty"`
	Role           string `json:"role,omitempty"`
	Matrix         string `json:"matrix,omitempty"`
}

type Correlation struct {
	FindingID         string       `json:"finding_id"`
	Kind              string       `json:"kind"`
	FindingStatus     string       `json:"finding_status"`
	FindingRuntime    string       `json:"finding_runtime_status"`
	Endpoint          *Endpoint    `json:"endpoint,omitempty"`
	Match             string       `json:"match"`
	Reason            string       `json:"reason,omitempty"`
	FindingEvidenceID []string     `json:"finding_evidence_ids"`
	Runtime           []RuntimeRef `json:"runtime_results"`
}

type Coverage struct {
	FindingsTotal           int `json:"findings_total"`
	FindingsWithEndpoint    int `json:"findings_with_endpoint"`
	FindingsWithoutEndpoint int `json:"findings_without_endpoint"`
	Correlated              int `json:"correlated"`
	Ambiguous               int `json:"ambiguous"`
	NotCorrelated           int `json:"not_correlated"`
	RuntimeResults          int `json:"runtime_results"`
	RuntimeResultsMatched   int `json:"runtime_results_matched"`
	RuntimeResultsUnmatched int `json:"runtime_results_unmatched"`
}

// Correlation limitation codes.
const (
	limitNotExploitProof = "correlation_not_exploit_proof: a matching route and an observed response do not prove exploitability, control absence or production impact"
	limitRuntimeOnly     = "runtime_observed_not_exploit_proof: runtime_status=observed records these responses only"
	limitRouteExact      = "route_method_exact_match: annotation-level paths are compared literally; context path, deployment prefix, path variables and normalization are not resolved"
	limitNoWriteBack     = "static_findings_not_modified: both inputs are read-only and finding status/runtime_status are never rewritten"
	limitWildcardMethod  = "method_unrestricted_matches_any_observed_method: a static route without HTTP methods is treated as unrestricted and may match more than one observed method"
)

type findingsDoc struct {
	SchemaVersion int       `json:"schema_version"`
	AnalysisKind  string    `json:"analysis_kind"`
	Findings      []finding `json:"findings"`
}

type finding struct {
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"`
	RuntimeStatus string     `json:"runtime_status"`
	Endpoint      *endpoint  `json:"endpoint"`
	Evidence      []evidence `json:"evidence"`
}

type endpoint struct {
	Path        string   `json:"path"`
	HTTPMethods []string `json:"http_methods"`
	File        string   `json:"file"`
	SHA256      string   `json:"sha256"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
}

type evidence struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type runtimeDoc struct {
	SchemaVersion int             `json:"schema_version"`
	AnalysisKind  string          `json:"analysis_kind"`
	PlanName      string          `json:"plan_name"`
	Origin        string          `json:"origin"`
	Status        string          `json:"status"`
	RuntimeStatus string          `json:"runtime_status"`
	Results       []runtimeResult `json:"results"`
}

type runtimeResult struct {
	ID             string `json:"id"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Status         string `json:"status"`
	ObservedStatus int    `json:"observed_status"`
	Location       string `json:"location"`
	BodySHA256     string `json:"body_sha256"`
	Role           string `json:"role"`
	Matrix         string `json:"matrix"`
}

// Correlate builds an independent report. Both inputs must be complete reports
// produced by this tool; malformed or unobserved inputs fail closed.
func Correlate(findingsInput, runtimeInput Input) (Report, error) {
	if len(findingsInput.Data) == 0 || len(findingsInput.Data) > MaxInputBytes {
		return Report{}, fmt.Errorf("findings report must contain 1 to %d bytes", MaxInputBytes)
	}
	if len(runtimeInput.Data) == 0 || len(runtimeInput.Data) > MaxInputBytes {
		return Report{}, fmt.Errorf("runtime report must contain 1 to %d bytes", MaxInputBytes)
	}
	var findings findingsDoc
	if err := json.Unmarshal(findingsInput.Data, &findings); err != nil {
		return Report{}, fmt.Errorf("invalid findings JSON: %w", err)
	}
	if findings.SchemaVersion != SchemaVersion || findings.AnalysisKind != FindingsAnalysisKind {
		return Report{}, fmt.Errorf("findings report must be schema_version=%d analysis_kind=%s", SchemaVersion, FindingsAnalysisKind)
	}
	if len(findings.Findings) > MaxFindings {
		return Report{}, fmt.Errorf("findings report exceeds %d findings", MaxFindings)
	}
	var runtime runtimeDoc
	if err := json.Unmarshal(runtimeInput.Data, &runtime); err != nil {
		return Report{}, fmt.Errorf("invalid runtime JSON: %w", err)
	}
	if runtime.SchemaVersion != SchemaVersion || runtime.AnalysisKind != RuntimeAnalysisKind {
		return Report{}, fmt.Errorf("runtime report must be schema_version=%d analysis_kind=%s", SchemaVersion, RuntimeAnalysisKind)
	}
	if runtime.RuntimeStatus != "observed" || len(runtime.Results) == 0 {
		return Report{}, fmt.Errorf("runtime report must contain observed results")
	}
	if len(runtime.Results) > MaxRuntimeResults {
		return Report{}, fmt.Errorf("runtime report exceeds %d results", MaxRuntimeResults)
	}

	refs := make([]RuntimeRef, 0, len(runtime.Results))
	for _, item := range runtime.Results {
		method := strings.ToUpper(strings.TrimSpace(item.Method))
		if item.ID == "" || method == "" || strings.TrimSpace(item.Path) == "" {
			return Report{}, fmt.Errorf("runtime result must declare id, method and path")
		}
		if !strings.HasPrefix(item.Path, "/") {
			return Report{}, fmt.Errorf("runtime result %q path must start with /", item.ID)
		}
		refs = append(refs, RuntimeRef{
			ID: item.ID, Method: method, Path: item.Path, Status: item.Status,
			ObservedStatus: item.ObservedStatus, Location: item.Location,
			BodySHA256: item.BodySHA256, Role: item.Role, Matrix: item.Matrix,
		})
	}

	seen := map[string]bool{}
	correlations := make([]Correlation, 0, len(findings.Findings))
	matched := map[string]bool{}
	wildcardUsed := false
	coverage := Coverage{FindingsTotal: len(findings.Findings), RuntimeResults: len(refs)}
	for _, item := range findings.Findings {
		if item.ID == "" {
			return Report{}, fmt.Errorf("finding without id")
		}
		if seen[item.ID] {
			return Report{}, fmt.Errorf("duplicate finding id %q", item.ID)
		}
		seen[item.ID] = true
		entry := Correlation{
			FindingID:         item.ID,
			Kind:              item.Kind,
			FindingStatus:     item.Status,
			FindingRuntime:    item.RuntimeStatus,
			FindingEvidenceID: routeEvidence(item.Evidence),
			Runtime:           []RuntimeRef{},
		}
		if item.Endpoint == nil {
			coverage.FindingsWithoutEndpoint++
			entry.Match = MatchNotCorrelated
			entry.Reason = "finding_has_no_endpoint"
			coverage.NotCorrelated++
			correlations = append(correlations, entry)
			continue
		}
		path := strings.TrimSpace(item.Endpoint.Path)
		if !strings.HasPrefix(path, "/") {
			return Report{}, fmt.Errorf("finding %q endpoint path must start with /", item.ID)
		}
		coverage.FindingsWithEndpoint++
		methods := make([]string, 0, len(item.Endpoint.HTTPMethods))
		for _, method := range item.Endpoint.HTTPMethods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if method != "" {
				methods = append(methods, method)
			}
		}
		entry.Endpoint = &Endpoint{
			Path: path, Methods: methods, File: item.Endpoint.File, SHA256: item.Endpoint.SHA256,
			StartLine: item.Endpoint.StartLine, EndLine: item.Endpoint.EndLine,
		}
		for _, ref := range refs {
			if ref.Path != path {
				continue
			}
			if len(methods) > 0 && !containsMethod(methods, ref.Method) {
				continue
			}
			if len(methods) == 0 {
				wildcardUsed = true
			}
			entry.Runtime = append(entry.Runtime, ref)
			if len(entry.Runtime) >= MaxRuntimeRefs {
				break
			}
		}
		switch len(entry.Runtime) {
		case 0:
			entry.Match = MatchNotCorrelated
			entry.Reason = "no_runtime_result_with_matching_route_and_method"
			coverage.NotCorrelated++
		case 1:
			entry.Match = MatchCorrelated
			coverage.Correlated++
			matched[entry.Runtime[0].ID] = true
		default:
			entry.Match = MatchAmbiguous
			entry.Reason = "multiple_runtime_results_with_matching_route_and_method"
			coverage.Ambiguous++
			for _, ref := range entry.Runtime {
				matched[ref.ID] = true
			}
		}
		correlations = append(correlations, entry)
	}
	sort.SliceStable(correlations, func(i, j int) bool {
		return correlations[i].FindingID < correlations[j].FindingID
	})

	unmatched := make([]RuntimeRef, 0)
	for _, ref := range refs {
		if matched[ref.ID] {
			coverage.RuntimeResultsMatched++
			continue
		}
		unmatched = append(unmatched, ref)
	}
	sort.SliceStable(unmatched, func(i, j int) bool {
		return unmatched[i].ID < unmatched[j].ID
	})
	coverage.RuntimeResultsUnmatched = len(unmatched)

	limitations := []string{limitNotExploitProof, limitRuntimeOnly, limitRouteExact, limitNoWriteBack}
	if wildcardUsed {
		limitations = append(limitations, limitWildcardMethod)
	}
	return Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		AnalysisKind:  AnalysisKind,
		RuntimeStatus: "observed",
		Findings: Source{
			Path: findingsInput.Path, SHA256: digest(findingsInput.Data),
			SchemaVersion: findings.SchemaVersion, AnalysisKind: findings.AnalysisKind,
		},
		Runtime: RuntimeSource{
			Path: runtimeInput.Path, SHA256: digest(runtimeInput.Data),
			SchemaVersion: runtime.SchemaVersion, AnalysisKind: runtime.AnalysisKind,
			PlanName: runtime.PlanName, Origin: runtime.Origin,
			Status: runtime.Status, RuntimeStatus: runtime.RuntimeStatus,
		},
		Results:     correlations,
		Unmatched:   unmatched,
		Coverage:    coverage,
		Limitations: limitations,
	}, nil
}

func containsMethod(methods []string, method string) bool {
	for _, candidate := range methods {
		if candidate == method {
			return true
		}
	}
	return false
}

// routeEvidence keeps the static references that describe the route; other
// evidence kinds stay in the original findings report.
func routeEvidence(items []evidence) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item.Kind != "route" && item.Kind != "method" {
			continue
		}
		if item.ID == "" {
			continue
		}
		ids = append(ids, item.ID)
		if len(ids) >= MaxEvidenceIDs {
			break
		}
	}
	return ids
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
