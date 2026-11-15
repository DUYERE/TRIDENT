package webui

import (
	"net/http"
	"sort"
	"strings"

	"trident/internal/authz"
	"trident/internal/javaast"
)

// authzCounts summarises the endpoint decision distribution. The four states
// are the same ones the CLI prints; none of them proves runtime exposure.
type authzCounts struct {
	Protected   int `json:"protected"`
	Public      int `json:"public"`
	Unprotected int `json:"unprotected"`
	Unknown     int `json:"unknown"`
}

type authzResponse struct {
	SchemaVersion int                      `json:"schema_version"`
	ToolVersion   string                   `json:"tool_version"`
	SnapshotHash  string                   `json:"snapshot_hash"`
	AnalysisKind  string                   `json:"analysis_kind"`
	Partial       bool                     `json:"partial"`
	Total         int                      `json:"total"`
	Counts        authzCounts              `json:"counts"`
	Endpoints     []authz.EndpointDecision `json:"endpoints"`
	Controls      []authz.Control          `json:"controls"`
	Chains        []authz.FilterChain      `json:"chains"`
	Coverage      authz.Coverage           `json:"coverage"`
	Limitations   []string                 `json:"limitations"`
	RuntimeStatus string                   `json:"runtime_status"`
	Limit         int                      `json:"limit"`
	Offset        int                      `json:"offset"`
}

func (c *Console) handleAuthz(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	report := state.authz
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	counts := authzCounts{}
	matched := make([]authz.EndpointDecision, 0, len(report.Endpoints))
	for _, endpoint := range report.Endpoints {
		switch endpoint.Decision {
		case "protected":
			counts.Protected++
		case "public":
			counts.Public++
		case "unprotected":
			counts.Unprotected++
		default:
			counts.Unknown++
		}
		if decision != "" && decision != "all" && endpoint.Decision != decision {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(endpoint.Path+" "+endpoint.Symbol+" "+endpoint.Requirement), query) {
			continue
		}
		matched = append(matched, endpoint)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if rank(matched[i].Decision) != rank(matched[j].Decision) {
			return rank(matched[i].Decision) < rank(matched[j].Decision)
		}
		return matched[i].Path < matched[j].Path
	})
	page := pageSlice(matched, offset, limit)
	writeJSON(w, http.StatusOK, authzResponse{
		SchemaVersion: report.SchemaVersion,
		ToolVersion:   report.ToolVersion,
		SnapshotHash:  report.SnapshotHash,
		AnalysisKind:  report.AnalysisKind,
		Partial:       report.Partial,
		Total:         len(matched),
		Counts:        counts,
		Endpoints:     page,
		Controls:      report.Controls,
		Chains:        report.Chains,
		Coverage:      report.Coverage,
		Limitations:   report.Limitations,
		RuntimeStatus: report.RuntimeStatus,
		Limit:         limit,
		Offset:        offset,
	})
}

// rank orders the most actionable decisions first: an endpoint with no
// recognised control is what a reviewer opens first.
func rank(decision string) int {
	switch decision {
	case "unprotected":
		return 0
	case "unknown":
		return 1
	case "public":
		return 2
	default:
		return 3
	}
}

type modelTypeSummary struct {
	FQN         string `json:"fqn"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Methods     int    `json:"methods"`
	Fields      int    `json:"fields"`
	Annotations int    `json:"annotations"`
	Extends     string `json:"extends,omitempty"`
	Nested      int    `json:"nested"`
}

type modelResponse struct {
	SchemaVersion int                `json:"schema_version"`
	Enabled       bool               `json:"enabled"`
	Reason        string             `json:"reason,omitempty"`
	ToolVersion   string             `json:"tool_version,omitempty"`
	SnapshotHash  string             `json:"snapshot_hash"`
	AnalysisKind  string             `json:"analysis_kind,omitempty"`
	Partial       bool               `json:"partial"`
	Total         int                `json:"total"`
	Types         []modelTypeSummary `json:"types"`
	Coverage      *javaast.Coverage  `json:"coverage,omitempty"`
	Limitations   []string           `json:"limitations,omitempty"`
	RuntimeStatus string             `json:"runtime_status"`
	Limit         int                `json:"limit"`
	Offset        int                `json:"offset"`
}

func (c *Console) handleModel(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	if state.model == nil {
		writeJSON(w, http.StatusOK, modelResponse{
			SchemaVersion: SchemaVersion,
			Enabled:       false,
			Reason:        state.modelErr,
			SnapshotHash:  c.snapshotRef().Hash(),
			Types:         []modelTypeSummary{},
			RuntimeStatus: "not_run",
		})
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	all := make([]modelTypeSummary, 0, len(state.model.Types))
	for _, item := range state.model.Types {
		if query != "" && !strings.Contains(strings.ToLower(item.FQN+" "+item.File), query) {
			continue
		}
		all = append(all, modelTypeSummary{
			FQN: item.FQN, Name: item.Name, Kind: item.Kind, File: item.File, Line: item.Line,
			Methods: len(item.Methods), Fields: len(item.Fields), Annotations: len(item.Annotations),
			Extends: item.Extends, Nested: len(item.Nested),
		})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].FQN < all[j].FQN })
	coverage := state.model.Coverage
	writeJSON(w, http.StatusOK, modelResponse{
		SchemaVersion: state.model.SchemaVersion,
		Enabled:       true,
		ToolVersion:   state.model.ToolVersion,
		SnapshotHash:  state.model.SnapshotHash,
		AnalysisKind:  state.model.AnalysisKind,
		Partial:       state.model.Partial,
		Total:         len(all),
		Types:         pageSlice(all, offset, limit),
		Coverage:      &coverage,
		Limitations:   state.model.Limitations,
		RuntimeStatus: state.model.Coverage.RuntimeStatus,
		Limit:         limit,
		Offset:        offset,
	})
}

type modelTypeResponse struct {
	SchemaVersion int                `json:"schema_version"`
	Type          javaast.TypeInfo   `json:"type"`
	Outgoing      []javaast.CallEdge `json:"outgoing"`
	Incoming      []javaast.CallEdge `json:"incoming"`
	RuntimeStatus string             `json:"runtime_status"`
}

func (c *Console) handleModelType(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	if state.model == nil {
		writeError(w, http.StatusNotFound, "model_disabled", state.modelErr)
		return
	}
	fqn := strings.TrimSpace(r.URL.Query().Get("fqn"))
	if fqn == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "需要 fqn 参数")
		return
	}
	var found *javaast.TypeInfo
	for i := range state.model.Types {
		if state.model.Types[i].FQN == fqn {
			found = &state.model.Types[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "type_not_found", "未在该快照的语义模型中索引该类型："+fqn)
		return
	}
	prefix := fqn + "#"
	outgoing := make([]javaast.CallEdge, 0, 16)
	incoming := make([]javaast.CallEdge, 0, 16)
	for _, edge := range state.model.Calls {
		if strings.HasPrefix(edge.Caller, prefix) {
			outgoing = append(outgoing, edge)
		}
		if strings.HasPrefix(edge.Target, prefix) {
			incoming = append(incoming, edge)
		}
	}
	writeJSON(w, http.StatusOK, modelTypeResponse{
		SchemaVersion: SchemaVersion,
		Type:          *found,
		Outgoing:      capEdges(outgoing, 200),
		Incoming:      capEdges(incoming, 200),
		RuntimeStatus: "not_run",
	})
}

func capEdges(edges []javaast.CallEdge, limit int) []javaast.CallEdge {
	if len(edges) <= limit {
		return edges
	}
	return edges[:limit]
}

func pageSlice[T any](items []T, offset, limit int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}
