package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trident/internal/casework"
	"trident/internal/codescan"
	"trident/internal/findings"
)

const MaxCaseBodyBytes = 32 << 10

type caseListResponse struct {
	SchemaVersion int                    `json:"schema_version"`
	Available     bool                   `json:"available"`
	Root          string                 `json:"root,omitempty"`
	Cases         []casework.CaseSummary `json:"cases"`
}

type caseCreateRequest struct {
	CaseID    string `json:"case_id"`
	FindingID string `json:"finding_id"`
	Title     string `json:"title"`
}

type caseCreateResponse struct {
	SchemaVersion int                 `json:"schema_version"`
	Created       bool                `json:"created"`
	Case          casework.CaseDetail `json:"case"`
}

type caseActionRequest struct {
	ID string `json:"id"`
}

type caseActionResponse struct {
	SchemaVersion int                        `json:"schema_version"`
	CaseID        string                     `json:"case_id"`
	Stage         string                     `json:"stage"`
	Status        string                     `json:"status"`
	Source        string                     `json:"source,omitempty"`
	Message       string                     `json:"message,omitempty"`
	Patch         *casework.PatchArtifact    `json:"patch,omitempty"`
	Validation    *casework.ValidationRecord `json:"validation,omitempty"`
}

type caseExportResponse struct {
	SchemaVersion int                 `json:"schema_version"`
	Product       string              `json:"product"`
	ExportedAt    string              `json:"exported_at"`
	Case          casework.CaseDetail `json:"case"`
	Patch         string              `json:"patch,omitempty"`
	UpstreamFiles map[string]string   `json:"upstream_files,omitempty"`
}

func (c *Console) catalog() *casework.Catalog {
	if c.cases == nil {
		c.cases = casework.NewCatalog("", c.workspace)
	}
	return c.cases
}

func (c *Console) handleCases(w http.ResponseWriter, _ *http.Request) {
	cases, err := c.catalog().List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "case_catalog_failed", err.Error())
		return
	}
	available := c.catalog().Available() || len(cases) > 0
	writeJSON(w, http.StatusOK, caseListResponse{
		SchemaVersion: SchemaVersion,
		Available:     available,
		Root:          "cases",
		Cases:         cases,
	})
}

func (c *Console) handleCase(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	detail, err := c.catalog().Get(id)
	if err != nil {
		mapCaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (c *Console) handleCaseCreate(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, MaxCaseBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request caseCreateRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "case request is not valid JSON")
		return
	}
	if strings.TrimSpace(request.CaseID) != "" {
		detail, err := c.catalog().Get(strings.TrimSpace(request.CaseID))
		if err != nil {
			mapCaseError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, caseCreateResponse{SchemaVersion: SchemaVersion, Created: false, Case: detail})
		return
	}
	if strings.TrimSpace(request.FindingID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "finding_id or case_id is required")
		return
	}
	if c.catalog().StoreDir == "" {
		writeError(w, http.StatusConflict, "pinned_console", "该控制台以固定快照启动；使用 --workspace 启动后才能创建 Case")
		return
	}
	finding, ok, err := c.sourceFinding(r, request.FindingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "finding_not_found", "当前快照没有该 Finding")
		return
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "finding encoding failed")
		return
	}
	detail, err := casework.NewFindingCase(finding.ID, request.Title, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_case", err.Error())
		return
	}
	if existing, getErr := c.catalog().Get(detail.ID); getErr == nil {
		writeJSON(w, http.StatusOK, caseCreateResponse{SchemaVersion: SchemaVersion, Created: false, Case: existing})
		return
	}
	saved, err := c.catalog().Save(detail)
	if errors.Is(err, casework.ErrExists) {
		if existing, getErr := c.catalog().Get(detail.ID); getErr == nil {
			writeJSON(w, http.StatusOK, caseCreateResponse{SchemaVersion: SchemaVersion, Created: false, Case: existing})
			return
		}
	}
	if err != nil {
		mapCaseError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, caseCreateResponse{SchemaVersion: SchemaVersion, Created: true, Case: saved})
}

func (c *Console) sourceFinding(r *http.Request, id string) (findings.Finding, bool, error) {
	state, err := c.analyze(r.Context())
	if err != nil {
		return findings.Finding{}, false, err
	}
	for _, finding := range state.findings.Findings {
		if finding.ID == id {
			return finding, true, nil
		}
	}
	if cached, _, ok := c.codeAuditCached(); ok {
		merged := codescan.AsFindingsReport(cached)
		for _, finding := range merged.Findings {
			if finding.ID == id {
				return finding, true, nil
			}
		}
	}
	return findings.Finding{}, false, nil
}

func (c *Console) handleCasePropose(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeCaseAction(w, r)
	if !ok {
		return
	}
	detail, err := c.catalog().Get(request.ID)
	if err != nil {
		mapCaseError(w, err)
		return
	}
	if detail.Patch == nil {
		writeError(w, http.StatusConflict, "no_patch", "该 Case 还没有补丁产物；先生成 patch.diff，再执行验证")
		return
	}
	writeJSON(w, http.StatusOK, caseActionResponse{
		SchemaVersion: SchemaVersion,
		CaseID:        detail.ID,
		Stage:         "patch",
		Status:        detail.Patch.Status,
		Message:       "读取已落盘的补丁产物；没有重新生成或覆盖源码",
		Patch:         detail.Patch,
	})
}

func (c *Console) handleCaseVerify(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeCaseAction(w, r)
	if !ok {
		return
	}
	detail, err := c.catalog().Get(request.ID)
	if err != nil {
		mapCaseError(w, err)
		return
	}
	if detail.Validation == nil {
		writeError(w, http.StatusConflict, "not_verified", "该 Case 还没有验证记录；不得把未执行写成已验证")
		return
	}
	status := "verified"
	if !strings.Contains(strings.ToUpper(detail.Validation.Result), "VERIFIED") {
		status = "failed"
	}
	writeJSON(w, http.StatusOK, caseActionResponse{
		SchemaVersion: SchemaVersion,
		CaseID:        detail.ID,
		Stage:         "validation",
		Status:        status,
		Source:        detail.Validation.Source,
		Message:       "读取已落盘的双实例验证记录；状态来自 verify.log 或 patch_meta.json",
		Validation:    detail.Validation,
	})
}

func (c *Console) handleCaseExport(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	detail, err := c.catalog().Get(id)
	if err != nil {
		mapCaseError(w, err)
		return
	}
	export := caseExportResponse{
		SchemaVersion: SchemaVersion,
		Product:       Product,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Case:          detail,
	}
	if detail.Patch != nil {
		if text, err := c.catalog().ReadFile(detail.ID, detail.Patch.File); err == nil {
			export.Patch = text
		}
	}
	if detail.Upstream != nil && detail.Upstream.Present {
		export.UpstreamFiles = map[string]string{}
		for _, name := range detail.Upstream.Files {
			if text, err := c.catalog().ReadFile(detail.ID, "upstream/"+name); err == nil {
				export.UpstreamFiles[name] = text
			}
		}
	}
	encoded, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "case export encoding failed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="trident-case-%s.json"`, detail.ID))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func decodeCaseAction(w http.ResponseWriter, r *http.Request) (caseActionRequest, bool) {
	body := http.MaxBytesReader(w, r.Body, MaxCaseBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request caseActionRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "case action request is not valid JSON")
		return caseActionRequest{}, false
	}
	request.ID = strings.TrimSpace(request.ID)
	if request.ID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return caseActionRequest{}, false
	}
	return request, true
}

func mapCaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, casework.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_case", "Case 标识不合法")
	case errors.Is(err, casework.ErrNotFound):
		writeError(w, http.StatusNotFound, "case_not_found", "Case 不存在")
	case errors.Is(err, casework.ErrNoStore):
		writeError(w, http.StatusConflict, "pinned_console", "该控制台没有可写的工作区")
	case errors.Is(err, casework.ErrNoPatch):
		writeError(w, http.StatusConflict, "no_patch", "该 Case 还没有补丁产物")
	default:
		writeError(w, http.StatusInternalServerError, "case_failed", err.Error())
	}
}
