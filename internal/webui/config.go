package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trident/internal/project"
	"trident/internal/sca"
)

// workspaceFile is the persisted console state inside a workspace directory.
// It is plain configuration: no secrets, no analysis output.
type workspaceFile struct {
	SchemaVersion int            `json:"schema_version"`
	Project       *workspaceProj `json:"project,omitempty"`
	AdvisoryPath  string         `json:"advisories_path,omitempty"`
	AdvisoryDir   string         `json:"advisories_dir,omitempty"`
	PackageMap    string         `json:"package_map_path,omitempty"`
	RuntimeReport string         `json:"runtime_report,omitempty"`
	AgentModel    string         `json:"agent_model,omitempty"`
}

type workspaceProj struct {
	Source       string `json:"source"`
	SnapshotDir  string `json:"snapshot_dir"`
	SnapshotHash string `json:"snapshot_hash"`
}

const workspaceSchemaVersion = 1

func workspaceConfigPath(workspace string) string {
	return filepath.Join(workspace, "console.json")
}

// loadWorkspaceConfig reads the persisted file. A missing file is not an error;
// an unreadable or invalid one is, so a corrupt workspace never silently
// changes analysis scope.
func loadWorkspaceConfig(workspace string) (workspaceFile, error) {
	path := workspaceConfigPath(workspace)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return workspaceFile{SchemaVersion: workspaceSchemaVersion}, nil
	}
	if err != nil {
		return workspaceFile{}, fmt.Errorf("console workspace is unreadable: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var file workspaceFile
	if err := decoder.Decode(&file); err != nil {
		return workspaceFile{}, fmt.Errorf("console workspace is invalid: %v", err)
	}
	if file.SchemaVersion != workspaceSchemaVersion {
		return workspaceFile{}, fmt.Errorf("console workspace schema %d is not supported", file.SchemaVersion)
	}
	return file, nil
}

func saveWorkspaceConfig(workspace string, file workspaceFile) error {
	if workspace == "" {
		return nil
	}
	file.SchemaVersion = workspaceSchemaVersion
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return fmt.Errorf("console workspace is not writable: %w", err)
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := workspaceConfigPath(workspace)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("console workspace is not writable: %w", err)
	}
	return os.Rename(temporary, path)
}

// mergeConfig keeps explicit flags and only fills fields the caller left empty.
func mergeConfig(persisted workspaceFile, current consoleConfig) consoleConfig {
	merged := current
	if merged.AdvisoryPath == "" && merged.AdvisoryDir == "" {
		merged.AdvisoryPath = persisted.AdvisoryPath
		merged.AdvisoryDir = persisted.AdvisoryDir
	}
	if merged.PackageMapPath == "" {
		merged.PackageMapPath = persisted.PackageMap
	}
	if merged.RuntimeReport == "" {
		merged.RuntimeReport = persisted.RuntimeReport
	}
	return merged
}

func configToWorkspace(projectSource, snapshotDir, snapshotHash string, cfg consoleConfig) workspaceFile {
	file := workspaceFile{
		SchemaVersion: workspaceSchemaVersion,
		AdvisoryPath:  cfg.AdvisoryPath,
		AdvisoryDir:   cfg.AdvisoryDir,
		PackageMap:    cfg.PackageMapPath,
		RuntimeReport: cfg.RuntimeReport,
	}
	if projectSource != "" {
		file.Project = &workspaceProj{Source: projectSource, SnapshotDir: snapshotDir, SnapshotHash: snapshotHash}
	}
	return file
}

func randomSuffix() (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	return token[:16], nil
}

// ImportProject imports source into <workspace>/snapshots and returns the
// snapshot directory and digest. Re-importing unchanged sources converges on
// the same digest, so the existing snapshot directory is reused instead of
// being duplicated.
func ImportProject(ctx context.Context, workspace, source string) (string, string, error) {
	if workspace == "" {
		return "", "", fmt.Errorf("project import requires a console workspace")
	}
	expanded := strings.TrimSpace(source)
	if expanded == "" {
		return "", "", fmt.Errorf("source directory is required")
	}
	info, err := os.Stat(expanded)
	if err != nil || !info.IsDir() {
		return "", "", fmt.Errorf("source directory is not readable: %s", expanded)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "snapshots"), 0o700); err != nil {
		return "", "", fmt.Errorf("console workspace is not writable: %w", err)
	}
	suffix, err := randomSuffix()
	if err != nil {
		return "", "", err
	}
	temporary := filepath.Join(workspace, ".import-"+suffix)
	imported, err := project.Import(ctx, expanded, temporary)
	if err != nil {
		return "", "", err
	}
	final := filepath.Join(workspace, "snapshots", imported.Hash)
	if _, statErr := os.Stat(final); statErr == nil {
		_ = os.RemoveAll(temporary)
		return final, imported.Hash, nil
	}
	if err := os.Rename(temporary, final); err != nil {
		_ = os.RemoveAll(temporary)
		return "", "", fmt.Errorf("store imported snapshot: %w", err)
	}
	return final, imported.Hash, nil
}

// configSnapshot is the subset of console state the settings page needs.
type configSnapshot struct {
	SchemaVersion int    `json:"schema_version"`
	Mode          string `json:"mode"`
	Workspace     string `json:"workspace,omitempty"`
	Project       struct {
		Source string `json:"source,omitempty"`
		Hash   string `json:"hash"`
		Files  int    `json:"files"`
		Bytes  int64  `json:"bytes"`
	} `json:"project"`
	Paths struct {
		Advisories        string `json:"advisories_path"`
		AdvisoriesDir     string `json:"advisories_dir"`
		AdvisoriesCount   int    `json:"advisories_count"`
		AdvisoriesError   string `json:"advisories_error,omitempty"`
		PackageMap        string `json:"package_map_path"`
		RuntimeReport     string `json:"runtime_report"`
		RuntimeConfigured bool   `json:"runtime_configured"`
	} `json:"paths"`
	Features struct {
		WorkspaceEditable bool `json:"workspace_editable"`
		ProjectImport     bool `json:"project_import"`
		JavaModel         bool `json:"java_model"`
		AgentStore        bool `json:"agent_store"`
	} `json:"features"`
	JavaModelReason string `json:"java_model_reason,omitempty"`
	Analysis        struct {
		Ready      bool   `json:"ready"`
		At         string `json:"at,omitempty"`
		DurationMS int64  `json:"duration_ms"`
		Partial    bool   `json:"partial"`
		Error      string `json:"error,omitempty"`
	} `json:"analysis"`
}

func (c *Console) buildConfigSnapshot() configSnapshot {
	cfg := c.currentConfig()
	snapshot := c.snapshotRef()
	out := configSnapshot{SchemaVersion: SchemaVersion, Workspace: c.workspace}
	if c.workspace != "" {
		out.Mode = "workspace"
	} else {
		out.Mode = "pinned"
	}
	out.Project.Source = c.projectSource
	if snapshot != nil {
		out.Project.Hash = snapshot.Hash()
		manifest := snapshot.Manifest()
		out.Project.Files = manifest.TotalFiles
		out.Project.Bytes = manifest.TotalBytes
	}
	out.Paths.Advisories = cfg.AdvisoryPath
	out.Paths.AdvisoriesDir = cfg.AdvisoryDir
	out.Paths.PackageMap = cfg.PackageMapPath
	out.Paths.RuntimeReport = cfg.RuntimeReport
	out.Paths.RuntimeConfigured = cfg.RuntimeReport != ""
	if cfg.AdvisoryPath != "" || cfg.AdvisoryDir != "" {
		if count, err := countAdvisories(cfg); err != nil {
			out.Paths.AdvisoriesError = err.Error()
		} else {
			out.Paths.AdvisoriesCount = count
		}
	}
	out.Features.WorkspaceEditable = c.workspace != ""
	out.Features.ProjectImport = c.workspace != ""
	out.Features.AgentStore = c.agentStore != nil
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	if state != nil {
		out.Analysis.Ready = state.err == nil
		out.Analysis.At = state.at.Format("2006-01-02T15:04:05Z07:00")
		out.Analysis.DurationMS = state.duration.Milliseconds()
		out.Analysis.Partial = state.findings.Partial
		if state.err != nil {
			out.Analysis.Error = state.err.Error()
		}
		out.Features.JavaModel = state.model != nil
		out.JavaModelReason = state.modelErr
	} else {
		out.Features.JavaModel = true
	}
	return out
}

type configUpdateRequest struct {
	AdvisoriesPath string `json:"advisories_path"`
	PackageMapPath string `json:"package_map_path"`
	RuntimeReport  string `json:"runtime_report"`
}

func (c *Console) handleConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, c.buildConfigSnapshot())
}

// handleConfigUpdate applies path configuration at runtime. It never imports or
// executes project code, and it always drops the cached analysis so no page can
// mix results produced with different configuration.
func (c *Console) handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "该控制台以固定快照启动；使用 --workspace 启动后才能在界面修改配置")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxConfigBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request configUpdateRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "配置请求不是合法 JSON")
		return
	}
	next := consoleConfig{}
	advisories := strings.TrimSpace(request.AdvisoriesPath)
	if advisories != "" {
		info, err := os.Stat(advisories)
		switch {
		case err != nil:
			writeError(w, http.StatusBadRequest, "advisories_missing", "公告路径不存在或不可读："+advisories)
			return
		case info.IsDir():
			next.AdvisoryDir = advisories
		case info.Mode().IsRegular():
			next.AdvisoryPath = advisories
		default:
			writeError(w, http.StatusBadRequest, "advisories_invalid", "公告路径必须是目录或 JSON 文件")
			return
		}
	}
	packageMap := strings.TrimSpace(request.PackageMapPath)
	if packageMap != "" {
		if err := validatePackageMapFile(packageMap); err != nil {
			writeError(w, http.StatusBadRequest, "package_map_invalid", err.Error())
			return
		}
		next.PackageMapPath = packageMap
	}
	runtimeReport := strings.TrimSpace(request.RuntimeReport)
	if runtimeReport != "" {
		info, err := os.Stat(runtimeReport)
		if err != nil || !info.Mode().IsRegular() {
			writeError(w, http.StatusBadRequest, "runtime_report_invalid", "运行时关联报告必须是可读文件："+runtimeReport)
			return
		}
		next.RuntimeReport = runtimeReport
	}
	// Fail before persisting so a bad catalog never becomes the stored default.
	if _, err := countAdvisories(next); err != nil {
		writeError(w, http.StatusBadRequest, "advisories_invalid", err.Error())
		return
	}
	c.cfgMu.Lock()
	c.config = next
	c.cfgMu.Unlock()
	c.resetAnalysis()
	file, err := loadWorkspaceConfig(c.workspace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	dir := c.currentSnapshotDir()
	file.AdvisoryPath = next.AdvisoryPath
	file.AdvisoryDir = next.AdvisoryDir
	file.PackageMap = next.PackageMapPath
	file.RuntimeReport = next.RuntimeReport
	if file.Project != nil {
		file.Project.SnapshotDir = dir
		file.Project.SnapshotHash = c.snapshotRef().Hash()
	}
	if err := saveWorkspaceConfig(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.buildConfigSnapshot())
}

func countAdvisories(cfg consoleConfig) (int, error) {
	if cfg.AdvisoryPath == "" && cfg.AdvisoryDir == "" {
		return 0, nil
	}
	// Reuse the SCA loader through a cheap analysis-free probe: a directory with
	// an invalid catalog must be rejected here, not on the next page load.
	return sca.CountAdvisories(cfg.AdvisoryPath, cfg.AdvisoryDir)
}

type configResetResponse struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Analysis      struct {
		DurationMS  int64 `json:"duration_ms"`
		Findings    int   `json:"findings"`
		Endpoints   int   `json:"endpoints"`
		Unprotected int   `json:"unprotected"`
		JavaTypes   int   `json:"java_types"`
	} `json:"analysis"`
}

// handleAnalysisRerun drops the cached analysis and recomputes it immediately
// so the caller learns whether the new configuration is usable.
func (c *Console) handleAnalysisRerun(w http.ResponseWriter, r *http.Request) {
	c.resetAnalysis()
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	response := configResetResponse{SchemaVersion: SchemaVersion, Status: "ok"}
	response.Analysis.DurationMS = state.duration.Milliseconds()
	response.Analysis.Findings = len(state.findings.Findings)
	response.Analysis.Endpoints = len(state.audit.Endpoints)
	response.Analysis.Unprotected = state.authz.Coverage.Unprotected
	if state.model != nil {
		response.Analysis.JavaTypes = state.model.Coverage.TypesIndexed
	}
	writeJSON(w, http.StatusOK, response)
}

type projectImportRequest struct {
	Source string `json:"source"`
}

type projectImportResponse struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Source        string `json:"source"`
	Hash          string `json:"hash"`
	Files         int    `json:"files"`
	Bytes         int64  `json:"bytes"`
}

// handleProjectImport switches the console to another local source directory.
// The source is only read; the snapshot is created inside the workspace and the
// previous snapshot stays on disk untouched.
func (c *Console) handleProjectImport(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "该控制台以固定快照启动；使用 --workspace 启动后才能导入其他项目")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request projectImportRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "导入请求不是合法 JSON")
		return
	}
	source := strings.TrimSpace(request.Source)
	if source == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "需要提供源码目录")
		return
	}
	dir, hash, err := ImportProject(r.Context(), c.workspace, source)
	if err != nil {
		writeError(w, http.StatusBadRequest, "import_failed", err.Error())
		return
	}
	opened, err := project.Open(r.Context(), dir, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "snapshot_open_failed", err.Error())
		return
	}
	c.snapMu.Lock()
	previous := c.snapshot
	c.snapshot = opened
	c.snapshotDir = dir
	c.projectSource = source
	c.snapMu.Unlock()
	c.resetAnalysis()
	if previous != nil && previous != opened {
		_ = previous.Close()
	}
	file, err := loadWorkspaceConfig(c.workspace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	cfg := c.currentConfig()
	file.Project = &workspaceProj{Source: source, SnapshotDir: dir, SnapshotHash: hash}
	file.AdvisoryPath = cfg.AdvisoryPath
	file.AdvisoryDir = cfg.AdvisoryDir
	file.PackageMap = cfg.PackageMapPath
	file.RuntimeReport = cfg.RuntimeReport
	if err := saveWorkspaceConfig(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	manifest := opened.Manifest()
	c.rememberProject(projectEntry{
		Source: source, SnapshotDir: dir, Hash: hash,
		Files: manifest.TotalFiles, Bytes: manifest.TotalBytes,
		ImportedAt: time.Now().UTC().Format(time.RFC3339),
	})
	writeJSON(w, http.StatusOK, projectImportResponse{
		SchemaVersion: SchemaVersion,
		Status:        "ok",
		Source:        source,
		Hash:          hash,
		Files:         manifest.TotalFiles,
		Bytes:         manifest.TotalBytes,
	})
}

func (c *Console) currentSnapshotDir() string {
	c.snapMu.RLock()
	defer c.snapMu.RUnlock()
	return c.snapshotDir
}

// validatePackageMapFile mirrors the loader's shape contract so the console can
// reject a bad map with a 400 instead of caching a failed analysis.
func validatePackageMapFile(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("package map 必须是可读文件：%s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("package map 不可读：%s", path)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var mapping struct {
		SchemaVersion int                 `json:"schema_version"`
		Dependencies  map[string][]string `json:"dependencies"`
	}
	if err := decoder.Decode(&mapping); err != nil {
		return fmt.Errorf("package map 不是合法 JSON：%v", err)
	}
	if mapping.SchemaVersion != 1 {
		return errors.New("package map schema_version 必须为 1")
	}
	if len(mapping.Dependencies) == 0 {
		return errors.New("package map 需要至少一条 group:artifact 映射")
	}
	keys := make([]string, 0, len(mapping.Dependencies))
	for key := range mapping.Dependencies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.Contains(key, ":") {
			return fmt.Errorf("package map 键必须是 group:artifact：%s", key)
		}
		if len(mapping.Dependencies[key]) == 0 {
			return fmt.Errorf("package map 条目没有包前缀：%s", key)
		}
	}
	return nil
}

// WorkspaceProject reports the project persisted in a workspace so the CLI can
// reopen the last imported source without repeating --project.
func WorkspaceProject(workspace string) (source, snapshotDir, snapshotHash string, err error) {
	file, err := loadWorkspaceConfig(workspace)
	if err != nil {
		return "", "", "", err
	}
	if file.Project == nil {
		return "", "", "", nil
	}
	return file.Project.Source, file.Project.SnapshotDir, file.Project.SnapshotHash, nil
}
