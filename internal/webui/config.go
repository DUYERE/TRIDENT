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

	"trident/internal/project"
	"trident/internal/sca"
	"trident/internal/store"
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
	// AgentDSN persists the Agent session database connection so the console
	// connects on every start without repeating --agent-dsn. It contains
	// database credentials and must never leave the machine; the file is
	// written 0600 and .trident/ is git-ignored.
	AgentDSN string `json:"agent_dsn,omitempty"`
	// AgentToken is the write principal token used to create Runs. It is stored
	// locally (0600) so the console can start unattended, is never returned to
	// the browser, and can be cleared from the runtime settings page.
	AgentToken string `json:"agent_token,omitempty"`
	// AgentChatEnabled mirrors the runtime toggle so a disabled feature stays
	// disabled after restart without requiring a flag.
	AgentChatEnabled bool `json:"agent_chat_enabled,omitempty"`
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
	return writeFileAtomic(path, data, 0o600)
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
		WorkspaceEditable bool   `json:"workspace_editable"`
		ProjectImport     bool   `json:"project_import"`
		JavaModel         bool   `json:"java_model"`
		AgentStore        bool   `json:"agent_store"`
		AgentDSNStored    bool   `json:"agent_dsn_stored"`
		AgentDSNError     string `json:"agent_dsn_error,omitempty"`
		AgentChatEnabled  bool   `json:"agent_chat_enabled"`
		AgentChatReady    bool   `json:"agent_chat_ready"`
		AgentTokenStored  bool   `json:"agent_token_stored"`
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
	runtime := c.agentRuntimeStatus()
	out.Features.AgentChatEnabled = runtime.Enabled
	out.Features.AgentChatReady = runtime.Ready
	out.Features.AgentTokenStored = runtime.TokenStored
	out.Features.AgentDSNStored = c.workspace != "" && c.storedAgentDSN != ""
	c.agentStoreMu.Lock()
	agentErr := c.agentConnectError
	c.agentStoreMu.Unlock()
	out.Features.AgentDSNError = agentErr
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
	AgentDSN       string `json:"agent_dsn,omitempty"`
	ClearAgentDSN  bool   `json:"agent_dsn_clear,omitempty"`
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
	// The Agent session DSN is validated against the real database before it is
	// persisted; a bad connection string must never replace a working one.
	agentDSN := strings.TrimSpace(request.AgentDSN)
	var pendingStore *store.Store
	if agentDSN != "" {
		observation, err := store.Open(r.Context(), agentDSN, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "agent_dsn_invalid", "Agent 会话库连接失败："+err.Error())
			return
		}
		pendingStore = observation
	}
	c.cfgMu.Lock()
	previous := c.config
	c.config = next
	c.cfgMu.Unlock()
	// Saving only the Agent DSN must not throw away a 40-second analysis:
	// reset the cache only when a path that feeds the analysis changed.
	if previous != next {
		c.resetAnalysis()
	}
	file, err := loadWorkspaceConfig(c.workspace)
	if err != nil {
		if pendingStore != nil {
			pendingStore.Close()
		}
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	dir := c.currentSnapshotDir()
	file.AdvisoryPath = next.AdvisoryPath
	file.AdvisoryDir = next.AdvisoryDir
	file.PackageMap = next.PackageMapPath
	file.RuntimeReport = next.RuntimeReport
	switch {
	case request.ClearAgentDSN:
		file.AgentDSN = ""
		file.AgentChatEnabled = false
		c.storedAgentDSN = ""
		c.agentChatEnabled = false
		c.cfgMu.Lock()
		c.chat.enabled = false
		c.chat.reason = "未启用：在「设置 → Agent 与编排」里开启（无需重启）"
		c.cfgMu.Unlock()
		if c.agentWrite != nil {
			c.agentWrite.Close()
			c.agentWrite = nil
			c.agentSession = store.Session{}
			c.orchEngine = nil
		}
		c.swapAgentStore(nil)
	case pendingStore != nil:
		file.AgentDSN = agentDSN
		c.storedAgentDSN = agentDSN
		c.swapAgentStore(pendingStore)
	}
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
