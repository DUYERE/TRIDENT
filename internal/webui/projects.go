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
)

// projectEntry is one imported source directory inside the workspace. The
// snapshot it points to is immutable; only the registry and the "current"
// pointer change.
type projectEntry struct {
	Source      string `json:"source"`
	SnapshotDir string `json:"snapshot_dir"`
	Hash        string `json:"hash"`
	Files       int    `json:"files"`
	Bytes       int64  `json:"bytes"`
	ImportedAt  string `json:"imported_at"`
}

type projectsFile struct {
	SchemaVersion int            `json:"schema_version"`
	Projects      []projectEntry `json:"projects"`
}

const (
	projectsSchemaVersion = 1
	maxProjects           = 50
	maxBrowseEntries      = 500
)

func projectsPath(workspace string) string {
	return filepath.Join(workspace, "projects.json")
}

func loadProjects(workspace string) (projectsFile, error) {
	file := projectsFile{SchemaVersion: projectsSchemaVersion}
	if workspace == "" {
		return file, nil
	}
	data, err := os.ReadFile(projectsPath(workspace))
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return file, fmt.Errorf("project registry is unreadable: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return file, fmt.Errorf("project registry is invalid: %v", err)
	}
	if file.SchemaVersion != projectsSchemaVersion {
		return file, fmt.Errorf("project registry schema %d is not supported", file.SchemaVersion)
	}
	return file, nil
}

func saveProjects(workspace string, file projectsFile) error {
	if workspace == "" {
		return nil
	}
	file.SchemaVersion = projectsSchemaVersion
	if len(file.Projects) > maxProjects {
		file.Projects = file.Projects[:maxProjects]
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return fmt.Errorf("console workspace is not writable: %w", err)
	}
	path := projectsPath(workspace)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("console workspace is not writable: %w", err)
	}
	return os.Rename(temporary, path)
}

// rememberProject inserts or refreshes one registry entry, newest first.
func (c *Console) rememberProject(entry projectEntry) {
	if c.workspace == "" {
		return
	}
	file, err := loadProjects(c.workspace)
	if err != nil {
		return
	}
	kept := make([]projectEntry, 0, len(file.Projects)+1)
	kept = append(kept, entry)
	for _, item := range file.Projects {
		if item.Hash == entry.Hash {
			continue
		}
		kept = append(kept, item)
	}
	file.Projects = kept
	_ = saveProjects(c.workspace, file)
}

// switchSnapshot opens the target snapshot before releasing the current one, so
// a failed switch leaves the console serving the previous project.
func (c *Console) switchSnapshot(ctx context.Context, dir, hash, source string) (*project.Snapshot, error) {
	opened, err := project.Open(ctx, dir, hash)
	if err != nil {
		return nil, err
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
	return opened, nil
}

type projectsView struct {
	SchemaVersion int            `json:"schema_version"`
	Mode          string         `json:"mode"`
	Current       string         `json:"current,omitempty"`
	Projects      []projectEntry `json:"projects"`
	Workspace     string         `json:"workspace,omitempty"`
	Total         int            `json:"total"`
}

func (c *Console) handleProjects(w http.ResponseWriter, _ *http.Request) {
	view := projectsView{SchemaVersion: SchemaVersion, Mode: "pinned", Workspace: c.workspace, Projects: []projectEntry{}}
	if c.workspace != "" {
		view.Mode = "workspace"
		if file, err := loadProjects(c.workspace); err != nil {
			writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
			return
		} else {
			view.Projects = append(view.Projects, file.Projects...)
		}
	}
	view.Current = c.SnapshotHash()
	if view.Current != "" {
		// Keep the registry in sync when the console was started from flags.
		known := false
		for _, item := range view.Projects {
			if item.Hash == view.Current {
				known = true
				break
			}
		}
		if !known {
			c.snapMu.RLock()
			entry := projectEntry{Source: c.projectSource, SnapshotDir: c.snapshotDir, Hash: view.Current, ImportedAt: time.Now().UTC().Format(time.RFC3339)}
			snapshot := c.snapshot
			c.snapMu.RUnlock()
			if snapshot != nil {
				manifest := snapshot.Manifest()
				entry.Files = manifest.TotalFiles
				entry.Bytes = manifest.TotalBytes
			}
			c.rememberProject(entry)
			view.Projects = append([]projectEntry{entry}, view.Projects...)
		}
	}
	view.Total = len(view.Projects)
	writeJSON(w, http.StatusOK, view)
}

type projectImportBody struct {
	Source string `json:"source"`
}

// handleProjectCreate imports a local directory, registers it and switches to
// it. The source tree is only read; the snapshot lives inside the workspace.
func (c *Console) handleProjectCreate(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "该控制台以固定快照启动；使用 --workspace 启动后才能在界面导入项目")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request projectImportBody
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
	opened, err := c.switchSnapshot(r.Context(), dir, hash, source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "snapshot_open_failed", err.Error())
		return
	}
	manifest := opened.Manifest()
	entry := projectEntry{
		Source: source, SnapshotDir: dir, Hash: hash,
		Files: manifest.TotalFiles, Bytes: manifest.TotalBytes,
		ImportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	c.rememberProject(entry)
	c.persistProject(dir, hash, source)
	writeJSON(w, http.StatusOK, struct {
		SchemaVersion int          `json:"schema_version"`
		Status        string       `json:"status"`
		Project       projectEntry `json:"project"`
	}{SchemaVersion: SchemaVersion, Status: "ok", Project: entry})
}

type projectSelectBody struct {
	Hash string `json:"hash"`
}

// handleProjectSelect switches to an already imported project without
// re-importing it.
func (c *Console) handleProjectSelect(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持切换项目")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request projectSelectBody
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "切换请求不是合法 JSON")
		return
	}
	hash := strings.TrimSpace(request.Hash)
	if hash == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "需要提供项目摘要")
		return
	}
	file, err := loadProjects(c.workspace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	var target *projectEntry
	for index := range file.Projects {
		if file.Projects[index].Hash == hash {
			target = &file.Projects[index]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "project_unknown", "该项目不在工作区列表中")
		return
	}
	if _, err := c.switchSnapshot(r.Context(), target.SnapshotDir, target.Hash, target.Source); err != nil {
		writeError(w, http.StatusBadRequest, "snapshot_open_failed", err.Error())
		return
	}
	c.persistProject(target.SnapshotDir, target.Hash, target.Source)
	writeJSON(w, http.StatusOK, struct {
		SchemaVersion int          `json:"schema_version"`
		Status        string       `json:"status"`
		Project       projectEntry `json:"project"`
	}{SchemaVersion: SchemaVersion, Status: "ok", Project: *target})
}

// handleProjectForget removes an entry from the list. Snapshot files stay on
// disk on purpose: deleting imported evidence is never a side effect of a UI
// click.
func (c *Console) handleProjectForget(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式没有项目列表")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request projectSelectBody
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求不是合法 JSON")
		return
	}
	hash := strings.TrimSpace(request.Hash)
	if hash == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "需要提供项目摘要")
		return
	}
	if hash == c.SnapshotHash() {
		writeError(w, http.StatusConflict, "project_active", "不能移除当前正在分析的项目；先切换到其他项目")
		return
	}
	file, err := loadProjects(c.workspace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	kept := make([]projectEntry, 0, len(file.Projects))
	removed := false
	for _, item := range file.Projects {
		if item.Hash == hash {
			removed = true
			continue
		}
		kept = append(kept, item)
	}
	if !removed {
		writeError(w, http.StatusNotFound, "project_unknown", "该项目不在工作区列表中")
		return
	}
	file.Projects = kept
	if err := saveProjects(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
	}{SchemaVersion: SchemaVersion, Status: "ok"})
}

func (c *Console) persistProject(dir, hash, source string) {
	if c.workspace == "" {
		return
	}
	file, err := loadWorkspaceConfig(c.workspace)
	if err != nil {
		return
	}
	file.Project = &workspaceProj{Source: source, SnapshotDir: dir, SnapshotHash: hash}
	cfg := c.currentConfig()
	file.AdvisoryPath = cfg.AdvisoryPath
	file.AdvisoryDir = cfg.AdvisoryDir
	file.PackageMap = cfg.PackageMapPath
	file.RuntimeReport = cfg.RuntimeReport
	_ = saveWorkspaceConfig(c.workspace, file)
}

// ── filesystem picker ──────────────────────────────────────────────────

type fsEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Project bool   `json:"looks_like_project"`
}

type fsView struct {
	SchemaVersion int       `json:"schema_version"`
	Path          string    `json:"path"`
	Parent        string    `json:"parent,omitempty"`
	Entries       []fsEntry `json:"entries"`
	Roots         []string  `json:"roots,omitempty"`
	Truncated     bool      `json:"truncated"`
	Error         string    `json:"error,omitempty"`
}

// handleFilesystem lists directories only. It never returns file contents, never
// follows symlinks and is token gated like every other console route. It exists
// so the browser can offer a directory picker without asking the user to paste
// absolute paths from memory.
func (c *Console) handleFilesystem(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持浏览目录")
		return
	}
	requested := strings.TrimSpace(r.URL.Query().Get("path"))
	if requested == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "fs_unavailable", "无法确定用户主目录")
			return
		}
		requested = home
	}
	if len(requested) > 4096 || strings.ContainsAny(requested, "\x00\r\n") {
		writeError(w, http.StatusBadRequest, "invalid_path", "路径非法")
		return
	}
	absolute, err := filepath.Abs(requested)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", "路径非法")
		return
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		writeError(w, http.StatusBadRequest, "invalid_path", "目录不存在或不可读："+absolute)
		return
	}
	view := fsView{SchemaVersion: SchemaVersion, Path: absolute, Entries: []fsEntry{}}
	if parent := filepath.Dir(absolute); parent != absolute {
		view.Parent = parent
	}
	if roots := filesystemRoots(); len(roots) > 0 {
		view.Roots = roots
	}
	entries, err := os.ReadDir(absolute)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", "目录不可读："+absolute)
		return
	}
	names := make([]fsEntry, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Symlinks and junctions can point anywhere; the picker stays literal.
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		child := filepath.Join(absolute, name)
		names = append(names, fsEntry{Name: name, Path: child, Project: looksLikeProject(child)})
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i].Name) < strings.ToLower(names[j].Name) })
	if len(names) > maxBrowseEntries {
		names = names[:maxBrowseEntries]
		view.Truncated = true
	}
	view.Entries = names
	writeJSON(w, http.StatusOK, view)
}

// looksLikeProject is a shallow hint for the picker: build files or a source
// directory directly inside the candidate. It never walks the tree.
func looksLikeProject(dir string) bool {
	markers := []string{"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "src", ".git"}
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

func filesystemRoots() []string {
	if os.PathSeparator != '\\' {
		return nil
	}
	roots := make([]string, 0, 8)
	for letter := 'A'; letter <= 'Z'; letter++ {
		candidate := string(letter) + ":\\"
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			roots = append(roots, candidate)
		}
	}
	return roots
}
