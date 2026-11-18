// Package casework reads the local, file-backed Case workbench. It does not
// execute project code or call a model: it turns existing evidence artifacts
// into a reviewable state chain and stores explicitly-created finding cases in
// the console workspace.
package casework

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = 1

var (
	ErrNotFound = errors.New("case not found")
	ErrInvalid  = errors.New("invalid case id")
	ErrNoStore  = errors.New("case store is not available")
	ErrNoPatch  = errors.New("case has no patch artifact")
	ErrExists   = errors.New("case already exists")
)

var caseIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Stage is one step of the evidence -> runtime -> patch -> validation -> upstream
// chain. Status values are verified, ready, draft, pending and missing.
type Stage struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

type FindingView struct {
	ID             string               `json:"id"`
	CVE            string               `json:"cve,omitempty"`
	Title          string               `json:"title"`
	Severity       string               `json:"severity,omitempty"`
	Status         string               `json:"status,omitempty"`
	RuntimeResult  string               `json:"runtime_result,omitempty"`
	SourceEvidence []SourceEvidenceView `json:"source_evidence,omitempty"`
}

type SourceEvidenceView struct {
	File        string `json:"file"`
	Lines       string `json:"lines,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Observation string `json:"observation,omitempty"`
}

type EvidenceArtifact struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
	Result string `json:"result,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type PatchArtifact struct {
	File       string   `json:"file"`
	Bytes      int64    `json:"bytes"`
	SHA256     string   `json:"sha256,omitempty"`
	Status     string   `json:"status"`
	ApplyCheck string   `json:"apply_check,omitempty"`
	Files      []string `json:"files,omitempty"`
	Origin     string   `json:"origin,omitempty"`
}

type ValidationRecord struct {
	Result     string         `json:"result"`
	Source     string         `json:"source"`
	Log        string         `json:"log,omitempty"`
	VerifiedAt string         `json:"verified_at,omitempty"`
	Checks     map[string]any `json:"checks,omitempty"`
}

type UpstreamBundle struct {
	Present   bool     `json:"present"`
	Submitted bool     `json:"submitted"`
	Files     []string `json:"files,omitempty"`
	Advisory  string   `json:"advisory,omitempty"`
	Repro     string   `json:"repro,omitempty"`
	TestPlan  string   `json:"test_plan,omitempty"`
	PRBody    string   `json:"pr_body,omitempty"`
}

type CaseSummary struct {
	ID                string  `json:"id"`
	Title             string  `json:"title"`
	Repository        string  `json:"repository,omitempty"`
	VulnerableVersion string  `json:"vulnerable_version,omitempty"`
	FixedVersion      string  `json:"fixed_version,omitempty"`
	Severity          string  `json:"severity,omitempty"`
	Status            string  `json:"status"`
	FindingCount      int     `json:"finding_count"`
	Stages            []Stage `json:"stages"`
	UpdatedAt         string  `json:"updated_at,omitempty"`
	Source            string  `json:"source"`
}

type CaseDetail struct {
	SchemaVersion int `json:"schema_version"`
	CaseSummary
	Findings    []FindingView      `json:"findings"`
	Evidence    []EvidenceArtifact `json:"evidence,omitempty"`
	Patch       *PatchArtifact     `json:"patch,omitempty"`
	Validation  *ValidationRecord  `json:"validation,omitempty"`
	Upstream    *UpstreamBundle    `json:"upstream,omitempty"`
	Limitations []string           `json:"limitations,omitempty"`
	// RawFindings preserves the original finding documents for export. It is
	// not rendered by the console and may be empty for scanned cases.
	RawFindings []json.RawMessage `json:"raw_findings,omitempty"`
}

// Catalog discovers case directories and a workspace-backed case store.
type Catalog struct {
	Root     string
	StoreDir string
}

func NewCatalog(root, workspace string) *Catalog {
	if strings.TrimSpace(root) == "" {
		if env := strings.TrimSpace(os.Getenv("TRIDENT_CASES_DIR")); env != "" {
			root = env
		} else if cwd, err := os.Getwd(); err == nil {
			if info, statErr := os.Stat(filepath.Join(cwd, "cases")); statErr == nil && info.IsDir() {
				root = filepath.Join(cwd, "cases")
			}
		}
	}
	if strings.TrimSpace(root) != "" {
		root = filepath.Clean(root)
	}
	store := ""
	if strings.TrimSpace(workspace) != "" {
		store = filepath.Join(workspace, "cases")
	}
	return &Catalog{Root: root, StoreDir: store}
}

func (c *Catalog) Available() bool {
	if c == nil || strings.TrimSpace(c.Root) == "" {
		return false
	}
	info, err := os.Stat(c.Root)
	return err == nil && info.IsDir()
}

func validID(id string) bool {
	return caseIDPattern.MatchString(id) && id != "." && id != ".."
}

func (c *Catalog) List() ([]CaseSummary, error) {
	items := map[string]CaseSummary{}
	if c.Available() {
		entries, err := os.ReadDir(c.Root)
		if err != nil {
			return nil, fmt.Errorf("read cases directory: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			detail, err := c.loadDir(entry.Name(), filepath.Join(c.Root, entry.Name()))
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					continue
				}
				continue
			}
			items[detail.ID] = detail.CaseSummary
		}
	}
	if c.StoreDir != "" {
		entries, err := os.ReadDir(c.StoreDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				id := strings.TrimSuffix(entry.Name(), ".json")
				detail, err := c.loadStored(id)
				if err != nil {
					continue
				}
				items[detail.ID] = detail.CaseSummary
			}
		}
	}
	out := make([]CaseSummary, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt == out[j].UpdatedAt {
			return out[i].ID < out[j].ID
		}
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	return out, nil
}

func (c *Catalog) Get(id string) (CaseDetail, error) {
	if !validID(id) {
		return CaseDetail{}, ErrInvalid
	}
	if c.StoreDir != "" {
		if detail, err := c.loadStored(id); err == nil {
			return detail, nil
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrNotFound) {
			return CaseDetail{}, err
		}
	}
	if c.Available() {
		detail, err := c.loadDir(id, filepath.Join(c.Root, id))
		if err == nil {
			return detail, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return CaseDetail{}, err
		}
	}
	return CaseDetail{}, ErrNotFound
}

// ReadFile reads one relative artifact inside a discovery case directory. The
// caller supplies an artifact name already present in the CaseDetail; absolute
// paths and traversal are rejected. Workspace-created cases have no source
// directory and therefore return ErrNotFound.
func (c *Catalog) ReadFile(id, rel string) (string, error) {
	if !validID(id) || !c.Available() {
		return "", ErrNotFound
	}
	rel = filepath.Clean(rel)
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
		return "", ErrInvalid
	}
	base := filepath.Join(c.Root, id)
	path := filepath.Join(base, rel)
	if !strings.HasPrefix(path, base+string(os.PathSeparator)) && path != base {
		return "", ErrInvalid
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return "", ErrNotFound
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (c *Catalog) loadStored(id string) (CaseDetail, error) {
	if !validID(id) {
		return CaseDetail{}, ErrInvalid
	}
	path := filepath.Join(c.StoreDir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CaseDetail{}, ErrNotFound
		}
		return CaseDetail{}, err
	}
	var detail CaseDetail
	if err := json.Unmarshal(data, &detail); err != nil {
		return CaseDetail{}, fmt.Errorf("case %s is invalid: %w", id, err)
	}
	if detail.SchemaVersion == 0 {
		detail.SchemaVersion = SchemaVersion
	}
	detail.Source = "workspace"
	return detail, nil
}

// Save persists an explicitly-created case. Only a workspace-backed console may
// create cases; a pinned console has no writable state directory.
func (c *Catalog) Save(detail CaseDetail) (CaseDetail, error) {
	if c.StoreDir == "" {
		return CaseDetail{}, ErrNoStore
	}
	if !validID(detail.ID) {
		return CaseDetail{}, ErrInvalid
	}
	if err := os.MkdirAll(c.StoreDir, 0o700); err != nil {
		return CaseDetail{}, fmt.Errorf("create case store: %w", err)
	}
	detail.SchemaVersion = SchemaVersion
	detail.Source = "workspace"
	detail.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		return CaseDetail{}, err
	}
	data = append(data, '\n')
	path := filepath.Join(c.StoreDir, detail.ID+".json")
	if _, err := os.Stat(path); err == nil {
		return CaseDetail{}, ErrExists
	}
	temp, err := os.CreateTemp(c.StoreDir, ".case-*")
	if err != nil {
		return CaseDetail{}, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return CaseDetail{}, err
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return CaseDetail{}, err
	}
	if err := temp.Close(); err != nil {
		return CaseDetail{}, err
	}
	if err := os.Rename(tempName, path); err != nil {
		return CaseDetail{}, err
	}
	return detail, nil
}

func NewFindingCase(findingID, title string, raw json.RawMessage) (CaseDetail, error) {
	findingID = strings.TrimSpace(findingID)
	if findingID == "" {
		return CaseDetail{}, fmt.Errorf("finding_id is required")
	}
	if strings.TrimSpace(title) == "" {
		title = "Finding " + findingID
	}
	sum := sha256.Sum256([]byte(findingID))
	id := "finding-" + hex.EncodeToString(sum[:])[:12]
	views := parseFindingsFromRaw([]json.RawMessage{raw})
	if len(views) == 0 {
		return CaseDetail{}, fmt.Errorf("finding document is invalid")
	}
	stages := []Stage{
		{Key: "finding", Label: "源码 Finding", Status: "verified", Detail: "已从当前快照的 Finding 创建", Evidence: []string{findingID}},
		{Key: "poc", Label: "运行时 PoC", Status: "pending", Detail: "尚未附加运行时证明"},
		{Key: "patch", Label: "最小补丁", Status: "pending", Detail: "尚未生成补丁"},
		{Key: "validation", Label: "双实例验证", Status: "pending", Detail: "尚未执行补丁验证"},
		{Key: "upstream", Label: "上游 Bundle", Status: "pending", Detail: "尚未准备上游材料"},
	}
	detail := CaseDetail{
		SchemaVersion: SchemaVersion,
		CaseSummary: CaseSummary{
			ID: id, Title: strings.TrimSpace(title), Status: "in_progress",
			FindingCount: len(views), Stages: stages, Source: "workspace",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Findings: views, RawFindings: []json.RawMessage{append([]byte(nil), raw...)},
		Limitations: []string{
			"该 Case 从当前快照 Finding 创建；运行时、补丁与验证尚未附加。",
			"未执行的阶段保持 pending，不能视为已验证。",
		},
	}
	return detail, nil
}

func (c *Catalog) loadDir(id, dir string) (CaseDetail, error) {
	if !validID(id) {
		return CaseDetail{}, ErrInvalid
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return CaseDetail{}, ErrNotFound
	}
	detail := CaseDetail{SchemaVersion: SchemaVersion}
	detail.ID = id
	detail.Source = "directory"
	detail.Title = readTitle(filepath.Join(dir, "README.md"))
	detail.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)

	meta, err := readMap(filepath.Join(dir, "finding.json"))
	if err != nil {
		// A directory without a finding.json is not a Case.
		return CaseDetail{}, ErrNotFound
	}
	detail.Repository = firstString(meta, "repository")
	detail.VulnerableVersion = firstString(meta, "vulnerable_version")
	detail.FixedVersion = nestedString(meta, "fixed_reference", "version")
	if detail.Title == "" {
		detail.Title = detail.ID
	}

	findingFiles, _ := filepath.Glob(filepath.Join(dir, "findings", "*.json"))
	for _, path := range findingFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		detail.RawFindings = append(detail.RawFindings, raw)
	}
	detail.Findings = parseFindingsFromRaw(detail.RawFindings)
	detail.Severity = highestSeverity(detail.Findings)

	evidenceFiles, _ := filepath.Glob(filepath.Join(dir, "evidence", "*.json"))
	for _, path := range evidenceFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		artifact := EvidenceArtifact{
			Name:   filepath.Base(path),
			Bytes:  fileSize(path),
			SHA256: fileSHA256(path),
			Result: firstString(item, "result"),
		}
		if artifact.Result == "" {
			if marker, ok := item["marker_observed"].(bool); ok && marker {
				artifact.Result = "VULNERABLE"
			}
		}
		if delta, ok := item["delta_seconds"].(float64); ok {
			artifact.Detail = fmt.Sprintf("delta %.2fs", delta)
		}
		detail.Evidence = append(detail.Evidence, artifact)
	}
	sort.Slice(detail.Evidence, func(i, j int) bool { return detail.Evidence[i].Name < detail.Evidence[j].Name })

	detail.Patch = readPatch(dir)
	detail.Validation = readValidation(dir)
	detail.Upstream = readUpstream(dir)
	detail.Stages = buildStages(detail, dir)
	detail.Status = overallStatus(detail)
	detail.FindingCount = len(detail.Findings)
	detail.CaseSummary = summaryOf(detail)
	detail.Limitations = []string{
		"认证后漏洞：两个 Finding 都需要已登录会话。",
		"补丁控制副本按官方 v30.0.01 安全改动落地，不是整棵 v30.0.01 源码树的逐字节对照。",
		"上游 bundle 是本地草稿；未经明确批准不提交 GitHub。",
	}
	latest := latestModTime(dir)
	if latest.After(info.ModTime()) {
		detail.UpdatedAt = latest.UTC().Format(time.RFC3339)
	}
	return detail, nil
}

func summaryOf(detail CaseDetail) CaseSummary {
	return CaseSummary{
		ID: detail.ID, Title: detail.Title, Repository: detail.Repository,
		VulnerableVersion: detail.VulnerableVersion, FixedVersion: detail.FixedVersion,
		Severity: detail.Severity, Status: detail.Status, FindingCount: detail.FindingCount,
		Stages: detail.Stages, UpdatedAt: detail.UpdatedAt, Source: detail.Source,
	}
}

func buildStages(detail CaseDetail, dir string) []Stage {
	sourceStatus, sourceDetail := "verified", fmt.Sprintf("%d 个 Finding 已落盘", len(detail.Findings))
	if len(detail.Findings) == 0 {
		sourceStatus, sourceDetail = "missing", "没有 finding 文档"
	}
	pocStatus, pocDetail := "pending", "尚未捕获运行时证明"
	readings := []string{}
	for _, evidence := range detail.Evidence {
		if strings.EqualFold(evidence.Result, "VULNERABLE") || evidence.Result == "PATCH_VERIFIED" {
			pocStatus, pocDetail = "verified", "运行时结果已捕获"
			readings = append(readings, evidence.Name)
		}
	}
	if pocStatus == "verified" && len(readings) > 0 {
		pocDetail = "运行时结果已捕获：" + strings.Join(readings, "、")
	}
	patchStatus, patchDetail := "pending", "尚未生成补丁"
	if detail.Patch != nil {
		patchStatus, patchDetail = "ready", fmt.Sprintf("%s · %d bytes", detail.Patch.File, detail.Patch.Bytes)
		if detail.Patch.ApplyCheck != "" {
			patchDetail += " · " + detail.Patch.ApplyCheck
		}
	}
	validationStatus, validationDetail := "pending", "尚未执行验证"
	if detail.Validation != nil && detail.Validation.Result != "" {
		validationStatus, validationDetail = "verified", detail.Validation.Result
	}
	upstreamStatus, upstreamDetail := "pending", "尚未准备上游材料"
	if detail.Upstream != nil && detail.Upstream.Present {
		upstreamStatus, upstreamDetail = "draft", "本地 bundle 已准备；未提交上游"
	}
	return []Stage{
		{Key: "finding", Label: "源码 Finding", Status: sourceStatus, Detail: sourceDetail},
		{Key: "poc", Label: "运行时 PoC", Status: pocStatus, Detail: pocDetail, Evidence: readings},
		{Key: "patch", Label: "最小补丁", Status: patchStatus, Detail: patchDetail},
		{Key: "validation", Label: "双实例验证", Status: validationStatus, Detail: validationDetail},
		{Key: "upstream", Label: "上游 Bundle", Status: upstreamStatus, Detail: upstreamDetail},
	}
}

func overallStatus(detail CaseDetail) string {
	if detail.Validation != nil {
		value := strings.ToUpper(detail.Validation.Result)
		if strings.Contains(value, "VERIFIED") {
			return "verified"
		}
	}
	if detail.Patch != nil {
		return "ready"
	}
	if len(detail.Findings) > 0 {
		return "in_progress"
	}
	return "blocked"
}

func readPatch(dir string) *PatchArtifact {
	paths := []string{
		filepath.Join(dir, "patch.diff"),
		filepath.Join(dir, "patch.patch"),
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "upstream", "*.patch")); len(matches) > 0 {
		paths = append(paths, matches[0])
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		artifact := &PatchArtifact{
			File: relName(dir, path), Bytes: info.Size(), SHA256: fileSHA256(path),
			Status: "ready", Origin: "case artifact",
		}
		var meta map[string]any
		if raw, err := os.ReadFile(filepath.Join(dir, "patch_meta.json")); err == nil {
			_ = json.Unmarshal(raw, &meta)
			if checks, ok := meta["checks"].(map[string]any); ok {
				artifact.ApplyCheck = firstString(checks, "patch_apply_check")
			}
			if files, ok := meta["files"].([]any); ok {
				for _, item := range files {
					if entry, ok := item.(map[string]any); ok {
						if p := firstString(entry, "path"); p != "" {
							artifact.Files = append(artifact.Files, p)
						}
					}
				}
			}
			if origin := firstString(meta, "generator"); origin != "" {
				artifact.Origin = origin
			}
		}
		if len(artifact.Files) == 0 {
			artifact.Files = patchFiles(path)
		}
		return artifact
	}
	return nil
}

func readValidation(dir string) *ValidationRecord {
	var record *ValidationRecord
	if raw, err := os.ReadFile(filepath.Join(dir, "verify.log")); err == nil {
		var mapValue map[string]any
		if json.Unmarshal(raw, &mapValue) == nil {
			if result := firstString(mapValue, "result"); result != "" {
				record = &ValidationRecord{Result: result, Source: "recorded", Log: "verify.log"}
				info, _ := os.Stat(filepath.Join(dir, "verify.log"))
				if info != nil {
					record.VerifiedAt = info.ModTime().UTC().Format(time.RFC3339)
				}
				if patched, ok := mapValue["patched"].(map[string]any); ok {
					record.Checks = map[string]any{
						"login_ok": patched["login_ok"], "tracking_page_ok": patched["tracking_page_ok"],
						"sqli_neutralized": patched["sqli_neutralized"], "lfi_blocked": patched["lfi_blocked"],
					}
				}
			}
		}
	}
	if record != nil {
		return record
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "patch_meta.json")); err == nil {
		var meta map[string]any
		if json.Unmarshal(raw, &meta) == nil {
			if checks, ok := meta["checks"].(map[string]any); ok {
				if result := firstString(checks, "result"); result != "" {
					return &ValidationRecord{Result: result, Source: "recorded", Log: "patch_meta.json", Checks: checks}
				}
			}
		}
	}
	return nil
}

func readUpstream(dir string) *UpstreamBundle {
	upstreamDir := filepath.Join(dir, "upstream")
	entries, err := os.ReadDir(upstreamDir)
	if err != nil {
		return nil
	}
	bundle := &UpstreamBundle{Present: true}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		bundle.Files = append(bundle.Files, entry.Name())
		switch entry.Name() {
		case "advisory.md":
			bundle.Advisory = "upstream/advisory.md"
		case "repro.md":
			bundle.Repro = "upstream/repro.md"
		case "test-plan.md":
			bundle.TestPlan = "upstream/test-plan.md"
		case "pr-body.md":
			bundle.PRBody = "upstream/pr-body.md"
		}
	}
	sort.Strings(bundle.Files)
	if raw, err := os.ReadFile(filepath.Join(dir, "patch_meta.json")); err == nil {
		var meta map[string]any
		if json.Unmarshal(raw, &meta) == nil {
			if submitted, ok := meta["upstream_submitted"].(bool); ok {
				bundle.Submitted = submitted
			}
		}
	}
	return bundle
}

func parseFindingsFromRaw(raws []json.RawMessage) []FindingView {
	out := []FindingView{}
	for _, raw := range raws {
		var item map[string]any
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		view := FindingView{
			ID: firstString(item, "finding_id"), CVE: firstString(item, "cve"),
			Title: firstString(item, "title"), Severity: firstString(item, "severity"),
			Status: firstString(item, "status"),
		}
		if view.ID == "" {
			view.ID = firstString(item, "id")
		}
		if view.Title == "" {
			view.Title = view.ID
		}
		if proof, ok := item["runtime_proof"].(map[string]any); ok {
			view.RuntimeResult = firstString(proof, "result")
			if view.RuntimeResult == "" {
				if marker, ok := proof["marker_observed"].(bool); ok && marker {
					view.RuntimeResult = "VULNERABLE"
				}
			}
		}
		if evidence, ok := item["source_evidence"].([]any); ok {
			for _, entry := range evidence {
				value, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				view.SourceEvidence = append(view.SourceEvidence, SourceEvidenceView{
					File: firstString(value, "file"), Lines: firstString(value, "lines"),
					SHA256: firstString(value, "sha256"), Observation: firstString(value, "observation"),
				})
			}
		}
		out = append(out, view)
	}
	return out
}

func highestSeverity(findings []FindingView) string {
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	best := ""
	bestRank := 0
	for _, finding := range findings {
		value := strings.ToLower(finding.Severity)
		if rank[value] > bestRank {
			best, bestRank = value, rank[value]
		}
	}
	return best
}

func readTitle(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return ""
}

func readMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func firstString(value map[string]any, key string) string {
	if item, ok := value[key].(string); ok {
		return item
	}
	return ""
}

func nestedString(value map[string]any, key, nested string) string {
	if item, ok := value[key].(map[string]any); ok {
		return firstString(item, nested)
	}
	return ""
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func fileSHA256(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func relName(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

func latestModTime(dir string) time.Time {
	var latest time.Time
	_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if info, statErr := entry.Info(); statErr == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return latest
}

func patchFiles(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			name := strings.TrimPrefix(line, "+++ b/")
			if name != "" && name != "/dev/null" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
