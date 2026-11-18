// Package caseagent exposes the controlled write tools used by an explicitly
// approved Agent repair run. It wraps the read-only tools registry and never
// edits the pinned snapshot or a discovery Case directory.
package caseagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"trident/internal/casework"
	"trident/internal/model"
	"trident/internal/project"
	"trident/internal/r3"
	"trident/internal/tools"
)

const (
	DefaultMaxOutputTokens = 8192
	MaxExportBytes         = 16 << 20
	MaxPatchBytes          = r3.MaxPatchBytes
	maxToolArgumentBytes   = 4 << 10
	auditName              = "audit.jsonl"
)

var (
	ErrArguments  = errors.New("invalid repair tool arguments")
	ErrApproval   = errors.New("repair tool requires explicit approval")
	ErrWorkspace  = errors.New("repair workspace is unavailable or unsafe")
	ErrRepairCase = errors.New("repair case is unavailable")
)

type ProposeFunc func(context.Context, *project.Snapshot, r3.CompletionClient, r3.ProposeOptions) (r3.Proposal, error)

type VerifyFunc func(context.Context, r3.VerifyOptions) (r3.Report, error)

// Options binds one Run to one snapshot and one workspace. Approve must come
// from the server-side request decision; it is never derived from model output.
type Options struct {
	Base        *tools.Registry
	Snapshot    *project.Snapshot
	SnapshotDir string
	Workspace   string
	Catalog     *casework.Catalog
	Approve     bool
	Client      r3.CompletionClient
	Model       string
	MaxOutput   int64
	Propose     ProposeFunc
	Verify      VerifyFunc
	Now         func() time.Time
}

// Registry satisfies agent.ToolRegistry. The embedded read-only registry is
// still the only source for inspect/read/search/analysis tools.
type Registry struct {
	base        *tools.Registry
	snapshot    *project.Snapshot
	snapshotDir string
	workspace   string
	workRoot    string
	catalog     *casework.Catalog
	approve     bool
	client      r3.CompletionClient
	model       string
	maxOutput   int64
	propose     ProposeFunc
	verify      VerifyFunc
	now         func() time.Time
	auditMu     sync.Mutex
}

func New(opts Options) (*Registry, error) {
	if opts.Base == nil || opts.Snapshot == nil || opts.Catalog == nil {
		return nil, fmt.Errorf("%w: base registry, snapshot and case catalog are required", ErrWorkspace)
	}
	workspace, err := filepath.Abs(opts.Workspace)
	if err != nil || strings.TrimSpace(opts.Workspace) == "" {
		return nil, fmt.Errorf("%w: an absolute workspace is required", ErrWorkspace)
	}
	snapshotDir, err := filepath.Abs(opts.SnapshotDir)
	if err != nil || strings.TrimSpace(opts.SnapshotDir) == "" {
		return nil, fmt.Errorf("%w: an absolute snapshot directory is required", ErrWorkspace)
	}
	workRoot := filepath.Join(workspace, "repairs")
	if pathInside(workRoot, snapshotDir) || pathInside(snapshotDir, workRoot) {
		return nil, fmt.Errorf("%w: repair workspace must be outside the pinned snapshot", ErrWorkspace)
	}
	maxOutput := opts.MaxOutput
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutputTokens
	}
	if maxOutput > 16384 {
		return nil, fmt.Errorf("%w: output token bound is invalid", ErrArguments)
	}
	propose := opts.Propose
	if propose == nil {
		propose = r3.Propose
	}
	verify := opts.Verify
	if verify == nil {
		verify = r3.Verify
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Registry{
		base: opts.Base, snapshot: opts.Snapshot, snapshotDir: snapshotDir,
		workspace: workspace, workRoot: workRoot, catalog: opts.Catalog,
		approve: opts.Approve, client: opts.Client, model: opts.Model,
		maxOutput: maxOutput, propose: propose, verify: verify, now: now,
	}, nil
}

func (r *Registry) SnapshotHash() string {
	if r == nil || r.base == nil {
		return ""
	}
	return r.base.SnapshotHash()
}

// Definitions exposes write tools only when the server-side approval is present.
// Execute performs a second check so a malformed caller cannot bypass it.
func (r *Registry) Definitions() []model.Tool {
	if r == nil || r.base == nil {
		return nil
	}
	defs := append([]model.Tool(nil), r.base.Definitions()...)
	if r.approve {
		defs = append(defs, repairDefinitions...)
	}
	return defs
}

func (r *Registry) Execute(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	if r == nil || r.base == nil {
		return nil, fmt.Errorf("repair registry is unavailable")
	}
	switch name {
	case "propose_patch", "verify_patch", "export_case":
		if !r.approve {
			return marshalResult(map[string]any{
				"status": "approval_required", "tool": name,
				"message": "this Repair Run was not approved for Case work-copy writes; report approval_required and do not claim a fix",
			})
		}
		if ctx == nil {
			return nil, fmt.Errorf("nil tool context")
		}
		switch name {
		case "propose_patch":
			return r.proposePatch(ctx, arguments)
		case "verify_patch":
			return r.verifyPatch(ctx, arguments)
		default:
			return r.exportCase(arguments)
		}
	default:
		return r.base.Execute(ctx, name, arguments)
	}
}

type repairArguments struct {
	CaseID    string `json:"case_id"`
	Goal      string `json:"goal,omitempty"`
	PatchPath string `json:"patch_path,omitempty"`
}

func decodeArguments(raw json.RawMessage) (repairArguments, error) {
	var args repairArguments
	trimmed := bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxToolArgumentBytes || !utf8.Valid(raw) || len(trimmed) == 0 || trimmed[0] != '{' {
		return args, fmt.Errorf("%w: bounded JSON object required", ErrArguments)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&args); err != nil {
		return args, fmt.Errorf("%w: invalid JSON", ErrArguments)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return args, fmt.Errorf("%w: trailing JSON", ErrArguments)
	}
	if args.CaseID == "" || len(args.CaseID) > 128 || strings.ContainsAny(args.CaseID, "\r\n\x00") {
		return args, fmt.Errorf("%w: case_id is required", ErrArguments)
	}
	if len(args.Goal) > 2048 || strings.ContainsAny(args.Goal, "\x00\r") {
		return args, fmt.Errorf("%w: goal must be bounded text", ErrArguments)
	}
	if len(args.PatchPath) > 4096 || strings.ContainsAny(args.PatchPath, "\r\n\x00") {
		return args, fmt.Errorf("%w: patch_path is invalid", ErrArguments)
	}
	return args, nil
}

func (r *Registry) caseDetail(id string) (casework.CaseDetail, error) {
	detail, err := r.catalog.Get(id)
	if err != nil {
		return casework.CaseDetail{}, fmt.Errorf("%w: %v", ErrRepairCase, err)
	}
	if detail.ID == "" || detail.ID != id {
		return casework.CaseDetail{}, fmt.Errorf("%w: case identity mismatch", ErrRepairCase)
	}
	return detail, nil
}

func (r *Registry) proposePatch(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	args, err := decodeArguments(raw)
	if err != nil {
		return marshalResult(map[string]any{"status": "invalid_arguments", "tool": "propose_patch", "message": err.Error()})
	}
	detail, err := r.caseDetail(args.CaseID)
	if err != nil {
		return marshalResult(map[string]any{"status": "case_unavailable", "tool": "propose_patch", "case_id": args.CaseID, "message": err.Error()})
	}
	paths, omitted := r.sourceWindows(detail)
	if len(paths) == 0 {
		return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "source_not_in_snapshot"},
			map[string]any{
				"status": "source_not_in_snapshot", "tool": "propose_patch", "case_id": detail.ID,
				"message":       "the Case source paths are not present in this Run's pinned snapshot; select or import the matching project snapshot",
				"omitted_paths": omitted,
			})
	}
	if r.client == nil {
		return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "model_unavailable"},
			map[string]any{"status": "model_unavailable", "tool": "propose_patch", "case_id": detail.ID,
				"message": "the configured model client is unavailable; no patch was written"})
	}
	goal := strings.TrimSpace(args.Goal)
	if goal == "" {
		goal = fmt.Sprintf("Fix the vulnerability described by Case %s. Produce one minimal unified diff using only the supplied source context; do not modify tests, generated files or unrelated code. Keep the diff under 40 changed lines and at most 2 files; do not rewrite whole files.", detail.ID)
	}
	proposal, err := r.propose(ctx, r.snapshot, r.client, r3.ProposeOptions{
		Windows: paths, Goal: goal, Model: r.model, MaxOutputTokens: r.maxOutput,
	})
	if err != nil {
		return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "proposal_failed", Error: boundedError(err)},
			map[string]any{"status": "proposal_failed", "tool": "propose_patch", "case_id": detail.ID,
				"message": boundedError(err), "omitted_paths": omitted})
	}
	if strings.TrimSpace(proposal.Patch) == "" || !utf8.ValidString(proposal.Patch) || len(proposal.Patch) > MaxPatchBytes {
		return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "proposal_failed", Error: "empty or oversized patch"},
			map[string]any{"status": "proposal_failed", "tool": "propose_patch", "case_id": detail.ID,
				"message": "model returned an empty or oversized patch; no patch was written"})
	}
	reason := proposal.PatchSHA256
	if reason == "" {
		reason = patchDigest([]byte(proposal.Patch))
	}
	nonce, err := r.nonce()
	if err != nil {
		return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "write_failed", Error: err.Error()},
			map[string]any{"status": "write_failed", "tool": "propose_patch", "case_id": detail.ID, "message": err.Error()})
	}
	dir := filepath.Join(r.workRoot, detail.ID, "proposals", nonce)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "write_failed", Error: err.Error()},
			map[string]any{"status": "write_failed", "tool": "propose_patch", "case_id": detail.ID, "message": "create proposal directory failed"})
	}
	patchPath := filepath.Join(dir, "patch.diff")
	if err := writeNewFile(patchPath, []byte(proposal.Patch), 0o600); err != nil {
		return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "write_failed", Error: err.Error()},
			map[string]any{"status": "write_failed", "tool": "propose_patch", "case_id": detail.ID, "message": "write patch failed"})
	}
	result := map[string]any{
		"status": "patch_proposed", "tool": "propose_patch", "case_id": detail.ID,
		"patch_path": patchPath, "patch_sha256": reason, "patch_bytes": len(proposal.Patch),
		"files": proposal.Files, "rationale": proposal.Rationale,
		"limitations": proposal.Limitations, "omitted_paths": omitted,
		"claim": "patch_written_to_case_work_copy_only",
	}
	return r.finish(repairAudit{Tool: "propose_patch", CaseID: detail.ID, Status: "patch_proposed",
		Artifact: relativeArtifact(r.workspace, patchPath), PatchSHA256: reason}, result)
}

func (r *Registry) verifyPatch(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	args, err := decodeArguments(raw)
	if err != nil {
		return marshalResult(map[string]any{"status": "invalid_arguments", "tool": "verify_patch", "message": err.Error()})
	}
	detail, err := r.caseDetail(args.CaseID)
	if err != nil {
		return marshalResult(map[string]any{"status": "case_unavailable", "tool": "verify_patch", "case_id": args.CaseID, "message": err.Error()})
	}
	patchPath, err := r.patchForCase(detail.ID, args.PatchPath)
	if err != nil {
		return r.finish(repairAudit{Tool: "verify_patch", CaseID: detail.ID, Status: "invalid_patch_path", Error: err.Error()},
			map[string]any{"status": "invalid_patch_path", "tool": "verify_patch", "case_id": detail.ID, "message": err.Error()})
	}
	sum, size, err := fileDigest(patchPath)
	if err != nil {
		return r.finish(repairAudit{Tool: "verify_patch", CaseID: detail.ID, Status: "patch_unreadable", Error: err.Error()},
			map[string]any{"status": "patch_unreadable", "tool": "verify_patch", "case_id": detail.ID, "message": err.Error()})
	}
	if size <= 0 || size > MaxPatchBytes {
		return r.finish(repairAudit{Tool: "verify_patch", CaseID: detail.ID, Status: "patch_unreadable", Error: "patch size outside bounds"},
			map[string]any{"status": "patch_unreadable", "tool": "verify_patch", "case_id": detail.ID, "message": "patch size outside supported bounds"})
	}
	profile, err := profileForPatch(patchPath)
	if err != nil {
		return r.finish(repairAudit{Tool: "verify_patch", CaseID: detail.ID, Status: "profile_unavailable", Error: err.Error()},
			map[string]any{"status": "profile_unavailable", "tool": "verify_patch", "case_id": detail.ID, "message": err.Error()})
	}
	nonce, err := r.nonce()
	if err != nil {
		return r.finish(repairAudit{Tool: "verify_patch", CaseID: detail.ID, Status: "setup_failed", Error: err.Error()},
			map[string]any{"status": "setup_failed", "tool": "verify_patch", "case_id": detail.ID, "message": err.Error()})
	}
	verifyRoot := filepath.Join(r.workRoot, detail.ID, "verify", nonce)
	workspace := filepath.Join(verifyRoot, "workspace")
	if err := os.MkdirAll(verifyRoot, 0o700); err != nil {
		return r.finish(repairAudit{Tool: "verify_patch", CaseID: detail.ID, Status: "setup_failed", Error: err.Error()},
			map[string]any{"status": "setup_failed", "tool": "verify_patch", "case_id": detail.ID, "message": "create verify directory failed"})
	}
	report, verifyErr := r.verify(ctx, r3.VerifyOptions{
		SnapshotDir: r.snapshotDir, SnapshotHash: r.snapshot.Hash(), Workspace: workspace,
		PatchPath: patchPath, Profile: profile, ApproveExecution: true,
	})
	reportPath := filepath.Join(verifyRoot, "report.json")
	reportBytes, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr == nil && writeNewFile(reportPath, append(reportBytes, '\n'), 0o600) != nil {
		marshalErr = fmt.Errorf("write verification report failed")
	}
	status := report.Status
	if status == "" {
		status = "setup_failed"
	}
	if verifyErr != nil && status == "" {
		status = "setup_failed"
	}
	result := map[string]any{
		"status": status, "tool": "verify_patch", "case_id": detail.ID,
		"profile": profile, "patch_path": patchPath, "patch_sha256": sum,
		"report_path": reportPath, "runtime_status": report.RuntimeStatus,
		"original_snapshot_intact": report.OriginalSnapshotIntact,
		"limitations":              report.Limitations,
		"claim":                    "isolated_profile_result_only; this does not prove the vulnerability is fixed",
	}
	if verifyErr != nil {
		result["message"] = boundedError(verifyErr)
	}
	if marshalErr != nil {
		result["report_write_error"] = marshalErr.Error()
	}
	audit := repairAudit{Tool: "verify_patch", CaseID: detail.ID, Status: status,
		Artifact: relativeArtifact(r.workspace, reportPath), PatchSHA256: sum}
	if verifyErr != nil {
		audit.Error = boundedError(verifyErr)
	}
	return r.finish(audit, result)
}

func (r *Registry) exportCase(raw json.RawMessage) (json.RawMessage, error) {
	args, err := decodeArguments(raw)
	if err != nil {
		return marshalResult(map[string]any{"status": "invalid_arguments", "tool": "export_case", "message": err.Error()})
	}
	detail, err := r.caseDetail(args.CaseID)
	if err != nil {
		return marshalResult(map[string]any{"status": "case_unavailable", "tool": "export_case", "case_id": args.CaseID, "message": err.Error()})
	}
	var patchText, patchSource string
	if latest, err := r.latestPatch(detail.ID); err == nil {
		if raw, readErr := os.ReadFile(latest); readErr == nil {
			patchText, patchSource = string(raw), "case_work_copy"
		}
	}
	if patchText == "" && detail.Patch != nil && detail.Patch.File != "" {
		if raw, readErr := r.catalog.ReadFile(detail.ID, detail.Patch.File); readErr == nil {
			patchText, patchSource = raw, "case_artifact"
		}
	}
	upstream := map[string]string{}
	if detail.Upstream != nil {
		for _, name := range detail.Upstream.Files {
			if len(upstream) >= 32 {
				break
			}
			if raw, readErr := r.catalog.ReadFile(detail.ID, name); readErr == nil {
				upstream[name] = raw
			}
		}
	}
	payload := map[string]any{
		"schema_version": 1, "generated_at": r.now().UTC().Format(time.RFC3339),
		"case": detail, "patch_source": patchSource, "patch": patchText,
		"upstream_files": upstream,
		"claim":          "local Case export only; no upstream submission was made",
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return r.finish(repairAudit{Tool: "export_case", CaseID: detail.ID, Status: "write_failed", Error: err.Error()},
			map[string]any{"status": "write_failed", "tool": "export_case", "case_id": detail.ID, "message": err.Error()})
	}
	fileBytes := make([]byte, len(encoded)+1)
	copy(fileBytes, encoded)
	fileBytes[len(encoded)] = '\n'
	if len(fileBytes) > MaxExportBytes {
		return r.finish(repairAudit{Tool: "export_case", CaseID: detail.ID, Status: "export_too_large"},
			map[string]any{"status": "export_too_large", "tool": "export_case", "case_id": detail.ID,
				"message": "export exceeded the 16 MiB local bound; no file was written"})
	}
	nonce, err := r.nonce()
	if err != nil {
		return r.finish(repairAudit{Tool: "export_case", CaseID: detail.ID, Status: "write_failed", Error: err.Error()},
			map[string]any{"status": "write_failed", "tool": "export_case", "case_id": detail.ID, "message": err.Error()})
	}
	dir := filepath.Join(r.workRoot, detail.ID, "exports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return r.finish(repairAudit{Tool: "export_case", CaseID: detail.ID, Status: "write_failed", Error: err.Error()},
			map[string]any{"status": "write_failed", "tool": "export_case", "case_id": detail.ID, "message": "create export directory failed"})
	}
	exportPath := filepath.Join(dir, "case-"+nonce+".json")
	if err := writeNewFile(exportPath, fileBytes, 0o600); err != nil {
		return r.finish(repairAudit{Tool: "export_case", CaseID: detail.ID, Status: "write_failed", Error: err.Error()},
			map[string]any{"status": "write_failed", "tool": "export_case", "case_id": detail.ID, "message": "write export failed"})
	}
	exportSum := patchDigest(fileBytes)
	patchSum := patchDigest([]byte(patchText))
	result := map[string]any{
		"status": "case_exported", "tool": "export_case", "case_id": detail.ID,
		"export_path": exportPath, "export_sha256": exportSum, "export_bytes": len(fileBytes),
		"patch_sha256": patchSum, "patch_source": patchSource, "upstream_files": len(upstream),
		"claim": "local Case export only; no upstream submission was made",
	}
	return r.finish(repairAudit{Tool: "export_case", CaseID: detail.ID, Status: "case_exported",
		Artifact: relativeArtifact(r.workspace, exportPath), PatchSHA256: patchSum}, result)
}

func (r *Registry) finish(audit repairAudit, result map[string]any) (json.RawMessage, error) {
	if err := r.appendAudit(audit); err != nil {
		// The write already happened; keep the structured status but expose the
		// audit failure so it cannot be mistaken for a clean repair event.
		result["audit_error"] = boundedError(err)
	}
	return marshalResult(result)
}

func (r *Registry) caseRoot(caseID string) string {
	return filepath.Join(r.workRoot, caseID)
}

func (r *Registry) patchForCase(caseID, supplied string) (string, error) {
	root := r.caseRoot(caseID)
	if supplied == "" {
		return r.latestPatch(caseID)
	}
	pathValue := supplied
	if !filepath.IsAbs(pathValue) {
		pathValue = filepath.Join(root, pathValue)
	}
	abs, err := filepath.Abs(pathValue)
	if err != nil || !pathInside(abs, root) {
		return "", fmt.Errorf("patch_path must stay inside this Case work copy")
	}
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("patch_path must be an existing regular file")
	}
	if info.Size() <= 0 || info.Size() > MaxPatchBytes {
		return "", fmt.Errorf("patch size outside supported bounds")
	}
	return abs, nil
}

func (r *Registry) latestPatch(caseID string) (string, error) {
	root := filepath.Join(r.caseRoot(caseID), "proposals")
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("no work-copy proposal exists for this Case")
	}
	var candidates []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pathValue := filepath.Join(root, entry.Name(), "patch.diff")
		if info, statErr := os.Stat(pathValue); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
			candidates = append(candidates, pathValue)
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no work-copy proposal exists for this Case")
	}
	sort.Strings(candidates)
	return candidates[len(candidates)-1], nil
}

func (r *Registry) appendAudit(event repairAudit) error {
	if err := os.MkdirAll(r.workRoot, 0o700); err != nil {
		return err
	}
	event.Time = r.now().UTC().Format(time.RFC3339Nano)
	event.Approval = r.approve
	if event.Error != "" {
		event.Error = boundedError(errors.New(event.Error))
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	r.auditMu.Lock()
	defer r.auditMu.Unlock()
	f, err := os.OpenFile(filepath.Join(r.workRoot, auditName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(encoded, '\n'))
	return err
}

type repairAudit struct {
	Time        string `json:"time"`
	Tool        string `json:"tool"`
	CaseID      string `json:"case_id"`
	Approval    bool   `json:"approval"`
	Status      string `json:"status"`
	Artifact    string `json:"artifact,omitempty"`
	PatchSHA256 string `json:"patch_sha256,omitempty"`
	Error       string `json:"error,omitempty"`
}

var repairDefinitions = []model.Tool{
	{
		Name:        "propose_patch",
		Description: "Generate one bounded unified diff for a Case in this approved Repair Run. Writes only a new patch inside <workspace>/repairs/<case>/proposals/. Does not edit the pinned snapshot. Requires server approval; model arguments cannot grant it.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"case_id":{"type":"string","minLength":1,"maxLength":128,"description":"Case identifier from the Case catalog"},"goal":{"type":"string","maxLength":2048,"description":"Optional bounded repair goal; omitted uses the Case description"}},"required":["case_id"],"additionalProperties":false}`),
	},
	{
		Name:        "verify_patch",
		Description: "Apply one work-copy patch in an isolated snapshot copy and run the fixed validation profile. A validation_passed result proves only that profile, not that the vulnerability is fixed. Requires server approval.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"case_id":{"type":"string","minLength":1,"maxLength":128,"description":"Case identifier from the Case catalog"},"patch_path":{"type":"string","maxLength":4096,"description":"Optional patch path inside this Case work copy; omitted selects the latest proposal"}},"required":["case_id"],"additionalProperties":false}`),
	},
	{
		Name:        "export_case",
		Description: "Write a new local JSON export containing the Case, latest work-copy patch and upstream files. Never overwrites an existing artifact and never submits upstream. Requires server approval.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"case_id":{"type":"string","minLength":1,"maxLength":128,"description":"Case identifier from the Case catalog"}},"required":["case_id"],"additionalProperties":false}`),
	},
}

func marshalResult(value map[string]any) (json.RawMessage, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

func pathInside(child, parent string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func relativeArtifact(workspace, pathValue string) string {
	rel, err := filepath.Rel(workspace, pathValue)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

func patchDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func fileDigest(pathValue string) (string, int64, error) {
	info, err := os.Stat(pathValue)
	if err != nil || !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("patch must be an existing regular file")
	}
	raw, err := os.ReadFile(pathValue)
	if err != nil {
		return "", 0, err
	}
	return patchDigest(raw), int64(len(raw)), nil
}

func (r *Registry) nonce() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return r.now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(b[:]), nil
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := []rune(strings.ReplaceAll(err.Error(), "\n", " "))
	if len(value) > 512 {
		value = value[:512]
	}
	return string(value)
}

func profileForPatch(pathValue string) (string, error) {
	raw, err := os.ReadFile(pathValue)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxPatchBytes || !utf8.Valid(raw) {
		return "", fmt.Errorf("patch must be bounded UTF-8 text")
	}
	extensionSet := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- ") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name := strings.TrimPrefix(strings.TrimPrefix(fields[1], "b/"), "a/")
			if name == "/dev/null" {
				continue
			}
			extensionSet[strings.ToLower(filepath.Ext(name))] = true
		}
	}
	switch {
	case extensionSet[".php"]:
		return "php-lint", nil
	case extensionSet[".go"]:
		return "go-test", nil
	case extensionSet[".js"], extensionSet[".ts"]:
		return "node-check", nil
	case extensionSet[".py"]:
		return "python-compile", nil
	case extensionSet[".java"]:
		return "maven-compile", nil
	case extensionSet[".cs"]:
		return "dotnet-build", nil
	default:
		return "", fmt.Errorf("no fixed validation profile for the changed file types")
	}
}

// Ensure the compiler checks the narrow registry contract in this package too.
var _ interface {
	SnapshotHash() string
	Definitions() []model.Tool
	Execute(context.Context, string, json.RawMessage) (json.RawMessage, error)
} = (*Registry)(nil)
