package r3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"trident/internal/project"
)

const (
	SchemaVersion        = 1
	QualityRubricVersion = "r3-quality-rubric-v2"
)

type VerifyOptions struct {
	SnapshotDir      string
	SnapshotHash     string
	Workspace        string
	PatchPath        string
	Profile          string
	Modules          []string
	MainClass        string
	TestClass        string
	TestClasses      []string
	TestClasspath    []string
	JUnitReportDir   string
	JacocoAgent      string
	JacocoReport     string
	Timeout          time.Duration
	ApproveExecution bool
	// KeepWorkspace preserves the writable copy after a hard failure. The
	// default removes it so repeated verification does not accumulate full
	// source trees; validation results are kept in the report either way.
	KeepWorkspace bool
	Sandbox       Sandbox
}

type Report struct {
	SchemaVersion          int               `json:"schema_version"`
	Status                 string            `json:"status"`
	SnapshotHash           string            `json:"snapshot_hash"`
	Workspace              WorkspaceInfo     `json:"workspace"`
	Patch                  PatchResult       `json:"patch"`
	Rollback               *RollbackPlan     `json:"rollback,omitempty"`
	Validation             *ValidationResult `json:"validation,omitempty"`
	Quality                QualityScore      `json:"quality"`
	OriginalSnapshotIntact bool              `json:"original_snapshot_intact"`
	RuntimeStatus          string            `json:"runtime_status"`
	Limitations            []string          `json:"limitations"`
	Error                  string            `json:"error,omitempty"`
}

// RollbackPlan contains manual instructions derived from the applied patch. It
// is never executed by trident and contains no shell command interpolation.
type RollbackPlan struct {
	SnapshotHash string         `json:"snapshot_hash"`
	Steps        []RollbackStep `json:"steps"`
	Note         string         `json:"note"`
}

type RollbackStep struct {
	Path         string `json:"path"`
	Action       string `json:"action"`
	SHA256Before string `json:"sha256_before,omitempty"`
	SHA256After  string `json:"sha256_after"`
}

type QualityScore struct {
	RubricVersion string   `json:"rubric_version"`
	Score         int      `json:"score"`
	Grade         string   `json:"grade"`
	Dimensions    []string `json:"dimensions"`
	Limitations   []string `json:"limitations"`
}

// Verify executes the bounded R3 slice: isolated copy, caller-supplied patch,
// fixed validation profile, and original snapshot re-verification.
func Verify(ctx context.Context, opts VerifyOptions) (Report, error) {
	sandbox, err := opts.Sandbox.normalized()
	if err != nil {
		return Report{}, err
	}
	limitations := []string{
		"isolated_directory_copy_not_os_sandbox: process isolation is not enforced by a container or VM",
		"caller_or_model_supplied_patch: patch provenance is not verified here; review every AI-generated diff",
		"validation_executes_untrusted_source: explicit --approve-execution is required",
		"maven_profile_offline: requires cached Maven plugins and artifacts; no network fetch is attempted",
		"runtime_validation_of_isolated_copy_only: passes or failures do not prove production exploitability",
		"network_isolation_not_enforced: the validation process is not network-namespaced",
		"original_snapshot_is_read_only: only the writable workspace copy is patched",
	}
	if sandbox.Kind == SandboxDocker {
		limitations[0] = "docker_container_isolation_not_vm: network-none and capability drop are container controls, not a VM or kernel boundary"
		limitations[5] = "network_isolation_container_only: validation containers use --network none; the host workspace bind mount remains visible"
		limitations = append(limitations, "docker_sandbox_image_pinned_by_digest: the caller-selected image is trusted to contain the expected JDK/Maven toolchain")
	}
	if sandbox.Kind == SandboxGVisor {
		limitations[0] = "gvisor_user_space_kernel_not_full_vm: runsc intercepts syscalls but is not a hardware VM boundary"
		limitations[5] = "network_isolation_container_only: gVisor validation uses --network none; the host workspace bind mount remains visible"
		limitations = append(limitations, "gvisor_requires_registered_runsc: validation fails closed when Docker does not expose the runsc runtime")
	}
	if opts.JacocoAgent != "" {
		limitations = append(limitations, "coverage_is_observation_only: JaCoCo line/branch counters do not prove that the vulnerability path or the fix is exercised")
	}
	if opts.Profile == "maven-compile" {
		limitations = append(limitations, "maven_compile_profile_compiles_only: no application entry point, tests or runtime behavior are executed")
	}
	if opts.Profile == "maven-test" {
		limitations = append(limitations, "maven_test_profile_runs_tests_only: Maven Surefire tests are executed, but no application entry point or HTTP request is run")
	}
	if opts.Profile == "gradle-test" {
		limitations = append(limitations,
			"gradle_test_profile_runs_tests_only: Gradle tests are executed, but no application entry point or HTTP request is run",
			"gradle_profile_offline: requires a pre-populated Gradle cache; no network fetch is attempted",
		)
	}
	if len(opts.Modules) > 0 {
		limitations = append(limitations, "module_selection_caller_supplied: validation runs only in the explicitly selected module directories")
	}
	report := Report{
		SchemaVersion: SchemaVersion, Status: "setup_failed", SnapshotHash: opts.SnapshotHash,
		RuntimeStatus: "not_run", Limitations: limitations,
	}
	if !opts.ApproveExecution {
		return report, fmt.Errorf("isolated execution requires explicit --approve-execution")
	}
	if opts.SnapshotDir == "" || opts.SnapshotHash == "" || opts.Workspace == "" || opts.PatchPath == "" {
		return report, fmt.Errorf("verify requires snapshot, snapshot hash, new workspace and patch")
	}
	snapshot, err := project.Open(ctx, opts.SnapshotDir, opts.SnapshotHash)
	if err != nil {
		return report, err
	}
	defer snapshot.Close()
	patchInfo, err := os.Lstat(opts.PatchPath)
	if err != nil || !patchInfo.Mode().IsRegular() {
		return report, fmt.Errorf("patch must be an existing regular file")
	}
	if patchInfo.Size() <= 0 || patchInfo.Size() > MaxPatchBytes {
		return report, fmt.Errorf("patch size outside supported bounds")
	}
	patch, err := os.ReadFile(opts.PatchPath)
	if err != nil {
		return report, err
	}
	sum := sha256.Sum256(patch)
	report.Patch = PatchResult{SHA256: hex.EncodeToString(sum[:]), Files: []FileChange{}}

	workspace, err := CreateWorkspace(ctx, snapshot, opts.SnapshotDir, opts.Workspace)
	if err != nil {
		return report, err
	}
	report.Workspace = workspace
	report.Status = "patch_failed"
	patchResult, err := Apply(workspace.Path, patch)
	report.Patch = patchResult
	report.Rollback = rollbackPlan(opts.SnapshotHash, patchResult)
	if err != nil {
		report.Error = err.Error()
		report.OriginalSnapshotIntact = snapshotIntact(ctx, opts.SnapshotDir, opts.SnapshotHash)
		discardFailedWorkspace(&report, opts)
		return report, err
	}
	validation, err := Validate(ctx, workspace.Path, ValidationOptions{
		Profile: opts.Profile, Modules: opts.Modules, MainClass: opts.MainClass, TestClass: opts.TestClass,
		TestClasses: opts.TestClasses, TestClasspath: opts.TestClasspath,
		JUnitReportDir: opts.JUnitReportDir, JacocoAgent: opts.JacocoAgent, JacocoReport: opts.JacocoReport,
		Timeout: opts.Timeout, ApproveExecution: true,
		Sandbox: sandbox,
	})
	if err != nil {
		report.Status = ValidationError
		report.Error = err.Error()
		if len(validation.Commands) > 0 {
			report.RuntimeStatus = "isolated_validation_only"
		}
		report.OriginalSnapshotIntact = snapshotIntact(ctx, opts.SnapshotDir, opts.SnapshotHash)
		discardFailedWorkspace(&report, opts)
		return report, err
	}
	report.Validation = &validation
	report.Status = validation.Status
	report.RuntimeStatus = "isolated_validation_only"
	report.Quality = scorePatch(validation, patchResult)
	report.OriginalSnapshotIntact = snapshotIntact(ctx, opts.SnapshotDir, opts.SnapshotHash)
	if !report.OriginalSnapshotIntact {
		report.Status = "snapshot_integrity_failed"
		report.Error = "pinned snapshot no longer matches the expected hash"
		discardFailedWorkspace(&report, opts)
		return report, fmt.Errorf("pinned snapshot integrity failed after validation")
	}
	return report, nil
}

// discardFailedWorkspace removes the writable copy after a hard failure. The
// report keeps the outcome; only the source tree is dropped. KeepWorkspace is
// the explicit escape hatch for inspecting a failed run.
func discardFailedWorkspace(report *Report, opts VerifyOptions) {
	if opts.KeepWorkspace || report.Workspace.Path == "" {
		return
	}
	if err := os.RemoveAll(report.Workspace.Path); err != nil {
		report.Limitations = append(report.Limitations, "failed_workspace_left_in_place: "+err.Error())
		return
	}
	report.Workspace = WorkspaceInfo{}
	report.Limitations = append(report.Limitations, "failed_workspace_removed: the isolated copy was deleted after the failure; pass keep-workspace to inspect it")
}

func scorePatch(validation ValidationResult, patch PatchResult) QualityScore {
	score := 0
	dimensions := []string{}
	switch validation.Status {
	case ValidationPassed:
		score += 50
		dimensions = append(dimensions, "validation_passed=50")
	case ValidationFailed:
		score += 10
		dimensions = append(dimensions, "validation_failed=10")
	default:
		dimensions = append(dimensions, "validation_not_passed=0")
	}
	var tests *TestRunSummary
	if validation.TestSummary != nil {
		copied := *validation.TestSummary
		tests = &copied
	} else if validation.JUnitXML != nil {
		tests = &TestRunSummary{
			Tests: validation.JUnitXML.Tests, Failures: validation.JUnitXML.Failures,
			Errors: validation.JUnitXML.Errors, Skipped: validation.JUnitXML.Skipped,
		}
	}
	if tests != nil && tests.Tests > 0 {
		if tests.Failures == 0 && tests.Errors == 0 {
			score += 20
			dimensions = append(dimensions, "tests_passed=20")
		} else {
			score += 5
			dimensions = append(dimensions, "tests_failed=5")
		}
	} else if validation.Status == ValidationPassed {
		score += 10
		dimensions = append(dimensions, "no_test_report=10")
	}
	additions, deletions := 0, 0
	for _, file := range patch.Files {
		additions += file.Additions
		deletions += file.Deletions
	}
	lines := additions + deletions
	switch {
	case lines <= 10:
		score += 15
		dimensions = append(dimensions, "patch_size_small=15")
	case lines <= 50:
		score += 10
		dimensions = append(dimensions, "patch_size_medium=10")
	case lines <= 200:
		score += 5
		dimensions = append(dimensions, "patch_size_large=5")
	default:
		dimensions = append(dimensions, "patch_size_very_large=0")
	}
	switch {
	case len(patch.Files) == 1:
		score += 10
		dimensions = append(dimensions, "single_file=10")
	case len(patch.Files) <= 3:
		score += 5
		dimensions = append(dimensions, "few_files=5")
	default:
		dimensions = append(dimensions, "many_files=0")
	}
	if tests != nil && tests.Tests > 0 && tests.Failures == 0 && tests.Errors == 0 && validation.Status == ValidationPassed {
		score += 5
		dimensions = append(dimensions, "regression_clean=5")
	}
	if score > 100 {
		score = 100
	}
	grade := "D"
	switch {
	case score >= 85:
		grade = "A"
	case score >= 70:
		grade = "B"
	case score >= 50:
		grade = "C"
	}
	return QualityScore{
		RubricVersion: QualityRubricVersion,
		Score:         score, Grade: grade, Dimensions: dimensions,
		Limitations: []string{
			"quality_score_is_heuristic: it does not prove security, correctness or production safety",
			"no_mutation_or_differential_test_analysis",
			"single_validation_profile_only",
		},
	}
}

// rollbackPlan records the per-file original hashes so a failed validation can
// be reverted by a human. Every step is descriptive; trident never runs it.
func rollbackPlan(snapshotHash string, patch PatchResult) *RollbackPlan {
	steps := make([]RollbackStep, 0, len(patch.Files))
	for _, file := range patch.Files {
		action := "restore_original"
		if file.SHA256Before == "" {
			action = "remove_created_file"
		}
		steps = append(steps, RollbackStep{
			Path: file.Path, Action: action,
			SHA256Before: file.SHA256Before, SHA256After: file.SHA256After,
		})
	}
	return &RollbackPlan{
		SnapshotHash: snapshotHash, Steps: steps,
		Note: "manual rollback instructions only: restore original files from the pinned snapshot or your VCS; trident does not execute rollback commands",
	}
}

func snapshotIntact(ctx context.Context, dir, expected string) bool {
	snapshot, err := project.Open(ctx, dir, expected)
	if err != nil {
		return false
	}
	_ = snapshot.Close()
	return true
}
