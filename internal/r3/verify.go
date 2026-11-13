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

const SchemaVersion = 1

type VerifyOptions struct {
	SnapshotDir      string
	SnapshotHash     string
	Workspace        string
	PatchPath        string
	Profile          string
	MainClass        string
	TestClass        string
	TestClasses      []string
	TestClasspath    []string
	JUnitReportDir   string
	JacocoAgent      string
	JacocoReport     string
	Timeout          time.Duration
	ApproveExecution bool
	Sandbox          Sandbox
}

type Report struct {
	SchemaVersion          int               `json:"schema_version"`
	Status                 string            `json:"status"`
	SnapshotHash           string            `json:"snapshot_hash"`
	Workspace              WorkspaceInfo     `json:"workspace"`
	Patch                  PatchResult       `json:"patch"`
	Validation             *ValidationResult `json:"validation,omitempty"`
	Quality                QualityScore      `json:"quality"`
	OriginalSnapshotIntact bool              `json:"original_snapshot_intact"`
	RuntimeStatus          string            `json:"runtime_status"`
	Limitations            []string          `json:"limitations"`
	Error                  string            `json:"error,omitempty"`
}

type QualityScore struct {
	Score       int      `json:"score"`
	Grade       string   `json:"grade"`
	Dimensions  []string `json:"dimensions"`
	Limitations []string `json:"limitations"`
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
	report := Report{
		SchemaVersion: SchemaVersion, Status: "setup_failed", SnapshotHash: opts.SnapshotHash,
		RuntimeStatus: "isolated_validation_only", Limitations: limitations,
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
	if err != nil {
		report.Error = err.Error()
		report.OriginalSnapshotIntact = snapshotIntact(ctx, opts.SnapshotDir, opts.SnapshotHash)
		return report, err
	}
	validation, err := Validate(ctx, workspace.Path, ValidationOptions{
		Profile: opts.Profile, MainClass: opts.MainClass, TestClass: opts.TestClass,
		TestClasses: opts.TestClasses, TestClasspath: opts.TestClasspath,
		JUnitReportDir: opts.JUnitReportDir, JacocoAgent: opts.JacocoAgent, JacocoReport: opts.JacocoReport,
		Timeout: opts.Timeout, ApproveExecution: true,
		Sandbox: sandbox,
	})
	if err != nil {
		report.Status = ValidationError
		report.Error = err.Error()
		report.OriginalSnapshotIntact = snapshotIntact(ctx, opts.SnapshotDir, opts.SnapshotHash)
		return report, err
	}
	report.Validation = &validation
	report.Status = validation.Status
	report.Quality = scorePatch(validation, patchResult)
	report.OriginalSnapshotIntact = snapshotIntact(ctx, opts.SnapshotDir, opts.SnapshotHash)
	if !report.OriginalSnapshotIntact {
		report.Status = "snapshot_integrity_failed"
		report.Error = "pinned snapshot no longer matches the expected hash"
		return report, fmt.Errorf("pinned snapshot integrity failed after validation")
	}
	return report, nil
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
	tests := validation.TestSummary
	if validation.JUnitXML != nil {
		if tests == nil {
			tests = &TestRunSummary{}
		}
		tests.Tests += validation.JUnitXML.Tests
		tests.Failures += validation.JUnitXML.Failures
		tests.Errors += validation.JUnitXML.Errors
		tests.Skipped += validation.JUnitXML.Skipped
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
		Score: score, Grade: grade, Dimensions: dimensions,
		Limitations: []string{
			"quality_score_is_heuristic: it does not prove security, correctness or production safety",
			"no_mutation_or_differential_test_analysis",
			"single_validation_profile_only",
		},
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
