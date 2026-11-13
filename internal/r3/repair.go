package r3

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"trident/internal/project"
)

const (
	MaxRepairRounds = 5
	RepairSchema    = 1
)

type RepairOptions struct {
	Snapshot      *project.Snapshot
	SnapshotDir   string
	WorkspaceRoot string
	Propose       ProposeOptions
	Verify        VerifyOptions
	MaxRounds     int
	Client        CompletionClient
}

type RepairRound struct {
	Round         int           `json:"round"`
	Status        string        `json:"status"`
	PatchSHA256   string        `json:"patch_sha256,omitempty"`
	Patch         string        `json:"patch,omitempty"`
	Rationale     string        `json:"rationale,omitempty"`
	ProposalError string        `json:"proposal_error,omitempty"`
	VerifyError   string        `json:"verify_error,omitempty"`
	Validation    *Report       `json:"validation,omitempty"`
	Quality       *QualityScore `json:"quality,omitempty"`
}

type RepairReport struct {
	SchemaVersion int           `json:"schema_version"`
	SnapshotHash  string        `json:"snapshot_hash"`
	Rounds        []RepairRound `json:"rounds"`
	FinalStatus   string        `json:"final_status"`
	RuntimeStatus string        `json:"runtime_status"`
	Limitations   []string      `json:"limitations"`
}

// Repair runs at most MaxRounds propose→isolated-verify cycles. It never writes
// the pinned snapshot, never retries a failed model call, and stops as soon as
// the caller's validation profile passes or a patch repeats.
func Repair(ctx context.Context, opts RepairOptions) (RepairReport, error) {
	report := RepairReport{
		SchemaVersion: RepairSchema,
		FinalStatus:   "setup_failed",
		RuntimeStatus: "not_run",
		Rounds:        []RepairRound{},
		Limitations: []string{
			"repair_is_bounded_and_iterative: each round creates a fresh writable copy of the pinned snapshot",
			"no_semantic_equivalence_proof: passing one offline validation profile does not prove the fix is complete or production-safe",
			"model_failures_are_not_retried: a proposal error stops the repair loop",
			"runtime_status_not_run: no deployed target or runtime exploit test is executed",
		},
	}
	if opts.Snapshot == nil || opts.Snapshot.Hash() == "" {
		return report, fmt.Errorf("repair requires a pinned snapshot")
	}
	report.SnapshotHash = opts.Snapshot.Hash()
	if opts.Client == nil {
		return report, fmt.Errorf("repair requires a model client")
	}
	if opts.MaxRounds < 1 || opts.MaxRounds > MaxRepairRounds {
		return report, fmt.Errorf("repair rounds must be between 1 and %d", MaxRepairRounds)
	}
	if opts.SnapshotDir == "" || opts.WorkspaceRoot == "" {
		return report, fmt.Errorf("repair requires snapshot directory and workspace root")
	}
	root, err := filepath.Abs(opts.WorkspaceRoot)
	if err != nil {
		return report, err
	}
	if info, statErr := os.Stat(root); statErr != nil || !info.IsDir() {
		return report, fmt.Errorf("repair workspace root must be an existing directory")
	}
	snapshotAbs, err := filepath.Abs(opts.SnapshotDir)
	if err != nil {
		return report, err
	}
	if insideSnapshotPath(snapshotAbs, root) {
		return report, fmt.Errorf("repair workspace root must be outside the snapshot")
	}
	for round := 1; round <= opts.MaxRounds; round++ {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		item := RepairRound{Round: round, Status: "proposal_failed"}
		proposal, proposeErr := Propose(ctx, opts.Snapshot, opts.Client, opts.Propose)
		if proposeErr != nil {
			item.ProposalError = proposeErr.Error()
			report.Rounds = append(report.Rounds, item)
			report.FinalStatus = "proposal_failed"
			return report, nil
		}
		item.PatchSHA256 = proposal.PatchSHA256
		item.Patch = proposal.Patch
		item.Rationale = proposal.Rationale
		for _, previous := range report.Rounds {
			if previous.PatchSHA256 == proposal.PatchSHA256 {
				item.Status = "duplicate_patch"
				report.Rounds = append(report.Rounds, item)
				report.FinalStatus = "duplicate_patch"
				return report, nil
			}
		}
		patchDir, tempErr := os.MkdirTemp("", "trident-repair-patch-")
		if tempErr != nil {
			return report, tempErr
		}
		patchPath := filepath.Join(patchDir, fmt.Sprintf("round-%d.patch", round))
		writeErr := os.WriteFile(patchPath, []byte(proposal.Patch), 0o600)
		if writeErr != nil {
			_ = os.RemoveAll(patchDir)
			return report, writeErr
		}
		verify := opts.Verify
		verify.SnapshotDir = opts.SnapshotDir
		verify.SnapshotHash = opts.Snapshot.Hash()
		verify.PatchPath = patchPath
		verify.Workspace = filepath.Join(root, fmt.Sprintf("round-%d", round))
		verify.ApproveExecution = true
		validation, verifyErr := Verify(ctx, verify)
		_ = os.RemoveAll(patchDir)
		item.Validation = &validation
		item.Quality = &validation.Quality
		item.Status = validation.Status
		if verifyErr != nil {
			item.VerifyError = verifyErr.Error()
		}
		report.Rounds = append(report.Rounds, item)
		switch validation.Status {
		case ValidationPassed:
			report.FinalStatus = ValidationPassed
			report.RuntimeStatus = "isolated_validation_only"
			return report, nil
		case ValidationTimeout, ValidationError, "setup_failed", "snapshot_integrity_failed":
			report.FinalStatus = validation.Status
			return report, nil
		}
	}
	report.FinalStatus = ValidationFailed
	return report, nil
}

func insideSnapshotPath(snapshot, target string) bool {
	relative, err := filepath.Rel(snapshot, target)
	if err != nil {
		return false
	}
	return relative == "." || (!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && relative != "..")
}
