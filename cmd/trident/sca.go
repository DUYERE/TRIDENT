package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"trident/internal/project"
	"trident/internal/sbom"
	"trident/internal/sca"
)

// runSCA performs declaration-level Maven/Gradle analysis on an existing
// trusted snapshot. `resolve` is the only subcommand that executes a build
// tool, and it runs on a disposable copy with offline default and explicit
// per-tool approval.
func runSCA(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident sca <inspect|sbom|tree|resolve> --snapshot <dir> --snapshot-hash <sha256> [--advisories <file>]")
	}
	command := args[0]
	if command != "inspect" && command != "sbom" && command != "tree" && command != "resolve" {
		return fmt.Errorf("unknown sca command %q", command)
	}
	if command == "resolve" {
		return runSCAResolve(ctx, args[1:], out)
	}
	flags := flag.NewFlagSet("sca "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, advisoryPath string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&advisoryPath, "advisories", "", "explicit local advisory JSON file; never read from the snapshot implicitly")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("invalid sca arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("sca %s requires --snapshot and --snapshot-hash and no positional arguments", command)
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := sca.Inspect(ctx, snapshot, sca.Options{AdvisoryPath: advisoryPath})
	if err != nil {
		return err
	}
	if command == "inspect" {
		return json.NewEncoder(out).Encode(report)
	}
	if command == "tree" {
		return json.NewEncoder(out).Encode(sca.Tree(report))
	}
	document, err := sbom.Build(report, sbom.Options{SnapshotHash: snapshot.Hash(), ToolVersion: sbom.ToolVersion, Partial: report.Partial})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(document)
}

func runSCAResolve(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("sca resolve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, mavenRepo, tool, gradlePath, gradleUserHome, gradleInitScript string
	var approveNetwork, approveMaven, approveGradle bool
	var timeoutSeconds int
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&tool, "tool", "maven", "dependency resolver: maven or gradle")
	flags.StringVar(&mavenRepo, "maven-repo", "", "optional absolute local Maven repository")
	flags.StringVar(&gradlePath, "gradle", "", "optional absolute path to the Gradle executable")
	flags.StringVar(&gradleUserHome, "gradle-user-home", "", "optional absolute Gradle user home")
	flags.StringVar(&gradleInitScript, "gradle-init-script", "", "optional absolute Gradle init script")
	flags.BoolVar(&approveNetwork, "approve-network", false, "allow the build tool to download missing artifacts")
	flags.BoolVar(&approveMaven, "approve-maven", false, "explicitly approve Maven execution on a disposable snapshot copy")
	flags.BoolVar(&approveGradle, "approve-gradle", false, "explicitly approve Gradle execution on a disposable snapshot copy")
	flags.IntVar(&timeoutSeconds, "timeout-seconds", sca.DefaultResolveTimeoutS, "dependency resolution timeout (1..600)")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid sca resolve arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("sca resolve requires --snapshot and --snapshot-hash and no positional arguments")
	}
	if tool != "maven" && tool != "gradle" {
		return fmt.Errorf("--tool must be maven or gradle")
	}
	if tool == "maven" {
		if !approveMaven {
			return fmt.Errorf("sca resolve --tool maven executes Maven; explicit --approve-maven is required")
		}
		if gradlePath != "" || gradleUserHome != "" || gradleInitScript != "" || approveGradle {
			return fmt.Errorf("Gradle options require --tool gradle")
		}
	} else {
		if !approveGradle {
			return fmt.Errorf("sca resolve --tool gradle executes Gradle; explicit --approve-gradle is required")
		}
		if mavenRepo != "" || approveMaven {
			return fmt.Errorf("Maven options require --tool maven")
		}
	}
	if timeoutSeconds < 1 || timeoutSeconds > sca.MaxResolveTimeoutS {
		return fmt.Errorf("timeout-seconds must be between 1 and %d", sca.MaxResolveTimeoutS)
	}
	absoluteSnapshot, err := filepath.Abs(snapshotDir)
	if err != nil {
		return err
	}
	snapshot, err := project.Open(ctx, absoluteSnapshot, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	options := sca.ResolveOptions{
		AllowNetwork:     approveNetwork,
		ApproveMaven:     approveMaven,
		ApproveGradle:    approveGradle,
		MavenRepo:        mavenRepo,
		GradlePath:       gradlePath,
		GradleUserHome:   gradleUserHome,
		GradleInitScript: gradleInitScript,
		Timeout:          time.Duration(timeoutSeconds) * time.Second,
	}
	var report sca.ResolveReport
	var resolveErr error
	if tool == "gradle" {
		report, resolveErr = sca.ResolveGradleEffectiveTree(ctx, snapshot, options)
	} else {
		report, resolveErr = sca.ResolveEffectiveTree(ctx, snapshot, options)
	}
	if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
		return encodeErr
	}
	return resolveErr
}
