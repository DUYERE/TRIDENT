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
// trusted snapshot. `resolve` is the only subcommand that executes Maven, and
// it runs on a disposable copy with offline default and explicit approval.
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
	var snapshotDir, expectedHash, mavenRepo string
	var approveNetwork, approveMaven bool
	var timeoutSeconds int
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&mavenRepo, "maven-repo", "", "optional absolute local Maven repository")
	flags.BoolVar(&approveNetwork, "approve-network", false, "allow Maven to download missing artifacts/plugins")
	flags.BoolVar(&approveMaven, "approve-maven", false, "explicitly approve Maven execution on a disposable snapshot copy")
	flags.IntVar(&timeoutSeconds, "timeout-seconds", sca.DefaultResolveTimeoutS, "Maven resolution timeout (1..600)")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid sca resolve arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("sca resolve requires --snapshot and --snapshot-hash and no positional arguments")
	}
	if !approveMaven {
		return fmt.Errorf("sca resolve executes Maven; explicit --approve-maven is required")
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
	report, resolveErr := sca.ResolveEffectiveTree(ctx, snapshot, sca.ResolveOptions{
		AllowNetwork: approveNetwork, ApproveMaven: true, MavenRepo: mavenRepo,
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	})
	if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
		return encodeErr
	}
	return resolveErr
}
