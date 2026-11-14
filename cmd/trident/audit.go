package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"trident/internal/audit"
	"trident/internal/authz"
	"trident/internal/cache"
	"trident/internal/project"
)

// runAudit extracts a bounded, annotation-level endpoint inventory from an
// existing trusted snapshot. It never compiles or runs Java and makes no taint
// or vulnerability claim.
func runAudit(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident audit <endpoints|dataflow|findings|authz|sarif|reachability|java-model> --snapshot <dir> --snapshot-hash <sha256>")
	}
	if args[0] == "dataflow" {
		return runDataflow(ctx, args[1:], out)
	}
	if args[0] == "findings" {
		return runFindings(ctx, args[1:], out)
	}
	if args[0] == "authz" {
		return runAuthz(ctx, args[1:], out)
	}
	if args[0] == "sarif" {
		return runSARIF(ctx, args[1:], out)
	}
	if args[0] == "reachability" {
		return runReachability(ctx, args[1:], out)
	}
	if args[0] == "java-model" {
		return runJavaModel(ctx, args[1:], out)
	}
	if args[0] != "endpoints" {
		return fmt.Errorf("unknown audit command %q", args[0])
	}
	flags := flag.NewFlagSet("audit endpoints", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, cacheDir string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&cacheDir, "cache-dir", "", "optional derived-index cache directory outside the snapshot")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("invalid audit arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit endpoints requires --snapshot and --snapshot-hash and no positional arguments")
	}
	if cacheDir != "" {
		if err := ensureSeparateTree(cacheDir, snapshotDir); err != nil {
			return err
		}
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	if cacheDir == "" {
		report, err := audit.Inspect(ctx, snapshot)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	store, err := cache.Open(cacheDir)
	if err != nil {
		return err
	}
	report, err := audit.InspectCached(ctx, snapshot, store)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

// ensureSeparateTree rejects cache locations inside the snapshot and snapshots
// inside the cache so a read-only input can never receive cache writes.
func ensureSeparateTree(cacheDir, snapshotDir string) error {
	cacheAbs, err := filepath.Abs(cacheDir)
	if err != nil {
		return err
	}
	snapshotAbs, err := filepath.Abs(snapshotDir)
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{cacheAbs, snapshotAbs}, {snapshotAbs, cacheAbs}} {
		relative, relErr := filepath.Rel(pair[1], pair[0])
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return fmt.Errorf("cache directory and snapshot must not overlap")
		}
	}
	return nil
}

func runAuthz(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit authz", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid audit authz arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit authz requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := authz.Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
