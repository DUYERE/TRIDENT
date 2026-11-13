package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/project"
	"trident/internal/sbom"
	"trident/internal/sca"
)

// runSCA performs offline, declaration-level Maven analysis on an existing
// trusted snapshot. It never executes Maven, resolves artifacts or writes to
// the snapshot; an advisory catalog must be an explicit local file.
func runSCA(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident sca <inspect|sbom|tree> --snapshot <dir> --snapshot-hash <sha256> [--advisories <file>]")
	}
	command := args[0]
	if command != "inspect" && command != "sbom" && command != "tree" {
		return fmt.Errorf("unknown sca command %q", command)
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
