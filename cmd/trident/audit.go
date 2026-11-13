package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/audit"
	"trident/internal/project"
)

// runAudit extracts a bounded, annotation-level endpoint inventory from an
// existing trusted snapshot. It never compiles or runs Java and makes no taint
// or vulnerability claim.
func runAudit(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident audit <endpoints|dataflow|findings> --snapshot <dir> --snapshot-hash <sha256>")
	}
	if args[0] == "dataflow" {
		return runDataflow(ctx, args[1:], out)
	}
	if args[0] == "findings" {
		return runFindings(ctx, args[1:], out)
	}
	if args[0] != "endpoints" {
		return fmt.Errorf("unknown audit command %q", args[0])
	}
	flags := flag.NewFlagSet("audit endpoints", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("invalid audit arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit endpoints requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := audit.Inspect(ctx, snapshot)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
