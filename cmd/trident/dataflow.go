package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/dataflow"
	"trident/internal/project"
)

// runDataflow traces request parameters into JDBC SQL sinks on an existing
// trusted snapshot. It never compiles or runs Java and reports no runtime claim.
func runDataflow(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit dataflow", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid dataflow arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit dataflow requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := dataflow.Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
