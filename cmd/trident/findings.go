package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/findings"
	"trident/internal/project"
)

// runFindings links SCA, endpoint inventory and JDBC dataflow evidence on an
// existing trusted snapshot. It never compiles or runs Java and keeps runtime
// status separate from static finding status.
func runFindings(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit findings", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, advisoryPath string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&advisoryPath, "advisories", "", "optional explicit local advisory catalog JSON")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid findings arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit findings requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := findings.Analyze(ctx, snapshot, findings.Options{AdvisoryPath: advisoryPath})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
