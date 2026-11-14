package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/javaast"
	"trident/internal/project"
)

// runJavaModel emits the restricted-subset semantic model: declarations,
// erased signatures, folded constants/annotations and a bounded call graph. It
// does not run, compile or decompile Java and makes no vulnerability claim.
func runJavaModel(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit java-model", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid java-model arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit java-model requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := javaast.Analyze(ctx, snapshot)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
