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
	var emitUnobserved, includeSinkAnchors bool
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.BoolVar(&emitUnobserved, "emit-unobserved", false, "v1 compatibility: also emit findings with no observed sink, protection or boundary")
	flags.BoolVar(&includeSinkAnchors, "include-sink-anchors", false, "also include endpoint-independent sink anchors in sink_anchors[]")
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
	report, err := dataflow.AnalyzeWithOptions(ctx, snapshot, dataflow.Options{
		EmitUnobserved: emitUnobserved, IncludeSinkAnchors: includeSinkAnchors,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

// runSinks reports endpoint-independent sink locations. It is deliberately a
// separate report: anchors are code review positions, not vulnerability
// findings with a proven attacker-controlled source.
func runSinks(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit sinks", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid audit sinks arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit sinks requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := dataflow.InspectSinks(ctx, snapshot, nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
