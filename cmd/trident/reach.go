package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/project"
	"trident/internal/reach"
)

// runReachability matches declared dependencies to Java imports through a
// caller-supplied package map. Import matches are not call reachability.
func runReachability(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit reachability", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, packageMap string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&packageMap, "package-map", "", "optional JSON map from group:artifact to package prefixes")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid reachability arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit reachability requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := reach.Inspect(ctx, snapshot, reach.Options{PackageMapPath: packageMap})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
