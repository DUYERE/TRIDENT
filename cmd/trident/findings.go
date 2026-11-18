package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/findings"
	"trident/internal/project"
	"trident/internal/sarif"
)

// runFindings links SCA, endpoint inventory and JDBC dataflow evidence on an
// existing trusted snapshot. It never compiles or runs Java and keeps runtime
// status separate from static finding status.
func runFindings(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit findings", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, advisoryPath, packageMap, codeRules, codeLanguage string
	var includeCode bool
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&advisoryPath, "advisories", "", "optional explicit local advisory catalog JSON")
	flags.StringVar(&packageMap, "package-map", "", "optional JSON map from group:artifact to package prefixes enabling bounded reachability")
	flags.BoolVar(&includeCode, "include-code-audit", false, "also merge multi-language code audit findings")
	flags.StringVar(&codeRules, "code-rules", "", "optional caller-supplied code audit rule catalog JSON")
	flags.StringVar(&codeLanguage, "code-language", "", "optional comma-separated code audit language filter")
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
	report, err := findings.Analyze(ctx, snapshot, findings.Options{AdvisoryPath: advisoryPath, PackageMapPath: packageMap})
	if err != nil {
		return err
	}
	if err := maybeMergeCodeAudit(ctx, snapshot, &report, includeCode, codeRules, codeLanguage); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

// runSARIF exports the same static findings as a SARIF 2.1.0 log. It neither
// reruns analysis differently nor upgrades runtime_status.
func runSARIF(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit sarif", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, advisoryPath, packageMap, codeRules, codeLanguage string
	var includeCode bool
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&advisoryPath, "advisories", "", "optional explicit local advisory catalog JSON")
	flags.StringVar(&packageMap, "package-map", "", "optional JSON map from group:artifact to package prefixes enabling bounded reachability")
	flags.BoolVar(&includeCode, "include-code-audit", false, "also merge multi-language code audit findings")
	flags.StringVar(&codeRules, "code-rules", "", "optional caller-supplied code audit rule catalog JSON")
	flags.StringVar(&codeLanguage, "code-language", "", "optional comma-separated code audit language filter")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid sarif arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit sarif requires --snapshot and --snapshot-hash and no positional arguments")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := findings.Analyze(ctx, snapshot, findings.Options{AdvisoryPath: advisoryPath, PackageMapPath: packageMap})
	if err != nil {
		return err
	}
	if err := maybeMergeCodeAudit(ctx, snapshot, &report, includeCode, codeRules, codeLanguage); err != nil {
		return err
	}
	document, err := sarif.Build(report, "")
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(document)
}
