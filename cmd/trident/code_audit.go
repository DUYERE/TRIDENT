package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"trident/internal/codescan"
	"trident/internal/findings"
	"trident/internal/project"
	"trident/internal/sarif"
)

// maybeMergeCodeAudit is the opt-in bridge into the unified evidence model.
// Existing `audit findings`/`audit sarif` output is byte-identical when the
// flag is absent.
func maybeMergeCodeAudit(ctx context.Context, snapshot *project.Snapshot, report *findings.Report, include bool, rulesPath, languageArg string) error {
	if !include {
		return nil
	}
	codeReport, err := codescan.Analyze(ctx, snapshot, codescan.Options{Languages: splitLanguages(languageArg), RulePath: rulesPath})
	if err != nil {
		return err
	}
	codescan.MergeFindings(report, codeReport)
	return nil
}

// runCodeAudit runs the bounded multi-language rule engine over a pinned
// snapshot. It never executes the audited code, never resolves dependencies
// and never accesses the network.
func runCodeAudit(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit code", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, languageArg, rulesPath, format string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&languageArg, "language", "", "optional comma-separated languages: php,csharp(.net/dotnet),python,javascript,js,typescript,ts,java,go")
	flags.StringVar(&rulesPath, "rules", "", "optional caller-supplied rule catalog JSON (appended to built-in rules)")
	flags.StringVar(&format, "format", "json", "output format: json (default), findings, sarif")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid audit code arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("audit code requires --snapshot and --snapshot-hash and no positional arguments")
	}
	languages := splitLanguages(languageArg)
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := codescan.Analyze(ctx, snapshot, codescan.Options{Languages: languages, RulePath: rulesPath})
	if err != nil {
		return err
	}
	switch format {
	case "json":
		return json.NewEncoder(out).Encode(report)
	case "findings":
		return json.NewEncoder(out).Encode(codescan.AsFindingsReport(report))
	case "sarif":
		document, err := sarif.Build(codescan.AsFindingsReport(report), codescan.ToolVersion)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(document)
	default:
		return fmt.Errorf("unknown audit code format %q (json|findings|sarif)", format)
	}
}

func splitLanguages(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
