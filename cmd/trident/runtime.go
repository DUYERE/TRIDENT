package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trident/internal/correlate"
	"trident/internal/httpverify"
)

// runRuntime dispatches explicit runtime verification. It never reads a
// snapshot, database or model, and only contacts the caller-approved origin.
func runRuntime(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident runtime <http|correlate>")
	}
	switch args[0] {
	case "http":
		return runRuntimeHTTP(ctx, args[1:], out)
	case "correlate":
		return runRuntimeCorrelate(args[1:], out)
	default:
		return fmt.Errorf("unknown runtime command %q", args[0])
	}
}

func runRuntimeHTTP(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("runtime http", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var planPath, approvedOrigin string
	var allowLoopback bool
	var timeoutSeconds, maxRequests int
	flags.StringVar(&planPath, "plan", "", "absolute JSON HTTP verification plan")
	flags.StringVar(&approvedOrigin, "approve-target", "", "exact http(s) origin approved for this run")
	flags.BoolVar(&allowLoopback, "allow-loopback", false, "allow localhost/loopback targets")
	flags.IntVar(&timeoutSeconds, "timeout-seconds", httpverify.DefaultTimeoutS, "per-request timeout (1..60)")
	flags.IntVar(&maxRequests, "max-requests", httpverify.MaxRequests, "maximum requests (1..64)")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid runtime http arguments: %w", err)
	}
	if flags.NArg() != 0 || planPath == "" || approvedOrigin == "" {
		return fmt.Errorf("runtime http requires --plan and --approve-target")
	}
	if timeoutSeconds < 1 || timeoutSeconds > httpverify.MaxTimeoutS {
		return fmt.Errorf("timeout-seconds must be between 1 and %d", httpverify.MaxTimeoutS)
	}
	if maxRequests < 1 || maxRequests > httpverify.MaxRequests {
		return fmt.Errorf("max-requests must be between 1 and %d", httpverify.MaxRequests)
	}
	absolutePlan, err := filepath.Abs(planPath)
	if err != nil {
		return err
	}
	info, err := os.Stat(absolutePlan)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("plan must be an existing regular file")
	}
	if info.Size() <= 0 || info.Size() > httpverify.MaxPlanBytes {
		return fmt.Errorf("plan size outside supported bounds")
	}
	data, err := os.ReadFile(absolutePlan)
	if err != nil {
		return err
	}
	plan, err := httpverify.ParsePlan(data)
	if err != nil {
		return err
	}
	report, err := httpverify.Execute(ctx, plan, httpverify.Options{
		ApprovedOrigin: approvedOrigin, AllowLoopback: allowLoopback,
		Timeout: time.Duration(timeoutSeconds) * time.Second, MaxRequests: maxRequests,
	})
	if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
		return encodeErr
	}
	if err != nil {
		return err
	}
	if report.Status != "passed" {
		return fmt.Errorf("runtime verification status: %s", report.Status)
	}
	return nil
}

// runRuntimeCorrelate links a static findings report with a runtime report
// without modifying either input or upgrading any finding.
func runRuntimeCorrelate(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("runtime correlate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var findingsPath, runtimePath, outPath string
	flags.StringVar(&findingsPath, "findings", "", "JSON report from audit findings")
	flags.StringVar(&runtimePath, "runtime", "", "JSON report from runtime http")
	flags.StringVar(&outPath, "out", "", "new correlation report file")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid runtime correlate arguments: %w", err)
	}
	if flags.NArg() != 0 || findingsPath == "" || runtimePath == "" || outPath == "" {
		return fmt.Errorf("runtime correlate requires --findings, --runtime and --out")
	}
	absoluteFindings, findingsData, err := readCorrelationInput(findingsPath, "findings")
	if err != nil {
		return err
	}
	absoluteRuntime, runtimeData, err := readCorrelationInput(runtimePath, "runtime")
	if err != nil {
		return err
	}
	absoluteOut, err := filepath.Abs(outPath)
	if err != nil {
		return err
	}
	if samePath(absoluteOut, absoluteFindings) || samePath(absoluteOut, absoluteRuntime) {
		return fmt.Errorf("correlation output must not overwrite an input report")
	}
	report, err := correlate.Correlate(
		correlate.Input{Path: absoluteFindings, Data: findingsData},
		correlate.Input{Path: absoluteRuntime, Data: runtimeData},
	)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(absoluteOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("correlation output must be a new file: %w", err)
	}
	if _, err = file.Write(encoded); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"out": absoluteOut, "bytes": len(encoded), "runtime_status": report.RuntimeStatus,
		"findings": report.Coverage.FindingsTotal, "runtime_results": report.Coverage.RuntimeResults,
		"correlated": report.Coverage.Correlated, "ambiguous": report.Coverage.Ambiguous,
		"not_correlated": report.Coverage.NotCorrelated,
	})
}

func readCorrelationInput(path, label string) (string, []byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%s report must be an existing regular file", label)
	}
	if info.Size() <= 0 || info.Size() > correlate.MaxInputBytes {
		return "", nil, fmt.Errorf("%s report size outside supported bounds", label)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return "", nil, err
	}
	return absolute, data, nil
}

func samePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if strings.EqualFold(left, right) {
		return true
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}
