package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"trident/internal/httpverify"
)

// runRuntime dispatches explicit runtime verification. It never reads a
// snapshot, database or model, and only contacts the caller-approved origin.
func runRuntime(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident runtime http --plan <file> --approve-target <origin> [--allow-loopback]")
	}
	if args[0] != "http" {
		return fmt.Errorf("unknown runtime command %q", args[0])
	}
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
	if err := flags.Parse(args[1:]); err != nil {
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
