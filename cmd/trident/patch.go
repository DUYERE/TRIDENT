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

	openaiadapter "trident/internal/model/openai"
	"trident/internal/project"
	"trident/internal/r3"
)

// runPatch dispatches the bounded R3 slices. Neither command writes the pinned
// snapshot; propose validates a generated diff on a temporary copy, and verify
// applies a caller/generated diff to a new isolated workspace.
func runPatch(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident patch propose|verify ...")
	}
	switch args[0] {
	case "verify":
		return runPatchVerify(ctx, args[1:], out)
	case "propose":
		return runPatchPropose(ctx, args[1:], out)
	case "repair":
		return runPatchRepair(ctx, args[1:], out)
	default:
		return fmt.Errorf("unknown patch command %q", args[0])
	}
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type patchProposalReport struct {
	SchemaVersion  int             `json:"schema_version"`
	SnapshotHash   string          `json:"snapshot_hash"`
	FindingID      string          `json:"finding_id,omitempty"`
	Model          string          `json:"model"`
	Out            string          `json:"out"`
	PatchSHA256    string          `json:"patch_sha256"`
	PatchBytes     int             `json:"patch_bytes"`
	Files          []r3.FileChange `json:"validated_files"`
	Rationale      string          `json:"rationale"`
	EgressApproved bool            `json:"egress_approved"`
	RuntimeStatus  string          `json:"runtime_status"`
	Limitations    []string        `json:"limitations"`
}

// runPatchPropose asks an approved model for one unified diff and writes it only
// after exact-context validation against the pinned snapshot. Execution remains
// a separate explicit `patch verify --approve-execution` step.
func runPatchPropose(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("patch propose", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, findingID, goal, outPath, endpoint, modelName string
	var policyPath string
	var paths stringList
	var apiKeyEnv, outputParam string
	var maxOutputTokens, timeoutSeconds int64
	var approve, allowLoopback bool
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&findingID, "finding", "", "finding ID from audit findings")
	flags.Var(&paths, "path", "snapshot-relative source path; repeatable")
	flags.StringVar(&goal, "goal", "", "patch goal (also disclosed to the approved model)")
	flags.StringVar(&outPath, "out", "", "new patch file outside the snapshot")
	flags.StringVar(&policyPath, "policy", "", "optional remediation policy JSON")
	flags.StringVar(&endpoint, "endpoint", "", "explicit API base URL")
	flags.StringVar(&modelName, "model", "", "explicit model identifier")
	flags.StringVar(&apiKeyEnv, "api-key-env", "TRIDENT_MODEL_API_KEY", "host environment variable containing model key (never persisted)")
	flags.StringVar(&outputParam, "output-parameter", "max_tokens", "max_tokens or max_completion_tokens")
	flags.Int64Var(&maxOutputTokens, "max-output-tokens", 4096, "output token ceiling")
	flags.Int64Var(&timeoutSeconds, "timeout-seconds", 120, "model and validation timeout (1..600)")
	flags.BoolVar(&approve, "approve-egress", false, "approve the selected source context to this endpoint/model")
	flags.BoolVar(&allowLoopback, "allow-loopback-http", false, "allow numeric loopback HTTP protocol test service")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid patch propose arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" || goal == "" || outPath == "" || endpoint == "" || modelName == "" {
		return fmt.Errorf("patch propose requires --snapshot --snapshot-hash --goal --out --endpoint --model")
	}
	if findingID == "" && len(paths) == 0 {
		return fmt.Errorf("patch propose requires --finding or at least one --path")
	}
	if !approve {
		return fmt.Errorf("patch propose sends selected source to a model; explicit --approve-egress is required")
	}
	if timeoutSeconds < 1 || timeoutSeconds > 600 || maxOutputTokens < 1 || maxOutputTokens > 16384 {
		return fmt.Errorf("timeout-seconds or max-output-tokens outside supported bounds")
	}
	if outputParam != "max_tokens" && outputParam != "max_completion_tokens" {
		return fmt.Errorf("invalid output-parameter")
	}
	absoluteSnapshot, err := filepath.Abs(snapshotDir)
	if err != nil {
		return err
	}
	absoluteOut, err := filepath.Abs(outPath)
	if err != nil {
		return err
	}
	if insideSnapshot(absoluteSnapshot, absoluteOut) {
		return fmt.Errorf("patch output must be outside the snapshot")
	}
	if info, err := os.Lstat(absoluteOut); err == nil || !os.IsNotExist(err) {
		if err == nil && info.Mode().IsRegular() {
			return fmt.Errorf("patch output already exists; choose a new file")
		}
		return fmt.Errorf("patch output must be a new regular file")
	}
	normalized, err := openaiadapter.NormalizeEndpoint(endpoint, allowLoopback)
	if err != nil {
		return err
	}
	apiKey := os.Getenv(apiKeyEnv)
	if apiKey == "" {
		return fmt.Errorf("model key missing from %s", apiKeyEnv)
	}
	client, err := openaiadapter.New(openaiadapter.Config{
		Endpoint: normalized, Model: modelName, APIKey: apiKey,
		Timeout:         time.Duration(timeoutSeconds) * time.Second,
		MaxRequestBytes: 2 << 20, MaxResponseBytes: 512 << 10,
		OutputParameter: openaiadapter.OutputParameter(outputParam), AllowLoopbackHTTP: allowLoopback,
	})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	snapshot, err := project.Open(ctx, absoluteSnapshot, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	policy, err := r3.LoadPolicy(policyPath)
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	proposal, err := r3.Propose(callCtx, snapshot, client, r3.ProposeOptions{
		FindingID: findingID, Paths: paths, Goal: goal, Model: modelName, MaxOutputTokens: maxOutputTokens,
		Policy: &policy,
	})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(absoluteOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(proposal.Patch); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(patchProposalReport{
		SchemaVersion: 1, SnapshotHash: proposal.SnapshotHash, FindingID: proposal.FindingID,
		Model: proposal.Model, Out: absoluteOut, PatchSHA256: proposal.PatchSHA256,
		PatchBytes: proposal.PatchBytes, Files: proposal.Files, Rationale: proposal.Rationale,
		EgressApproved: true, RuntimeStatus: "not_run", Limitations: proposal.Limitations,
	})
}

func insideSnapshot(snapshot, target string) bool {
	relative, err := filepath.Rel(snapshot, target)
	if err != nil {
		return false
	}
	return relative == "." || (!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && relative != "..")
}

// runPatchVerify implements the first bounded R3 slice: isolated workspace,
// caller supplied unified diff, fixed validation profile. It never writes the snapshot.
func runPatchVerify(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("patch verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, workspace, patchPath, profile, mainClass, testClass, testClasspath string
	var junitReportDir, jacocoAgent, jacocoReport string
	var sandboxKind, sandboxImage, sandboxNetwork, sandboxMemory, sandboxCPUs, sandboxMavenRepo string
	var timeoutSeconds, sandboxPids int
	var approve bool
	var modules stringList
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&workspace, "workspace", "", "new writable workspace directory outside the snapshot")
	flags.StringVar(&patchPath, "patch", "", "caller-supplied unified diff file")
	flags.StringVar(&profile, "profile", "maven", "validation profile: maven, maven-compile, maven-test, gradle-test, javac, junit, php-lint, python-compile, pytest, node-check, npm-test, go-test, dotnet-build or dotnet-test")
	flags.Var(&modules, "module", "workspace-relative module directory to validate; repeatable, at most 8")
	flags.StringVar(&mainClass, "main-class", "", "Java main class for maven/javac profiles")
	flags.StringVar(&testClass, "test-class", "", "JUnit test class(es), comma-separated")
	flags.StringVar(&testClasspath, "test-classpath", "", "OS-separated absolute JUnit/classpath entries for junit")
	flags.StringVar(&junitReportDir, "junit-report-dir", "", "optional directory containing Surefire-style JUnit XML reports")
	flags.StringVar(&jacocoAgent, "jacoco-agent", "", "optional absolute JaCoCo agent jar for junit coverage")
	flags.StringVar(&jacocoReport, "jacoco-report", "", "optional absolute JaCoCo XML output path inside the workspace")
	flags.StringVar(&sandboxKind, "sandbox", "process", "sandbox: process, docker or gvisor")
	flags.StringVar(&sandboxImage, "sandbox-image", "", "docker/gvisor image pinned by @sha256 digest")
	flags.StringVar(&sandboxNetwork, "sandbox-network", "none", "docker network: none or default")
	flags.StringVar(&sandboxMemory, "sandbox-memory", "1g", "docker memory limit")
	flags.StringVar(&sandboxCPUs, "sandbox-cpus", "1", "docker CPU limit")
	flags.IntVar(&sandboxPids, "sandbox-pids", 256, "docker pid limit (1..4096)")
	flags.StringVar(&sandboxMavenRepo, "sandbox-maven-repo", "", "absolute host .m2 directory mounted read-only for offline Maven")
	flags.IntVar(&timeoutSeconds, "timeout-seconds", r3.DefaultTimeoutS, "total validation timeout (1..600)")
	flags.BoolVar(&approve, "approve-execution", false, "explicitly approve compiling and running the patched isolated copy")
	var keepWorkspace bool
	flags.BoolVar(&keepWorkspace, "keep-workspace", false, "keep the isolated copy after a failed patch or validation setup")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid patch arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" || workspace == "" || patchPath == "" {
		return fmt.Errorf("patch verify requires snapshot, snapshot hash, new workspace and patch")
	}
	if profile == "junit" {
		if testClass == "" || testClasspath == "" {
			return fmt.Errorf("junit profile requires --test-class and --test-classpath")
		}
	} else if !r3.IsBuildOnlyProfile(profile) && mainClass == "" {
		return fmt.Errorf("maven, javac and non-build language profiles require --main-class")
	}
	if timeoutSeconds < 1 || timeoutSeconds > r3.MaxTimeoutS {
		return fmt.Errorf("timeout-seconds must be between 1 and %d", r3.MaxTimeoutS)
	}
	if len(modules) > r3.MaxModules {
		return fmt.Errorf("at most %d modules can be validated", r3.MaxModules)
	}
	if !approve {
		return fmt.Errorf("patch verification compiles and executes the patched copy; explicit --approve-execution is required")
	}
	var classpath []string
	if testClasspath != "" {
		classpath = filepath.SplitList(testClasspath)
	}
	report, err := r3.Verify(ctx, r3.VerifyOptions{
		SnapshotDir: snapshotDir, SnapshotHash: expectedHash, Workspace: workspace, PatchPath: patchPath,
		Profile: profile, Modules: []string(modules), MainClass: mainClass, TestClass: testClass, TestClasspath: classpath,
		JUnitReportDir: junitReportDir, JacocoAgent: jacocoAgent, JacocoReport: jacocoReport,
		Timeout: time.Duration(timeoutSeconds) * time.Second, ApproveExecution: true, KeepWorkspace: keepWorkspace,
		Sandbox: r3.Sandbox{
			Kind: sandboxKind, Image: sandboxImage, Network: sandboxNetwork,
			Memory: sandboxMemory, CPUs: sandboxCPUs, PidsLimit: sandboxPids, MavenRepo: sandboxMavenRepo,
		},
	})
	encodeErr := json.NewEncoder(out).Encode(report)
	if encodeErr != nil {
		return encodeErr
	}
	if err != nil {
		return err
	}
	if report.Status != r3.ValidationPassed {
		return fmt.Errorf("patch verification status: %s", report.Status)
	}
	return nil
}

// runPatchRepair runs bounded propose→isolated-verify rounds. Each round uses a
// fresh workspace and the same caller-selected validation profile; model
// failures stop the loop instead of being retried.
func runPatchRepair(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("patch repair", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, findingID, goal, workspaceRoot, policyPath string
	var endpoint, modelName, apiKeyEnv, outputParam string
	var profile, mainClass, testClass, testClasspath, junitReportDir, jacocoAgent, jacocoReport string
	var sandboxKind, sandboxImage, sandboxNetwork, sandboxMemory, sandboxCPUs, sandboxMavenRepo string
	var paths stringList
	var rounds, timeoutSeconds, maxOutputTokens, sandboxPids int
	var approveEgress, approveExecution, allowLoopback bool
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&findingID, "finding", "", "finding ID from audit findings")
	flags.Var(&paths, "path", "snapshot-relative source path; repeatable")
	flags.StringVar(&goal, "goal", "", "repair goal disclosed to the approved model")
	flags.StringVar(&workspaceRoot, "workspace-root", "", "existing directory outside the snapshot for round workspaces")
	flags.StringVar(&policyPath, "policy", "", "optional remediation policy JSON")
	flags.StringVar(&endpoint, "endpoint", "", "explicit API base URL")
	flags.StringVar(&modelName, "model", "", "explicit model identifier")
	flags.StringVar(&apiKeyEnv, "api-key-env", "TRIDENT_MODEL_API_KEY", "host environment variable containing model key (never persisted)")
	flags.StringVar(&outputParam, "output-parameter", "max_tokens", "max_tokens or max_completion_tokens")
	flags.IntVar(&maxOutputTokens, "max-output-tokens", 4096, "output token ceiling per round")
	flags.IntVar(&rounds, "rounds", 3, "repair rounds (1..5)")
	flags.StringVar(&profile, "profile", "junit", "validation profile: maven, maven-compile, maven-test, gradle-test, javac, junit, php-lint, python-compile, pytest, node-check, npm-test, go-test, dotnet-build or dotnet-test")
	flags.StringVar(&mainClass, "main-class", "", "Java main class for maven/javac profiles")
	flags.StringVar(&testClass, "test-class", "", "JUnit test class(es), comma-separated")
	flags.StringVar(&testClasspath, "test-classpath", "", "OS-separated absolute JUnit/classpath entries for junit")
	flags.StringVar(&junitReportDir, "junit-report-dir", "", "optional directory containing JUnit XML reports")
	flags.StringVar(&jacocoAgent, "jacoco-agent", "", "optional absolute JaCoCo agent jar")
	flags.StringVar(&jacocoReport, "jacoco-report", "", "optional absolute JaCoCo XML output path")
	flags.StringVar(&sandboxKind, "sandbox", "process", "sandbox: process, docker or gvisor")
	flags.StringVar(&sandboxImage, "sandbox-image", "", "docker/gvisor image pinned by @sha256 digest")
	flags.StringVar(&sandboxNetwork, "sandbox-network", "none", "docker network: none or default")
	flags.StringVar(&sandboxMemory, "sandbox-memory", "1g", "docker memory limit")
	flags.StringVar(&sandboxCPUs, "sandbox-cpus", "1", "docker CPU limit")
	flags.IntVar(&sandboxPids, "sandbox-pids", 256, "docker pid limit (1..4096)")
	flags.StringVar(&sandboxMavenRepo, "sandbox-maven-repo", "", "absolute host .m2 directory mounted read-only")
	flags.IntVar(&timeoutSeconds, "timeout-seconds", r3.DefaultTimeoutS, "per-round validation timeout (1..600)")
	flags.BoolVar(&approveEgress, "approve-egress", false, "approve source context egress to this endpoint/model")
	flags.BoolVar(&approveExecution, "approve-execution", false, "approve compiling/running each patched copy")
	flags.BoolVar(&allowLoopback, "allow-loopback-http", false, "allow numeric loopback HTTP protocol test service")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid patch repair arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" || goal == "" || workspaceRoot == "" || endpoint == "" || modelName == "" {
		return fmt.Errorf("patch repair requires --snapshot --snapshot-hash --goal --workspace-root --endpoint --model")
	}
	if findingID == "" && len(paths) == 0 {
		return fmt.Errorf("patch repair requires --finding or at least one --path")
	}
	if !approveEgress {
		return fmt.Errorf("patch repair sends source to a model; explicit --approve-egress is required")
	}
	if !approveExecution {
		return fmt.Errorf("patch repair executes each patched copy; explicit --approve-execution is required")
	}
	if rounds < 1 || rounds > r3.MaxRepairRounds || timeoutSeconds < 1 || timeoutSeconds > r3.MaxTimeoutS || maxOutputTokens < 1 || maxOutputTokens > 16384 {
		return fmt.Errorf("rounds, timeout or output token bound outside supported range")
	}
	if profile == "junit" {
		if testClass == "" || testClasspath == "" {
			return fmt.Errorf("junit profile requires --test-class and --test-classpath")
		}
	} else if !r3.IsBuildOnlyProfile(profile) && mainClass == "" {
		return fmt.Errorf("maven, javac and non-build language profiles require --main-class")
	}
	if outputParam != "max_tokens" && outputParam != "max_completion_tokens" {
		return fmt.Errorf("invalid output-parameter")
	}
	absoluteSnapshot, err := filepath.Abs(snapshotDir)
	if err != nil {
		return err
	}
	absoluteRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return err
	}
	if insideSnapshot(absoluteSnapshot, absoluteRoot) {
		return fmt.Errorf("repair workspace root must be outside the snapshot")
	}
	normalized, err := openaiadapter.NormalizeEndpoint(endpoint, allowLoopback)
	if err != nil {
		return err
	}
	apiKey := os.Getenv(apiKeyEnv)
	if apiKey == "" {
		return fmt.Errorf("model key missing from %s", apiKeyEnv)
	}
	client, err := openaiadapter.New(openaiadapter.Config{
		Endpoint: normalized, Model: modelName, APIKey: apiKey,
		Timeout:         time.Duration(timeoutSeconds) * time.Second,
		MaxRequestBytes: 2 << 20, MaxResponseBytes: 512 << 10,
		OutputParameter: openaiadapter.OutputParameter(outputParam), AllowLoopbackHTTP: allowLoopback,
	})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	policy, err := r3.LoadPolicy(policyPath)
	if err != nil {
		return err
	}
	snapshot, err := project.Open(ctx, absoluteSnapshot, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	var classpath []string
	if testClasspath != "" {
		classpath = filepath.SplitList(testClasspath)
	}
	report, err := r3.Repair(ctx, r3.RepairOptions{
		Snapshot: snapshot, SnapshotDir: absoluteSnapshot, WorkspaceRoot: absoluteRoot, MaxRounds: rounds, Client: client,
		ApproveExecution: true,
		Propose: r3.ProposeOptions{
			FindingID: findingID, Paths: paths, Goal: goal, Model: modelName,
			MaxOutputTokens: int64(maxOutputTokens), Policy: &policy,
		},
		Verify: r3.VerifyOptions{
			Profile: profile, MainClass: mainClass, TestClass: testClass, TestClasspath: classpath,
			JUnitReportDir: junitReportDir, JacocoAgent: jacocoAgent, JacocoReport: jacocoReport,
			Timeout: time.Duration(timeoutSeconds) * time.Second, ApproveExecution: true,
			Sandbox: r3.Sandbox{
				Kind: sandboxKind, Image: sandboxImage, Network: sandboxNetwork,
				Memory: sandboxMemory, CPUs: sandboxCPUs, PidsLimit: sandboxPids, MavenRepo: sandboxMavenRepo,
			},
		},
	})
	if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
		return encodeErr
	}
	if err != nil {
		return err
	}
	if report.FinalStatus != r3.ValidationPassed {
		return fmt.Errorf("patch repair final status: %s", report.FinalStatus)
	}
	return nil
}
