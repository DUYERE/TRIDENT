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

	"trident/internal/project"
	"trident/internal/r3"
	"trident/internal/reach"
	"trident/internal/sbom"
	"trident/internal/sca"
)

// runSCA performs declaration-level Maven/Gradle analysis on an existing
// trusted snapshot. `resolve` executes a build tool on a disposable copy;
// `upgrade` prepares a version bump and can validate it on a fresh workspace.
func runSCA(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident sca <inspect|sbom|tree|resolve|upgrade> --snapshot <dir> --snapshot-hash <sha256> [--advisories <file>]")
	}
	command := args[0]
	if command != "inspect" && command != "sbom" && command != "tree" && command != "resolve" && command != "upgrade" {
		return fmt.Errorf("unknown sca command %q", command)
	}
	if command == "resolve" {
		return runSCAResolve(ctx, args[1:], out)
	}
	if command == "upgrade" {
		return runSCAUpgrade(ctx, args[1:], out)
	}
	flags := flag.NewFlagSet("sca "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, advisoryPath, mavenRepo, gradleUserHome, hashCatalog, packageMap string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&advisoryPath, "advisories", "", "explicit local advisory JSON file; never read from the snapshot implicitly")
	flags.StringVar(&mavenRepo, "maven-repo", "", "optional absolute local Maven repository used only to hash existing artifacts")
	flags.StringVar(&gradleUserHome, "gradle-user-home", "", "optional absolute Gradle user home used only to hash cached artifacts")
	flags.StringVar(&hashCatalog, "hash-catalog", "", "optional local JSON catalog of expected artifact SHA-256 values")
	flags.StringVar(&packageMap, "package-map", "", "sbom only: optional JSON map from group:artifact to package prefixes; enables VEX reachability analysis")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("invalid sca arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("sca %s requires --snapshot and --snapshot-hash and no positional arguments", command)
	}
	if packageMap != "" && command != "sbom" {
		return fmt.Errorf("--package-map is only valid for sca sbom")
	}
	snapshot, err := project.Open(ctx, snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	report, err := sca.Inspect(ctx, snapshot, sca.Options{
		AdvisoryPath: advisoryPath, MavenRepo: mavenRepo,
		GradleUserHome: gradleUserHome, HashCatalogPath: hashCatalog,
	})
	if err != nil {
		return err
	}
	if command == "inspect" {
		return json.NewEncoder(out).Encode(report)
	}
	if command == "tree" {
		return json.NewEncoder(out).Encode(sca.Tree(report))
	}
	// VEX declarations require caller-provided reachability evidence computed in
	// this process; without a package map every candidate stays in_triage.
	reachability := map[string]reach.Reachability{}
	if packageMap != "" {
		reachReport, err := reach.Inspect(ctx, snapshot, reach.Options{PackageMapPath: packageMap})
		if err != nil {
			return err
		}
		for _, item := range reachReport.Dependencies {
			reachability[item.Module+"\x00"+item.Dependency+"\x00"+item.Version] = item
		}
	}
	document, err := sbom.Build(report, sbom.Options{SnapshotHash: snapshot.Hash(), ToolVersion: sbom.ToolVersion, Partial: report.Partial, Reachability: reachability})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(document)
}

func runSCAResolve(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("sca resolve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, mavenRepo, tool, gradlePath, gradleUserHome, gradleInitScript string
	var approveNetwork, approveMaven, approveGradle bool
	var timeoutSeconds int
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&tool, "tool", "maven", "dependency resolver: maven or gradle")
	flags.StringVar(&mavenRepo, "maven-repo", "", "optional absolute local Maven repository")
	flags.StringVar(&gradlePath, "gradle", "", "optional absolute path to the Gradle executable")
	flags.StringVar(&gradleUserHome, "gradle-user-home", "", "optional absolute Gradle user home")
	flags.StringVar(&gradleInitScript, "gradle-init-script", "", "optional absolute Gradle init script")
	flags.BoolVar(&approveNetwork, "approve-network", false, "allow the build tool to download missing artifacts")
	flags.BoolVar(&approveMaven, "approve-maven", false, "explicitly approve Maven execution on a disposable snapshot copy")
	flags.BoolVar(&approveGradle, "approve-gradle", false, "explicitly approve Gradle execution on a disposable snapshot copy")
	flags.IntVar(&timeoutSeconds, "timeout-seconds", sca.DefaultResolveTimeoutS, "dependency resolution timeout (1..600)")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid sca resolve arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("sca resolve requires --snapshot and --snapshot-hash and no positional arguments")
	}
	if tool != "maven" && tool != "gradle" {
		return fmt.Errorf("--tool must be maven or gradle")
	}
	if tool == "maven" {
		if !approveMaven {
			return fmt.Errorf("sca resolve --tool maven executes Maven; explicit --approve-maven is required")
		}
		if gradlePath != "" || gradleUserHome != "" || gradleInitScript != "" || approveGradle {
			return fmt.Errorf("Gradle options require --tool gradle")
		}
	} else {
		if !approveGradle {
			return fmt.Errorf("sca resolve --tool gradle executes Gradle; explicit --approve-gradle is required")
		}
		if mavenRepo != "" || approveMaven {
			return fmt.Errorf("Maven options require --tool maven")
		}
	}
	if timeoutSeconds < 1 || timeoutSeconds > sca.MaxResolveTimeoutS {
		return fmt.Errorf("timeout-seconds must be between 1 and %d", sca.MaxResolveTimeoutS)
	}
	absoluteSnapshot, err := filepath.Abs(snapshotDir)
	if err != nil {
		return err
	}
	snapshot, err := project.Open(ctx, absoluteSnapshot, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	options := sca.ResolveOptions{
		AllowNetwork:     approveNetwork,
		ApproveMaven:     approveMaven,
		ApproveGradle:    approveGradle,
		MavenRepo:        mavenRepo,
		GradlePath:       gradlePath,
		GradleUserHome:   gradleUserHome,
		GradleInitScript: gradleInitScript,
		Timeout:          time.Duration(timeoutSeconds) * time.Second,
	}
	var report sca.ResolveReport
	var resolveErr error
	if tool == "gradle" {
		report, resolveErr = sca.ResolveGradleEffectiveTree(ctx, snapshot, options)
	} else {
		report, resolveErr = sca.ResolveEffectiveTree(ctx, snapshot, options)
	}
	if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
		return encodeErr
	}
	return resolveErr
}

type scaUpgradeReport struct {
	sca.UpgradePlan
	Baseline     *r3.ValidationResult `json:"baseline,omitempty"`
	Verification *r3.Report           `json:"verification,omitempty"`
}

// runSCAUpgrade prepares a minimal dependency version bump and, when a new
// workspace is supplied, validates it through the same isolated R3 pipeline as
// a caller-supplied patch. Planning alone never executes a build tool.
func runSCAUpgrade(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("sca upgrade", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, module, dependency, toVersion, outPath, workspace string
	var profile, mainClass, testClass, testClasspath, junitReportDir, jacocoAgent, jacocoReport string
	var sandboxKind, sandboxImage, sandboxNetwork, sandboxMemory, sandboxCPUs, sandboxMavenRepo string
	var timeoutSeconds, sandboxPids int
	var approveExecution bool
	var modules stringList
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import")
	flags.StringVar(&module, "module", ".", "module directory or build file containing the declaration")
	flags.StringVar(&dependency, "dependency", "", "dependency to upgrade: group:artifact")
	flags.StringVar(&toVersion, "to", "", "target version literal")
	flags.StringVar(&outPath, "out", "", "new patch file outside the snapshot")
	flags.StringVar(&workspace, "workspace", "", "optional new workspace outside the snapshot for validation")
	flags.StringVar(&profile, "profile", "maven-test", "validation profile: maven, maven-compile, maven-test, gradle-test, javac or junit")
	flags.Var(&modules, "module-dir", "workspace-relative module directory to validate; repeatable, at most 8")
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
	flags.IntVar(&timeoutSeconds, "timeout-seconds", r3.DefaultTimeoutS, "validation timeout (1..600)")
	flags.BoolVar(&approveExecution, "approve-execution", false, "explicitly approve compiling and running the upgraded isolated copy")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid sca upgrade arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" || dependency == "" || toVersion == "" || outPath == "" {
		return fmt.Errorf("sca upgrade requires --snapshot --snapshot-hash --dependency --to --out")
	}
	if profile == "junit" {
		if testClass == "" || testClasspath == "" {
			return fmt.Errorf("junit profile requires --test-class and --test-classpath")
		}
	} else if profile != "maven-compile" && profile != "maven-test" && profile != "gradle-test" && mainClass == "" {
		return fmt.Errorf("maven, gradle-test and javac profiles require --main-class")
	}
	if len(modules) > r3.MaxModules {
		return fmt.Errorf("at most %d modules can be validated", r3.MaxModules)
	}
	if timeoutSeconds < 1 || timeoutSeconds > r3.MaxTimeoutS {
		return fmt.Errorf("timeout-seconds must be between 1 and %d", r3.MaxTimeoutS)
	}
	if workspace != "" && !approveExecution {
		return fmt.Errorf("sca upgrade validation compiles and runs the upgraded copy; explicit --approve-execution is required")
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
		return fmt.Errorf("upgrade patch output must be outside the snapshot")
	}
	if info, err := os.Lstat(absoluteOut); err == nil || !os.IsNotExist(err) {
		if err == nil && info.Mode().IsRegular() {
			return fmt.Errorf("upgrade patch output already exists; choose a new file")
		}
		return fmt.Errorf("upgrade patch output must be a new regular file")
	}
	snapshot, err := project.Open(ctx, absoluteSnapshot, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	plan, err := sca.PlanUpgrade(ctx, snapshot, sca.UpgradeOptions{
		Module: module, Dependency: dependency, ToVersion: toVersion,
	})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(absoluteOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.WriteString(plan.Patch); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	report := scaUpgradeReport{UpgradePlan: plan}
	if workspace != "" {
		var classpath []string
		if testClasspath != "" {
			classpath = filepath.SplitList(testClasspath)
		}
		baseline, baselineErr := runUpgradeBaseline(ctx, snapshot, absoluteSnapshot, r3.ValidationOptions{
			Profile: profile, Modules: []string(modules), MainClass: mainClass, TestClass: testClass, TestClasses: nil,
			TestClasspath: classpath, JUnitReportDir: junitReportDir,
			JacocoAgent: jacocoAgent, JacocoReport: jacocoReport,
			Timeout: time.Duration(timeoutSeconds) * time.Second, ApproveExecution: true,
			Sandbox: r3.Sandbox{
				Kind: sandboxKind, Image: sandboxImage, Network: sandboxNetwork,
				Memory: sandboxMemory, CPUs: sandboxCPUs, PidsLimit: sandboxPids, MavenRepo: sandboxMavenRepo,
			},
		})
		report.Baseline = baseline
		if baselineErr != nil || baseline == nil || baseline.Status != r3.ValidationPassed {
			report.Status = "baseline_validation_failed"
			if baseline != nil && baseline.Status != "" {
				report.Status = "baseline_" + baseline.Status
				report.RuntimeStatus = "isolated_validation_only"
			}
			if baselineErr == nil {
				baselineErr = fmt.Errorf("baseline validation did not pass")
			}
			if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
				return encodeErr
			}
			return baselineErr
		}
		verification, verifyErr := r3.Verify(ctx, r3.VerifyOptions{
			SnapshotDir: absoluteSnapshot, SnapshotHash: expectedHash, Workspace: workspace, PatchPath: absoluteOut,
			Profile: profile, Modules: []string(modules), MainClass: mainClass, TestClass: testClass, TestClasspath: classpath,
			JUnitReportDir: junitReportDir, JacocoAgent: jacocoAgent, JacocoReport: jacocoReport,
			Timeout: time.Duration(timeoutSeconds) * time.Second, ApproveExecution: true,
			Sandbox: r3.Sandbox{
				Kind: sandboxKind, Image: sandboxImage, Network: sandboxNetwork,
				Memory: sandboxMemory, CPUs: sandboxCPUs, PidsLimit: sandboxPids, MavenRepo: sandboxMavenRepo,
			},
		})
		report.Verification = &verification
		report.Status = verification.Status
		report.RuntimeStatus = verification.RuntimeStatus
		if verifyErr != nil {
			if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
				return encodeErr
			}
			return verifyErr
		}
	}
	if err := json.NewEncoder(out).Encode(report); err != nil {
		return err
	}
	if report.Verification != nil && report.Verification.Status != r3.ValidationPassed {
		return fmt.Errorf("dependency upgrade verification status: %s", report.Verification.Status)
	}
	return nil
}

// runUpgradeBaseline validates the unmodified snapshot in a disposable
// workspace so a post-upgrade failure can be distinguished from a project that
// was already broken before the version bump.
func runUpgradeBaseline(ctx context.Context, snapshot *project.Snapshot, snapshotDir string, opts r3.ValidationOptions) (*r3.ValidationResult, error) {
	parent, err := os.MkdirTemp("", "trident-upgrade-baseline-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(parent)
	destination := filepath.Join(parent, "workspace")
	if _, err = r3.CreateWorkspace(ctx, snapshot, snapshotDir, destination); err != nil {
		return nil, err
	}
	result, err := r3.Validate(ctx, destination, opts)
	if err != nil {
		return &result, err
	}
	return &result, nil
}
