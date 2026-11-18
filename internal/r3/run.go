package r3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	MaxOutputBytes  = 64 << 10
	MaxJavacFiles   = 100
	MaxModules      = 8
	DefaultTimeoutS = 180
	MaxTimeoutS     = 600
)

const (
	ValidationPassed  = "validation_passed"
	ValidationFailed  = "validation_failed"
	ValidationTimeout = "validation_timeout"
	ValidationError   = "validation_error"
)

type ValidationOptions struct {
	Profile          string
	Modules          []string
	MainClass        string
	TestClass        string
	TestClasses      []string
	TestClasspath    []string
	JUnitReportDir   string
	JacocoAgent      string
	JacocoReport     string
	Timeout          time.Duration
	ApproveExecution bool
	Sandbox          Sandbox
}

type CommandResult struct {
	Command      string `json:"command"`
	Module       string `json:"module,omitempty"`
	ExitCode     int    `json:"exit_code"`
	Status       string `json:"status"`
	DurationMS   int64  `json:"duration_ms"`
	Stdout       string `json:"stdout,omitempty"`
	Stderr       string `json:"stderr,omitempty"`
	OutputTrunc  bool   `json:"output_truncated,omitempty"`
	ErrorMessage string `json:"error,omitempty"`
}

type ValidationResult struct {
	Profile     string           `json:"profile"`
	MainClass   string           `json:"main_class,omitempty"`
	TestClass   string           `json:"test_class,omitempty"`
	TestClasses []string         `json:"test_classes,omitempty"`
	Sandbox     string           `json:"sandbox"`
	Status      string           `json:"status"`
	DurationMS  int64            `json:"duration_ms"`
	Commands    []CommandResult  `json:"commands"`
	TestSummary *TestRunSummary  `json:"test_summary,omitempty"`
	JUnitXML    *JUnitXMLSummary `json:"junit_xml,omitempty"`
	Coverage    *CoverageSummary `json:"coverage,omitempty"`
	Modules     []ModuleResult   `json:"modules,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// ModuleResult records one explicitly selected module's validation outcome.
type ModuleResult struct {
	Module     string `json:"module"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Tests      int    `json:"tests,omitempty"`
	Failures   int    `json:"failures,omitempty"`
	Errors     int    `json:"errors,omitempty"`
	Error      string `json:"error,omitempty"`
}

type TestRunSummary struct {
	Tests    int    `json:"tests"`
	Failures int    `json:"failures"`
	Errors   int    `json:"errors"`
	Skipped  int    `json:"skipped"`
	Raw      string `json:"raw,omitempty"`
}

type JUnitXMLSummary struct {
	Suites   int      `json:"suites"`
	Tests    int      `json:"tests"`
	Failures int      `json:"failures"`
	Errors   int      `json:"errors"`
	Skipped  int      `json:"skipped"`
	Files    []string `json:"files"`
}

type CoverageSummary struct {
	LineCovered   int     `json:"line_covered"`
	LineTotal     int     `json:"line_total"`
	LinePercent   float64 `json:"line_percent"`
	BranchCovered int     `json:"branch_covered"`
	BranchTotal   int     `json:"branch_total"`
	BranchPercent float64 `json:"branch_percent"`
	MethodCovered int     `json:"method_covered"`
	MethodTotal   int     `json:"method_total"`
	ReportPath    string  `json:"report_path,omitempty"`
}

var mainClassPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

// Validate runs a fixed offline profile inside the isolated workspace. It never
// uses a shell on Unix and uses only a fixed cmd.exe command form on Windows.
func Validate(ctx context.Context, workspace string, opts ValidationOptions) (ValidationResult, error) {
	sandbox, err := opts.Sandbox.normalized()
	if err != nil {
		return ValidationResult{}, err
	}
	if sandbox.Kind == SandboxGVisor {
		if err = preflightGVisor(ctx); err != nil {
			return ValidationResult{}, err
		}
	}
	result := ValidationResult{Profile: opts.Profile, MainClass: opts.MainClass, TestClass: opts.TestClass, Sandbox: sandbox.Kind, Commands: []CommandResult{}}
	if !opts.ApproveExecution {
		return result, fmt.Errorf("isolated execution requires explicit approval")
	}
	if opts.Profile != "maven" && opts.Profile != "maven-compile" && opts.Profile != "maven-test" &&
		opts.Profile != "gradle-test" && opts.Profile != "javac" && opts.Profile != "junit" &&
		opts.Profile != "php-lint" && opts.Profile != "python-compile" && opts.Profile != "pytest" &&
		opts.Profile != "node-check" && opts.Profile != "npm-test" && opts.Profile != "go-test" &&
		opts.Profile != "dotnet-build" && opts.Profile != "dotnet-test" {
		return result, fmt.Errorf("profile must be maven, maven-compile, maven-test, gradle-test, javac, junit, php-lint, python-compile, pytest, node-check, npm-test, go-test, dotnet-build or dotnet-test")
	}
	var testClasses []string
	if opts.Profile == "junit" {
		var classErr error
		testClasses, classErr = junitTestClasses(opts.TestClass, opts.TestClasses)
		if classErr != nil {
			return result, classErr
		}
		result.TestClasses = append([]string{}, testClasses...)
		result.TestClass = strings.Join(testClasses, ",")
		if opts.JUnitReportDir != "" {
			info, statErr := os.Stat(opts.JUnitReportDir)
			if statErr != nil || !info.IsDir() || !filepath.IsAbs(opts.JUnitReportDir) {
				return result, fmt.Errorf("junit report directory must be an absolute existing directory")
			}
		}
		if opts.JacocoAgent != "" {
			info, statErr := os.Stat(opts.JacocoAgent)
			if statErr != nil || !info.Mode().IsRegular() || !filepath.IsAbs(opts.JacocoAgent) {
				return result, fmt.Errorf("jacoco agent must be an absolute regular jar file")
			}
		}
	} else if !buildOnlyProfile(opts.Profile) && (!mainClassPattern.MatchString(opts.MainClass) || len(opts.MainClass) > 256) {
		return result, fmt.Errorf("main class must be a dotted Java identifier")
	}
	root, err := filepath.Abs(workspace)
	if err != nil {
		return result, err
	}
	if info, statErr := os.Stat(root); statErr != nil || !info.IsDir() {
		return result, fmt.Errorf("workspace does not exist or is not a directory")
	}
	if len(opts.Modules) > 0 {
		return validateModules(ctx, root, opts)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeoutS * time.Second
	}
	if timeout > MaxTimeoutS*time.Second {
		timeout = MaxTimeoutS * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	status := ValidationPassed
	appendStep := func(step CommandResult) {
		result.Commands = append(result.Commands, step)
		switch step.Status {
		case "timeout":
			status = ValidationTimeout
		case "start_error":
			status = ValidationError
		case "failed":
			if status == ValidationPassed {
				status = ValidationFailed
			}
		}
	}
	switch opts.Profile {
	case "maven":
		if info, statErr := os.Stat(filepath.Join(root, "pom.xml")); statErr != nil || info.IsDir() {
			return result, fmt.Errorf("maven profile requires pom.xml in the workspace")
		}
		var step CommandResult
		if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
			step = runDockerCommand(runCtx, sandbox, root, dockerDisplay(sandbox, "mvn -o -B -q -DskipTests compile"), "mvn", "-o", "-B", "-q", "-DskipTests", "compile")
		} else {
			step = runCommand(runCtx, mavenCompileCommand(runCtx, root), "mvn -o -B -q -DskipTests compile", root)
		}
		appendStep(step)
		if step.Status == "ok" {
			if info, statErr := os.Stat(filepath.Join(root, "target", "classes")); statErr != nil || !info.IsDir() {
				last := len(result.Commands) - 1
				result.Commands[last].Status = "start_error"
				result.Commands[last].ErrorMessage = "maven compile did not produce target/classes"
				status = ValidationError
			} else if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
				appendStep(runDockerCommand(runCtx, sandbox, root, dockerDisplay(sandbox, "java -cp target/classes "+opts.MainClass), "java", "-cp", "target/classes", opts.MainClass))
			} else {
				appendStep(runCommand(runCtx, javaCommand(runCtx, "target/classes", opts.MainClass), "java -cp target/classes "+opts.MainClass, root))
			}
		}
	case "maven-compile":
		if info, statErr := os.Stat(filepath.Join(root, "pom.xml")); statErr != nil || info.IsDir() {
			return result, fmt.Errorf("maven-compile profile requires pom.xml in the workspace")
		}
		var step CommandResult
		if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
			step = runDockerCommand(runCtx, sandbox, root, dockerDisplay(sandbox, "mvn -o -B -q -DskipTests compile"), "mvn", "-o", "-B", "-q", "-DskipTests", "compile")
		} else {
			step = runCommand(runCtx, mavenCompileCommand(runCtx, root), "mvn -o -B -q -DskipTests compile", root)
		}
		appendStep(step)
		if step.Status == "ok" {
			if info, statErr := os.Stat(filepath.Join(root, "target", "classes")); statErr != nil || !info.IsDir() {
				last := len(result.Commands) - 1
				result.Commands[last].Status = "start_error"
				result.Commands[last].ErrorMessage = "maven compile did not produce target/classes"
				status = ValidationError
			}
		}
	case "maven-test":
		if info, statErr := os.Stat(filepath.Join(root, "pom.xml")); statErr != nil || info.IsDir() {
			return result, fmt.Errorf("maven-test profile requires pom.xml in the workspace")
		}
		var step CommandResult
		if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
			step = runDockerCommand(runCtx, sandbox, root, dockerDisplay(sandbox, "mvn -o -B -q test"), "mvn", "-o", "-B", "-q", "test")
		} else {
			step = runCommand(runCtx, exec.CommandContext(runCtx, "mvn", "-o", "-B", "-q", "test"), "mvn -o -B -q test", root)
		}
		appendStep(step)
		if step.Status == "ok" {
			reportDir := filepath.Join(root, "target", "surefire-reports")
			if info, statErr := os.Stat(reportDir); statErr == nil && info.IsDir() {
				summary, summaryErr := parseJUnitXMLDir(reportDir)
				if summaryErr != nil {
					result.Error = summaryErr.Error()
				} else if summary != nil {
					result.JUnitXML = summary
					result.TestSummary = &TestRunSummary{
						Tests: summary.Tests, Failures: summary.Failures,
						Errors: summary.Errors, Skipped: summary.Skipped,
						Raw: "surefire:" + strings.Join(summary.Files, ","),
					}
				}
			}
		}
	case "gradle-test":
		if !hasGradleBuild(root) {
			return result, fmt.Errorf("gradle-test profile requires build.gradle or build.gradle.kts in the workspace")
		}
		var step CommandResult
		if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
			step = runDockerCommand(runCtx, sandbox, root, dockerDisplay(sandbox, "gradle --offline -q test"), "gradle", "--offline", "-q", "test")
		} else {
			step = runCommand(runCtx, exec.CommandContext(runCtx, "gradle", "--offline", "-q", "test"), "gradle --offline -q test", root)
		}
		appendStep(step)
		if step.Status == "ok" {
			reportDir := filepath.Join(root, "build", "test-results", "test")
			if info, statErr := os.Stat(reportDir); statErr == nil && info.IsDir() {
				summary, summaryErr := parseJUnitXMLDir(reportDir)
				if summaryErr != nil {
					result.Error = summaryErr.Error()
				} else if summary != nil {
					result.JUnitXML = summary
					result.TestSummary = &TestRunSummary{
						Tests: summary.Tests, Failures: summary.Failures,
						Errors: summary.Errors, Skipped: summary.Skipped,
						Raw: "gradle:" + strings.Join(summary.Files, ","),
					}
				}
			}
		}
	case "javac":
		files, collectErr := collectJavaFiles(root, "src/main/java")
		if collectErr != nil {
			return result, collectErr
		}
		classes := filepath.Join(root, "build", "classes")
		if err = os.MkdirAll(classes, 0o700); err != nil {
			return result, err
		}
		var step CommandResult
		if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
			relativeFiles, relErr := relativeJavaFiles(root, "src/main/java")
			if relErr != nil {
				return result, relErr
			}
			args := append([]string{"javac", "-encoding", "UTF-8", "-d", "build/classes"}, relativeFiles...)
			step = runDockerCommand(runCtx, sandbox, root, dockerDisplay(sandbox, displayPathList("javac -encoding UTF-8 -d build/classes", relativeFiles)), args...)
		} else {
			args := []string{"-encoding", "UTF-8", "-d", classes}
			args = append(args, files...)
			step = runCommand(runCtx, exec.CommandContext(runCtx, "javac", args...), "javac -encoding UTF-8 -d build/classes <sources>", root)
		}
		appendStep(step)
		if step.Status == "ok" {
			if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
				appendStep(runDockerCommand(runCtx, sandbox, root, dockerDisplay(sandbox, "java -cp build/classes "+opts.MainClass), "java", "-cp", "build/classes", opts.MainClass))
			} else {
				appendStep(runCommand(runCtx, javaCommand(runCtx, "build/classes", opts.MainClass), "java -cp build/classes "+opts.MainClass, root))
			}
		}
	case "junit":
		classpathEntries, pathErr := junitClasspathEntries(opts.TestClasspath)
		if pathErr != nil {
			return result, pathErr
		}
		classpath := strings.Join(classpathEntries, string(os.PathListSeparator))
		mainFiles, collectErr := collectJavaFiles(root, "src/main/java")
		if collectErr != nil {
			return result, collectErr
		}
		testFiles, collectErr := collectJavaFiles(root, "src/test/java")
		if collectErr != nil {
			return result, collectErr
		}
		classes := filepath.Join(root, "build", "classes")
		testClassesDir := filepath.Join(root, "build", "test-classes")
		if err = os.MkdirAll(classes, 0o700); err != nil {
			return result, err
		}
		if err = os.MkdirAll(testClassesDir, 0o700); err != nil {
			return result, err
		}
		coverageReport := ""
		if opts.JacocoAgent != "" {
			coverageReport = opts.JacocoReport
			if coverageReport == "" {
				coverageReport = filepath.Join(root, "build", "coverage", "jacoco.xml")
			}
			coverageReport, err = filepath.Abs(coverageReport)
			if err != nil {
				return result, err
			}
			if err = os.MkdirAll(filepath.Dir(coverageReport), 0o700); err != nil {
				return result, err
			}
		}
		if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
			mounts, containerClasspath, mountErr := junitContainerClasspath(classpathEntries)
			if mountErr != nil {
				return result, mountErr
			}
			relativeMain, relErr := relativeJavaFiles(root, "src/main/java")
			if relErr != nil {
				return result, relErr
			}
			relativeTest, relErr := relativeJavaFiles(root, "src/test/java")
			if relErr != nil {
				return result, relErr
			}
			mainArgs := append([]string{"javac", "-encoding", "UTF-8", "-cp", containerClasspath, "-d", "build/classes"}, relativeMain...)
			mainStep := runDockerCommandWithMounts(runCtx, sandbox, root, dockerDisplay(sandbox, "javac -encoding UTF-8 -cp <test-classpath> -d build/classes <main-sources>"), mounts, mainArgs...)
			appendStep(mainStep)
			if mainStep.Status == "ok" {
				testArgs := append([]string{"javac", "-encoding", "UTF-8", "-cp", "build/classes:" + containerClasspath, "-d", "build/test-classes"}, relativeTest...)
				testStep := runDockerCommandWithMounts(runCtx, sandbox, root, dockerDisplay(sandbox, "javac -encoding UTF-8 -cp <test-classpath> -d build/test-classes <test-sources>"), mounts, testArgs...)
				appendStep(testStep)
				if testStep.Status == "ok" {
					runArgs := []string{"java"}
					if opts.JacocoAgent != "" {
						mounts = append(mounts, SandboxMount{Host: opts.JacocoAgent, Container: "/trident-jacoco.jar", ReadOnly: true})
						runArgs = append(runArgs, "-javaagent:/trident-jacoco.jar=destfile=build/coverage/jacoco.xml,append=false")
					}
					runArgs = append(runArgs, "-cp", "build/classes:build/test-classes:"+containerClasspath, "org.junit.runner.JUnitCore")
					runArgs = append(runArgs, testClasses...)
					runStep := runDockerCommandWithMounts(runCtx, sandbox, root, dockerDisplay(sandbox, "java -cp <build-classes> org.junit.runner.JUnitCore "+strings.Join(testClasses, " ")), mounts, runArgs...)
					appendStep(runStep)
					result.TestSummary = parseTestSummary(runStep.Stdout + "\n" + runStep.Stderr)
				}
			}
		} else {
			mainArgs := append([]string{"-encoding", "UTF-8", "-cp", classpath, "-d", classes}, mainFiles...)
			mainStep := runCommand(runCtx, exec.CommandContext(runCtx, "javac", mainArgs...), "javac -encoding UTF-8 -cp <test-classpath> -d build/classes <main-sources>", root)
			appendStep(mainStep)
			if mainStep.Status == "ok" {
				testArgs := append([]string{"-encoding", "UTF-8", "-cp", classpath + string(os.PathListSeparator) + classes, "-d", testClassesDir}, testFiles...)
				testStep := runCommand(runCtx, exec.CommandContext(runCtx, "javac", testArgs...), "javac -encoding UTF-8 -cp <test-classpath> -d build/test-classes <test-sources>", root)
				appendStep(testStep)
				if testStep.Status == "ok" {
					runClasspath := classes + string(os.PathListSeparator) + testClassesDir + string(os.PathListSeparator) + classpath
					javaArgs := []string{}
					if opts.JacocoAgent != "" {
						javaArgs = append(javaArgs, "-javaagent:"+opts.JacocoAgent+"=destfile="+coverageReport+",append=false")
					}
					javaArgs = append(javaArgs, "-cp", runClasspath, "org.junit.runner.JUnitCore")
					javaArgs = append(javaArgs, testClasses...)
					command := exec.CommandContext(runCtx, "java", javaArgs...)
					runStep := runCommand(runCtx, command, "java -cp <build-classes> org.junit.runner.JUnitCore "+strings.Join(testClasses, " "), root)
					appendStep(runStep)
					result.TestSummary = parseTestSummary(runStep.Stdout + "\n" + runStep.Stderr)
				}
			}
		}
		if opts.JUnitReportDir != "" {
			summary, summaryErr := parseJUnitXMLDir(opts.JUnitReportDir)
			if summaryErr != nil {
				result.Error = summaryErr.Error()
			} else if summary != nil {
				result.JUnitXML = summary
			}
		}
		if coverageReport != "" {
			coverage, coverageErr := parseJacocoXML(coverageReport)
			if coverageErr != nil {
				result.Error = coverageErr.Error()
			} else if coverage != nil {
				coverage.ReportPath = filepath.Base(coverageReport)
				result.Coverage = coverage
			}
		}
	case "php-lint", "python-compile", "pytest", "node-check", "npm-test", "go-test", "dotnet-build", "dotnet-test":
		steps := runLanguageValidation(runCtx, root, opts.Profile, sandbox)
		for _, step := range steps {
			appendStep(step)
		}
	}
	result.Status = status
	result.DurationMS = time.Since(started).Milliseconds()
	if status == ValidationError {
		for _, step := range result.Commands {
			if step.ErrorMessage != "" {
				result.Error = step.ErrorMessage
				break
			}
		}
	}
	return result, nil
}

func mavenCompileCommand(ctx context.Context, dir string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		shell := os.Getenv("COMSPEC")
		if shell == "" {
			shell = "cmd.exe"
		}
		command := exec.CommandContext(ctx, shell, "/d", "/s", "/c", "mvn -o -B -q -DskipTests compile")
		command.Dir = dir
		return command
	}
	command := exec.CommandContext(ctx, "mvn", "-o", "-B", "-q", "-DskipTests", "compile")
	command.Dir = dir
	return command
}

func javaCommand(ctx context.Context, classes, mainClass string) *exec.Cmd {
	command := exec.CommandContext(ctx, "java", "-cp", classes, mainClass)
	return command
}

func collectJavaFiles(root, relative string) ([]string, error) {
	base := filepath.Join(root, filepath.FromSlash(relative))
	var files []string
	var total int64
	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || !strings.HasSuffix(info.Name(), ".java") {
			return nil
		}
		if len(files) >= MaxJavacFiles {
			return fmt.Errorf("javac profile exceeds %d source files", MaxJavacFiles)
		}
		if info.Size() > MaxFileBytes {
			return fmt.Errorf("javac source exceeds per-file budget")
		}
		total += info.Size()
		if total > 32<<20 {
			return fmt.Errorf("javac sources exceed total budget")
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no Java sources found under %s", relative)
	}
	sort.Strings(files)
	return files, nil
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := MaxOutputBytes - b.buffer.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.truncated = true
		p = p[:remaining]
	}
	_, _ = b.buffer.Write(p)
	return len(p), nil
}

func runCommand(ctx context.Context, command *exec.Cmd, display, dir string) CommandResult {
	result := CommandResult{Command: display, ExitCode: -1}
	command.Dir = dir
	command.Env = safeEnv()
	stdout := &limitedBuffer{}
	stderr := &limitedBuffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 2 * time.Second
	started := time.Now()
	err := command.Run()
	result.DurationMS = time.Since(started).Milliseconds()
	result.Stdout = stdout.buffer.String()
	result.Stderr = stderr.buffer.String()
	result.OutputTrunc = stdout.truncated || stderr.truncated
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.Status, result.ErrorMessage = "timeout", "validation command timed out"
	case err == nil:
		result.Status, result.ExitCode = "ok", 0
	case errors.Is(err, exec.ErrNotFound):
		result.Status, result.ErrorMessage = "start_error", "validation executable not found"
	case command.ProcessState != nil:
		result.Status, result.ExitCode = "failed", command.ProcessState.ExitCode()
	default:
		result.Status, result.ErrorMessage = "start_error", err.Error()
	}
	return result
}

// safeEnv avoids forwarding model keys, database URLs or other host secrets to
// the validation process.
func safeEnv() []string {
	allowed := []string{
		"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "JAVA_HOME", "M2_HOME", "MAVEN_HOME",
		"SystemRoot", "WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC", "USERPROFILE",
		"HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "GRADLE_USER_HOME",
	}
	env := make([]string, 0, len(allowed))
	for _, name := range allowed {
		if value := os.Getenv(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// buildOnlyProfile reports profiles that do not execute an application entry
// point and therefore do not require --main-class.
func buildOnlyProfile(profile string) bool {
	return IsBuildOnlyProfile(profile)
}

func IsBuildOnlyProfile(profile string) bool {
	return profile == "maven-compile" || profile == "maven-test" || profile == "gradle-test" ||
		profile == "php-lint" || profile == "python-compile" || profile == "pytest" ||
		profile == "node-check" || profile == "npm-test" || profile == "go-test" ||
		profile == "dotnet-build" || profile == "dotnet-test"
}

func hasGradleBuild(root string) bool {
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		if info, err := os.Stat(filepath.Join(root, name)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// validateModules runs the same bounded profile inside each explicitly selected
// module directory. It never guesses modules from a build file and never walks
// outside the workspace. The aggregate status is the worst module status.
func validateModules(ctx context.Context, root string, opts ValidationOptions) (ValidationResult, error) {
	if len(opts.Modules) > MaxModules {
		return ValidationResult{}, fmt.Errorf("at most %d modules can be validated", MaxModules)
	}
	sandbox, err := opts.Sandbox.normalized()
	if err != nil {
		return ValidationResult{}, err
	}
	aggregate := ValidationResult{
		Profile: opts.Profile, MainClass: opts.MainClass, TestClass: opts.TestClass,
		TestClasses: append([]string{}, opts.TestClasses...), Sandbox: sandbox.Kind,
		Commands: []CommandResult{}, Modules: []ModuleResult{}, Status: ValidationPassed,
	}
	seen := map[string]bool{}
	for _, module := range opts.Modules {
		directory, relative, pathErr := moduleDirectory(root, module)
		if pathErr != nil {
			return aggregate, pathErr
		}
		if seen[relative] {
			return aggregate, fmt.Errorf("duplicate module %q", relative)
		}
		seen[relative] = true
		sub := opts
		sub.Modules = nil
		result, subErr := Validate(ctx, directory, sub)
		if subErr != nil {
			return aggregate, subErr
		}
		for index := range result.Commands {
			result.Commands[index].Module = relative
		}
		aggregate.Commands = append(aggregate.Commands, result.Commands...)
		aggregate.DurationMS += result.DurationMS
		aggregate.Status = worstStatus(aggregate.Status, result.Status)
		moduleResult := ModuleResult{Module: relative, Status: result.Status, DurationMS: result.DurationMS}
		if result.TestSummary != nil {
			moduleResult.Tests = result.TestSummary.Tests
			moduleResult.Failures = result.TestSummary.Failures
			moduleResult.Errors = result.TestSummary.Errors
			aggregate.TestSummary = addTestSummary(aggregate.TestSummary, result.TestSummary)
		}
		if result.JUnitXML != nil {
			aggregate.JUnitXML = addJUnitSummary(aggregate.JUnitXML, result.JUnitXML, relative)
		}
		if result.Coverage != nil {
			aggregate.Coverage = addCoverage(aggregate.Coverage, result.Coverage)
		}
		if result.Error != "" {
			moduleResult.Error = result.Error
			if aggregate.Error == "" {
				aggregate.Error = result.Error
			}
		}
		aggregate.Modules = append(aggregate.Modules, moduleResult)
	}
	return aggregate, nil
}

func moduleDirectory(root, module string) (string, string, error) {
	module = strings.TrimSpace(module)
	if module == "" || len(module) > 256 || filepath.IsAbs(module) {
		return "", "", fmt.Errorf("module must be a relative path inside the workspace")
	}
	cleaned := filepath.Clean(filepath.FromSlash(module))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("module %q escapes the workspace", module)
	}
	absolute := filepath.Join(root, cleaned)
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", "", fmt.Errorf("module %q escapes the workspace", module)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return "", "", fmt.Errorf("module %q is not an existing directory inside the workspace", module)
	}
	return absolute, filepath.ToSlash(relative), nil
}

var statusRank = map[string]int{
	ValidationPassed:  0,
	ValidationFailed:  1,
	ValidationError:   2,
	ValidationTimeout: 3,
}

func worstStatus(left, right string) string {
	if statusRank[right] > statusRank[left] {
		return right
	}
	return left
}

func addTestSummary(total, next *TestRunSummary) *TestRunSummary {
	if total == nil {
		copied := *next
		return &copied
	}
	total.Tests += next.Tests
	total.Failures += next.Failures
	total.Errors += next.Errors
	total.Skipped += next.Skipped
	if next.Raw != "" {
		if total.Raw != "" {
			total.Raw += ","
		}
		total.Raw += next.Raw
	}
	return total
}

func addJUnitSummary(total, next *JUnitXMLSummary, module string) *JUnitXMLSummary {
	if total == nil {
		total = &JUnitXMLSummary{Files: []string{}}
	}
	total.Suites += next.Suites
	total.Tests += next.Tests
	total.Failures += next.Failures
	total.Errors += next.Errors
	total.Skipped += next.Skipped
	for _, file := range next.Files {
		total.Files = append(total.Files, module+"/"+file)
	}
	return total
}

func addCoverage(total, next *CoverageSummary) *CoverageSummary {
	if total == nil {
		copied := *next
		return &copied
	}
	total.LineCovered += next.LineCovered
	total.LineTotal += next.LineTotal
	total.BranchCovered += next.BranchCovered
	total.BranchTotal += next.BranchTotal
	total.MethodCovered += next.MethodCovered
	total.MethodTotal += next.MethodTotal
	if total.LineTotal > 0 {
		total.LinePercent = float64(total.LineCovered) / float64(total.LineTotal) * 100
	}
	if total.BranchTotal > 0 {
		total.BranchPercent = float64(total.BranchCovered) / float64(total.BranchTotal) * 100
	}
	return total
}
