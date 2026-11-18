package r3

import (
	"context"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const MaxLanguageValidationFiles = 100

type toolchainProbe struct {
	Profile string
	Tool    string
	Found   bool
	Path    string
	Reason  string
}

func runLanguageValidation(ctx context.Context, root, profile string, sandbox Sandbox) []CommandResult {
	if sandbox.Kind == SandboxDocker || sandbox.Kind == SandboxGVisor {
		return []CommandResult{{Command: profile, Status: "start_error", ErrorMessage: "language validation profiles currently run on the host toolchain; container sandbox is not wired for them"}}
	}
	switch profile {
	case "php-lint":
		files, err := collectFilesWithExt(root, ".php", MaxLanguageValidationFiles)
		if err != nil || len(files) == 0 {
			return []CommandResult{{Command: "php -l <php-files>", Status: "start_error", ErrorMessage: "no PHP files found or collection failed"}}
		}
		probe := probeTool("php")
		if !probe.Found {
			return []CommandResult{{Command: "php -l <php-files>", Status: "start_error", ErrorMessage: "php executable not found"}}
		}
		result := make([]CommandResult, 0, len(files))
		for _, file := range files {
			args := []string{"-l", file}
			result = append(result, runCommand(ctx, exec.CommandContext(ctx, probe.Path, args...), "php -l "+relativeDisplay(root, file), root))
		}
		return result
	case "python-compile":
		probe := probePython()
		if !probe.Found {
			return []CommandResult{{Command: "python -m compileall", Status: "start_error", ErrorMessage: "python executable not found"}}
		}
		return []CommandResult{runCommand(ctx, exec.CommandContext(ctx, probe.Path, "-m", "compileall", "-q", "."), "python -m compileall -q .", root)}
	case "pytest":
		probe := probePython()
		if !probe.Found {
			return []CommandResult{{Command: "python -m pytest -q", Status: "start_error", ErrorMessage: "python executable not found"}}
		}
		return []CommandResult{runCommand(ctx, exec.CommandContext(ctx, probe.Path, "-m", "pytest", "-q"), "python -m pytest -q", root)}
	case "node-check":
		files, err := collectFilesWithExt(root, ".js", MaxLanguageValidationFiles)
		if err != nil || len(files) == 0 {
			return []CommandResult{{Command: "node --check <js-files>", Status: "start_error", ErrorMessage: "no JavaScript files found or collection failed"}}
		}
		probe := probeTool("node")
		if !probe.Found {
			return []CommandResult{{Command: "node --check <js-files>", Status: "start_error", ErrorMessage: "node executable not found"}}
		}
		result := make([]CommandResult, 0, len(files))
		for _, file := range files {
			args := []string{"--check", file}
			result = append(result, runCommand(ctx, exec.CommandContext(ctx, probe.Path, args...), "node --check "+relativeDisplay(root, file), root))
		}
		return result
	case "npm-test":
		probe := probeTool("npm")
		if !probe.Found {
			return []CommandResult{{Command: "npm test -- --runInBand", Status: "start_error", ErrorMessage: "npm executable not found"}}
		}
		if info, err := os.Stat(filepath.Join(root, "package.json")); err != nil || !info.Mode().IsRegular() {
			return []CommandResult{{Command: "npm test", Status: "start_error", ErrorMessage: "package.json not found"}}
		}
		return []CommandResult{runCommand(ctx, exec.CommandContext(ctx, probe.Path, "test", "--", "--runInBand"), "npm test -- --runInBand", root)}
	case "go-test":
		probe := probeTool("go")
		if !probe.Found {
			return []CommandResult{{Command: "go test ./...", Status: "start_error", ErrorMessage: "go executable not found"}}
		}
		if info, err := os.Stat(filepath.Join(root, "go.mod")); err != nil || !info.Mode().IsRegular() {
			return []CommandResult{{Command: "go test ./...", Status: "start_error", ErrorMessage: "go.mod not found"}}
		}
		return []CommandResult{runCommand(ctx, exec.CommandContext(ctx, probe.Path, "test", "./..."), "go test ./...", root)}
	case "dotnet-build", "dotnet-test":
		probe := probeTool("dotnet")
		if !probe.Found {
			return []CommandResult{{Command: "dotnet " + profile, Status: "start_error", ErrorMessage: "dotnet executable not found"}}
		}
		project, err := firstFileWithExt(root, ".csproj", MaxLanguageValidationFiles)
		if err != nil || project == "" {
			return []CommandResult{{Command: "dotnet " + strings.TrimPrefix(profile, "dotnet-"), Status: "start_error", ErrorMessage: "no .csproj found"}}
		}
		args := []string{strings.TrimPrefix(profile, "dotnet-"), project}
		return []CommandResult{runCommand(ctx, exec.CommandContext(ctx, probe.Path, args...), "dotnet "+strings.TrimPrefix(profile, "dotnet-")+" "+relativeDisplay(root, project), root)}
	}
	return []CommandResult{{Command: profile, Status: "start_error", ErrorMessage: "unsupported language profile"}}
}

func probeTool(name string) toolchainProbe {
	pathValue, err := exec.LookPath(name)
	if err != nil || pathValue == "" {
		return toolchainProbe{Tool: name, Found: false, Reason: "not_found_in_path"}
	}
	return toolchainProbe{Tool: name, Found: true, Path: pathValue}
}

func probePython() toolchainProbe {
	for _, name := range []string{"python3", "python"} {
		if probe := probeTool(name); probe.Found {
			return probe
		}
	}
	return toolchainProbe{Tool: "python", Found: false, Reason: "not_found_in_path"}
}

func collectFilesWithExt(root, ext string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = MaxLanguageValidationFiles
	}
	var files []string
	err := filepath.Walk(root, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := strings.ToLower(info.Name())
			if name == "node_modules" || name == "vendor" || name == ".git" || name == "dist" || name == "bin" || name == "obj" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode().IsRegular() && strings.EqualFold(path.Ext(current), ext) {
			files = append(files, current)
			if len(files) >= limit {
				return filepath.SkipAll
			}
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func firstFileWithExt(root, ext string, limit int) (string, error) {
	files, err := collectFilesWithExt(root, ext, limit)
	if err != nil || len(files) == 0 {
		return "", err
	}
	return files[0], nil
}

func relativeDisplay(root, file string) string {
	relative, err := filepath.Rel(root, file)
	if err != nil {
		return file
	}
	return relative
}
