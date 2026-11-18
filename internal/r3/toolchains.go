package r3

import "path/filepath"

const (
	ToolchainAvailable   = "available"
	ToolchainUnavailable = "toolchain_unavailable"
)

// ToolchainStatus is the read-only host probe used by the Web console. It
// reports what is reachable in PATH; it does not execute the compiler or test
// runner, so "available" never means the profile will pass.
type ToolchainStatus struct {
	Profile    string `json:"profile"`
	Language   string `json:"language"`
	Tool       string `json:"tool"`
	Available  bool   `json:"available"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Path       string `json:"path,omitempty"`
	Limitation string `json:"limitation"`
}

type toolchainSpec struct {
	profile    string
	language   string
	tool       string
	python     bool
	limitation string
}

func toolchainSpecs() []toolchainSpec {
	return []toolchainSpec{
		{"php-lint", "php", "php", false, "php -l only checks syntax; it does not run PHP 8 or prove a vulnerability is fixed"},
		{"python-compile", "python", "python", true, "compileall only checks syntax; imports and runtime behavior are not executed"},
		{"pytest", "python", "python", true, "only the interpreter is probed; the pytest module and project dependencies may still be missing"},
		{"node-check", "javascript", "node", false, "node --check only checks syntax; runtime behavior is not executed"},
		{"npm-test", "javascript", "npm", false, "requires package.json and the project test runner; execution is isolated"},
		{"go-test", "go", "go", false, "requires go.mod; tests may access the network unless the workspace isolates them"},
		{"dotnet-build", "dotnet", "dotnet", false, "dotnet build only compiles; runtime behavior is not verified"},
		{"dotnet-test", "dotnet", "dotnet", false, "only the dotnet executable is probed; the project's test runner and SDK version may still differ"},
	}
}

// ProbeToolchains reports the host toolchain for language validation profiles.
// Missing tools are explicit toolchain_unavailable, never a synthetic pass.
func ProbeToolchains() []ToolchainStatus {
	specs := toolchainSpecs()
	statuses := make([]ToolchainStatus, 0, len(specs))
	for _, spec := range specs {
		probe := probeTool(spec.tool)
		if spec.python {
			probe = probePython()
		}
		status := ToolchainStatus{
			Profile: spec.profile, Language: spec.language, Tool: probe.Tool,
			Available: probe.Found, Limitation: spec.limitation,
		}
		if probe.Found {
			status.Status = ToolchainAvailable
			status.Path = filepath.Base(probe.Path)
		} else {
			status.Status = ToolchainUnavailable
			status.Reason = probe.Reason
			if status.Reason == "" {
				status.Reason = "not_found_in_path"
			}
		}
		statuses = append(statuses, status)
	}
	return statuses
}
