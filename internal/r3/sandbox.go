package r3

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Sandbox selects where validation commands run. The process profile is the
// existing host-process slice; docker adds container and network isolation but
// is not a full VM boundary.
type Sandbox struct {
	Kind      string `json:"kind,omitempty"`
	Image     string `json:"image,omitempty"`
	Network   string `json:"network,omitempty"`
	Memory    string `json:"memory,omitempty"`
	CPUs      string `json:"cpus,omitempty"`
	PidsLimit int    `json:"pids_limit,omitempty"`
	// MavenRepo is an optional absolute host directory mounted read-only at
	// /root/.m2 so offline Maven can resolve cached plugins and artifacts.
	MavenRepo string `json:"maven_repo,omitempty"`
}

const (
	SandboxProcess = "process"
	SandboxDocker  = "docker"
	SandboxGVisor  = "gvisor"
	dockerMemory   = "1g"
	dockerCPUs     = "1"
	dockerPids     = 256
)

var pinnedImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$`)

func (s Sandbox) normalized() (Sandbox, error) {
	if s.Kind == "" {
		s.Kind = SandboxProcess
	}
	switch s.Kind {
	case SandboxProcess:
		if s.Image != "" {
			return s, fmt.Errorf("sandbox image is only valid for docker")
		}
		return s, nil
	case SandboxDocker, SandboxGVisor:
		if !pinnedImagePattern.MatchString(s.Image) {
			return s, fmt.Errorf("docker/gvisor sandbox image must be pinned by @sha256 digest")
		}
		if s.Network == "" {
			s.Network = "none"
		}
		if s.Network != "none" && s.Network != "default" {
			return s, fmt.Errorf("docker sandbox network must be none or default")
		}
		if s.Memory == "" {
			s.Memory = dockerMemory
		}
		if s.CPUs == "" {
			s.CPUs = dockerCPUs
		}
		if s.PidsLimit == 0 {
			s.PidsLimit = dockerPids
		}
		if s.PidsLimit < 1 || s.PidsLimit > 4096 {
			return s, fmt.Errorf("docker sandbox pids limit outside supported bounds")
		}
		if s.MavenRepo != "" {
			info, err := os.Stat(s.MavenRepo)
			if err != nil || !info.IsDir() || !filepath.IsAbs(s.MavenRepo) {
				return s, fmt.Errorf("docker sandbox maven repo must be an absolute directory")
			}
		}
		return s, nil
	default:
		return s, fmt.Errorf("sandbox must be process, docker or gvisor")
	}
}

// preflightGVisor fails closed unless the Docker daemon exposes the runsc
// runtime. gVisor intercepts syscalls in a user-space kernel; it is not a full
// VM, but it is a stronger boundary than the default container runtime.
func preflightGVisor(ctx context.Context) error {
	command := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Runtimes}}")
	command.Env = safeEnv()
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("gvisor sandbox requires a reachable Docker daemon with runsc: %w", err)
	}
	if !strings.Contains(string(output), "runsc") {
		return fmt.Errorf("gvisor sandbox requires the runsc runtime to be registered with Docker")
	}
	return nil
}

type SandboxMount struct {
	Host      string
	Container string
	ReadOnly  bool
}

func newContainerName() string {
	return fmt.Sprintf("trident-r3-%d", time.Now().UnixNano())
}

// dockerCommand builds a fixed docker run invocation. The workspace is mounted
// read-write at /workspace because the build writes target/ or build/; the root
// filesystem stays ephemeral and all capabilities are dropped.
func dockerCommand(ctx context.Context, sandbox Sandbox, root, name string, command ...string) *exec.Cmd {
	return dockerCommandWithMounts(ctx, sandbox, root, name, nil, command...)
}

func dockerCommandWithMounts(ctx context.Context, sandbox Sandbox, root, name string, mounts []SandboxMount, command ...string) *exec.Cmd {
	args := []string{
		"run", "--rm", "--name", name,
		"--network", sandbox.Network,
		"--memory", sandbox.Memory,
		"--cpus", sandbox.CPUs,
		"--pids-limit", strconv.Itoa(sandbox.PidsLimit),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"-e", "HOME=/root",
		"-v", root + ":/workspace",
		"-w", "/workspace",
	}
	if sandbox.Kind == SandboxGVisor {
		args = append(args, "--runtime", "runsc")
	}
	if sandbox.MavenRepo != "" {
		args = append(args, "-v", sandbox.MavenRepo+":/root/.m2:ro")
	}
	for _, mount := range mounts {
		binding := mount.Host + ":" + mount.Container
		if mount.ReadOnly {
			binding += ":ro"
		}
		args = append(args, "-v", binding)
	}
	args = append(args, sandbox.Image)
	args = append(args, command...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = root
	return cmd
}

func dockerCleanup(name string) {
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
}

// dockerDisplay is the stable, secret-free command label stored in reports.
func dockerDisplay(sandbox Sandbox, command string) string {
	return "docker run --network " + sandbox.Network + " --cap-drop ALL " + sandbox.Image + " " + command
}

func relativeJavaFiles(root, relative string) ([]string, error) {
	files, err := collectJavaFiles(root, relative)
	if err != nil {
		return nil, err
	}
	relativeFiles := make([]string, 0, len(files))
	for _, file := range files {
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return nil, err
		}
		relativeFiles = append(relativeFiles, filepath.ToSlash(rel))
	}
	return relativeFiles, nil
}

func displayPathList(prefix string, values []string) string {
	if len(values) == 0 {
		return prefix
	}
	return prefix + " " + strings.Join(values, " ")
}

func runDockerCommand(ctx context.Context, sandbox Sandbox, root, display string, command ...string) CommandResult {
	return runDockerCommandWithMounts(ctx, sandbox, root, display, nil, command...)
}

func runDockerCommandWithMounts(ctx context.Context, sandbox Sandbox, root, display string, mounts []SandboxMount, command ...string) CommandResult {
	name := newContainerName()
	result := runCommand(ctx, dockerCommandWithMounts(ctx, sandbox, root, name, mounts, command...), display, root)
	if result.Status != "ok" {
		// A killed docker CLI or timed-out container may outlive --rm.
		dockerCleanup(name)
	}
	return result
}
