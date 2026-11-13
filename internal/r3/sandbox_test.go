package r3

import (
	"context"
	"strings"
	"testing"
)

const testImage = "maven:3.9.9-eclipse-temurin-17@sha256:f58d59b6273e785ac0a4477f6e9b5ba1d7731c75b906c0f7b34076f1851318cc"

func TestSandboxValidation(t *testing.T) {
	if _, err := (Sandbox{}).normalized(); err != nil {
		t.Fatal(err)
	}
	if _, err := (Sandbox{Kind: SandboxProcess, Image: testImage}).normalized(); err == nil {
		t.Fatal("process sandbox accepted an image")
	}
	if _, err := (Sandbox{Kind: SandboxDocker}).normalized(); err == nil {
		t.Fatal("docker sandbox accepted a missing image")
	}
	if _, err := (Sandbox{Kind: SandboxDocker, Image: "maven:3.9.9"}).normalized(); err == nil {
		t.Fatal("docker sandbox accepted an unpinned tag")
	}
	if _, err := (Sandbox{Kind: SandboxDocker, Image: testImage, Network: "host"}).normalized(); err == nil {
		t.Fatal("docker sandbox accepted an arbitrary network")
	}
	if _, err := (Sandbox{Kind: SandboxDocker, Image: testImage, PidsLimit: 99999}).normalized(); err == nil {
		t.Fatal("docker sandbox accepted an unbounded pid limit")
	}
	sandbox, err := (Sandbox{Kind: SandboxDocker, Image: testImage}).normalized()
	if err != nil || sandbox.Network != "none" || sandbox.Memory != "1g" || sandbox.CPUs != "1" || sandbox.PidsLimit != 256 {
		t.Fatalf("defaults: %+v (%v)", sandbox, err)
	}
}

func TestDockerCommandIsolationArguments(t *testing.T) {
	sandbox, err := (Sandbox{Kind: SandboxDocker, Image: testImage, MavenRepo: t.TempDir()}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	command := dockerCommand(context.Background(), sandbox, "/workspace", "trident-test", "mvn", "-o", "compile")
	joined := strings.Join(command.Args, " ")
	for _, required := range []string{"run", "--rm", "--name trident-test", "--network none", "--memory 1g", "--cpus 1", "--pids-limit 256", "--cap-drop ALL", "--security-opt no-new-privileges", "-v /workspace:/workspace", "-w /workspace", testImage, "mvn -o compile"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("docker args missing %q: %s", required, joined)
		}
	}
	if strings.Contains(joined, "TRIDENT_") || strings.Contains(joined, "--privileged") {
		t.Fatalf("unsafe docker args: %s", joined)
	}
}

func TestGVisorAndJUnitContainerArguments(t *testing.T) {
	sandbox, err := (Sandbox{Kind: SandboxGVisor, Image: testImage}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	command := dockerCommand(context.Background(), sandbox, "/workspace", "trident-test", "java", "-version")
	joined := strings.Join(command.Args, " ")
	if !strings.Contains(joined, "--runtime runsc") || !strings.Contains(joined, "--network none") {
		t.Fatalf("gvisor args: %s", joined)
	}
	classpath := []string{t.TempDir(), t.TempDir()}
	mounts, containerPath, err := junitContainerClasspath(classpath)
	if err != nil {
		t.Fatal(err)
	}
	command = dockerCommandWithMounts(context.Background(), sandbox, "/workspace", "trident-test", mounts, "java", "-cp", "build/classes"+":"+containerPath, "org.junit.runner.JUnitCore", "demo.A")
	joined = strings.Join(command.Args, " ")
	for _, required := range []string{"--runtime runsc", "/trident-cp/0:ro", "/trident-cp/1:ro", "org.junit.runner.JUnitCore demo.A"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("junit docker args missing %q: %s", required, joined)
		}
	}
}
