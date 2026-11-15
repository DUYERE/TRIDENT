package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestValidateLoopbackAddr(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8787", "127.0.0.2:1", "localhost:9000", "[::1]:8787"} {
		if _, err := validateLoopbackAddr(addr); err != nil {
			t.Fatalf("valid loopback address rejected: %s: %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8787", "192.168.1.10:8787", "example.com:8787", "127.0.0.1", ":8787", ""} {
		if _, err := validateLoopbackAddr(addr); err == nil {
			t.Fatalf("non-loopback address accepted: %q", addr)
		}
	}
}

func TestRunWebRejectsUnsafeArguments(t *testing.T) {
	if err := runWeb(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("web without a snapshot must fail")
	}
	err := runWeb(context.Background(), []string{
		"--snapshot", "snapshot", "--snapshot-hash", strings.Repeat("a", 64), "--addr", "0.0.0.0:8787",
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("wildcard listener must be rejected: %v", err)
	}
}

func TestRunWebExplainsBadArguments(t *testing.T) {
	// A missing dash turns the flag into a positional argument; the error must
	// name it instead of printing a bare usage line.
	err := runWeb(context.Background(), []string{"workspace", ".trident", "--token", "123"}, io.Discard)
	if err == nil {
		t.Fatal("positional arguments must fail")
	}
	if !strings.Contains(err.Error(), "--workspace") || !strings.Contains(err.Error(), "缺少 --") {
		t.Fatalf("missing-dash diagnostic is not actionable: %v", err)
	}

	// A short token must be reported as a token problem with its actual length.
	err = runWeb(context.Background(), []string{"--workspace", t.TempDir(), "--token", "123"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--token") || !strings.Contains(err.Error(), "当前 3 字节") {
		t.Fatalf("short token diagnostic is not actionable: %v", err)
	}
}
