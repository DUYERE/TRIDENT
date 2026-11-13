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
