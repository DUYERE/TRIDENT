package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// [01] 误配置和未批准外发必须在数据库连接、模型网络之前失败。
func TestAgentCLIRejectsInvalidArgumentsBeforeIO(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "not-a-valid-database")
	for _, args := range [][]string{
		nil, {"shell"}, {"run"}, {"status"}, {"resume", "--id", "0"},
		{"run", "--key", "x", "--snapshot", "not-opened", "--snapshot-hash", strings.Repeat("a", 64), "--goal", "synthetic", "--endpoint", "https://example.invalid/v1", "--model", "explicit"},
		{"run", "--key", "x", "--snapshot", "not-opened", "--snapshot-hash", strings.Repeat("a", 64), "--goal", "synthetic", "--approve-egress", "--endpoint", "http://example.invalid/v1", "--model", "explicit"},
	} {
		var output bytes.Buffer
		if e := runAgent(context.Background(), args, &output); e == nil || output.Len() != 0 {
			t.Fatalf("invalid command accepted %q", args)
		}
	}
}
