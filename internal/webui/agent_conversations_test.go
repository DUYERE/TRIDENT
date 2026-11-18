package webui

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestConversationTitle(t *testing.T) {
	if got := conversationTitle("  审计登录入口 \n 第二条"); got != "审计登录入口" {
		t.Fatalf("first line must become the title, got %q", got)
	}
	if got := conversationTitle("   "); got == "" {
		t.Fatal("empty goal must still produce a non-empty fallback title")
	}
	long := conversationTitle(strings.Repeat("审", 400))
	if len([]byte(long)) > 512 {
		t.Fatalf("title exceeds 512 bytes: %d", len([]byte(long)))
	}
	if !utf8.ValidString(long) {
		t.Fatal("title must remain valid UTF-8")
	}
	if !strings.HasSuffix(long, "…") {
		t.Fatalf("truncated title must be marked, got suffix %q", long[len(long)-3:])
	}
}
