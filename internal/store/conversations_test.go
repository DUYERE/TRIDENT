package store

import (
	"strings"
	"testing"
)

func TestNormalizeConversationCreate(t *testing.T) {
	valid := CreateConversationParams{
		Key:          "conv-key",
		SnapshotHash: strings.Repeat("a", 64),
		Title:        " 审计登录入口 ",
		Mode:         "chat",
	}
	got, err := normalizeConversationCreate(valid)
	if err != nil {
		t.Fatalf("valid conversation rejected: %v", err)
	}
	if got.Title != "审计登录入口" {
		t.Fatalf("title must be trimmed, got %q", got.Title)
	}
	if got.SnapshotHash != strings.Repeat("a", 64) {
		t.Fatalf("hash must stay lowercase, got %q", got.SnapshotHash)
	}

	tests := []struct {
		name string
		p    CreateConversationParams
	}{
		{"empty key", CreateConversationParams{SnapshotHash: strings.Repeat("a", 64), Title: "x", Mode: "chat"}},
		{"short hash", CreateConversationParams{Key: "k", SnapshotHash: "abc", Title: "x", Mode: "chat"}},
		{"non-hex hash", CreateConversationParams{Key: "k", SnapshotHash: strings.Repeat("z", 64), Title: "x", Mode: "chat"}},
		{"empty title", CreateConversationParams{Key: "k", SnapshotHash: strings.Repeat("a", 64), Title: " ", Mode: "chat"}},
		{"bad mode", CreateConversationParams{Key: "k", SnapshotHash: strings.Repeat("a", 64), Title: "x", Mode: "other"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizeConversationCreate(tc.p); err == nil {
				t.Fatalf("case %s must be rejected", tc.name)
			}
		})
	}
}
