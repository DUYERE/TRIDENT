package webui

import "testing"

// The chat page no longer offers per-run budget controls, so every limit has to
// resolve from the selected profile. A profile without defaults (hand-edited or
// migrated models.json) must fall back to the built-in baseline instead of
// producing a zero-call run.
func TestChatLimitsResolveFromProfile(t *testing.T) {
	cases := []struct {
		name     string
		value    int64
		fallback int64
		want     int64
	}{
		{"profile value wins", 18, chatDefaultModelCalls, 18},
		{"zeroed profile falls back", 0, chatDefaultModelCalls, chatDefaultModelCalls},
		{"negative profile falls back", -4, chatDefaultToolCalls, chatDefaultToolCalls},
	}
	for _, tc := range cases {
		if got := profileLimit(tc.value, tc.fallback); got != tc.want {
			t.Errorf("%s: profileLimit(%d, %d) = %d, want %d", tc.name, tc.value, tc.fallback, got, tc.want)
		}
	}

	if got := clampInt(0, profileLimit(0, chatDefaultModelCalls), 1, ChatMaxModelCalls); got != chatDefaultModelCalls {
		t.Fatalf("an absent request field must use the profile default, got %d", got)
	}
	if got := clampInt(999_999, profileLimit(0, chatDefaultTokens), 4096, ChatMaxTokens); got != ChatMaxTokens {
		t.Fatalf("a request override must stay capped, got %d", got)
	}
	if got := clampInt(512, profileLimit(0, chatDefaultTokens), 4096, ChatMaxTokens); got != 4096 {
		t.Fatalf("a token override below the floor must be raised, got %d", got)
	}
}
