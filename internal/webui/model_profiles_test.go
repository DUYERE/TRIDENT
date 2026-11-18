package webui

import "testing"

// Env var NAMES are case-sensitive on Linux/macOS and case-insensitive on
// Windows; forcing uppercase rejected legitimate configurations such as
// deepseek_api_key. Only the POSIX identifier shape stays enforced.
func TestBuildProfileAcceptsAnyEnvNameCase(t *testing.T) {
	base := profileUpsertRequest{
		Label: "demo", Endpoint: "https://api.deepseek.com/v1", Model: "deepseek-chat",
	}
	cases := map[string]string{
		"TRIDENT_MODEL_API_KEY": "TRIDENT_MODEL_API_KEY",
		"deepseek_api_key":      "deepseek_api_key",
		"DeepSeek_Api_Key":      "DeepSeek_Api_Key",
		"_private_key":          "_private_key",
		"key2":                  "key2",
	}
	for input, want := range cases {
		request := base
		request.KeyEnv = input
		profile, err := buildProfile(request)
		if err != nil {
			t.Fatalf("key_env %q rejected: %v", input, err)
		}
		if profile.KeyEnv != want {
			t.Fatalf("key_env %q stored as %q", input, profile.KeyEnv)
		}
	}
	// Values that are not environment variable names still fail closed,
	// because a shell could never export them under that exact name.
	for _, bad := range []string{"2start", "with space", "with-dash", "sk-abc.def"} {
		request := base
		request.KeyEnv = bad
		if _, err := buildProfile(request); err == nil {
			t.Fatalf("key_env %q must be rejected", bad)
		}
	}
	// Empty falls back to the documented default.
	profile, err := buildProfile(base)
	if err != nil || profile.KeyEnv != "TRIDENT_MODEL_API_KEY" {
		t.Fatalf("empty key_env must default: %+v %v", profile, err)
	}
}
