package agent

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"trident/internal/model"
)

func configFixture() Config {
	return Config{Version: Version, Endpoint: "https://api.example.invalid/v1", Model: "explicit-test-model", OutputParameter: "max_completion_tokens", TimeoutSeconds: 30, MaxOutputTokens: 1024, MaxRequestBytes: 2 << 20, MaxResponseBytes: 512 << 10}
}

func TestConfigDefaultDenyAndExpiry(t *testing.T) {
	c := configFixture()
	now := time.Now().UTC()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	if e := c.AllowRequest(now); !errors.Is(e, model.ErrDenied) {
		t.Fatalf("default egress allowed: %v", e)
	}
	c.EgressAllowed = true
	c.EgressExpiresAt = now.Add(time.Minute)
	if e := c.AllowRequest(now); e != nil {
		t.Fatal(e)
	}
	if e := c.AllowRequest(c.EgressExpiresAt); !errors.Is(e, model.ErrDenied) {
		t.Fatalf("expired approval accepted %v", e)
	}
}

func TestConfigEndpointAndLimits(t *testing.T) {
	for _, endpoint := range []string{"", "http://example.invalid/v1", "http://localhost/v1", "https://user:pass@example.invalid", "https://example.invalid/v1?key=x", "https://example.invalid/#fragment"} {
		c := configFixture()
		c.Endpoint = endpoint
		c.AllowLoopbackHTTP = true
		if e := c.Validate(); e == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	c := configFixture()
	c.Endpoint = "http://127.0.0.1:1234/v1"
	if c.Validate() == nil {
		t.Fatal("HTTP loopback implicitly enabled")
	}
	c.AllowLoopbackHTTP = true
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.MaxRequestBytes = 1 << 30
	if c.Validate() == nil {
		t.Fatal("unbounded request accepted")
	}
	if _, e := DecodeConfig([]byte(`{"version":"trident-agent-v1","api_key":"do-not-store"}`)); e == nil {
		t.Fatal("secret config field accepted")
	}
}

func TestConfigAnalysisAdvisoryPath(t *testing.T) {
	c := configFixture()
	c.AnalysisAdvisoryPath = "relative/advisory.json"
	if c.Validate() == nil {
		t.Fatal("relative advisory path accepted")
	}
	c.AnalysisAdvisoryPath = t.TempDir() + string(os.PathSeparator) + "advisory.json"
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(c)
	decoded, e := DecodeConfig(encoded)
	if e != nil || decoded.AnalysisAdvisoryPath != c.AnalysisAdvisoryPath {
		t.Fatalf("advisory config round trip: %+v %v", decoded, e)
	}
	c.AnalysisAdvisoryPath = "/tmp/advisory.json\nnext"
	if c.Validate() == nil {
		t.Fatal("control characters accepted")
	}
}
