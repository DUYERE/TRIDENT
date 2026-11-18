package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLegacyAPIRoutesRemoved locks the console API surface to the routes the
// current browser UI actually uses. These four endpoints were either replaced
// by a canonical route, fixed at 501, or left without a consumer.
func TestLegacyAPIRoutesRemoved(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/agent/runs"},
		{http.MethodPost, "/api/agent/models/default"},
		{http.MethodPost, "/api/agent/chat/cancel?run_id=1"},
		{http.MethodPost, "/api/project"},
	}
	for _, tc := range cases {
		response, body := c.do(tc.method, tc.path, true, true)
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s must be removed, got %d: %s", tc.method, tc.path, response.StatusCode, body)
		}
	}
}
