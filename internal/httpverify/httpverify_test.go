package httpverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("login page"))
	})
	mux.HandleFunc("/dologin", func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Form.Get("user") != "admin" || request.Form.Get("pass") != "secret" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
		http.Redirect(writer, request, "/admin", http.StatusFound)
	})
	mux.HandleFunc("/admin", func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("session")
		if err != nil {
			http.Redirect(writer, request, "/login", http.StatusFound)
			return
		}
		if cookie.Value == "guest" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("admin page"))
	})
	mux.HandleFunc("/csrf-login", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`<html><head><meta name="_csrf" content="token-abc"></head>` +
			`<body><form><input type="hidden" name="_csrf" value="token-abc"></form></body></html>`))
	})
	mux.HandleFunc("/secure-login", func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Form.Get("_csrf") != "token-abc" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		user := request.Form.Get("user")
		if request.Form.Get("pass") != "secret" || (user != "admin" && user != "guest") {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "session", Value: user, Path: "/"})
		http.Redirect(writer, request, "/admin", http.StatusFound)
	})
	mux.HandleFunc("/reports", func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("session")
		if err != nil || cookie.Value != "admin" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("reports page"))
	})
	mux.HandleFunc("/large", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(strings.Repeat("x", MaxBodyBytes+100) + "needle"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestExecuteSessionAndRedirectAssertions(t *testing.T) {
	server := testServer(t)
	plan := Plan{
		SchemaVersion: SchemaVersion, Name: "session-flow", BaseURL: server.URL,
		Requests: []Request{
			{ID: "login-page", Method: "GET", Path: "/login", Expect: Expect{Status: 200, BodyContains: "login page"}},
			{ID: "admin-unauth", Method: "GET", Path: "/admin", Expect: Expect{Status: 302, LocationPrefix: "/login"}},
			{ID: "do-login", Method: "POST", Path: "/dologin", Session: "manager",
				Form:   map[string]string{"user": "admin", "pass": "secret"},
				Expect: Expect{Status: 302, LocationPrefix: "/admin"}},
			{ID: "admin-auth", Method: "GET", Path: "/admin", Session: "manager",
				Expect: Expect{Status: 200, BodyContains: "admin page"}},
		},
	}
	report, err := Execute(context.Background(), plan, Options{
		ApprovedOrigin: server.URL, AllowLoopback: true, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || report.RuntimeStatus != "observed" || report.Coverage.Requests != 4 {
		t.Fatalf("report: %+v", report)
	}
	if report.Results[1].ObservedStatus != 302 || report.Results[1].Location != "/login" {
		t.Fatalf("redirect was followed or lost: %+v", report.Results[1])
	}
	if report.Results[3].ObservedStatus != 200 {
		t.Fatalf("session cookie not reused: %+v", report.Results[3])
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("form credentials leaked into report")
	}
}

func TestExecuteReportsFailingExpectation(t *testing.T) {
	server := testServer(t)
	plan := Plan{
		SchemaVersion: SchemaVersion, Name: "failing", BaseURL: server.URL,
		Requests: []Request{{ID: "wrong", Method: "GET", Path: "/admin", Expect: Expect{Status: 200}}},
	}
	report, err := Execute(context.Background(), plan, Options{ApprovedOrigin: server.URL, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || report.Results[0].Status != "failed" {
		t.Fatalf("failing report: %+v", report)
	}
}

func TestExecuteTruncatedBodyIsInconclusive(t *testing.T) {
	server := testServer(t)
	plan := Plan{
		SchemaVersion: SchemaVersion, Name: "large", BaseURL: server.URL,
		Requests: []Request{{ID: "large", Method: "GET", Path: "/large", Expect: Expect{Status: 200, BodyContains: "needle"}}},
	}
	report, err := Execute(context.Background(), plan, Options{ApprovedOrigin: server.URL, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "inconclusive" || report.Results[0].Status != "inconclusive" || !report.Results[0].BodyTruncated {
		t.Fatalf("truncation report: %+v", report)
	}
}

func TestExecuteRequiresApprovedOriginAndLoopback(t *testing.T) {
	server := testServer(t)
	plan := Plan{
		SchemaVersion: SchemaVersion, Name: "target", BaseURL: server.URL,
		Requests: []Request{{ID: "login", Method: "GET", Path: "/login", Expect: Expect{Status: 200}}},
	}
	if _, err := Execute(context.Background(), plan, Options{ApprovedOrigin: "http://127.0.0.1:1", AllowLoopback: true}); err == nil {
		t.Fatal("unapproved origin accepted")
	}
	if _, err := Execute(context.Background(), plan, Options{ApprovedOrigin: server.URL}); err == nil {
		t.Fatal("loopback accepted without explicit approval")
	}
}

func TestExecuteRoleMatrixWithCSRF(t *testing.T) {
	t.Setenv("TRIDENT_TEST_PASS", "secret")
	server := testServer(t)
	login := func(user string) []Request {
		return []Request{
			{ID: "page", Method: "GET", Path: "/csrf-login", Expect: Expect{Status: 200}},
			{ID: "submit", Method: "POST", Path: "/secure-login",
				Form:   map[string]string{"user": user, "pass": "${ENV:TRIDENT_TEST_PASS}"},
				Expect: Expect{Status: 302, LocationPrefix: "/admin"}},
		}
	}
	plan := Plan{
		SchemaVersion: SchemaVersion, Name: "matrix", BaseURL: server.URL,
		Roles: []Role{
			{ID: "admin", Login: login("admin"), CSRF: &CSRF{Selector: "meta[name=_csrf]", Field: "_csrf"}},
			{ID: "guest", Login: login("guest"), CSRF: &CSRF{Selector: "input[name=_csrf]", Field: "_csrf"}},
		},
		Requests: []Request{
			{ID: "admin-page", Method: "GET", Path: "/admin", Expect: Expect{Status: 302}},
			{ID: "reports", Method: "GET", Path: "/reports", Expect: Expect{Status: 403}},
		},
		Matrix: []MatrixCase{
			{Role: "admin", Request: "admin-page", Expect: Expect{Status: 200, BodyContains: "admin page"}},
			{Role: "admin", Request: "reports", Expect: Expect{Status: 200, BodyContains: "reports page"}},
			{Role: "guest", Request: "admin-page", Expect: Expect{Status: 403}},
			{Role: "guest", Request: "reports", Expect: Expect{Status: 403}},
		},
	}
	report, err := Execute(context.Background(), plan, Options{ApprovedOrigin: server.URL, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || report.Coverage.Requests != 10 {
		t.Fatalf("matrix report: %+v", report)
	}
	admin := report.Coverage.Roles["admin"]
	if admin.Requests != 4 || admin.Passed != 4 || admin.LoginStatus != "complete" {
		t.Fatalf("admin coverage: %+v", admin)
	}
	guest := report.Coverage.Roles["guest"]
	if guest.Requests != 4 || guest.Passed != 4 || guest.LoginStatus != "complete" {
		t.Fatalf("guest coverage: %+v", guest)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "token-abc"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("%q leaked into report", secret)
		}
	}
	if !strings.Contains(string(encoded), "token_injected") {
		t.Fatalf("csrf injection not reported: %s", encoded)
	}
}

func TestExecuteMissingCSRFTokenIsInconclusive(t *testing.T) {
	t.Setenv("TRIDENT_TEST_PASS", "secret")
	server := testServer(t)
	plan := Plan{
		SchemaVersion: SchemaVersion, Name: "csrf-missing", BaseURL: server.URL,
		Roles: []Role{{
			ID: "broken",
			Login: []Request{
				{ID: "page", Method: "GET", Path: "/csrf-login", Expect: Expect{Status: 200}},
				{ID: "submit", Method: "POST", Path: "/secure-login",
					Form:   map[string]string{"user": "admin", "pass": "${ENV:TRIDENT_TEST_PASS}"},
					Expect: Expect{Status: 302}},
			},
			CSRF: &CSRF{Selector: "input[name=missing]", Field: "_csrf"},
		}},
		Requests: []Request{{ID: "admin-page", Method: "GET", Path: "/admin", Expect: Expect{Status: 302}}},
		Matrix:   []MatrixCase{{Role: "broken", Request: "admin-page", Expect: Expect{Status: 200}}},
	}
	report, err := Execute(context.Background(), plan, Options{ApprovedOrigin: server.URL, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "inconclusive" || report.Coverage.Roles["broken"].LoginStatus != "incomplete" {
		t.Fatalf("csrf report: %+v", report)
	}
	results := map[string]Result{}
	for _, result := range report.Results {
		results[result.ID] = result
	}
	if results["role:broken:submit"].Error != "csrf_token_not_found" ||
		results["matrix:broken:admin-page"].Error != "role_login_incomplete" {
		t.Fatalf("csrf results: %+v", results)
	}
}

func TestParsePlanRejectsUnsafeMatrix(t *testing.T) {
	base := `{"schema_version":1,"name":"x","base_url":"http://127.0.0.1:8080",` +
		`"requests":[{"id":"a","method":"GET","path":"/a","expect":{"status":200}}],`
	cases := []string{
		base + `"roles":[{"id":"admin","csrf":{"selector":"div[name=_csrf]","field":"_csrf"}}],"matrix":[]}`,
		base + `"roles":[{"id":"admin"},{"id":"admin"}],"matrix":[]}`,
		base + `"roles":[{"id":"admin","session":"shared"},{"id":"guest","session":"shared"}],"matrix":[]}`,
		base + `"roles":[{"id":"admin","csrf":{"selector":"meta[name=_csrf]"}}],"matrix":[]}`,
		base + `"roles":[{"id":"admin"}],"matrix":[{"role":"guest","request":"a","expect":{"status":200}}]}`,
		base + `"roles":[{"id":"admin"}],"matrix":[{"role":"admin","request":"missing","expect":{"status":200}}]}`,
	}
	for _, value := range cases {
		if _, err := ParsePlan([]byte(value)); err == nil {
			t.Fatalf("unsafe matrix accepted: %s", value)
		}
	}
}

func TestParsePlanRejectsUnsafeInputs(t *testing.T) {
	valid := `{"schema_version":1,"name":"x","base_url":"http://127.0.0.1:8080","requests":[{"id":"a","method":"GET","path":"/a","expect":{"status":200}}]}`
	if _, err := ParsePlan([]byte(valid)); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	cases := []string{
		`{"schema_version":1,"name":"x","base_url":"http://127.0.0.1:8080","requests":[{"id":"a","method":"TRACE","path":"/a","expect":{"status":200}}]}`,
		`{"schema_version":1,"name":"x","base_url":"http://127.0.0.1:8080","requests":[{"id":"a","method":"GET","path":"http://evil/a","expect":{"status":200}}]}`,
		`{"schema_version":1,"name":"x","base_url":"http://127.0.0.1:8080","requests":[{"id":"a","method":"GET","path":"/a","expect":{"status":0}}]}`,
		`{"schema_version":1,"name":"x","base_url":"http://127.0.0.1:8080","requests":[{"id":"a","method":"GET","path":"/a","expect":{"status":200},"unknown":true}]}`,
	}
	for _, value := range cases {
		if _, err := ParsePlan([]byte(value)); err == nil {
			t.Fatalf("unsafe plan accepted: %s", value)
		}
	}
}
