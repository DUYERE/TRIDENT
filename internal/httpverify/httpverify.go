// Package httpverify executes caller-supplied HTTP assertions against one
// explicitly approved origin. It records bounded runtime evidence and never
// follows redirects, upgrades static findings, or echoes credentials.
package httpverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion   = 1
	ToolVersion     = "0.2.0-p1.1+r1-http-runtime-v2"
	MaxPlanBytes    = 1 << 20
	MaxRequests     = 64
	MaxRoleLogins   = 16
	MaxCSRFTokenLen = 512
	MaxBodyBytes    = 64 << 10
	DefaultTimeoutS = 10
	MaxTimeoutS     = 60
)

type Plan struct {
	SchemaVersion int          `json:"schema_version"`
	Name          string       `json:"name"`
	BaseURL       string       `json:"base_url"`
	Roles         []Role       `json:"roles,omitempty"`
	Requests      []Request    `json:"requests"`
	Matrix        []MatrixCase `json:"matrix,omitempty"`
}

type Request struct {
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Session string            `json:"session,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Form    map[string]string `json:"form,omitempty"`
	JSON    json.RawMessage   `json:"json,omitempty"`
	Expect  Expect            `json:"expect"`
}

type Expect struct {
	Status          int               `json:"status"`
	LocationPrefix  string            `json:"location_prefix,omitempty"`
	BodyContains    string            `json:"body_contains,omitempty"`
	BodyNotContains string            `json:"body_not_contains,omitempty"`
	HeaderContains  map[string]string `json:"header_contains,omitempty"`
}

type Options struct {
	ApprovedOrigin string
	AllowLoopback  bool
	Timeout        time.Duration
	MaxRequests    int
}

type Report struct {
	SchemaVersion int      `json:"schema_version"`
	ToolVersion   string   `json:"tool_version"`
	AnalysisKind  string   `json:"analysis_kind"`
	PlanName      string   `json:"plan_name"`
	Origin        string   `json:"origin"`
	Status        string   `json:"status"`
	RuntimeStatus string   `json:"runtime_status"`
	Results       []Result `json:"results"`
	Coverage      Coverage `json:"coverage"`
	Limitations   []string `json:"limitations"`
	Error         string   `json:"error,omitempty"`
}

type Result struct {
	ID             string      `json:"id"`
	Method         string      `json:"method"`
	Path           string      `json:"path"`
	Session        string      `json:"session,omitempty"`
	Status         string      `json:"status"`
	ObservedStatus int         `json:"observed_status,omitempty"`
	Location       string      `json:"location,omitempty"`
	ContentType    string      `json:"content_type,omitempty"`
	BodySHA256     string      `json:"body_sha256,omitempty"`
	BodyBytes      int         `json:"body_bytes"`
	BodyTruncated  bool        `json:"body_truncated,omitempty"`
	Assertions     []Assertion `json:"assertions"`
	Role           string      `json:"role,omitempty"`
	Matrix         string      `json:"matrix,omitempty"`
	CSRF           string      `json:"csrf,omitempty"`
	Error          string      `json:"error,omitempty"`
}

type Assertion struct {
	Name         string `json:"name"`
	Expected     string `json:"expected"`
	Observed     string `json:"observed"`
	Passed       bool   `json:"passed"`
	Inconclusive bool   `json:"inconclusive,omitempty"`
}

type Coverage struct {
	Requests     int                     `json:"requests"`
	Passed       int                     `json:"passed"`
	Failed       int                     `json:"failed"`
	Inconclusive int                     `json:"inconclusive"`
	Roles        map[string]RoleCoverage `json:"roles,omitempty"`
	RuntimeState string                  `json:"runtime_status"`
}

// ParsePlan strictly decodes one bounded HTTP verification plan.
func ParsePlan(data []byte) (Plan, error) {
	var plan Plan
	if len(data) == 0 || len(data) > MaxPlanBytes {
		return plan, fmt.Errorf("plan must contain 1 to %d bytes", MaxPlanBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return plan, fmt.Errorf("invalid plan JSON: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return plan, err
	}
	if plan.SchemaVersion != SchemaVersion {
		return plan, fmt.Errorf("plan schema_version must be %d", SchemaVersion)
	}
	if strings.TrimSpace(plan.Name) == "" || len(plan.Name) > 128 {
		return plan, fmt.Errorf("plan name is required and must be at most 128 characters")
	}
	if strings.TrimSpace(plan.BaseURL) == "" {
		return plan, fmt.Errorf("plan base_url is required")
	}
	if len(plan.Requests) == 0 || len(plan.Requests) > MaxRequests {
		return plan, fmt.Errorf("plan must contain 1 to %d requests", MaxRequests)
	}
	seen := map[string]bool{}
	for _, request := range plan.Requests {
		if strings.TrimSpace(request.ID) == "" || len(request.ID) > 128 || seen[request.ID] {
			return plan, fmt.Errorf("request IDs must be unique and at most 128 characters")
		}
		seen[request.ID] = true
		if !validMethod(request.Method) {
			return plan, fmt.Errorf("request %q has an unsupported method", request.ID)
		}
		if !validPath(request.Path) {
			return plan, fmt.Errorf("request %q path must be a bounded relative path starting with /", request.ID)
		}
		if len(request.Form) > 0 && len(request.JSON) > 0 {
			return plan, fmt.Errorf("request %q cannot set both form and json", request.ID)
		}
		if request.Expect.Status < 100 || request.Expect.Status > 599 {
			return plan, fmt.Errorf("request %q must declare an expected HTTP status", request.ID)
		}
	}
	if err := validateRolesAndMatrix(&plan); err != nil {
		return plan, err
	}
	return plan, nil
}

// Execute runs the plan against exactly one approved origin. Redirects are not
// followed, so a 3xx assertion observes the server's first response.
func Execute(ctx context.Context, plan Plan, opts Options) (Report, error) {
	report := Report{
		SchemaVersion: SchemaVersion, ToolVersion: ToolVersion,
		AnalysisKind: "http_runtime_assertions_v1", PlanName: plan.Name,
		Status: "failed", RuntimeStatus: "not_run", Results: []Result{},
		Coverage: Coverage{RuntimeState: "not_run"},
		Limitations: []string{
			"runtime_observed_not_exploit_proof: passing assertions only prove the observed responses for the supplied requests",
			"redirects_not_followed: 3xx responses are recorded without executing the target",
			"body_bounded_to_64KiB: body assertions beyond the bound are reported as inconclusive",
			"credentials_caller_supplied_and_not_echoed: form/json/header values, tokens and resolved env placeholders are never written to the report",
			"roles_caller_defined: role ids, login steps and matrix expectations are caller supplied; accounts are not discovered",
			"csrf_token_extraction_bounded: tokens are read only from explicit meta/input selectors and injected into form fields or headers; extraction failure is inconclusive",
			"no_proxy_or_concurrency: requests run sequentially with the default HTTP transport and TLS verification",
			"target_allowlist_exact_origin: only the origin approved by the caller is contacted",
		},
	}
	origin, err := approvedOrigin(plan.BaseURL, opts.ApprovedOrigin, opts.AllowLoopback)
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	report.Origin = origin.String()
	if opts.Timeout <= 0 || opts.Timeout > MaxTimeoutS*time.Second {
		opts.Timeout = DefaultTimeoutS * time.Second
	}
	if opts.MaxRequests <= 0 || opts.MaxRequests > MaxRequests {
		opts.MaxRequests = MaxRequests
	}
	if len(plan.Requests) > opts.MaxRequests {
		report.Error = "plan exceeds the configured request bound"
		return report, fmt.Errorf("%s", report.Error)
	}
	client := &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	sessions := map[string]map[string]string{}
	report.RuntimeStatus = "observed"
	report.Coverage.RuntimeState = "observed"
	for _, request := range plan.Requests {
		result, _ := executeRequest(ctx, client, origin, request, sessions)
		appendResult(&report, result)
	}
	runRolesAndMatrix(ctx, client, origin, plan, sessions, &report)
	report.Coverage.Requests = len(report.Results)
	switch {
	case report.Coverage.Failed > 0:
		report.Status = "failed"
	case report.Coverage.Inconclusive > 0:
		report.Status = "inconclusive"
	default:
		report.Status = "passed"
	}
	sort.Strings(report.Limitations)
	return report, nil
}

func executeRequest(ctx context.Context, client *http.Client, origin *url.URL, request Request, sessions map[string]map[string]string) (Result, string) {
	result := Result{
		ID: request.ID, Method: strings.ToUpper(request.Method), Path: request.Path,
		Session: request.Session, Status: "error", Assertions: []Assertion{},
	}
	target, err := joinTarget(origin, request.Path)
	if err != nil {
		result.Error = err.Error()
		return result, ""
	}
	var body io.Reader
	contentType := ""
	switch {
	case len(request.Form) > 0:
		values := url.Values{}
		for key, value := range request.Form {
			values.Set(key, value)
		}
		body = strings.NewReader(values.Encode())
		contentType = "application/x-www-form-urlencoded"
	case len(request.JSON) > 0:
		body = bytes.NewReader(request.JSON)
		contentType = "application/json"
	}
	httpRequest, err := http.NewRequestWithContext(ctx, result.Method, target, body)
	if err != nil {
		result.Error = "could not build request"
		return result, ""
	}
	for name, value := range request.Headers {
		if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Cookie") {
			continue
		}
		httpRequest.Header.Set(name, value)
	}
	if contentType != "" && httpRequest.Header.Get("Content-Type") == "" {
		httpRequest.Header.Set("Content-Type", contentType)
	}
	if request.Session != "" {
		for name, value := range sessions[request.Session] {
			httpRequest.AddCookie(&http.Cookie{Name: name, Value: value})
		}
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		result.Error = "request failed"
		return result, ""
	}
	defer response.Body.Close()
	result.ObservedStatus = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	result.Location = safeLocation(response.Header.Get("Location"))
	if request.Session != "" {
		stored := sessions[request.Session]
		if stored == nil {
			stored = map[string]string{}
			sessions[request.Session] = stored
		}
		for _, cookie := range response.Cookies() {
			if cookie.Name != "" {
				stored[cookie.Name] = cookie.Value
			}
		}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
	if err != nil {
		result.Error = "response body read failed"
		return result, ""
	}
	if len(data) > MaxBodyBytes {
		data = data[:MaxBodyBytes]
		result.BodyTruncated = true
	}
	sum := sha256.Sum256(data)
	result.BodySHA256 = hex.EncodeToString(sum[:])
	result.BodyBytes = len(data)
	result.Assertions = evaluate(response, request, result, string(data))
	result.Status = assertionStatus(result.Assertions)
	return result, string(data)
}

func evaluate(response *http.Response, request Request, result Result, body string) []Assertion {
	var assertions []Assertion
	add := func(name, expected, observed string, passed bool) {
		assertions = append(assertions, Assertion{Name: name, Expected: expected, Observed: observed, Passed: passed})
	}
	add("status", fmt.Sprintf("%d", request.Expect.Status), fmt.Sprintf("%d", result.ObservedStatus), result.ObservedStatus == request.Expect.Status)
	if request.Expect.LocationPrefix != "" {
		location := result.Location
		add("location_prefix", request.Expect.LocationPrefix, location, strings.HasPrefix(location, request.Expect.LocationPrefix))
	}
	if request.Expect.BodyContains != "" {
		if result.BodyTruncated && !strings.Contains(body, request.Expect.BodyContains) {
			assertions = append(assertions, Assertion{
				Name: "body_contains", Expected: request.Expect.BodyContains,
				Observed: "body_truncated", Passed: false, Inconclusive: true,
			})
		} else {
			add("body_contains", request.Expect.BodyContains, redactBodyMatch(request.Expect.BodyContains, body), strings.Contains(body, request.Expect.BodyContains))
		}
	}
	if request.Expect.BodyNotContains != "" {
		if result.BodyTruncated && strings.Contains(body, request.Expect.BodyNotContains) {
			assertions = append(assertions, Assertion{
				Name: "body_not_contains", Expected: request.Expect.BodyNotContains,
				Observed: "body_truncated", Passed: false, Inconclusive: true,
			})
		} else {
			add("body_not_contains", request.Expect.BodyNotContains, "absent", !strings.Contains(body, request.Expect.BodyNotContains))
		}
	}
	var names []string
	for name := range request.Expect.HeaderContains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		expected := request.Expect.HeaderContains[name]
		value := response.Header.Get(name)
		observed := "absent"
		if strings.Contains(value, expected) {
			observed = "present"
		}
		add("header_contains:"+strings.ToLower(name), expected, observed, observed == "present")
	}
	return assertions
}

func assertionStatus(assertions []Assertion) string {
	status := "passed"
	for _, assertion := range assertions {
		if assertion.Inconclusive {
			if status == "passed" {
				status = "inconclusive"
			}
			continue
		}
		if !assertion.Passed {
			return "failed"
		}
	}
	return status
}

func approvedOrigin(baseURL, approved string, allowLoopback bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("base_url must be an absolute http(s) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("base_url scheme must be http or https")
	}
	if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("base_url must be an origin without credentials, path, query or fragment")
	}
	origin := parsed.Scheme + "://" + parsed.Host
	approved = strings.TrimSpace(approved)
	if strings.TrimRight(approved, "/") != origin {
		return nil, fmt.Errorf("target origin %q is not approved; pass --approve-target %s", origin, origin)
	}
	host := parsed.Hostname()
	if isLoopback(host) && !allowLoopback {
		return nil, fmt.Errorf("loopback targets require explicit --allow-loopback")
	}
	return &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func joinTarget(origin *url.URL, path string) (string, error) {
	if !validPath(path) {
		return "", fmt.Errorf("invalid request path")
	}
	parsed, err := url.Parse(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "", fmt.Errorf("request path must be relative")
	}
	target := *origin
	target.Path = parsed.Path
	target.RawQuery = parsed.RawQuery
	return target.String(), nil
}

func validMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

func validPath(path string) bool {
	if path == "" || len(path) > 2048 || !strings.HasPrefix(path, "/") {
		return false
	}
	if strings.Contains(path, "://") || strings.Contains(path, "\\") || strings.ContainsRune(path, '\x00') {
		return false
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func safeLocation(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if parsed.IsAbs() {
		return parsed.EscapedPath()
	}
	return parsed.EscapedPath()
}

func redactBodyMatch(expected, body string) string {
	if strings.Contains(body, expected) {
		return "present"
	}
	return "absent"
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("plan must contain exactly one JSON object")
	}
	return nil
}
