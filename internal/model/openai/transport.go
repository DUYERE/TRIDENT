package openai

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"trident/internal/model"
)

// NormalizeEndpoint validates an explicit Chat Completions base URL, not a full
// completion URL. HTTP requires both opt-in and a literal loopback IP; hostnames
// (including localhost) are deliberately not resolved to establish that trust.
func NormalizeEndpoint(endpoint string, allowLoopback bool) (string, error) {
	// [01] Reject ambiguous URL forms before the SDK appends chat/completions.
	if endpoint == "" || strings.IndexFunc(endpoint, func(r rune) bool { return r <= ' ' || r >= 127 }) >= 0 {
		return "", configError("invalid endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(endpoint, "#") || u.RawPath != "" || strings.Contains(u.Path, "%") || strings.Contains(u.Path, "\\") {
		return "", configError("invalid endpoint")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", configError("endpoint must use HTTPS")
	}
	if u.Hostname() == "" || strings.Contains(u.Hostname(), "%") || strings.HasSuffix(u.Host, ":") {
		return "", configError("invalid endpoint host")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", configError("invalid endpoint port")
		}
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if !allowLoopback || ip == nil || !ip.IsLoopback() {
			return "", configError("HTTP requires explicit literal loopback opt-in")
		}
	}
	if strings.Contains(u.Path, "//") {
		return "", configError("invalid endpoint path")
	}
	if u.EscapedPath() != u.Path || (u.Path != "" && path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/")) {
		// A root slash is the only exception to the clean-path comparison.
		if u.Path != "/" {
			return "", configError("invalid endpoint path")
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String(), nil
}

// pinnedTransport is the final gate, after all SDK middleware/serialization.
// It owns its transport: no DefaultTransport, environment proxy, or redirects.
// Bodies are measured, not trusted based on Content-Length (including errors).
type pinnedTransport struct {
	inner       *http.Transport
	target      string
	host        string
	apiKey      string
	maxRequest  int64
	maxResponse int64
}

func newTransport(target *url.URL, cfg Config) *pinnedTransport {
	return &pinnedTransport{
		inner: &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    cfg.Timeout,
			ResponseHeaderTimeout:  cfg.Timeout,
			MaxResponseHeaderBytes: 32 << 10,
			DisableCompression:     true,
			MaxIdleConns:           4,
			MaxIdleConnsPerHost:    2,
			IdleConnTimeout:        30 * time.Second,
		},
		target: target.String(), host: target.Host, apiKey: cfg.APIKey,
		maxRequest: cfg.MaxRequestBytes, maxResponse: cfg.MaxResponseBytes,
	}
}

func (t *pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// [02] Pin the full URL and method, not just the destination hostname.
	if req.URL == nil || req.Method != http.MethodPost || req.URL.String() != t.target || (req.Host != "" && req.Host != t.host) {
		return nil, safeError(model.ErrDenied, "request destination rejected")
	}
	if req.Body == nil {
		return nil, safeError(model.ErrProtocol, "missing request body")
	}
	body, err := readBounded(req.Body, t.maxRequest)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.GetBody = nil // No transparent replay, including redirects/auth challenges.
	out.ContentLength = int64(len(body))
	out.TransferEncoding = nil
	out.Host = t.host
	// [03] Allowlist headers; SDK telemetry and ambient org/project cannot escape.
	out.Header = http.Header{
		"Authorization": {"Bearer " + t.apiKey},
		"Content-Type":  {"application/json"},
		"Accept":        {"application/json"},
		"User-Agent":    {"trident-model-openai"},
	}
	resp, err := t.inner.RoundTrip(out)
	if err != nil {
		return nil, sanitizeNetworkError(req.Context(), err)
	}
	if resp.Body == nil {
		return nil, safeError(model.ErrProtocol, "missing response body")
	}
	defer resp.Body.Close()
	if resp.ContentLength > t.maxResponse {
		return nil, safeError(model.ErrLimit, "response byte limit exceeded")
	}
	body, err = readBounded(resp.Body, t.maxResponse)
	if err != nil {
		if errors.Is(err, model.ErrLimit) {
			return nil, err
		}
		return nil, sanitizeNetworkError(req.Context(), err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// [04] Never expose provider error bodies, URLs, headers, or SDK errors.
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			return nil, safeError(model.ErrRateLimit, "provider rate limited request")
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || (resp.StatusCode >= 300 && resp.StatusCode < 400):
			return nil, safeError(model.ErrDenied, "provider denied request or redirect")
		case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500:
			return nil, safeError(model.ErrUnavailable, "provider unavailable")
		default:
			return nil, safeError(model.ErrProtocol, "provider rejected request")
		}
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, safeError(model.ErrProtocol, "encoded responses are unsupported")
	}
	media := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if !strings.EqualFold(media, "application/json") {
		return nil, safeError(model.ErrProtocol, "expected JSON response")
	}
	// [05] Validate the entire wire body before SDK parsing; its RawJSON may
	// expose only the first JSON value and would otherwise hide trailing data.
	if err := validateJSON(body); err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	// [05] The extra byte detects a chunked/lying response exceeding the cap.
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, safeError(model.ErrLimit, "body byte limit exceeded")
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

func sanitizeNetworkError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return safeError(ctx.Err(), "request interrupted")
	}
	if errors.Is(err, context.Canceled) {
		return safeError(context.Canceled, "request canceled")
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return safeError(context.DeadlineExceeded, "request timed out")
	}
	return safeError(model.ErrUnavailable, "provider transport failed")
}
