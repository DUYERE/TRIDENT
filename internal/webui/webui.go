// Package webui serves a read-only static-analysis console over HTTP for one
// pinned source snapshot.
//
// The console never imports sources, executes Java/Maven, calls a model or
// exposes a runtime control API. It requires an access token, expects the
// caller to bind it to a loopback address (the CLI enforces that), and reuses
// the same bounded snapshot readers and analysis packages as the CLI so page
// data keeps the CLI's limits.
package webui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trident/internal/audit"
	"trident/internal/findings"
	"trident/internal/project"
	"trident/internal/sca"
)

const (
	SchemaVersion = 1
	Product       = "TRIDENT"

	// SessionCookie carries the per-process access token. The token is generated
	// at start or supplied explicitly and is never derived from the snapshot.
	SessionCookie = "trident_console"
	// RequestHeader marks browser console requests. A cross-origin page cannot
	// set this header without a CORS preflight, which this server never grants.
	RequestHeader = "X-Trident-Request"
	// TokenHeader permits scripts to authenticate without a cookie.
	TokenHeader = "X-Trident-Token"

	DefaultLimit = 50
	MaxLimit     = 200
	MaxBodyBytes = 4 << 10
)

var (
	ErrUnauthorized = errors.New("console access token required")
	//go:embed assets/*
	assets embed.FS
)

type Options struct {
	SnapshotDir  string
	SnapshotHash string
	AdvisoryPath string
	// Token is the legacy single-user token. TokensFile and Token are mutually
	// exclusive; the file form carries per-user identities as SHA-256 hashes.
	Token      string
	TokensFile string
	// AccessLog, when set, appends one JSONL audit line per API/export request.
	AccessLog string
	// Version is the product build string shown in the console footer.
	Version string
}

// Console owns the pinned snapshot and the cached analysis reports. It must be
// closed by the caller; it is safe for concurrent HTTP handlers.
type Console struct {
	snapshot     *project.Snapshot
	advisoryPath string
	tokens       *tokenRegistry
	singleToken  string // plaintext of the legacy single-token mode; empty in file mode
	version      string
	startedAt    time.Time
	accessLog    *accessLogger

	requestsTotal     atomic.Int64
	unauthorizedTotal atomic.Int64
	forbiddenTotal    atomic.Int64
	analysisRuns      atomic.Int64
	analysisCacheHits atomic.Int64
	analysisFailures  atomic.Int64
	lastDurationMS    atomic.Int64
	lastAnalysisError atomic.Value // string

	mu    sync.Mutex
	state *analysisState
}

// metricsSnapshot is the JSON payload of GET /api/metrics. Counters are
// monotonic process-lifetime values; the endpoint is read-only and token
// gated. unauthorized/forbidden count middleware-level rejections only.
type metricsSnapshot struct {
	Product       string          `json:"product"`
	Version       string          `json:"version"`
	UptimeSeconds int64           `json:"uptime_seconds"`
	Requests      metricsRequests `json:"requests"`
	Analysis      metricsAnalysis `json:"analysis"`
}

type metricsRequests struct {
	Total        int64 `json:"total"`
	Unauthorized int64 `json:"unauthorized"`
	Forbidden    int64 `json:"forbidden"`
}

type metricsAnalysis struct {
	RunsTotal      int64  `json:"runs_total"`
	CacheHitsTotal int64  `json:"cache_hits_total"`
	FailuresTotal  int64  `json:"failures_total"`
	Cached         bool   `json:"cached"`
	CachedOK       bool   `json:"cached_ok"`
	LastDurationMS int64  `json:"last_duration_ms"`
	LastError      string `json:"last_error"`
}

type analysisState struct {
	findings findings.Report
	sca      sca.Report
	audit    audit.Report
	duration time.Duration
	at       time.Time
	err      error
}

// New opens an existing trusted snapshot. The expected hash must come from a
// record kept outside the snapshot, exactly like the CLI.
func New(ctx context.Context, opts Options) (*Console, error) {
	if opts.SnapshotDir == "" || opts.SnapshotHash == "" {
		return nil, fmt.Errorf("web console requires an existing --snapshot and trusted --snapshot-hash")
	}
	token := strings.TrimSpace(opts.Token)
	if opts.TokensFile != "" && token != "" {
		return nil, fmt.Errorf("use either --token or --tokens, not both")
	}
	var registry *tokenRegistry
	switch {
	case opts.TokensFile != "":
		loaded, err := newFileTokenRegistry(opts.TokensFile, os.Stderr)
		if err != nil {
			return nil, err
		}
		registry = loaded
	default:
		if token == "" {
			generated, err := randomToken()
			if err != nil {
				return nil, err
			}
			token = generated
		}
		if len(token) < 16 || len(token) > 256 || strings.ContainsAny(token, "\r\n\x00") {
			return nil, fmt.Errorf("console token must contain 16 to 256 bytes without control characters")
		}
		registry = newSingleTokenRegistry(token)
	}
	snapshot, err := project.Open(ctx, opts.SnapshotDir, opts.SnapshotHash)
	if err != nil {
		return nil, err
	}
	version := opts.Version
	if version == "" {
		version = Product
	}
	console := &Console{snapshot: snapshot, advisoryPath: opts.AdvisoryPath, tokens: registry, singleToken: token, version: version, startedAt: time.Now().UTC()}
	if opts.AccessLog != "" {
		logger, err := newAccessLogger(opts.AccessLog)
		if err != nil {
			_ = snapshot.Close()
			return nil, err
		}
		console.accessLog = logger
	}
	return console, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate console token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Token returns the legacy single-mode access token so the CLI can print it
// once; multi-user token files never expose a plaintext here.
func (c *Console) Token() string { return c.singleToken }

// TokenIDs returns the sorted identities currently loaded from the token
// registry.
func (c *Console) TokenIDs() []string { return c.tokens.TokenIDs() }

// MultiToken reports whether the console was started from a token file.
func (c *Console) MultiToken() bool { return c.tokens.source != "" }

// SnapshotHash returns the pinned snapshot digest.
func (c *Console) SnapshotHash() string { return c.snapshot.Hash() }

func (c *Console) Close() error {
	err := c.snapshot.Close()
	if logErr := c.accessLog.Close(); logErr != nil && err == nil {
		err = logErr
	}
	return err
}

// analyze runs SCA, the endpoint inventory, bounded dataflow and the unified
// evidence model once, then serves every page from the cached report. A failed
// analysis is cached as a terminal error instead of being retried per request.
func (c *Console) analyze(ctx context.Context) (*analysisState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != nil {
		c.analysisCacheHits.Add(1)
		return c.state, c.state.err
	}
	started := time.Now()
	state := &analysisState{}
	scaReport, scaErr := sca.Inspect(ctx, c.snapshot, sca.Options{AdvisoryPath: c.advisoryPath})
	endpointReport, auditErr := audit.Inspect(ctx, c.snapshot)
	findingReport, findingErr := findings.Analyze(ctx, c.snapshot, findings.Options{AdvisoryPath: c.advisoryPath})
	switch {
	case findingErr != nil:
		state.err = fmt.Errorf("analysis failed: %w", findingErr)
	case scaErr != nil:
		state.err = fmt.Errorf("SCA analysis failed: %w", scaErr)
	case auditErr != nil:
		state.err = fmt.Errorf("endpoint inventory failed: %w", auditErr)
	default:
		state.findings = findingReport
		state.sca = scaReport
		state.audit = endpointReport
	}
	state.duration = time.Since(started)
	state.at = time.Now().UTC()
	c.state = state
	c.analysisRuns.Add(1)
	c.lastDurationMS.Store(state.duration.Milliseconds())
	if state.err != nil {
		c.analysisFailures.Add(1)
		c.lastAnalysisError.Store(state.err.Error())
	}
	return state, state.err
}

// Handler returns the console HTTP handler. Static assets and the shell page
// are public; every API route requires the token and the console request
// header.
func (c *Console) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", c.handleIndex)
	mux.Handle("GET /assets/", c.assetHandler())
	mux.HandleFunc("POST /api/session", c.handleSession)
	mux.HandleFunc("GET /api/health", c.handleHealth)
	mux.HandleFunc("GET /api/overview", c.handleOverview)
	mux.HandleFunc("GET /api/findings", c.handleFindings)
	mux.HandleFunc("GET /api/finding", c.handleFinding)
	mux.HandleFunc("GET /api/endpoints", c.handleEndpoints)
	mux.HandleFunc("GET /api/dependencies", c.handleDependencies)
	mux.HandleFunc("GET /api/files", c.handleFiles)
	mux.HandleFunc("GET /api/file", c.handleFile)
	mux.HandleFunc("GET /api/search", c.handleSearch)
	mux.HandleFunc("GET /api/sbom", c.handleSBOM)
	mux.HandleFunc("GET /api/report", c.handleReport)
	mux.HandleFunc("GET /api/metrics", c.handleMetrics)
	mux.HandleFunc("GET /export/report", c.handleExportReport)
	mux.HandleFunc("GET /healthz", c.handleHealthz)
	return c.middleware(mux)
}

// handleHealthz serves an unauthenticated liveness probe for load balancers
// and reverse proxies; it exposes only the product identity, never analysis or
// token state.
func (c *Console) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Status  string `json:"status"`
		Product string `json:"product"`
		Version string `json:"version"`
	}{Status: "ok", Product: Product, Version: c.version})
}

// handleMetrics serves the read-only observability counters.
func (c *Console) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	snapshot := metricsSnapshot{
		Product:       Product,
		Version:       c.version,
		UptimeSeconds: int64(time.Since(c.startedAt).Seconds()),
		Requests: metricsRequests{
			Total:        c.requestsTotal.Load(),
			Unauthorized: c.unauthorizedTotal.Load(),
			Forbidden:    c.forbiddenTotal.Load(),
		},
		Analysis: metricsAnalysis{
			RunsTotal:      c.analysisRuns.Load(),
			CacheHitsTotal: c.analysisCacheHits.Load(),
			FailuresTotal:  c.analysisFailures.Load(),
			Cached:         state != nil,
			CachedOK:       state != nil && state.err == nil,
			LastDurationMS: c.lastDurationMS.Load(),
		},
	}
	if state != nil && state.err != nil {
		snapshot.Analysis.LastError = state.err.Error()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (c *Console) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		var entry TokenEntry
		gated := auditPath(r.URL.Path)
		if gated {
			c.requestsTotal.Add(1)
			h.Set("Cache-Control", "no-store")
			if r.URL.Path != "/api/session" {
				resolved, err := c.authorize(r)
				if err != nil {
					c.unauthorizedTotal.Add(1)
					c.accessLog.record(entry, r, http.StatusUnauthorized)
					writeError(w, http.StatusUnauthorized, "unauthorized", "a valid console token is required")
					return
				}
				entry = resolved
			}
			if r.Header.Get(RequestHeader) != "console" {
				c.forbiddenTotal.Add(1)
				c.accessLog.record(entry, r, http.StatusForbidden)
				writeError(w, http.StatusForbidden, "missing_console_header", "API requests require the console request header")
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodPost {
				c.accessLog.record(entry, r, http.StatusMethodNotAllowed)
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "read-only console")
				return
			}
		}
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if gated {
			c.accessLog.record(entry, r, recorder.recorded())
		}
	})
}

func (c *Console) authorize(r *http.Request) (TokenEntry, error) {
	token := r.Header.Get(TokenHeader)
	if token == "" {
		if cookie, err := r.Cookie(SessionCookie); err == nil {
			token = cookie.Value
		}
	}
	if entry, ok := c.tokens.lookup(token); ok {
		return entry, nil
	}
	return TokenEntry{}, ErrUnauthorized
}

func (c *Console) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "console assets unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// assetHandler serves only known static file extensions from the embedded
// bundle; it never exposes directory listings.
func (c *Console) assetHandler() http.Handler {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic("webui: embedded assets missing")
	}
	files := http.StripPrefix("/assets/", http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/assets/")
		if name == "" || strings.HasSuffix(name, "/") || strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(name, ".js"):
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case strings.HasSuffix(name, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case strings.HasSuffix(name, ".svg"):
			w.Header().Set("Content-Type", "image/svg+xml")
		case strings.HasSuffix(name, ".png"):
			w.Header().Set("Content-Type", "image/png")
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
}

type sessionRequest struct {
	Token string `json:"token"`
}

// handleSession exchanges a valid token for an HttpOnly, SameSite=Strict
// session cookie. Cross-origin pages cannot set the console request header, so
// they cannot brute-force this exchange from a browser.
func (c *Console) handleSession(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request sessionRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid session payload")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "trailing session payload")
		return
	}
	if _, ok := c.tokens.lookup(request.Token); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "access token rejected")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: request.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 60 * 60})
	w.WriteHeader(http.StatusNoContent)
}

type healthResponse struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Product       string `json:"product"`
	SnapshotHash  string `json:"snapshot_hash"`
	AnalysisReady bool   `json:"analysis_ready"`
	RuntimeStatus string `json:"runtime_status"`
}

func (c *Console) handleHealth(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	ready := c.state != nil && c.state.err == nil
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, healthResponse{SchemaVersion: SchemaVersion, Status: "ok", Product: Product, SnapshotHash: c.snapshot.Hash(), AnalysisReady: ready, RuntimeStatus: "not_run"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

type errorResponse struct {
	SchemaVersion int    `json:"schema_version"`
	Code          string `json:"code"`
	Error         string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{SchemaVersion: SchemaVersion, Code: code, Error: message})
}

func queryInt(r *http.Request, name string, fallback, minimum, maximum int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func queryOffset(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("offset")
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 || value > 1_000_000 {
		return 0, fmt.Errorf("offset must be an integer between 0 and 1000000")
	}
	return value, nil
}

func queryText(r *http.Request, name string, max int) (string, error) {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if len(value) > max {
		return "", fmt.Errorf("%s exceeds %d bytes", name, max)
	}
	return value, nil
}

// mapProjectError keeps invalid caller options distinguishable from integrity
// failures without leaking host paths.
func mapProjectError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		writeError(w, http.StatusNotFound, "not_found", "file is not present in the pinned snapshot")
	case errors.Is(err, project.ErrToolOptions), errors.Is(err, project.ErrToolCursor):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, project.ErrLimit):
		writeError(w, http.StatusRequestEntityTooLarge, "limit", "requested page exceeds a snapshot tool budget")
	case errors.Is(err, project.ErrIntegrity), errors.Is(err, project.ErrUnsafePath):
		writeError(w, http.StatusConflict, "snapshot_integrity", "snapshot content no longer matches the pinned manifest")
	default:
		writeError(w, http.StatusInternalServerError, "internal", "snapshot tool failed")
	}
}
