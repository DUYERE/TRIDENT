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
	"trident/internal/authz"
	"trident/internal/casework"
	"trident/internal/codescan"
	"trident/internal/findings"
	"trident/internal/javaast"
	"trident/internal/orchestrator"
	"trident/internal/project"
	"trident/internal/reach"
	"trident/internal/sca"
	"trident/internal/store"
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

	// MaxJavaModelFiles bounds the optional semantic model. Its memory grows with
	// the whole project, unlike the other analyzers that stream file by file.
	MaxJavaModelFiles = 2000
	// MaxCodeAuditFiles bounds the optional multi-language rule pass on the
	// console. CLI analysis keeps its own larger, explicit budget.
	MaxCodeAuditFiles = 1500
	// MaxConfigBytes bounds the runtime configuration payload.
	MaxConfigBytes = 256 << 10
)

var (
	ErrUnauthorized = errors.New("console access token required")
	// ErrNoProject means the workspace console has not imported a project yet.
	ErrNoProject = errors.New("no project selected")
	//go:embed assets/*
	assets embed.FS
)

type Options struct {
	SnapshotDir  string
	SnapshotHash string
	AdvisoryPath string
	// AdvisoryDir loads every *.json catalog inside one directory; it is
	// mutually exclusive with AdvisoryPath.
	AdvisoryDir string
	// Token is the legacy single-user token. TokensFile and Token are mutually
	// exclusive; the file form carries per-user identities as SHA-256 hashes.
	Token      string
	TokensFile string
	// AccessLog, when set, appends one JSONL audit line per API/export request.
	AccessLog string
	// PackageMap enables the reachability view (caller-supplied prefixes).
	PackageMap string
	// RuntimeReport is a caller-produced correlation report file to display.
	RuntimeReport string
	// AgentDSN opens a read-only observation database for the Agent view.
	AgentDSN string
	// AgentDSNExplicit records that the caller passed --agent-dsn on the
	// command line; an explicit DSN that fails must stop the start, while a
	// persisted or environment DSN degrades gracefully.
	AgentDSNExplicit bool
	// AgentToken authenticates the console against the Agent database when
	// chat is enabled. It is a principal token, never persisted by the console.
	AgentToken string
	// EnableAgentChat turns the console into an Agent control plane: the page
	// may create runs and call the model. Off by default on purpose.
	EnableAgentChat bool
	// AgentEndpoint, AgentModel and AgentKeyEnv bind the model used by chat.
	AgentEndpoint string
	AgentModel    string
	AgentKeyEnv   string
	// Workspace enables one-click mode: the console may import another local
	// source directory, persist path configuration and re-run analysis. Without
	// it the console stays pinned to the snapshot supplied at start.
	Workspace string
	// ProjectSource records where the pinned snapshot was imported from. It is
	// display metadata only and is never read again.
	ProjectSource string
	// CasesDir is the local evidence-case catalog. An empty value discovers
	// <working directory>/cases; a missing directory leaves the workbench empty.
	CasesDir string
	// Version is the product build string shown in the console footer.
	Version string
}

// Console owns the pinned snapshot and the cached analysis reports. It must be
// closed by the caller; it is safe for concurrent HTTP handlers.
type Console struct {
	snapshot          *project.Snapshot
	snapshotDir       string
	snapMu            sync.RWMutex
	projectSource     string
	workspace         string
	cases             *casework.Catalog
	tokens            *tokenRegistry
	singleToken       string // plaintext of the legacy single-token mode; empty in file mode
	sessionLimit      *sessionLimiter
	version           string
	startedAt         time.Time
	accessLog         *accessLogger
	reachState        *reach.Report
	reachMu           sync.Mutex
	codeState         *codescan.Report
	codeReason        string
	codeFatal         error
	codeMu            sync.Mutex
	agentStore        *store.Store
	agentStoreMu      sync.Mutex
	storedAgentDSN    string
	agentConnectError string
	agentWrite        *store.Store
	agentSession      store.Session
	orchEngine        *orchestrator.Engine
	agentChatEnabled  bool
	storedAgentToken  string
	chat              agentChat
	chatMu            sync.Mutex
	chatActive        int64
	chatError         string
	quickProbe        func(context.Context, string, []string) quickProbeResult

	cfgMu     sync.Mutex
	config    consoleConfig
	models    modelsFile
	modelKeys map[string]string

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

// consoleConfig holds the mutable path configuration. Values are resolved on
// every analysis so a configuration change never needs a restart.
type consoleConfig struct {
	AdvisoryPath   string `json:"advisories_path"`
	AdvisoryDir    string `json:"advisories_dir"`
	PackageMapPath string `json:"package_map_path"`
	RuntimeReport  string `json:"runtime_report"`
}

func (c consoleConfig) advisoryOptions() sca.Options {
	return sca.Options{AdvisoryPath: c.AdvisoryPath, AdvisoryDir: c.AdvisoryDir}
}

type analysisState struct {
	findings findings.Report
	sca      sca.Report
	audit    audit.Report
	authz    authz.Report
	model    *javaast.Model
	modelErr string
	duration time.Duration
	at       time.Time
	err      error
}

// New opens an existing trusted snapshot. The expected hash must come from a
// record kept outside the snapshot, exactly like the CLI.
func New(ctx context.Context, opts Options) (*Console, error) {
	// A workspace console may start without a project: the user picks one in the
	// browser. A pinned console still needs an existing snapshot and digest.
	if (opts.SnapshotDir == "") != (opts.SnapshotHash == "") {
		return nil, fmt.Errorf("--snapshot and --snapshot-hash must be supplied together")
	}
	if opts.SnapshotDir == "" && opts.Workspace == "" {
		return nil, fmt.Errorf("web console requires either --project/--workspace or --snapshot with --snapshot-hash")
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
	var snapshot *project.Snapshot
	if opts.SnapshotDir != "" {
		opened, err := project.Open(ctx, opts.SnapshotDir, opts.SnapshotHash)
		if err != nil {
			return nil, err
		}
		snapshot = opened
	}
	version := opts.Version
	if version == "" {
		version = Product
	}
	console := &Console{
		snapshot:      snapshot,
		snapshotDir:   opts.SnapshotDir,
		projectSource: opts.ProjectSource,
		workspace:     opts.Workspace,
		cases:         casework.NewCatalog(opts.CasesDir, opts.Workspace),
		tokens:        registry,
		singleToken:   token,
		sessionLimit:  newSessionLimiter(),
		version:       version,
		startedAt:     time.Now().UTC(),
		config: consoleConfig{
			AdvisoryPath:   opts.AdvisoryPath,
			AdvisoryDir:    opts.AdvisoryDir,
			PackageMapPath: opts.PackageMap,
			RuntimeReport:  opts.RuntimeReport,
		},
	}
	if opts.Workspace != "" {
		persisted, err := loadWorkspaceConfig(opts.Workspace)
		if err != nil {
			closeSnapshot(snapshot)
			return nil, err
		}
		// Explicit flags win over the persisted file so a one-off override is
		// possible without hand-editing the workspace.
		console.config = mergeConfig(persisted, console.config)
		console.storedAgentDSN = persisted.AgentDSN
		console.storedAgentToken = persisted.AgentToken
		console.agentChatEnabled = opts.EnableAgentChat || persisted.AgentChatEnabled
		if opts.AgentToken == "" {
			opts.AgentToken = persisted.AgentToken
		}
		if console.chat.model == "" && persisted.AgentModel != "" {
			console.chat.model = persisted.AgentModel
		}
		// Resolution order for the Agent session database: explicit flag, then
		// the persisted workspace value, then the environment. A persisted or
		// environment DSN that cannot connect must not stop the whole console.
		if opts.AgentDSN == "" {
			opts.AgentDSN = persisted.AgentDSN
		}
		if opts.AgentDSN == "" {
			opts.AgentDSN = os.Getenv("TRIDENT_AGENT_DSN")
		}
		// Record the served project so the next start only needs --workspace.
		source := opts.ProjectSource
		if source == "" && persisted.Project != nil {
			source = persisted.Project.Source
		}
		persisted.Project = &workspaceProj{
			Source:       source,
			SnapshotDir:  opts.SnapshotDir,
			SnapshotHash: opts.SnapshotHash,
		}
		persisted.AdvisoryPath = console.config.AdvisoryPath
		persisted.AdvisoryDir = console.config.AdvisoryDir
		persisted.PackageMap = console.config.PackageMapPath
		persisted.RuntimeReport = console.config.RuntimeReport
		if err := saveWorkspaceConfig(opts.Workspace, persisted); err != nil {
			closeSnapshot(snapshot)
			return nil, err
		}
		if snapshot != nil {
			manifest := snapshot.Manifest()
			console.rememberProject(projectEntry{
				Source: source, SnapshotDir: opts.SnapshotDir, Hash: opts.SnapshotHash,
				Files: manifest.TotalFiles, Bytes: manifest.TotalBytes,
				ImportedAt: time.Now().UTC().Format(time.RFC3339),
			})
		}
	}
	if opts.AgentDSN != "" {
		observation, err := store.Open(ctx, opts.AgentDSN, false)
		if err != nil {
			if opts.AgentDSNExplicit {
				closeSnapshot(snapshot)
				return nil, err
			}
			// A persisted or environment DSN that is temporarily unreachable
			// (container stopped, password rotated) degrades gracefully: the
			// Agent page reports the reason instead of blocking every start.
			console.agentConnectError = "打开 Agent 会话库失败：" + err.Error()
		} else {
			console.agentStore = observation
		}
	}
	if opts.AgentKeyEnv == "" {
		opts.AgentKeyEnv = "TRIDENT_MODEL_API_KEY"
	}
	console.chat = agentChat{
		enabled: false, endpoint: opts.AgentEndpoint, model: opts.AgentModel,
		outputParam: "max_tokens", keyEnv: opts.AgentKeyEnv, advisories: opts.AdvisoryPath,
	}
	if opts.Workspace != "" {
		if loaded, err := loadModels(opts.Workspace); err != nil {
			closeSnapshot(snapshot)
			return nil, err
		} else if len(loaded.Profiles) > 0 {
			console.models = loaded
		}
	}
	if len(console.models.Profiles) == 0 {
		seed := seedProfile(opts.AgentEndpoint, opts.AgentModel, opts.AgentKeyEnv)
		if seed.Endpoint != "" && seed.Model != "" {
			console.models = modelsFile{SchemaVersion: modelsSchemaVersion, Profiles: []modelProfile{seed}, Default: seed.ID}
		} else {
			console.models = modelsFile{SchemaVersion: modelsSchemaVersion, Profiles: []modelProfile{}}
		}
	}
	// Seeded or hand-written libraries must carry the v2 role slots before
	// applyModels resolves them.
	normalizeModels(&console.models)
	if opts.Workspace != "" && len(console.models.Profiles) > 0 {
		// Persist the seeded library once so the file is visible and editable
		// instead of being rebuilt from flags on every start.
		if _, statErr := os.Stat(modelsPath(opts.Workspace)); statErr != nil {
			_ = saveModels(opts.Workspace, console.models)
		}
	}
	if opts.Workspace != "" {
		keys, keyErr := loadModelKeys(opts.Workspace)
		if keyErr != nil {
			closeSnapshot(snapshot)
			return nil, keyErr
		}
		console.modelKeys = keys
	}
	if console.modelKeys == nil {
		console.modelKeys = map[string]string{}
	}
	// The library is the source of truth for endpoint/model/key variable once it
	// exists, so a saved profile survives a restart without repeating the flags.
	console.applyModels(console.models)

	switch {
	case !console.agentChatEnabled:
		console.chat.reason = "未启用：在「设置 → Agent 与编排」里开启（无需重启）"
	case opts.AgentDSN == "":
		console.chat.reason = "需要 Agent 会话库连接串：在「设置 → Agent 与编排」里填写"
	case opts.AgentToken == "":
		console.chat.reason = "需要主体令牌：在「设置 → Agent 与编排」里填写（具备创建 Run 权限）"
	default:
		writable, err := store.Open(ctx, opts.AgentDSN, false)
		if err != nil {
			console.chat.reason = "打开可写 Agent 数据库失败：" + err.Error()
			console.agentChatEnabled = true
			break
		}
		session, err := writable.Authenticate(ctx, opts.AgentToken)
		if err != nil {
			writable.Close()
			console.chat.reason = "Agent 令牌无效或已撤销：在「设置 → Agent 与编排」里更新"
			console.agentChatEnabled = true
			break
		}
		console.agentWrite = writable
		console.agentSession = session
		console.chat.enabled = true
		console.agentChatEnabled = true
		console.orchEngine = orchestrator.New(writable, session)
	}
	if opts.AccessLog != "" {
		logger, err := newAccessLogger(opts.AccessLog)
		if err != nil {
			closeSnapshot(snapshot)
			return nil, err
		}
		console.accessLog = logger
	}
	return console, nil
}

// swapAgentStore replaces the observation store at runtime after a settings
// save. A nil observation clears the stored connection and returns the Agent
// page to the "not configured" state.
func (c *Console) swapAgentStore(observation *store.Store) {
	c.agentStoreMu.Lock()
	defer c.agentStoreMu.Unlock()
	if c.agentStore != nil {
		c.agentStore.Close()
	}
	c.agentStore = observation
	c.agentConnectError = ""
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

// closeSnapshot closes a snapshot only when one is open. A workspace console can
// legitimately run with no project.
func closeSnapshot(snapshot *project.Snapshot) {
	if snapshot != nil {
		_ = snapshot.Close()
	}
}

// snapshotRef returns the snapshot currently being served. The console may swap
// it at runtime in workspace mode, so handlers must never cache the pointer.
func (c *Console) snapshotRef() *project.Snapshot {
	c.snapMu.RLock()
	defer c.snapMu.RUnlock()
	return c.snapshot
}

// SnapshotHash returns the pinned snapshot digest, or "" when no project is open.
func (c *Console) SnapshotHash() string {
	if snapshot := c.snapshotRef(); snapshot != nil {
		return snapshot.Hash()
	}
	return ""
}

func (c *Console) currentConfig() consoleConfig {
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	return c.config
}

func (c *Console) Close() error {
	c.snapMu.RLock()
	var err error
	if c.snapshot != nil {
		err = c.snapshot.Close()
	}
	c.snapMu.RUnlock()
	if logErr := c.accessLog.Close(); logErr != nil && err == nil {
		err = logErr
	}
	if c.agentStore != nil {
		c.agentStore.Close()
	}
	if c.agentWrite != nil {
		c.agentWrite.Close()
	}
	return err
}

// resetAnalysis drops the cached analysis and the lazily built reachability
// report. Callers must hold no lock; the next request re-runs every analyzer.
func (c *Console) resetAnalysis() {
	c.mu.Lock()
	c.state = nil
	c.mu.Unlock()
	c.reachMu.Lock()
	c.reachState = nil
	c.reachMu.Unlock()
	c.codeMu.Lock()
	c.codeState = nil
	c.codeReason = ""
	c.codeFatal = nil
	c.codeMu.Unlock()
}

// analyze runs SCA, the endpoint inventory, bounded dataflow, the authorization
// inventory and the unified evidence model once, then serves every page from the
// cached report. A failed analysis is cached as a terminal error instead of
// being retried per request.
func (c *Console) analyze(ctx context.Context) (*analysisState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != nil {
		c.analysisCacheHits.Add(1)
		return c.state, c.state.err
	}
	started := time.Now()
	state := &analysisState{}
	snapshot := c.snapshotRef()
	if snapshot == nil {
		state.err = fmt.Errorf("%w: no project selected", ErrNoProject)
		state.at = time.Now().UTC()
		c.state = state
		return state, state.err
	}
	cfg := c.currentConfig()
	scaReport, scaErr := sca.Inspect(ctx, snapshot, cfg.advisoryOptions())
	endpointReport, auditErr := audit.Inspect(ctx, snapshot)
	findingReport, findingErr := findings.Analyze(ctx, snapshot, findings.Options{AdvisoryPath: cfg.AdvisoryPath, PackageMapPath: cfg.PackageMapPath})
	authzReport, authzErr := authz.Analyze(ctx, snapshot)
	switch {
	case findingErr != nil:
		state.err = fmt.Errorf("analysis failed: %w", findingErr)
	case scaErr != nil:
		state.err = fmt.Errorf("SCA analysis failed: %w", scaErr)
	case auditErr != nil:
		state.err = fmt.Errorf("endpoint inventory failed: %w", auditErr)
	case authzErr != nil:
		state.err = fmt.Errorf("authorization inventory failed: %w", authzErr)
	default:
		state.findings = findingReport
		state.sca = scaReport
		state.audit = endpointReport
		state.authz = authzReport
	}
	// The Java semantic model is optional: it is the only analyzer whose memory
	// grows with the whole project, so a very large snapshot keeps it disabled
	// instead of exhausting the process.
	if state.err == nil {
		if files := endpointReport.Coverage.JavaFilesScanned; files > MaxJavaModelFiles {
			state.modelErr = fmt.Sprintf("项目包含 %d 个 Java 文件，超过代码模型上限 %d；已跳过语义模型", files, MaxJavaModelFiles)
		} else if model, modelErr := javaast.Analyze(ctx, snapshot); modelErr != nil {
			state.modelErr = modelErr.Error()
		} else {
			state.model = &model
		}
	}
	// Multi-language rule audit is deliberately NOT part of the synchronous
	// first analysis: a large PHP/.NET project can take tens of seconds, and
	// every page (including project import feedback) would block on it. It is
	// computed lazily on the first /api/code-audit request instead.
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
	mux.HandleFunc("GET /api/cases", c.handleCases)
	mux.HandleFunc("POST /api/cases", c.handleCaseCreate)
	mux.HandleFunc("GET /api/case", c.handleCase)
	mux.HandleFunc("POST /api/case/propose", c.handleCasePropose)
	mux.HandleFunc("POST /api/case/verify", c.handleCaseVerify)
	mux.HandleFunc("GET /api/case/export", c.handleCaseExport)
	mux.HandleFunc("GET /api/endpoints", c.handleEndpoints)
	mux.HandleFunc("GET /api/dependencies", c.handleDependencies)
	mux.HandleFunc("GET /api/files", c.handleFiles)
	mux.HandleFunc("GET /api/file", c.handleFile)
	mux.HandleFunc("GET /api/search", c.handleSearch)
	mux.HandleFunc("GET /api/sbom", c.handleSBOM)
	mux.HandleFunc("GET /api/report", c.handleReport)
	mux.HandleFunc("GET /api/metrics", c.handleMetrics)
	mux.HandleFunc("GET /metrics", c.handleMetricsText)
	mux.HandleFunc("GET /api/tree", c.handleTree)
	mux.HandleFunc("GET /api/sarif", c.handleSARIF)
	mux.HandleFunc("GET /api/reachability", c.handleReachability)
	mux.HandleFunc("GET /api/runtime-report", c.handleRuntimeReport)
	mux.HandleFunc("GET /api/agent/threads", c.handleAgentThreads)
	mux.HandleFunc("GET /api/agent/conversations", c.handleAgentConversations)
	mux.HandleFunc("GET /api/agent/conversations/detail", c.handleAgentConversationDetail)
	mux.HandleFunc("POST /api/agent/conversations/rename", c.handleAgentConversationRename)
	mux.HandleFunc("GET /api/agent/chat/state", c.handleAgentChatState)
	mux.HandleFunc("GET /api/agent/models", c.handleModelProfiles)
	mux.HandleFunc("POST /api/agent/models", c.handleModelProfileUpsert)
	mux.HandleFunc("POST /api/agent/models/remove", c.handleModelProfileRemove)
	mux.HandleFunc("POST /api/agent/models/probe", c.handleModelProbe)
	mux.HandleFunc("POST /api/agent/models/roles", c.handleModelRole)
	mux.HandleFunc("POST /api/agent/models/key", c.handleModelKey)
	mux.HandleFunc("GET /api/agent/runtime", c.handleAgentRuntime)
	mux.HandleFunc("POST /api/agent/runtime", c.handleAgentRuntimeUpdate)
	mux.HandleFunc("GET /api/agent/runtime/quick", c.handleAgentRuntimeQuick)
	mux.HandleFunc("POST /api/agent/runtime/quick", c.handleAgentRuntimeQuickEnable)
	mux.HandleFunc("GET /api/agent/model-channels", c.handleModelChannels)
	mux.HandleFunc("GET /api/agent/model-channels/{provider}/models", c.handleModelChannelModels)
	mux.HandleFunc("GET /api/agent/model-catalog/lookup", c.handleModelCatalogLookup)
	mux.HandleFunc("POST /api/agent/chat", c.handleAgentChat)
	mux.HandleFunc("GET /api/agent/steps", c.handleAgentSteps)
	mux.HandleFunc("POST /api/agent/orchestration", c.handleOrchestrationCreate)
	mux.HandleFunc("GET /api/agent/orchestration", c.handleOrchestrationList)
	mux.HandleFunc("GET /api/agent/orchestration/detail", c.handleOrchestrationDetail)
	mux.HandleFunc("POST /api/agent/orchestration/steer", c.handleOrchestrationSteer)
	mux.HandleFunc("POST /api/agent/orchestration/stop", c.handleOrchestrationStop)
	mux.HandleFunc("GET /api/authz", c.handleAuthz)
	mux.HandleFunc("GET /api/code-audit", c.handleCodeAudit)
	mux.HandleFunc("GET /api/toolchains", c.handleToolchains)
	mux.HandleFunc("GET /api/symbols", c.handleSymbols)
	mux.HandleFunc("GET /api/model", c.handleModel)
	mux.HandleFunc("GET /api/model/type", c.handleModelType)
	mux.HandleFunc("GET /api/config", c.handleConfig)
	mux.HandleFunc("POST /api/config", c.handleConfigUpdate)
	mux.HandleFunc("GET /api/projects", c.handleProjects)
	mux.HandleFunc("POST /api/projects", c.handleProjectCreate)
	mux.HandleFunc("POST /api/projects/select", c.handleProjectSelect)
	mux.HandleFunc("POST /api/projects/forget", c.handleProjectForget)
	mux.HandleFunc("GET /api/fs", c.handleFilesystem)
	mux.HandleFunc("POST /api/analysis/rerun", c.handleAnalysisRerun)
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

// handleMetricsText serves the same counters as Prometheus text format 0.0.4
// so a real Prometheus can scrape them with a bearer token. Metric names match
// the alert rule template in docs/deployment.md.
func (c *Console) handleMetricsText(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	cached, cachedOK := int64(0), int64(0)
	if state != nil {
		cached = 1
		if state.err == nil {
			cachedOK = 1
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP trident_console_build_info Product build metadata.\n# TYPE trident_console_build_info gauge\ntrident_console_build_info{product=\"TRIDENT\",version=\"%s\"} 1\n", escapeLabelValue(c.version))
	gauge := func(name, help string, value int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
	}
	counter := func(name, help string, value int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
	}
	gauge("trident_console_uptime_seconds", "Process uptime in seconds.", int64(time.Since(c.startedAt).Seconds()))
	counter("trident_console_requests_total", "Gated console requests served or rejected.", c.requestsTotal.Load())
	counter("trident_console_requests_unauthorized_total", "Middleware-level 401 rejections.", c.unauthorizedTotal.Load())
	counter("trident_console_requests_forbidden_total", "Middleware-level 403 rejections.", c.forbiddenTotal.Load())
	counter("trident_console_analysis_runs_total", "Cold analysis runs, including terminal failures.", c.analysisRuns.Load())
	counter("trident_console_analysis_cache_hits_total", "Cached analysis reads.", c.analysisCacheHits.Load())
	counter("trident_console_analysis_failures_total", "Analysis runs that ended in a terminal failure.", c.analysisFailures.Load())
	gauge("trident_console_analysis_cached", "Whether a terminal analysis state is cached.", cached)
	gauge("trident_console_analysis_cached_ok", "Whether the cached analysis succeeded.", cachedOK)
	gauge("trident_console_analysis_last_duration_milliseconds", "Wall-clock duration of the last cold analysis run.", c.lastDurationMS.Load())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// escapeLabelValue applies the Prometheus text-format escaping (backslash,
// quote, newline) without Go's extra escape sequences.
func escapeLabelValue(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(value)
}

// requiresProject reports whether a route needs an open snapshot. Project
// management, configuration, probes and metrics stay usable before the first
// import so the browser can bootstrap itself.
func requiresProject(path string) bool {
	if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/export/") {
		return false
	}
	switch {
	case path == "/api/session", path == "/api/health", path == "/api/metrics",
		path == "/api/config", path == "/api/fs",
		path == "/api/projects", path == "/api/projects/select", path == "/api/projects/forget",
		path == "/api/cases", path == "/api/case", path == "/api/case/propose",
		path == "/api/case/verify", path == "/api/case/export",
		path == "/api/agent/chat/state", path == "/api/agent/models", path == "/api/agent/models/key",
		path == "/api/agent/runtime", path == "/api/agent/runtime/quick":
		return false
	case strings.HasPrefix(path, "/api/agent/model-channels"),
		strings.HasPrefix(path, "/api/agent/model-catalog/"):
		// The catalog is static and needed before a project exists so the model
		// settings page can render its channel picker.
		return false
	}
	return true
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
		metricsProbe := r.URL.Path == "/metrics"
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
			// The scrape endpoint is part of the operations plane: token-gated
			// like every other gated path, but exempt from the browser-only
			// console request header so Prometheus can scrape it with a bearer
			// token.
			if metricsProbe {
				if r.Method != http.MethodGet {
					c.accessLog.record(entry, r, http.StatusMethodNotAllowed)
					writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "scrape endpoint is read-only")
					return
				}
			} else {
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
		}
		if gated && requiresProject(r.URL.Path) && c.snapshotRef() == nil {
			c.forbiddenTotal.Add(1)
			c.accessLog.record(entry, r, http.StatusConflict)
			writeError(w, http.StatusConflict, "no_project", "尚未导入项目：请先在「项目」页选择本地源码目录")
			return
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
		// Prometheus and other pollers present a bearer token instead of the
		// browser-only console header.
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
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
	key := sessionClientKey(r)
	if wait := c.sessionLimit.retryAfter(key); wait > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds()+0.999)))
		writeError(w, http.StatusTooManyRequests, "session_rate_limited", "too many rejected tokens; retry later")
		return
	}
	if _, ok := c.tokens.lookup(request.Token); !ok {
		c.sessionLimit.fail(key)
		writeError(w, http.StatusUnauthorized, "unauthorized", "access token rejected")
		return
	}
	c.sessionLimit.reset(key)
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
	writeJSON(w, http.StatusOK, healthResponse{SchemaVersion: SchemaVersion, Status: "ok", Product: Product, SnapshotHash: c.SnapshotHash(), AnalysisReady: ready, RuntimeStatus: "not_run"})
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
	Details       any    `json:"details,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{SchemaVersion: SchemaVersion, Code: code, Error: message})
}

// writeErrorDetails adds a bounded machine-readable payload (for example the
// roles that still reference a model entry). Existing errors stay unchanged.
func writeErrorDetails(w http.ResponseWriter, status int, code, message string, details any) {
	writeJSON(w, status, errorResponse{SchemaVersion: SchemaVersion, Code: code, Error: message, Details: details})
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
