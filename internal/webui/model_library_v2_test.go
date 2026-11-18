package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/domain"
)

func writeModelsFile(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "models.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaOneFileMigratesToV2(t *testing.T) {
	dir := t.TempDir()
	writeModelsFile(t, dir, `{
	  "schema_version": 1,
	  "default": "legacy",
	  "profiles": [
	    {"id": "legacy", "label": "Legacy", "endpoint": "https://api.example.com/v1",
	     "model": "legacy-1", "key_env": "TRIDENT_MODEL_API_KEY",
	     "defaults": {"model_calls": 8, "tool_calls": 16, "tokens": 65536}}
	  ]
	}`)
	file, err := loadModels(dir)
	if err != nil {
		t.Fatalf("legacy file must load: %v", err)
	}
	if file.SchemaVersion != modelsSchemaVersion {
		t.Fatalf("schema not upgraded: %d", file.SchemaVersion)
	}
	profile := file.Profiles[0]
	if profile.API != apiOpenAICompletions {
		t.Fatalf("legacy profile must default to openai-completions, got %q", profile.API)
	}
	if profile.Cost != nil || profile.Capabilities != (modelCapabilities{}) {
		t.Fatalf("migration must not invent capabilities or prices: %+v", profile)
	}
	if file.Roles.Main != "legacy" || file.Roles.Planner != followMain || file.Roles.Worker != followMain {
		t.Fatalf("unexpected roles after migration: %+v", file.Roles)
	}
	if err := saveModels(dir, file); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "models.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"schema_version": 2`) {
		t.Fatalf("saved file must be schema 2: %s", raw)
	}
	if !strings.Contains(string(raw), `"planner": "follow-main"`) {
		t.Fatalf("saved file must persist roles: %s", raw)
	}
}

func TestBuildProfileValidatesProtocolCapabilitiesAndCost(t *testing.T) {
	base := profileUpsertRequest{
		ID: "deepseek-chat", Endpoint: "https://api.deepseek.com", Model: "deepseek-chat",
		KeyEnv: "TRIDENT_MODEL_API_KEY", API: apiOpenAICompletions,
	}
	profile, err := buildProfile(base)
	if err != nil {
		t.Fatalf("baseline profile rejected: %v", err)
	}
	if profile.API != apiOpenAICompletions || profile.Cost != nil {
		t.Fatalf("unexpected defaults: %+v", profile)
	}

	badAPI := base
	badAPI.API = "grpc"
	if _, err := buildProfile(badAPI); err == nil {
		t.Fatal("unknown protocol must be rejected")
	}

	tooWide := base
	tooWide.Capabilities = &modelCapabilities{ContextWindow: maxContextWindow + 1}
	if _, err := buildProfile(tooWide); err == nil {
		t.Fatal("context window above the bound must be rejected")
	}

	negative := base
	negative.Cost = &modelCost{Input: -1}
	if _, err := buildProfile(negative); err == nil {
		t.Fatal("negative price must be rejected")
	}

	unsupported := base
	unsupported.API = apiAnthropicMessages
	if _, err := buildProfile(unsupported); err == nil {
		t.Fatal("protocols without an adapter must be rejected at save time")
	}

	rounded := base
	rounded.Cost = &modelCost{Input: 1.23456789, Output: 3.5}
	profile, err = buildProfile(rounded)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Cost == nil || profile.Cost.Input != 1.234568 {
		t.Fatalf("price must round to six decimals: %+v", profile.Cost)
	}

	allZero := base
	allZero.Cost = &modelCost{}
	profile, err = buildProfile(allZero)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Cost != nil {
		t.Fatalf("an all-zero price group means undeclared, got %+v", profile.Cost)
	}
}

func roleTestFile() modelsFile {
	return modelsFile{
		SchemaVersion: modelsSchemaVersion,
		Profiles: []modelProfile{
			{ID: "alpha", Label: "Alpha", Endpoint: "https://a.example.com", Model: "a1", KeyEnv: "K_A", API: apiOpenAICompletions},
			{ID: "beta", Label: "Beta", Endpoint: "https://b.example.com", Model: "b1", KeyEnv: "K_B", API: apiOpenAICompletions},
		},
		Default: "alpha",
		Roles:   modelRoles{Main: "alpha", Planner: followMain, Worker: "beta"},
	}
}

func TestResolveRolesFollowsMain(t *testing.T) {
	file := roleTestFile()
	resolved := resolveRoles(file)
	if resolved[roleMain].EntryID != "alpha" || resolved[roleMain].FollowedMain {
		t.Fatalf("main must resolve itself without follow flag: %+v", resolved[roleMain])
	}
	if resolved[rolePlanner].EntryID != "alpha" || !resolved[rolePlanner].FollowedMain {
		t.Fatalf("planner must follow main: %+v", resolved[rolePlanner])
	}
	if resolved[roleWorker].EntryID != "beta" || resolved[roleWorker].FollowedMain {
		t.Fatalf("worker must resolve to its own entry: %+v", resolved[roleWorker])
	}
	if got := profileRoleRefs(file, "beta"); len(got) != 1 || got[0] != roleWorker {
		t.Fatalf("explicit refs must list worker only: %v", got)
	}
	if got := profileRoleRefs(file, "alpha"); len(got) != 1 || got[0] != roleMain {
		t.Fatalf("follow-main must not count as an explicit ref: %v", got)
	}
}

func consoleWithModels(t *testing.T, file modelsFile) *Console {
	t.Helper()
	dir := t.TempDir()
	if err := saveModels(dir, file); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadModels(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &Console{workspace: dir, models: loaded}
}

func TestRoleEndpointRejectsMainFollowingItself(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	body := strings.NewReader(`{"role":"main","target":"follow-main"}`)
	recorder := httptest.NewRecorder()
	console.handleModelRole(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/roles", body))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("main must not follow itself, got %d %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid_role_target") {
		t.Fatalf("unexpected error code: %s", recorder.Body.String())
	}

	body = strings.NewReader(`{"role":"planner","target":"beta"}`)
	recorder = httptest.NewRecorder()
	console.handleModelRole(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/roles", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("planner assignment failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if console.models.Roles.Planner != "beta" {
		t.Fatalf("planner not persisted: %+v", console.models.Roles)
	}
	if console.models.Roles.Main != "alpha" {
		t.Fatalf("assigning planner must not move main: %+v", console.models.Roles)
	}
}

func TestDeleteIsBlockedByRoleReference(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	recorder := httptest.NewRecorder()
	console.handleModelProfileRemove(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/remove",
		strings.NewReader(`{"id":"beta"}`)))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("referenced profile must not be deleted: %d %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Code    string `json:"code"`
		Details struct {
			Roles []string `json:"roles"`
		} `json:"details"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "profile_in_use" || len(body.Details.Roles) != 1 || body.Details.Roles[0] != roleWorker {
		t.Fatalf("unexpected delete rejection: %+v", body)
	}

	// Removing the worker reference makes the same entry deletable.
	file := console.modelsSnapshot()
	file.Roles.Worker = followMain
	if err := saveModels(console.workspace, file); err != nil {
		t.Fatal(err)
	}
	console.applyModels(file)
	recorder = httptest.NewRecorder()
	console.handleModelProfileRemove(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/remove",
		strings.NewReader(`{"id":"beta"}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("unreferenced profile must be deletable: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestChannelCatalogSearchAndLookup(t *testing.T) {
	deepseek := channelViews("deepseek")
	if len(deepseek) != 1 || deepseek[0].Provider != "deepseek" || deepseek[0].ModelCount == 0 {
		t.Fatalf("deepseek search failed: %+v", deepseek)
	}
	all := channelViews("")
	if len(all) < 5 || !all[0].Featured {
		t.Fatalf("featured channels must sort first: %+v", all)
	}
	found := false
	for _, channel := range all {
		if channel.Provider == "openai" {
			found = true
		}
	}
	if !found {
		t.Fatal("openai channel missing from catalog")
	}
}

func TestProbeClassifiesFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"ok", http.StatusOK, `{"data":[{"id":"m1"}]}`, "ok"},
		{"auth", http.StatusUnauthorized, `{}`, "auth"},
		{"forbidden", http.StatusForbidden, `{}`, "auth"},
		{"not found", http.StatusNotFound, `{}`, "not_found"},
		{"upstream", http.StatusBadGateway, `{}`, "upstream"},
		{"rate limited", http.StatusTooManyRequests, `{}`, "upstream"},
		{"bad json", http.StatusOK, `not json`, "protocol"},
		{"empty", http.StatusOK, `{"data":[]}`, "empty"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			probe := probeProfile(t.Context(), modelProfile{
				ID: "p", Endpoint: server.URL, Model: "m1", KeyEnv: "TRIDENT_PROBE_KEY",
				API: apiOpenAICompletions,
			}, "sk-test")
			if probe.Status != test.want {
				t.Fatalf("status %q, want %q (%s)", probe.Status, test.want, probe.Error)
			}
			if probe.OK != (test.want == "ok") {
				t.Fatalf("ok flag mismatch: %+v", probe)
			}
			if test.want == "ok" && len(probe.Models) != 1 {
				t.Fatalf("models not parsed: %+v", probe)
			}
		})
	}
}

func TestProbeUsesBearerAndModelsPath(t *testing.T) {
	var gotPath, gotAuth, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"data":[{"id":"deepseek-chat"}]}`))
	}))
	defer server.Close()

	probe := probeProfile(t.Context(), modelProfile{
		ID: "p", Endpoint: server.URL, Model: "deepseek-chat", KeyEnv: "TRIDENT_PROBE_KEY",
		API: apiOpenAICompletions,
	}, "sk-test")
	if !probe.OK || gotPath != "/models" || gotAuth != "Bearer sk-test" || gotAccept == "" {
		t.Fatalf("openai-compatible probe mismatch: ok=%v path=%q auth=%q accept=%q", probe.OK, gotPath, gotAuth, gotAccept)
	}
	if probe.API != apiOpenAICompletions {
		t.Fatalf("probe must echo the protocol: %+v", probe)
	}
}

func TestProbeMissingKeyShortCircuits(t *testing.T) {
	probe := probeProfile(t.Context(), modelProfile{
		ID: "p", Endpoint: "https://api.example.com", Model: "m", KeyEnv: "TRIDENT_PROBE_KEY",
	}, "")
	if probe.Status != "key_missing" || probe.OK {
		t.Fatalf("missing key must short-circuit: %+v", probe)
	}
}

func TestCostEstimateAndRunUsage(t *testing.T) {
	cost := &modelCost{Input: 1, Output: 4}
	if got := estimateCost(cost, 1_000_000, 500_000); got != 3 {
		t.Fatalf("estimate cost = %v, want 3", got)
	}
	if got := estimateCost(cost, 1, 0); got != 0.000001 {
		t.Fatalf("micro cost = %v, want 0.000001", got)
	}

	console := consoleWithModels(t, modelsFile{
		SchemaVersion: modelsSchemaVersion,
		Profiles: []modelProfile{{
			ID: "priced", Label: "Priced", Endpoint: "https://api.example.com", Model: "m1",
			KeyEnv: "TRIDENT_MODEL_API_KEY", API: apiOpenAICompletions, Cost: cost,
		}},
		Default: "priced", Roles: modelRoles{Main: "priced", Planner: followMain, Worker: followMain},
	})
	config, _ := json.Marshal(runConfigRef{Endpoint: "https://api.example.com", Model: "m1"})
	run := domain.AgentRun{Config: config, TokensUsed: 1500, LastSeq: 2}
	steps := []domain.AgentStep{
		{Seq: 1, Kind: domain.AgentStepModelCompleted, Payload: json.RawMessage(`{"usage":{"known":true,"input_tokens":1000000,"output_tokens":250000}}`)},
		{Seq: 2, Kind: domain.AgentStepModelCompleted, Payload: json.RawMessage(`{"usage":{"known":false}}`)},
	}
	usage := console.runUsageOf(run, steps)
	if !usage.Known || usage.InputTokens != 1000000 || usage.OutputTokens != 250000 {
		t.Fatalf("usage aggregation failed: %+v", usage)
	}
	if usage.EstimatedCost == nil || *usage.EstimatedCost != 2 {
		t.Fatalf("cost estimate failed: %+v", usage)
	}
	if usage.PricingSource != "profile" || usage.Currency != "USD" {
		t.Fatalf("pricing metadata missing: %+v", usage)
	}

	// Unknown usage must not become a zero cost.
	unknown := console.runUsageOf(run, []domain.AgentStep{
		{Seq: 1, Kind: domain.AgentStepModelCompleted, Payload: json.RawMessage(`{"usage":{"known":false}}`)},
	})
	if unknown.EstimatedCost != nil || unknown.Known {
		t.Fatalf("unknown usage must stay unpriced: %+v", unknown)
	}

	// A run whose endpoint no longer matches any entry stays unpriced.
	otherConfig, _ := json.Marshal(runConfigRef{Endpoint: "https://gone.example.com", Model: "m1"})
	orphan := console.runUsageOf(domain.AgentRun{Config: otherConfig, LastSeq: 1}, steps[:1])
	if orphan.EstimatedCost != nil || orphan.PricingSource != "none" {
		t.Fatalf("orphan run must stay unpriced: %+v", orphan)
	}
}

func TestProbeRejectsUnsupportedModelsPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"list"}`))
	}))
	defer server.Close()
	probe := probeProfile(t.Context(), modelProfile{
		ID: "p", Endpoint: server.URL, Model: "m", KeyEnv: "TRIDENT_PROBE_KEY", API: apiOpenAICompletions,
	}, "sk-test")
	if probe.Status != "protocol" {
		t.Fatalf("missing data array must be a protocol error: %+v", probe)
	}
}
