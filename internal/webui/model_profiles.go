package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Model profiles are the console's model library. A profile names an endpoint,
// a model, a wire protocol and the environment variable that holds the key: the
// key itself is never written to the workspace or returned to the browser.
type modelProfile struct {
	ID           string            `json:"id"`
	Label        string            `json:"label,omitempty"`
	Endpoint     string            `json:"endpoint"`
	Model        string            `json:"model"`
	KeyEnv       string            `json:"key_env"`
	API          string            `json:"api"`
	Capabilities modelCapabilities `json:"capabilities"`
	Cost         *modelCost        `json:"cost,omitempty"`
	Defaults     profileBudget     `json:"defaults"`
}

// modelCapabilities is declarative metadata, never probe-verified. A zero value
// means "not declared" and the UI must show no capability chip.
type modelCapabilities struct {
	ContextWindow int64 `json:"context_window"`
	MaxOutput     int64 `json:"max_output"`
	Reasoning     bool  `json:"reasoning"`
	Vision        bool  `json:"vision"`
}

// modelCost is USD per million tokens. A nil group means "not declared"; it is
// never rendered as a zero price.
type modelCost struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cache_read"`
	CacheWrite float64 `json:"cache_write"`
}

type profileBudget struct {
	ModelCalls int64 `json:"model_calls"`
	ToolCalls  int64 `json:"tool_calls"`
	Tokens     int64 `json:"tokens"`
}

// modelRoles are the three model consumers TRIDENT actually has. Values are a
// profile ID or followMain; main cannot follow itself.
type modelRoles struct {
	Main    string `json:"main"`
	Planner string `json:"planner"`
	Worker  string `json:"worker"`
}

type modelsFile struct {
	SchemaVersion int            `json:"schema_version"`
	Profiles      []modelProfile `json:"profiles"`
	Default       string         `json:"default,omitempty"`
	Roles         modelRoles     `json:"roles"`
}

const (
	modelsSchemaVersion = 2
	modelsSchemaLegacy  = 1

	// RoleIDs are fixed slots tied to real consumers: the manual chat run, the
	// orchestration planner round and the orchestration worker sessions.
	roleMain    = "main"
	rolePlanner = "planner"
	roleWorker  = "worker"

	followMain = "follow-main"

	apiOpenAICompletions = "openai-completions"
	apiOpenAIResponses   = "openai-responses"
	apiAnthropicMessages = "anthropic-messages"
	apiGoogleGenerative  = "google-generative-ai"

	maxContextWindow  = 10_000_000
	maxOutputTokens   = 1_000_000
	maxCostPerMillion = 10_000
	maxCostDecimals   = 6
)

var (
	profileIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	keyEnvPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	modelNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

	// modelAPIs lists the wire protocols the schema can describe (legacy files
	// may carry any of them). runtimeAPIs is stricter: the console only ships an
	// OpenAI Chat Completions client, so anything else must be refused instead of
	// silently sending the wrong request shape.
	modelAPIs = map[string]bool{
		apiOpenAICompletions: true,
		apiOpenAIResponses:   true,
		apiAnthropicMessages: true,
		apiGoogleGenerative:  true,
	}
	runtimeAPIs = map[string]bool{apiOpenAICompletions: true}
)

func modelsPath(workspace string) string {
	return filepath.Join(workspace, "models.json")
}

func loadModels(workspace string) (modelsFile, error) {
	file := modelsFile{SchemaVersion: modelsSchemaVersion, Profiles: []modelProfile{}}
	if workspace == "" {
		normalizeModels(&file)
		return file, nil
	}
	data, err := os.ReadFile(modelsPath(workspace))
	if errors.Is(err, os.ErrNotExist) {
		normalizeModels(&file)
		return file, nil
	}
	if err != nil {
		return file, fmt.Errorf("model library is unreadable: %w", err)
	}
	if len(data) > 4<<20 {
		return file, errors.New("model library is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return file, fmt.Errorf("model library is invalid: %v", err)
	}
	if file.SchemaVersion != modelsSchemaLegacy && file.SchemaVersion != modelsSchemaVersion {
		return file, fmt.Errorf("model library schema %d is not supported", file.SchemaVersion)
	}
	// Schema 1 files simply leave the new fields empty; normalize fills the
	// documented defaults and mirrors default into the main role.
	normalizeModels(&file)
	return file, nil
}

// normalizeModels upgrades a decoded file (schema 1 or 2) to the in-memory v2
// shape. It is idempotent and never invents capabilities or prices.
func normalizeModels(file *modelsFile) {
	file.SchemaVersion = modelsSchemaVersion
	if file.Profiles == nil {
		file.Profiles = []modelProfile{}
	}
	sort.SliceStable(file.Profiles, func(i, j int) bool { return file.Profiles[i].ID < file.Profiles[j].ID })
	exists := make(map[string]bool, len(file.Profiles))
	for index := range file.Profiles {
		profile := &file.Profiles[index]
		if profile.API == "" || !modelAPIs[profile.API] {
			profile.API = apiOpenAICompletions
		}
		profile.Cost = normalizeCost(profile.Cost)
	}
	for _, profile := range file.Profiles {
		exists[profile.ID] = true
	}
	if file.Default == "" || !exists[file.Default] {
		file.Default = ""
		if len(file.Profiles) > 0 {
			file.Default = file.Profiles[0].ID
		}
	}
	if file.Roles.Main == "" || !exists[file.Roles.Main] {
		file.Roles.Main = file.Default
	}
	for _, role := range []*string{&file.Roles.Planner, &file.Roles.Worker} {
		if *role == "" || (*role != followMain && !exists[*role]) {
			*role = followMain
		}
	}
	// The default profile is the main role's mirror so older API consumers that
	// only read "default" keep resolving the same endpoint.
	if file.Roles.Main != "" {
		file.Default = file.Roles.Main
	}
}

func normalizeCost(cost *modelCost) *modelCost {
	if cost == nil {
		return nil
	}
	rounded := modelCost{
		Input:      roundCost(cost.Input),
		Output:     roundCost(cost.Output),
		CacheRead:  roundCost(cost.CacheRead),
		CacheWrite: roundCost(cost.CacheWrite),
	}
	if rounded == (modelCost{}) {
		return nil
	}
	return &rounded
}

func roundCost(value float64) float64 {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	scale := math.Pow(10, maxCostDecimals)
	return math.Round(value*scale) / scale
}

func saveModels(workspace string, file modelsFile) error {
	if workspace == "" {
		return nil
	}
	file.SchemaVersion = modelsSchemaVersion
	normalizeModels(&file)
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return fmt.Errorf("console workspace is not writable: %w", err)
	}
	path := modelsPath(workspace)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("console workspace is not writable: %w", err)
	}
	return os.Rename(temporary, path)
}

// seedProfile turns the startup flags into the first profile so an existing
// deployment keeps working without a migration step.
func seedProfile(endpoint, model, keyEnv string) modelProfile {
	return modelProfile{
		ID: "default", Label: "默认模型", Endpoint: strings.TrimRight(endpoint, "/"),
		Model: model, KeyEnv: keyEnv, API: apiOpenAICompletions,
		Defaults: profileBudget{ModelCalls: chatDefaultModelCalls, ToolCalls: chatDefaultToolCalls, Tokens: chatDefaultTokens},
	}
}

func (c *Console) modelsSnapshot() modelsFile {
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	copyFile := modelsFile{SchemaVersion: c.models.SchemaVersion, Default: c.models.Default, Roles: c.models.Roles}
	copyFile.Profiles = append([]modelProfile{}, c.models.Profiles...)
	for index := range copyFile.Profiles {
		if copyFile.Profiles[index].Cost != nil {
			copy := *copyFile.Profiles[index].Cost
			copyFile.Profiles[index].Cost = &copy
		}
	}
	return copyFile
}

// profileForRole resolves one role slot; follow-main falls back to the main
// entry. A missing main entry means the library has nothing usable.
func profileForRole(file modelsFile, role string) (modelProfile, bool) {
	target := file.Roles.Main
	switch role {
	case rolePlanner:
		target = file.Roles.Planner
	case roleWorker:
		target = file.Roles.Worker
	}
	if target == "" || target == followMain || role == roleMain {
		target = file.Roles.Main
	}
	if target == "" && len(file.Profiles) > 0 {
		// A hand-edited file without roles must still resolve to something
		// usable; normalizeModels also repairs this on load.
		target = file.Profiles[0].ID
	}
	for _, profile := range file.Profiles {
		if profile.ID == target {
			return profile, true
		}
	}
	return modelProfile{}, false
}

func (c *Console) profileForRole(role string) (modelProfile, bool) {
	return profileForRole(c.modelsSnapshot(), role)
}

func (c *Console) profileByID(id string) (modelProfile, bool) {
	file := c.modelsSnapshot()
	for _, profile := range file.Profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return modelProfile{}, false
}

// resolvedRole is the server-computed answer to "which endpoint does this role
// actually use". The browser never re-derives follow-main.
type resolvedRole struct {
	Role         string `json:"role"`
	EntryID      string `json:"entry_id"`
	EntryName    string `json:"entry_name"`
	Model        string `json:"model"`
	API          string `json:"api"`
	Endpoint     string `json:"endpoint"`
	KeyEnv       string `json:"key_env"`
	FollowedMain bool   `json:"followed_main"`
}

func resolveRoles(file modelsFile) map[string]resolvedRole {
	out := map[string]resolvedRole{}
	main, hasMain := profileForRole(file, roleMain)
	for _, role := range []string{roleMain, rolePlanner, roleWorker} {
		profile, ok := profileForRole(file, role)
		if !ok {
			continue
		}
		out[role] = resolvedRole{
			Role: role, EntryID: profile.ID, EntryName: profile.Label, Model: profile.Model,
			API: profile.API, Endpoint: profile.Endpoint, KeyEnv: profile.KeyEnv,
			FollowedMain: role != roleMain && hasMain && profile.ID == main.ID,
		}
	}
	return out
}

// profileRoleRefs lists the roles that explicitly name this profile. follow-main
// is not an explicit reference, so it never blocks deletion.
func profileIDTaken(file modelsFile, id string) bool {
	for _, profile := range file.Profiles {
		if profile.ID == id {
			return true
		}
	}
	return false
}

func profileRoleRefs(file modelsFile, id string) []string {
	roles := []string{}
	if file.Roles.Main == id {
		roles = append(roles, roleMain)
	}
	if file.Roles.Planner == id {
		roles = append(roles, rolePlanner)
	}
	if file.Roles.Worker == id {
		roles = append(roles, roleWorker)
	}
	return roles
}

var roleNames = map[string]string{roleMain: "主模型", rolePlanner: "规划者", roleWorker: "执行者"}

type roleCatalogEntry struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Hint   string `json:"hint"`
	Owner  string `json:"owner"`
	Follow bool   `json:"follow_main_allowed"`
}

func roleCatalog() []roleCatalogEntry {
	return []roleCatalogEntry{
		{ID: roleMain, Label: "主模型", Hint: "控制台对话的默认端点；编排未单配时也回退到它", Owner: "手动 Run", Follow: false},
		{ID: rolePlanner, Label: "规划者", Hint: "编排引擎的规划轮：只出意图与目标判定，调用少、上下文长", Owner: "编排 Planner", Follow: true},
		{ID: roleWorker, Label: "执行者", Hint: "编排引擎的执行会话：并发领意图读码，工具多、输出短", Owner: "编排 Worker", Follow: true},
	}
}

type profileView struct {
	modelProfile
	KeyPresent bool     `json:"key_present"`
	KeySource  string   `json:"key_source"`
	Roles      []string `json:"roles"`
}

func (c *Console) profileViewOf(profile modelProfile, file modelsFile) profileView {
	key, source := c.profileKey(profile)
	return profileView{
		modelProfile: profile,
		KeyPresent:   key != "",
		KeySource:    source,
		Roles:        profileRoleRefs(file, profile.ID),
	}
}

// handleModelProfiles lists the library. Probing is a separate call per profile
// so a slow or dead endpoint cannot stall the page.
func (c *Console) handleModelProfiles(w http.ResponseWriter, _ *http.Request) {
	file := c.modelsSnapshot()
	views := make([]profileView, 0, len(file.Profiles))
	for _, profile := range file.Profiles {
		views = append(views, c.profileViewOf(profile, file))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"profiles":       views,
		"default":        file.Default,
		"roles":          file.Roles,
		"resolved":       resolveRoles(file),
		"role_catalog":   roleCatalog(),
		"enabled":        c.chatState().enabled,
		"reason":         c.chatState().reason,
	})
}

type profileUpsertRequest struct {
	ID           string             `json:"id"`
	Label        string             `json:"label"`
	Endpoint     string             `json:"endpoint"`
	Model        string             `json:"model"`
	KeyEnv       string             `json:"key_env"`
	API          string             `json:"api"`
	Capabilities *modelCapabilities `json:"capabilities"`
	Cost         *modelCost         `json:"cost"`
	Defaults     *profileBudget     `json:"defaults"`
}

// handleModelProfileUpsert creates or updates one profile. It never accepts a
// key: only the name of the environment variable that holds it.
func (c *Console) handleModelProfileUpsert(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持编辑模型库")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request profileUpsertRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求不是合法 JSON")
		return
	}
	profile, err := buildProfile(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_profile", err.Error())
		return
	}
	if c.chatActiveRun() != 0 {
		writeError(w, http.StatusConflict, "agent_chat_busy", "有 Run 正在执行；等它结束后再改模型库")
		return
	}
	file := c.modelsSnapshot()
	if strings.TrimSpace(request.ID) == "" {
		// A new entry derives its ID from the model name. Same model on two
		// relays must not silently overwrite the first entry, so suffix it.
		base := profile.ID
		for suffix := 2; profileIDTaken(file, profile.ID) && suffix <= 99; suffix++ {
			profile.ID = fmt.Sprintf("%s-%d", base, suffix)
		}
	}
	existsBefore := false
	replaced := false
	for index := range file.Profiles {
		if file.Profiles[index].ID == profile.ID {
			file.Profiles[index] = profile
			replaced = true
			existsBefore = true
			break
		}
	}
	if !replaced {
		file.Profiles = append(file.Profiles, profile)
	}
	if file.Roles.Main == "" {
		file.Roles.Main = profile.ID
	}
	if !existsBefore && file.Default == "" {
		file.Default = profile.ID
	}
	if err := saveModels(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	c.applyModels(file)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion, "status": "ok",
		"profile": c.profileViewOf(profile, file),
	})
}

func buildProfile(request profileUpsertRequest) (modelProfile, error) {
	id := strings.ToLower(strings.TrimSpace(request.ID))
	if id == "" {
		id = strings.ToLower(strings.TrimSpace(request.Model))
		id = strings.NewReplacer(".", "-", "/", "-", ":", "-", "_", "-").Replace(id)
	}
	if !profileIDPattern.MatchString(id) {
		return modelProfile{}, errors.New("配置 ID 只能包含小写字母、数字、点、下划线和短横线")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(request.Endpoint), "/")
	if err := validateEndpoint(endpoint); err != nil {
		return modelProfile{}, err
	}
	model := strings.TrimSpace(request.Model)
	if !modelNamePattern.MatchString(model) {
		return modelProfile{}, errors.New("模型名不合法")
	}
	keyEnv := strings.TrimSpace(request.KeyEnv)
	if keyEnv == "" {
		keyEnv = "TRIDENT_MODEL_API_KEY"
	}
	if !keyEnvPattern.MatchString(keyEnv) {
		return modelProfile{}, errors.New("密钥变量名只能包含字母、数字与下划线，且不能以数字开头（例如 TRIDENT_MODEL_API_KEY 或 deepseek_api_key）；大小写须与系统环境变量一致")
	}
	api := strings.TrimSpace(request.API)
	if api == "" {
		api = apiOpenAICompletions
	}
	if !runtimeAPIs[api] {
		return modelProfile{}, errors.New("当前运行时只实现 OpenAI Chat Completions；协议只能是 openai-completions（其他协议需要先实现适配器）")
	}
	capabilities, err := buildCapabilities(request.Capabilities)
	if err != nil {
		return modelProfile{}, err
	}
	cost, err := buildCost(request.Cost)
	if err != nil {
		return modelProfile{}, err
	}
	profile := modelProfile{
		ID: id, Label: strings.TrimSpace(request.Label), Endpoint: endpoint,
		Model: model, KeyEnv: keyEnv, API: api,
		Capabilities: capabilities, Cost: cost,
		Defaults: profileBudget{ModelCalls: chatDefaultModelCalls, ToolCalls: chatDefaultToolCalls, Tokens: chatDefaultTokens},
	}
	if request.Defaults != nil {
		profile.Defaults = profileBudget{
			ModelCalls: clampInt(request.Defaults.ModelCalls, chatDefaultModelCalls, 1, ChatMaxModelCalls),
			ToolCalls:  clampInt(request.Defaults.ToolCalls, chatDefaultToolCalls, 1, ChatMaxToolCalls),
			Tokens:     clampInt(request.Defaults.Tokens, chatDefaultTokens, 4096, ChatMaxTokens),
		}
	}
	if profile.Label == "" {
		profile.Label = model
	}
	return profile, nil
}

func buildCapabilities(input *modelCapabilities) (modelCapabilities, error) {
	if input == nil {
		return modelCapabilities{}, nil
	}
	if input.ContextWindow < 0 || input.ContextWindow > maxContextWindow {
		return modelCapabilities{}, fmt.Errorf("上下文窗口必须是 0–%d 之间的整数", int64(maxContextWindow))
	}
	if input.MaxOutput < 0 || input.MaxOutput > maxOutputTokens {
		return modelCapabilities{}, fmt.Errorf("最大输出必须是 0–%d 之间的整数", int64(maxOutputTokens))
	}
	return modelCapabilities{
		ContextWindow: input.ContextWindow, MaxOutput: input.MaxOutput,
		Reasoning: input.Reasoning, Vision: input.Vision,
	}, nil
}

func buildCost(input *modelCost) (*modelCost, error) {
	if input == nil {
		return nil, nil
	}
	for label, value := range map[string]float64{
		"输入": input.Input, "输出": input.Output, "缓存读": input.CacheRead, "缓存写": input.CacheWrite,
	} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > maxCostPerMillion {
			return nil, fmt.Errorf("%s价格必须是 0–%d 之间的数字（美元/百万 token）", label, int64(maxCostPerMillion))
		}
	}
	return normalizeCost(input), nil
}

// validateEndpoint allows https anywhere and http only on loopback. The console
// is a local tool, so a private-network https endpoint stays allowed; plaintext
// to a non-loopback host would leak the key.
func validateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return errors.New("端点必须是完整的 URL，例如 https://api.deepseek.com/v1")
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		host := parsed.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return errors.New("http 只允许 loopback；其他端点必须使用 https")
	default:
		return errors.New("端点必须使用 https（loopback 可用 http）")
	}
}

type profileIDRequest struct {
	ID string `json:"id"`
}

type roleUpdateRequest struct {
	Role   string `json:"role"`
	Target string `json:"target"`
}

// handleModelRole assigns one role slot. The main role cannot follow itself and
// setting it also moves the default profile so legacy readers stay consistent.
func (c *Console) handleModelRole(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持修改角色分配")
		return
	}
	var request roleUpdateRequest
	if err := decodeSmallJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	role := strings.ToLower(strings.TrimSpace(request.Role))
	target := strings.TrimSpace(request.Target)
	if role != roleMain && role != rolePlanner && role != roleWorker {
		writeError(w, http.StatusBadRequest, "invalid_role", "角色只支持 main、planner、worker")
		return
	}
	file := c.modelsSnapshot()
	if target == followMain {
		if role == roleMain {
			writeError(w, http.StatusBadRequest, "invalid_role_target", "主模型不能跟随主模型")
			return
		}
	} else {
		found := false
		for _, profile := range file.Profiles {
			if profile.ID == target {
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusNotFound, "profile_unknown", "模型库中没有该配置")
			return
		}
	}
	switch role {
	case roleMain:
		file.Roles.Main = target
		file.Default = target
	case rolePlanner:
		file.Roles.Planner = target
	case roleWorker:
		file.Roles.Worker = target
	}
	if c.chatActiveRun() != 0 {
		writeError(w, http.StatusConflict, "agent_chat_busy", "有 Run 正在执行；等它结束后再改角色分配")
		return
	}
	if err := saveModels(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	c.applyModels(file)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion, "status": "ok",
		"roles": file.Roles, "resolved": resolveRoles(file),
	})
}

func (c *Console) handleModelProfileRemove(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持修改模型库")
		return
	}
	var request profileIDRequest
	if err := decodeSmallJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	file := c.modelsSnapshot()
	if len(file.Profiles) <= 1 {
		writeError(w, http.StatusConflict, "profile_last", "至少保留一个模型配置")
		return
	}
	if refs := profileRoleRefs(file, request.ID); len(refs) > 0 {
		names := make([]string, 0, len(refs))
		for _, ref := range refs {
			names = append(names, roleNames[ref])
		}
		writeErrorDetails(w, http.StatusConflict, "profile_in_use",
			fmt.Sprintf("该模型仍被 %s 使用，先更换这些角色再删除", strings.Join(names, "、")),
			map[string]any{"roles": refs})
		return
	}
	kept := make([]modelProfile, 0, len(file.Profiles))
	removed := false
	for _, profile := range file.Profiles {
		if profile.ID == request.ID {
			removed = true
			continue
		}
		kept = append(kept, profile)
	}
	if !removed {
		writeError(w, http.StatusNotFound, "profile_unknown", "模型库中没有该配置")
		return
	}
	file.Profiles = kept
	if err := saveModels(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	// Drop the stored key only after the library write succeeds; an orphaned
	// key is harmless, a profile without its key is not recoverable.
	c.removeModelKey(request.ID)
	c.applyModels(file)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion, "status": "ok",
		"roles": file.Roles, "resolved": resolveRoles(file),
	})
}

type modelKeyRequest struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// handleModelKey stores or clears one profile's key. The value is written to the
// workspace file with 0600 permissions and never echoed back; the response only
// reports presence and source.
func (c *Console) handleModelKey(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持保存模型密钥")
		return
	}
	var request modelKeyRequest
	if err := decodeSmallJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	profile, ok := c.profileByID(request.ID)
	if !ok {
		writeError(w, http.StatusNotFound, "profile_unknown", "模型库中没有该配置")
		return
	}
	key := strings.TrimSpace(request.Key)
	if key != "" {
		if err := validateStoredKey(key); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
			return
		}
	}
	if err := c.setModelKey(profile.ID, key); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	effective, source := c.profileKey(profile)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion, "status": "ok",
		"id": profile.ID, "key_present": effective != "", "key_source": source,
	})
}

type probeResponse struct {
	ID        string   `json:"id"`
	Endpoint  string   `json:"endpoint"`
	Model     string   `json:"model"`
	API       string   `json:"api"`
	OK        bool     `json:"ok"`
	Status    string   `json:"status"`
	Models    []string `json:"models"`
	LatencyMS int64    `json:"latency_ms"`
	Error     string   `json:"error,omitempty"`
	ProbedAt  string   `json:"probed_at,omitempty"`
}

func (c *Console) handleModelProbe(w http.ResponseWriter, r *http.Request) {
	var request profileIDRequest
	if err := decodeSmallJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	profile, ok := c.profileByID(request.ID)
	if !ok {
		writeError(w, http.StatusNotFound, "profile_unknown", "模型库中没有该配置")
		return
	}
	key, _ := c.profileKey(profile)
	writeJSON(w, http.StatusOK, probeProfile(r.Context(), profile, key))
}

// probeProfile performs one read-only round trip. The key comes from the
// profile's environment variable and is used for this request only.
func probeProfile(ctx context.Context, profile modelProfile, key string) probeResponse {
	started := time.Now()
	probe := probeResponse{
		ID: profile.ID, Endpoint: profile.Endpoint, Model: profile.Model,
		API: capabilitiesAPI(profile), Models: []string{},
	}
	if key == "" {
		probe.Status = "key_missing"
		probe.Error = fmt.Sprintf("未配置密钥：在「设置 → 模型」里填写 API Key，或设置环境变量 %s 后重启", profile.KeyEnv)
		return probe
	}
	request, err := newProbeRequest(ctx, profile, key)
	if err != nil {
		probe.Status = "network"
		probe.Error = "端点地址无法构造请求"
		return probe
	}
	firstHost := request.URL.Host
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host != firstHost {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	response, err := client.Do(request)
	probe.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		probe.Status = "network"
		probe.Error = "无法连接端点：" + sanitizeProbeError(err)
		return probe
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if readErr != nil {
		probe.Status = "network"
		probe.Error = "读取端点响应失败"
		return probe
	}
	if response.StatusCode != http.StatusOK {
		probe.Status, probe.Error = classifyProbeStatus(response.StatusCode)
		return probe
	}
	models, parseErr := parseProbeModels(profile, body)
	if parseErr != nil {
		probe.Status = "protocol"
		probe.Error = "端点响应不是预期的模型列表：" + parseErr.Error()
		return probe
	}
	probe.Models = models
	if len(models) == 0 {
		probe.Status = "empty"
		probe.Error = "端点未返回任何模型"
		return probe
	}
	probe.OK = true
	probe.Status = "ok"
	probe.ProbedAt = time.Now().UTC().Format(time.RFC3339)
	return probe
}

func capabilitiesAPI(profile modelProfile) string {
	if profile.API == "" {
		return apiOpenAICompletions
	}
	return profile.API
}

func newProbeRequest(ctx context.Context, profile modelProfile, key string) (*http.Request, error) {
	// The console's only wire protocol is OpenAI Chat Completions.
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, profile.Endpoint+"/models", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func classifyProbeStatus(status int) (string, string) {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "auth", fmt.Sprintf("认证失败（HTTP %d）：检查 Key 是否有效、是否属于该端点", status)
	case status == http.StatusNotFound:
		return "not_found", "端点返回 404：检查 Base URL 路径（OpenAI 兼容通常以 /v1 结尾）"
	case status == http.StatusTooManyRequests:
		return "upstream", "上游限流（HTTP 429）：稍后重试或更换渠道"
	case status >= 500:
		return "upstream", fmt.Sprintf("上游不可用（HTTP %d）：检查中转渠道是否被禁用、上游服务是否存活", status)
	default:
		return "upstream", fmt.Sprintf("端点返回 HTTP %d", status)
	}
}

func parseProbeModels(_ modelProfile, body []byte) ([]string, error) {
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Data == nil {
		return nil, errors.New("缺少 data 数组")
	}
	models := make([]string, 0, len(payload.Data))
	for _, item := range payload.Data {
		if item.ID != "" {
			models = append(models, item.ID)
		}
	}
	return models, nil
}

// sanitizeProbeError keeps transport errors informative while redacting the
// Google-style "?key=" credential that net/http embeds in its error string.
func sanitizeProbeError(err error) string {
	message := probeKeyPattern.ReplaceAllString(err.Error(), "key=***")
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

var probeKeyPattern = regexp.MustCompile(`key=[^&\s"]+`)

func decodeSmallJSON(w http.ResponseWriter, r *http.Request, target any) error {
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("请求不是合法 JSON")
	}
	return nil
}

// applyModels swaps the in-memory library and keeps the legacy chat binding in
// sync with the resolved main role so the composer always sees that endpoint.
func (c *Console) applyModels(file modelsFile) {
	c.cfgMu.Lock()
	c.models = file
	if main, ok := profileForRole(file, roleMain); ok {
		c.chat.endpoint = main.Endpoint
		c.chat.model = main.Model
		c.chat.keyEnv = main.KeyEnv
	}
	c.cfgMu.Unlock()
}
