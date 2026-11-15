package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// a model and the environment variable that holds the key: the key itself is
// never written to the workspace or returned to the browser.
type modelProfile struct {
	ID       string        `json:"id"`
	Label    string        `json:"label,omitempty"`
	Endpoint string        `json:"endpoint"`
	Model    string        `json:"model"`
	KeyEnv   string        `json:"key_env"`
	Defaults profileBudget `json:"defaults"`
}

type profileBudget struct {
	ModelCalls int64 `json:"model_calls"`
	ToolCalls  int64 `json:"tool_calls"`
	Tokens     int64 `json:"tokens"`
}

type modelsFile struct {
	SchemaVersion int            `json:"schema_version"`
	Profiles      []modelProfile `json:"profiles"`
	Default       string         `json:"default,omitempty"`
}

const modelsSchemaVersion = 1

var (
	profileIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	keyEnvPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	modelNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
)

func modelsPath(workspace string) string {
	return filepath.Join(workspace, "models.json")
}

func loadModels(workspace string) (modelsFile, error) {
	file := modelsFile{SchemaVersion: modelsSchemaVersion, Profiles: []modelProfile{}}
	if workspace == "" {
		return file, nil
	}
	data, err := os.ReadFile(modelsPath(workspace))
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return file, fmt.Errorf("model library is unreadable: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return file, fmt.Errorf("model library is invalid: %v", err)
	}
	if file.SchemaVersion != modelsSchemaVersion {
		return file, fmt.Errorf("model library schema %d is not supported", file.SchemaVersion)
	}
	return file, nil
}

func saveModels(workspace string, file modelsFile) error {
	if workspace == "" {
		return nil
	}
	file.SchemaVersion = modelsSchemaVersion
	if file.Profiles == nil {
		file.Profiles = []modelProfile{}
	}
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
		Model: model, KeyEnv: keyEnv,
		Defaults: profileBudget{ModelCalls: chatDefaultModelCalls, ToolCalls: chatDefaultToolCalls, Tokens: chatDefaultTokens},
	}
}

func (c *Console) modelsSnapshot() modelsFile {
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	copyFile := modelsFile{SchemaVersion: c.models.SchemaVersion, Default: c.models.Default}
	copyFile.Profiles = append([]modelProfile{}, c.models.Profiles...)
	return copyFile
}

func (c *Console) defaultProfile() (modelProfile, bool) {
	file := c.modelsSnapshot()
	for _, profile := range file.Profiles {
		if profile.ID == file.Default {
			return profile, true
		}
	}
	if len(file.Profiles) > 0 {
		return file.Profiles[0], true
	}
	return modelProfile{}, false
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

type profileView struct {
	modelProfile
	KeyPresent bool `json:"key_present"`
}

func profileViewOf(profile modelProfile) profileView {
	return profileView{modelProfile: profile, KeyPresent: os.Getenv(profile.KeyEnv) != ""}
}

// handleModelProfiles lists the library. Probing is a separate call per profile
// so a slow or dead endpoint cannot stall the page.
func (c *Console) handleModelProfiles(w http.ResponseWriter, _ *http.Request) {
	file := c.modelsSnapshot()
	views := make([]profileView, 0, len(file.Profiles))
	for _, profile := range file.Profiles {
		views = append(views, profileViewOf(profile))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"profiles":       views,
		"default":        file.Default,
		"enabled":        c.chatState().enabled,
		"reason":         c.chatState().reason,
	})
}

type profileUpsertRequest struct {
	ID       string         `json:"id"`
	Label    string         `json:"label"`
	Endpoint string         `json:"endpoint"`
	Model    string         `json:"model"`
	KeyEnv   string         `json:"key_env"`
	Defaults *profileBudget `json:"defaults"`
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
	replaced := false
	for index := range file.Profiles {
		if file.Profiles[index].ID == profile.ID {
			file.Profiles[index] = profile
			replaced = true
			break
		}
	}
	if !replaced {
		file.Profiles = append(file.Profiles, profile)
	}
	sort.SliceStable(file.Profiles, func(i, j int) bool { return file.Profiles[i].ID < file.Profiles[j].ID })
	if file.Default == "" {
		file.Default = profile.ID
	}
	if err := saveModels(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	c.applyModels(file)
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": SchemaVersion, "status": "ok", "profile": profileViewOf(profile)})
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
		return modelProfile{}, errors.New("密钥变量名必须是大写字母、数字与下划线，例如 TRIDENT_MODEL_API_KEY_DEEPSEEK")
	}
	profile := modelProfile{
		ID: id, Label: strings.TrimSpace(request.Label), Endpoint: endpoint,
		Model: model, KeyEnv: keyEnv,
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

func (c *Console) handleModelProfileDefault(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持修改默认模型")
		return
	}
	var request profileIDRequest
	if err := decodeSmallJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	file := c.modelsSnapshot()
	found := false
	for _, profile := range file.Profiles {
		if profile.ID == request.ID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "profile_unknown", "模型库中没有该配置")
		return
	}
	file.Default = request.ID
	if err := saveModels(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	c.applyModels(file)
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": SchemaVersion, "status": "ok", "default": request.ID})
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
	if file.Default == request.ID {
		file.Default = kept[0].ID
	}
	if err := saveModels(c.workspace, file); err != nil {
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	c.applyModels(file)
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": SchemaVersion, "status": "ok"})
}

type probeResponse struct {
	ID       string   `json:"id"`
	Endpoint string   `json:"endpoint"`
	Model    string   `json:"model"`
	Models   []string `json:"models"`
	Error    string   `json:"error,omitempty"`
	ProbedAt string   `json:"probed_at,omitempty"`
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
	writeJSON(w, http.StatusOK, probeProfile(r.Context(), profile))
}

// probeProfile asks one endpoint which models it serves. The key is read from the
// profile's environment variable and used for this request only.
func probeProfile(ctx context.Context, profile modelProfile) probeResponse {
	probe := probeResponse{ID: profile.ID, Endpoint: profile.Endpoint, Model: profile.Model, Models: []string{}}
	key := os.Getenv(profile.KeyEnv)
	if key == "" {
		probe.Error = fmt.Sprintf("环境变量 %s 未设置", profile.KeyEnv)
		return probe
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, profile.Endpoint+"/models", nil)
	if err != nil {
		probe.Error = "端点地址无法构造请求"
		return probe
	}
	request.Header.Set("Authorization", "Bearer "+key)
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		probe.Error = "无法连接端点：" + err.Error()
		return probe
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if err != nil {
		probe.Error = "读取端点响应失败"
		return probe
	}
	if response.StatusCode != http.StatusOK {
		probe.Error = fmt.Sprintf("端点返回 HTTP %d", response.StatusCode)
		return probe
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		probe.Error = "端点响应不是预期的模型列表"
		return probe
	}
	for _, item := range payload.Data {
		if item.ID != "" {
			probe.Models = append(probe.Models, item.ID)
		}
	}
	if len(probe.Models) == 0 {
		probe.Error = "端点未返回任何模型"
	}
	probe.ProbedAt = time.Now().UTC().Format(time.RFC3339)
	return probe
}

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
// sync so the composer always sees the default profile.
func (c *Console) applyModels(file modelsFile) {
	c.cfgMu.Lock()
	c.models = file
	for _, profile := range file.Profiles {
		if profile.ID == file.Default {
			c.chat.endpoint = profile.Endpoint
			c.chat.model = profile.Model
			c.chat.keyEnv = profile.KeyEnv
			break
		}
	}
	c.cfgMu.Unlock()
}
