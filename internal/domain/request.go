package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	OfflineToolName      = "offline.observe"
	OfflineToolVersion   = "1"
	OfflinePolicyVersion = "p0.2-offline-v1"

	executionArgumentsMaxBytes = 16 * 1024
	executionArgumentsMaxDepth = 16
)

// ExecutionRequest 是离线观察请求的输入快照，不执行网络请求或工具调用。
// Canonical 不修改输入；真实授权、租约有效性和 fencing 校验由上层负责。
type ExecutionRequest struct {
	TaskID          int64           `json:"task_id"`
	MissionID       int64           `json:"mission_id"`
	LeaseID         int64           `json:"lease_id"`
	FencingToken    int64           `json:"fencing_token"`
	RuntimeID       string          `json:"runtime_id"`
	RequesterID     int64           `json:"requester_id"`
	AuthorizationID int64           `json:"authorization_id"`
	ScopeVersion    int             `json:"scope_version"`
	ScopeHash       string          `json:"scope_hash"`
	ToolName        string          `json:"tool_name"`
	ToolVersion     string          `json:"tool_version"`
	Target          string          `json:"target"`
	Protocol        string          `json:"protocol"`
	Port            uint16          `json:"port"`
	Action          string          `json:"action"`
	Arguments       json.RawMessage `json:"arguments"`
	PolicyVersion   string          `json:"policy_version"`
}

// Canonical 返回规范 JSON 及其小写十六进制 SHA-256，失败不返回部分结果。
// Protocol 必须显式填写小写 http/https，Port 必须填写有效端口，不隐式补全。
// 参数数字保留 JSON 词法，不转换 float64；因此 1、1.0、1e0 的摘要可以不同。
// 原始及规范参数均不超过 16 KiB，容器深度包含根对象，最多 16 层。
func (r ExecutionRequest) Canonical() ([]byte, string, error) {
	// [01] 标识与版本全部正数，固定离线工具和唯一动作，禁止扩大能力。
	if r.TaskID <= 0 || r.MissionID <= 0 || r.LeaseID <= 0 || r.FencingToken <= 0 ||
		r.RequesterID <= 0 || r.AuthorizationID <= 0 || r.ScopeVersion <= 0 {
		return nil, "", fmt.Errorf("request IDs, fencing_token and scope_version must be positive")
	}
	if len(r.RuntimeID) == 0 || len(r.RuntimeID) > 128 || !executionVisibleASCII(r.RuntimeID) {
		return nil, "", fmt.Errorf("runtime_id must contain 1 to 128 visible ASCII bytes")
	}
	if r.ToolName != OfflineToolName || r.ToolVersion != OfflineToolVersion || r.PolicyVersion != OfflinePolicyVersion {
		return nil, "", fmt.Errorf("request must use the fixed offline tool, version and policy")
	}
	if r.Action != "observe" {
		return nil, "", fmt.Errorf("offline action must be observe")
	}
	if len(r.ScopeHash) != 64 {
		return nil, "", fmt.Errorf("scope_hash must contain exactly 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(r.ScopeHash); err != nil {
		return nil, "", fmt.Errorf("invalid scope_hash: %w", err)
	}

	// [02] 值接收者建立副本；参数另行解析，绝不复用调用方的可写字节数组。
	n := r
	n.ScopeHash = strings.ToLower(r.ScopeHash)
	var err error
	n.Target, err = canonicalExecutionTarget(r.Target, r.Protocol, r.Port)
	if err != nil {
		return nil, "", fmt.Errorf("invalid target: %w", err)
	}
	n.Arguments, err = canonicalExecutionArguments(r.Arguments)
	if err != nil {
		return nil, "", fmt.Errorf("invalid arguments: %w", err)
	}
	data, err := json.Marshal(n)
	if err != nil {
		return nil, "", fmt.Errorf("marshal canonical request: %w", err)
	}
	// [03] 摘要只覆盖返回的实际字节，不哈希原始输入或中间对象。
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func executionVisibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func canonicalExecutionTarget(raw, protocol string, port uint16) (string, error) {
	// [04] 拒绝原始非 ASCII、控制字符、空格和反斜杠，避免不同 URL 解析器歧义。
	if raw == "" || !executionVisibleASCII(raw) || strings.ContainsAny(raw, "\\#") {
		return "", fmt.Errorf("URL must use visible ASCII without backslashes or fragments")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	if !u.IsAbs() || u.Opaque != "" || u.Host == "" || u.User != nil ||
		(u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("URL must be absolute http/https without userinfo")
	}
	if protocol != u.Scheme || port == 0 {
		return "", fmt.Errorf("protocol and port must be supplied and match the URL")
	}
	effectivePort := uint64(80)
	if u.Scheme == "https" {
		effectivePort = 443
	}
	if explicit := u.Port(); explicit != "" {
		effectivePort, err = strconv.ParseUint(explicit, 10, 16)
		if err != nil || effectivePort == 0 {
			return "", fmt.Errorf("invalid explicit URL port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("explicit URL port must be nonempty")
	}
	if uint64(port) != effectivePort {
		return "", fmt.Errorf("port %d does not match URL effective port %d", port, effectivePort)
	}

	// [05] 临时 Scope 仅复用严格主机/URL 校验，不代表已有授权，不解析 DNS。
	check := Scope{
		Ports:          []uint16{port},
		Protocols:      []string{protocol},
		AllowedActions: []string{"observe"},
		MaxRPS:         1,
		MaxConcurrency: 1,
		DataPolicy:     "offline",
		StopConditions: []string{"offline_only"},
	}
	if addr, parseErr := netip.ParseAddr(u.Hostname()); parseErr == nil {
		check.IPRanges = []string{netip.PrefixFrom(addr, addr.BitLen()).String()}
	} else {
		check.Domains = []string{u.Hostname()}
	}
	if err := check.AllowsURL(raw, "observe"); err != nil {
		return "", fmt.Errorf("strict URL validation: %w", err)
	}
	host, addr, err := canonicalScopeHost(u.Hostname())
	if err != nil {
		return "", err
	}
	// [06] 仅规范主机、端口与空路径；保留 RawPath、RawQuery、ForceQuery 的业务语义。
	u.Host = host
	if addr.IsValid() && addr.Is6() {
		u.Host = "[" + host + "]"
	}
	if (u.Scheme == "http" && port != 80) || (u.Scheme == "https" && port != 443) {
		u.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func canonicalExecutionArguments(raw json.RawMessage) (json.RawMessage, error) {
	// [07] 限制输入体积并拒绝非法 UTF-8，避免解码器替换坏字节造成摘要碰撞。
	if len(raw) == 0 || len(raw) > executionArgumentsMaxBytes {
		return nil, fmt.Errorf("arguments must contain 1 to %d bytes", executionArgumentsMaxBytes)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("arguments must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readExecutionJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("arguments must be a JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("arguments must contain exactly one JSON object")
	}
	// [08] encoding/json 递归排序 map 键；json.Number 保留任意精度数字的原始词法。
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical arguments: %w", err)
	}
	// [11] HTML 安全转义可能扩大字节数，规范结果也限长以保证重新校验稳定。
	if len(data) > executionArgumentsMaxBytes {
		return nil, fmt.Errorf("canonical arguments exceed %d bytes", executionArgumentsMaxBytes)
	}
	return data, nil
}

func readExecutionJSONValue(decoder *json.Decoder, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read JSON value: %w", err)
	}
	delim, container := token.(json.Delim)
	if !container {
		// [09] UseNumber 避免浮点溢出；NaN、Infinity 等非 JSON 数字由解码器拒绝。
		return token, nil
	}
	if depth >= executionArgumentsMaxDepth {
		return nil, fmt.Errorf("JSON container depth exceeds %d", executionArgumentsMaxDepth)
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, fmt.Errorf("read JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("JSON object key must be a string")
			}
			// [10] 在每层对象按解码后的键检测重复，转义别名也不可覆盖已有值。
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON object key %q", key)
			}
			value, err := readExecutionJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("unterminated JSON object")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := readExecutionJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("unterminated JSON array")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}
