// Package agent 提供单一只读主循环；运行状态和恢复协议由 PostgreSQL 保存。
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"trident/internal/model"
)

const Version = "trident-agent-v1"

// Config 不含密钥；外发许可绑定 Run 的快照、目标和这里的精确服务配置。
type Config struct {
	Version           string    `json:"version"`
	Endpoint          string    `json:"endpoint"`
	Model             string    `json:"model"`
	OutputParameter   string    `json:"output_parameter"`
	TimeoutSeconds    int64     `json:"timeout_seconds"`
	MaxOutputTokens   int64     `json:"max_output_tokens"`
	MaxRequestBytes   int64     `json:"max_request_bytes"`
	MaxResponseBytes  int64     `json:"max_response_bytes"`
	AllowLoopbackHTTP bool      `json:"allow_loopback_http"`
	EgressAllowed     bool      `json:"egress_allowed"`
	EgressExpiresAt   time.Time `json:"egress_expires_at"`
	// AnalysisAdvisoryPath binds the optional local advisory catalog used by the
	// read-only analysis tools. It is configuration, not snapshot content.
	AnalysisAdvisoryPath string `json:"analysis_advisory_path,omitempty"`
}

func (c Config) Validate() error {
	if c.Version != Version || strings.TrimSpace(c.Model) == "" || len(c.Model) > 200 || strings.ContainsAny(c.Model, "\r\n\x00") {
		return fmt.Errorf("invalid agent version or explicit model")
	}
	if c.OutputParameter != "max_completion_tokens" && c.OutputParameter != "max_tokens" {
		return fmt.Errorf("invalid output token parameter profile")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 120 || c.MaxOutputTokens < 1 || c.MaxOutputTokens > 16384 || c.MaxRequestBytes < 1024 || c.MaxRequestBytes > 2<<20 || c.MaxResponseBytes < 1024 || c.MaxResponseBytes > 512<<10 {
		return fmt.Errorf("agent model limits outside supported bounds")
	}
	if c.AnalysisAdvisoryPath != "" {
		if len(c.AnalysisAdvisoryPath) > 1024 || strings.ContainsAny(c.AnalysisAdvisoryPath, "\r\n\x00") || !filepath.IsAbs(c.AnalysisAdvisoryPath) {
			return fmt.Errorf("analysis advisory path must be an absolute local path")
		}
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(c.Endpoint, "\r\n\x00") {
		return fmt.Errorf("invalid explicit model endpoint")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !c.AllowLoopbackHTTP || ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("model endpoint requires HTTPS or explicit numeric loopback HTTP")
		}
	}
	return nil
}

func DecodeConfig(raw json.RawMessage) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return c, fmt.Errorf("invalid agent config")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return c, fmt.Errorf("trailing agent config")
	}
	return c, c.Validate()
}

// [01] 每次发请求重验许可；读取许可、SDK凭据或仓库文本都不能替代这一步。
func (c Config) AllowRequest(now time.Time) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if !c.EgressAllowed || c.EgressExpiresAt.IsZero() || !now.Before(c.EgressExpiresAt) {
		return model.ErrDenied
	}
	return nil
}
