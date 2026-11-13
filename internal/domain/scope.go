package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Scope 表示不可变授权版本的输入；规范化时不修改调用方的切片。
// 当前只支持 ASCII DNS 名称，国际化域名转换与校验留待 P1，不隐式执行 IDNA 转换。
type Scope struct {
	Domains          []string `json:"domains"`
	IPRanges         []string `json:"ip_ranges"`
	Ports            []uint16 `json:"ports"`
	Protocols        []string `json:"protocols"`
	AllowedActions   []string `json:"allowed_actions"`
	ForbiddenActions []string `json:"forbidden_actions"`
	MaxRPS           int      `json:"max_rps"`
	MaxConcurrency   int      `json:"max_concurrency"`
	DataPolicy       string   `json:"data_policy"`
	StopConditions   []string `json:"stop_conditions"`
}

// Canonical 返回规范 JSON 以及该 JSON 的小写十六进制 SHA-256。
// 动作名大小写敏感，仅去除首尾空白；策略与停止条件保留文本大小写。
// 空列表统一编码为 []，端口或协议列表为空时不授权任何 URL。
func (s Scope) Canonical() ([]byte, string, error) {
	// [01] 显式构建并校验规范副本，不直接序列化原始输入。
	normalized, err := s.normalized()
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return nil, "", fmt.Errorf("marshal canonical scope: %w", err)
	}
	// [02] 哈希只覆盖实际返回的规范字节，避免摘要与持久化内容不一致。
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func (s Scope) normalized() (Scope, error) {
	n := Scope{
		Domains:          make([]string, 0, len(s.Domains)),
		IPRanges:         make([]string, 0, len(s.IPRanges)),
		Ports:            make([]uint16, 0, len(s.Ports)),
		Protocols:        make([]string, 0, len(s.Protocols)),
		AllowedActions:   make([]string, 0, len(s.AllowedActions)),
		ForbiddenActions: make([]string, 0, len(s.ForbiddenActions)),
		MaxRPS:           s.MaxRPS,
		MaxConcurrency:   s.MaxConcurrency,
		DataPolicy:       strings.TrimSpace(s.DataPolicy),
		StopConditions:   make([]string, 0, len(s.StopConditions)),
	}
	// [03] 域名精确匹配，地址只接受 netip 严格解析的无区域标识字面量。
	for _, raw := range s.Domains {
		host, _, err := canonicalScopeHost(strings.TrimSpace(raw))
		if err != nil {
			return Scope{}, fmt.Errorf("invalid domain %q: %w", raw, err)
		}
		n.Domains = append(n.Domains, host)
	}
	for _, raw := range s.IPRanges {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return Scope{}, fmt.Errorf("invalid IP range %q: %w", raw, err)
		}
		if prefix.Addr().Is4In6() {
			return Scope{}, fmt.Errorf("IPv4-mapped IPv6 range is unsupported: %q", raw)
		}
		n.IPRanges = append(n.IPRanges, prefix.Masked().String())
	}
	if len(n.Domains)+len(n.IPRanges) == 0 {
		return Scope{}, fmt.Errorf("scope requires at least one domain or CIDR")
	}
	for _, port := range s.Ports {
		if port == 0 {
			return Scope{}, fmt.Errorf("scope port must be nonzero")
		}
		n.Ports = append(n.Ports, port)
	}
	for _, raw := range s.Protocols {
		protocol := strings.ToLower(strings.TrimSpace(raw))
		if protocol != "http" && protocol != "https" {
			return Scope{}, fmt.Errorf("unsupported scope protocol %q", raw)
		}
		n.Protocols = append(n.Protocols, protocol)
	}
	var err error
	if n.AllowedActions, err = canonicalScopeTexts(s.AllowedActions, "allowed action"); err != nil {
		return Scope{}, err
	}
	if len(n.AllowedActions) == 0 {
		return Scope{}, fmt.Errorf("scope requires at least one allowed action")
	}
	if n.ForbiddenActions, err = canonicalScopeTexts(s.ForbiddenActions, "forbidden action"); err != nil {
		return Scope{}, err
	}
	// [04] 禁止集合与允许集合不得重叠；重复列表成员则统一去重。
	for _, action := range n.AllowedActions {
		if scopeContains(n.ForbiddenActions, action) {
			return Scope{}, fmt.Errorf("action %q is both allowed and forbidden", action)
		}
	}
	if n.MaxRPS <= 0 || n.MaxConcurrency <= 0 {
		return Scope{}, fmt.Errorf("max_rps and max_concurrency must be positive")
	}
	if n.DataPolicy == "" || !utf8.ValidString(n.DataPolicy) {
		return Scope{}, fmt.Errorf("data_policy must be nonempty valid UTF-8")
	}
	if n.StopConditions, err = canonicalScopeTexts(s.StopConditions, "stop condition"); err != nil {
		return Scope{}, err
	}
	if len(n.StopConditions) == 0 {
		return Scope{}, fmt.Errorf("scope requires at least one stop condition")
	}
	// [05] 所有数组排序去重；相同授权内容不因输入顺序产生不同摘要。
	n.Domains = canonicalScopeStrings(n.Domains)
	n.IPRanges = canonicalScopeStrings(n.IPRanges)
	n.Protocols = canonicalScopeStrings(n.Protocols)
	sort.Slice(n.Ports, func(i, j int) bool { return n.Ports[i] < n.Ports[j] })
	ports := n.Ports[:0]
	for _, port := range n.Ports {
		if len(ports) == 0 || ports[len(ports)-1] != port {
			ports = append(ports, port)
		}
	}
	n.Ports = ports
	return n, nil
}

// AllowsURL 只用于登记阶段的静态预检查，不是执行阶段的 Egress 安全边界。
// 本函数不解析 DNS、不建立网络连接、不检查重定向；调用方执行时仍须校验
// 实际解析地址、CIDR、授权版本及每一次重定向，并固定获准的拨号地址。
func (s Scope) AllowsURL(rawURL, action string) error {
	// [06] 即使调用方未先调用 Canonical，也必须先验证完整 Scope。
	n, err := s.normalized()
	if err != nil {
		return fmt.Errorf("invalid scope: %w", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if !u.IsAbs() || u.Opaque != "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("URL must be an absolute http or https URL with a host")
	}
	// [07] 连空片段标识和空 userinfo 也拒绝，不能只检查 Fragment 字段。
	if u.User != nil || strings.Contains(rawURL, "#") {
		return fmt.Errorf("URL userinfo and fragments are forbidden")
	}
	if !scopeContains(n.Protocols, u.Scheme) {
		return fmt.Errorf("protocol %q is outside scope", u.Scheme)
	}
	host, addr, err := canonicalScopeHost(u.Hostname())
	if err != nil {
		return fmt.Errorf("invalid URL host: %w", err)
	}
	// [08] 方括号只允许包围 IPv6；拒绝裸 IPv6、IPvFuture、区域标识等歧义。
	bracketed := strings.HasPrefix(u.Host, "[")
	if bracketed != (addr.IsValid() && addr.Is6()) {
		return fmt.Errorf("URL host must use brackets only for IPv6 literals")
	}
	port := uint64(80)
	if u.Scheme == "https" {
		port = 443
	}
	if explicitPort := u.Port(); explicitPort != "" {
		port, err = strconv.ParseUint(explicitPort, 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("invalid URL port %q", explicitPort)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("explicit URL port must be nonempty")
	}
	portAllowed := false
	for _, candidate := range n.Ports {
		if candidate == uint16(port) {
			portAllowed = true
			break
		}
	}
	if !portAllowed {
		return fmt.Errorf("port %d is outside scope", port)
	}
	action = strings.TrimSpace(action)
	if action == "" || scopeContains(n.ForbiddenActions, action) || !scopeContains(n.AllowedActions, action) {
		return fmt.Errorf("action %q is not allowed", action)
	}
	// [09] IP 字面量必须命中 CIDR，不能借助 Domains 中的 IP 绕过地址范围。
	if addr.IsValid() {
		for _, raw := range n.IPRanges {
			prefix, parseErr := netip.ParsePrefix(raw)
			if parseErr != nil {
				return fmt.Errorf("invalid normalized IP range: %w", parseErr)
			}
			if prefix.Contains(addr) {
				return nil
			}
		}
		return fmt.Errorf("IP %q is outside scoped CIDRs", host)
	}
	if !scopeContains(n.Domains, host) {
		return fmt.Errorf("domain %q is outside scope", host)
	}
	return nil
}

func canonicalScopeHost(raw string) (string, netip.Addr, error) {
	if raw == "" {
		return "", netip.Addr{}, fmt.Errorf("host is empty")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return "", netip.Addr{}, fmt.Errorf("host must contain only visible ASCII characters")
		}
	}
	host := strings.ToLower(raw)
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" || addr.Is4In6() {
			return "", netip.Addr{}, fmt.Errorf("scoped or IPv4-mapped IPv6 literals are unsupported")
		}
		return addr.String(), addr, nil
	}
	// [10] DNS 只去除一个合法根尾点；双尾点、空标签和数字尾标签一律拒绝。
	// 数字尾标签也覆盖十进制、八进制、十六进制和缩写 IPv4 的常见混淆形式。
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return "", netip.Addr{}, fmt.Errorf("DNS name length must be between 1 and 253")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", netip.Addr{}, fmt.Errorf("invalid DNS label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", netip.Addr{}, fmt.Errorf("DNS labels permit only ASCII letters, digits and interior hyphens")
			}
		}
	}
	last := labels[len(labels)-1]
	if scopeNumericLabel(last) {
		return "", netip.Addr{}, fmt.Errorf("ambiguous numeric host is forbidden")
	}
	return host, netip.Addr{}, nil
}

func scopeNumericLabel(label string) bool {
	base := byte(10)
	if strings.HasPrefix(label, "0x") {
		label = label[2:]
		base = 16
	}
	if label == "" {
		// [11] 某些 URL 解析器把单独的 0x 也解释为零地址，按模糊 IP 拒绝。
		return base == 16
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= '0' && c <= '9' || base == 16 && c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func canonicalScopeTexts(input []string, field string) ([]string, error) {
	values := make([]string, 0, len(input))
	for _, raw := range input {
		value := strings.TrimSpace(raw)
		if value == "" || !utf8.ValidString(value) {
			return nil, fmt.Errorf("%s must be nonempty valid UTF-8", field)
		}
		values = append(values, value)
	}
	return canonicalScopeStrings(values), nil
}

func canonicalScopeStrings(values []string) []string {
	sort.Strings(values)
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func scopeContains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}
