package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

func validExecutionTestRequest() ExecutionRequest {
	return ExecutionRequest{
		TaskID:          1,
		MissionID:       2,
		LeaseID:         3,
		FencingToken:    4,
		RuntimeID:       "runtime-01",
		RequesterID:     5,
		AuthorizationID: 6,
		ScopeVersion:    1,
		ScopeHash:       strings.Repeat("ab", 32),
		ToolName:        OfflineToolName,
		ToolVersion:     OfflineToolVersion,
		Target:          "https://example.com/",
		Protocol:        "https",
		Port:            443,
		Action:          "observe",
		Arguments:       json.RawMessage(`{}`),
		PolicyVersion:   OfflinePolicyVersion,
	}
}

func canonicalExecutionTestRequest(t *testing.T, r ExecutionRequest) ([]byte, string, ExecutionRequest) {
	t.Helper()
	data, hash, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hash != hex.EncodeToString(digest[:]) || len(hash) != 64 {
		t.Fatalf("digest does not cover canonical bytes: %q", hash)
	}
	var decoded ExecutionRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid canonical JSON: %v", err)
	}
	again, againHash, err := decoded.Canonical()
	if err != nil || !bytes.Equal(data, again) || hash != againHash {
		t.Fatalf("unstable canonical round trip: %s / %s, %v", data, again, err)
	}
	return data, hash, decoded
}

func rejectExecutionTestRequest(t *testing.T, r ExecutionRequest) {
	t.Helper()
	before := r
	before.Arguments = bytes.Clone(r.Arguments)
	data, hash, err := r.Canonical()
	if err == nil || data != nil || hash != "" {
		t.Fatalf("invalid request returned data=%s hash=%q error=%v", data, hash, err)
	}
	if !reflect.DeepEqual(r, before) {
		t.Fatal("failed normalization mutated input")
	}
}

func TestExecutionRequestCanonicalGolden(t *testing.T) {
	// [01] 固定输出字段、顺序和标签，验证参数递归排序及大整数不丢精度。
	if OfflineToolName != "offline.observe" || OfflineToolVersion != "1" || OfflinePolicyVersion != "p0.2-offline-v1" {
		t.Fatal("offline API constants changed")
	}
	r := validExecutionTestRequest()
	r.ScopeHash = strings.ToUpper(r.ScopeHash)
	r.Target = "HTTPS://EXAMPLE.COM.:00443?b=2&a=1&a=0"
	r.Arguments = json.RawMessage(` { "z": [ {"b":2,"a":1}, [], null, true, false ], "n":1234567890123456789012345678901234567890, "a":{} } `)
	want := `{"task_id":1,"mission_id":2,"lease_id":3,"fencing_token":4,"runtime_id":"runtime-01","requester_id":5,"authorization_id":6,"scope_version":1,"scope_hash":"` + strings.Repeat("ab", 32) + `","tool_name":"offline.observe","tool_version":"1","target":"https://example.com/?b=2&a=1&a=0","protocol":"https","port":443,"action":"observe","arguments":{"a":{},"n":1234567890123456789012345678901234567890,"z":[{"a":1,"b":2},[],null,true,false]},"policy_version":"p0.2-offline-v1"}`
	var escaped bytes.Buffer
	json.HTMLEscape(&escaped, []byte(want))
	want = escaped.String()
	data, _, _ := canonicalExecutionTestRequest(t, r)
	if string(data) != want {
		t.Fatalf("canonical JSON\n got: %s\nwant: %s", data, want)
	}
}

func TestExecutionRequestCanonicalEquivalentInputs(t *testing.T) {
	a := validExecutionTestRequest()
	a.Arguments = json.RawMessage(`{"z":{"b":2,"a":1},"a":[{"z":0,"b":true}],"text":"a"}`)
	b := a
	b.ScopeHash = strings.ToUpper(a.ScopeHash)
	b.Target = "HTTPS://EXAMPLE.COM.:00443"
	b.Arguments = json.RawMessage(` { "text":"a", "a":[{"b":true,"z":0}], "z":{"a":1,"b":2} } `)
	aj, ah, _ := canonicalExecutionTestRequest(t, a)
	bj, bh, _ := canonicalExecutionTestRequest(t, b)
	if !bytes.Equal(aj, bj) || ah != bh {
		t.Fatalf("equivalent requests differ: %s / %s", aj, bj)
	}
}

func TestExecutionRequestCanonicalDoesNotMutateInput(t *testing.T) {
	// [02] 参数保留额外容量，确认规范化既不改原始字节，也不泄露底层数组别名。
	r := validExecutionTestRequest()
	r.ScopeHash = strings.ToUpper(r.ScopeHash)
	r.Target = "HTTPS://EXAMPLE.COM.:00443"
	backing := bytes.Repeat([]byte{'x'}, 128)
	input := ` {"z":2, "a":1} `
	copy(backing, input)
	r.Arguments = json.RawMessage(backing[:len(input)])
	before := r
	before.Arguments = bytes.Clone(r.Arguments)
	beforeBacking := bytes.Clone(backing)
	data, _, _ := canonicalExecutionTestRequest(t, r)
	if !reflect.DeepEqual(r, before) || !bytes.Equal(backing, beforeBacking) {
		t.Fatal("canonicalization mutated caller-owned input")
	}
	for i := range data {
		data[i] = 0
	}
	if !bytes.Equal(backing, beforeBacking) {
		t.Fatal("returned canonical bytes alias input")
	}
}

func TestExecutionRequestCanonicalHashCoversFields(t *testing.T) {
	base := validExecutionTestRequest()
	_, original, _ := canonicalExecutionTestRequest(t, base)
	cases := []struct {
		name string
		edit func(*ExecutionRequest)
	}{
		{"task_id", func(r *ExecutionRequest) { r.TaskID++ }},
		{"mission_id", func(r *ExecutionRequest) { r.MissionID++ }},
		{"lease_id", func(r *ExecutionRequest) { r.LeaseID++ }},
		{"fencing_token", func(r *ExecutionRequest) { r.FencingToken++ }},
		{"runtime_id", func(r *ExecutionRequest) { r.RuntimeID += "-new" }},
		{"requester_id", func(r *ExecutionRequest) { r.RequesterID++ }},
		{"authorization_id", func(r *ExecutionRequest) { r.AuthorizationID++ }},
		{"scope_version", func(r *ExecutionRequest) { r.ScopeVersion++ }},
		{"scope_hash", func(r *ExecutionRequest) { r.ScopeHash = strings.Repeat("cd", 32) }},
		{"target", func(r *ExecutionRequest) { r.Target += "changed" }},
		{"protocol", func(r *ExecutionRequest) { r.Target = "http://example.com/"; r.Protocol = "http"; r.Port = 80 }},
		{"port", func(r *ExecutionRequest) { r.Target = "https://example.com:8443/"; r.Port = 8443 }},
		{"arguments", func(r *ExecutionRequest) { r.Arguments = json.RawMessage(`{"value":1}`) }},
	}
	seen := map[string]bool{original: true}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.edit(&r)
			_, changed, _ := canonicalExecutionTestRequest(t, r)
			if seen[changed] {
				t.Fatal("changed request did not produce a distinct hash")
			}
			seen[changed] = true
		})
	}
}

func TestExecutionRequestCanonicalInvalidFields(t *testing.T) {
	cases := []struct {
		name string
		edit func(*ExecutionRequest)
	}{
		{"runtime empty", func(r *ExecutionRequest) { r.RuntimeID = "" }},
		{"runtime too long", func(r *ExecutionRequest) { r.RuntimeID = strings.Repeat("a", 129) }},
		{"runtime space", func(r *ExecutionRequest) { r.RuntimeID = "runtime id" }},
		{"runtime trim", func(r *ExecutionRequest) { r.RuntimeID = " runtime" }},
		{"runtime tab", func(r *ExecutionRequest) { r.RuntimeID = "runtime\t" }},
		{"runtime newline", func(r *ExecutionRequest) { r.RuntimeID = "runtime\n" }},
		{"runtime NUL", func(r *ExecutionRequest) { r.RuntimeID = "runtime\x00" }},
		{"runtime DEL", func(r *ExecutionRequest) { r.RuntimeID = "runtime\x7f" }},
		{"runtime unicode", func(r *ExecutionRequest) { r.RuntimeID = "运行时" }},
		{"runtime invalid UTF8", func(r *ExecutionRequest) { r.RuntimeID = string([]byte{0xff}) }},
		{"hash empty", func(r *ExecutionRequest) { r.ScopeHash = "" }},
		{"hash short", func(r *ExecutionRequest) { r.ScopeHash = strings.Repeat("a", 63) }},
		{"hash long", func(r *ExecutionRequest) { r.ScopeHash = strings.Repeat("a", 65) }},
		{"hash nonhex", func(r *ExecutionRequest) { r.ScopeHash = strings.Repeat("g", 64) }},
		{"hash prefix", func(r *ExecutionRequest) { r.ScopeHash = "0x" + strings.Repeat("a", 62) }},
		{"hash whitespace", func(r *ExecutionRequest) { r.ScopeHash = " " + strings.Repeat("a", 63) }},
		{"tool empty", func(r *ExecutionRequest) { r.ToolName = "" }},
		{"tool execution", func(r *ExecutionRequest) { r.ToolName = "http.request" }},
		{"tool case", func(r *ExecutionRequest) { r.ToolName = "OFFLINE.OBSERVE" }},
		{"tool whitespace", func(r *ExecutionRequest) { r.ToolName += " " }},
		{"tool version empty", func(r *ExecutionRequest) { r.ToolVersion = "" }},
		{"tool version changed", func(r *ExecutionRequest) { r.ToolVersion = "2" }},
		{"tool version numeric alias", func(r *ExecutionRequest) { r.ToolVersion = "01" }},
		{"policy empty", func(r *ExecutionRequest) { r.PolicyVersion = "" }},
		{"policy changed", func(r *ExecutionRequest) { r.PolicyVersion = "p0.3-offline-v1" }},
		{"action empty", func(r *ExecutionRequest) { r.Action = "" }},
		{"action scan", func(r *ExecutionRequest) { r.Action = "scan" }},
		{"action execute", func(r *ExecutionRequest) { r.Action = "execute" }},
		{"action case", func(r *ExecutionRequest) { r.Action = "Observe" }},
		{"action whitespace", func(r *ExecutionRequest) { r.Action = " observe " }},
		{"protocol empty", func(r *ExecutionRequest) { r.Protocol = "" }},
		{"protocol mismatch", func(r *ExecutionRequest) { r.Protocol = "http" }},
		{"protocol case", func(r *ExecutionRequest) { r.Protocol = "HTTPS" }},
		{"protocol whitespace", func(r *ExecutionRequest) { r.Protocol = " https " }},
		{"port missing", func(r *ExecutionRequest) { r.Port = 0 }},
		{"port mismatch", func(r *ExecutionRequest) { r.Port = 80 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validExecutionTestRequest()
			tc.edit(&r)
			rejectExecutionTestRequest(t, r)
		})
	}
	// [03] 每个整型标识分别检查零和负值，不因其他字段合法而放行。
	fields := []string{"TaskID", "MissionID", "LeaseID", "FencingToken", "RequesterID", "AuthorizationID", "ScopeVersion"}
	for _, field := range fields {
		for _, value := range []int64{0, -1, math.MinInt64} {
			t.Run(fmt.Sprintf("%s=%d", field, value), func(t *testing.T) {
				r := validExecutionTestRequest()
				reflect.ValueOf(&r).Elem().FieldByName(field).SetInt(value)
				rejectExecutionTestRequest(t, r)
			})
		}
	}
}

func TestExecutionRequestCanonicalPositiveBoundaries(t *testing.T) {
	r := validExecutionTestRequest()
	r.TaskID, r.MissionID, r.LeaseID, r.FencingToken = math.MaxInt64, math.MaxInt64, math.MaxInt64, math.MaxInt64
	r.RequesterID, r.AuthorizationID, r.ScopeVersion = math.MaxInt64, math.MaxInt64, math.MaxInt
	r.RuntimeID = strings.Repeat("~", 128)
	r.ScopeHash = strings.Repeat("0", 64)
	canonicalExecutionTestRequest(t, r)
	var allVisible strings.Builder
	for c := byte(0x21); c <= 0x7e; c++ {
		allVisible.WriteByte(c)
	}
	r.RuntimeID = allVisible.String()
	canonicalExecutionTestRequest(t, r)
}

func TestExecutionRequestCanonicalTargets(t *testing.T) {
	cases := []struct {
		raw      string
		protocol string
		port     uint16
		want     string
	}{
		{"http://EXAMPLE.COM.", "http", 80, "http://example.com/"},
		{"HTTPS://EXAMPLE.COM.:00443", "https", 443, "https://example.com/"},
		{"https://example.com:08443/a", "https", 8443, "https://example.com:8443/a"},
		{"http://example.com:443", "http", 443, "http://example.com:443/"},
		{"https://example.com:80", "https", 80, "https://example.com:80/"},
		{"http://example.com:1", "http", 1, "http://example.com:1/"},
		{"https://example.com:65535", "https", 65535, "https://example.com:65535/"},
		{"https://192.0.2.1:443", "https", 443, "https://192.0.2.1/"},
		{"http://0.0.0.0", "http", 80, "http://0.0.0.0/"},
		{"http://255.255.255.255", "http", 80, "http://255.255.255.255/"},
		{"https://[2001:0DB8:0000:0000::1]:00443", "https", 443, "https://[2001:db8::1]/"},
		{"http://[2001:DB8::1]:08080", "http", 8080, "http://[2001:db8::1]:8080/"},
		{"https://[::1]", "https", 443, "https://[::1]/"},
		{"http://localhost", "http", 80, "http://localhost/"},
		{"https://unresolvable.example.invalid", "https", 443, "https://unresolvable.example.invalid/"},
		{"https://123.example", "https", 443, "https://123.example/"},
		{"https://xn--bcher-kva.example", "https", 443, "https://xn--bcher-kva.example/"},
		{"https://example.com?", "https", 443, "https://example.com/?"},
		{"https://example.com/a%2fb/%7e//../c?b=2&a=1&a=0&x=%2f&space=+&space=%20&flag", "https", 443, "https://example.com/a%2fb/%7e//../c?b=2&a=1&a=0&x=%2f&space=+&space=%20&flag"},
		{"https://example.com/a%23b?q=%23&next=https%3A%2F%2Fother.invalid", "https", 443, "https://example.com/a%23b?q=%23&next=https%3A%2F%2Fother.invalid"},
		{"https://example.com/%E4%B8%AD?q=%zz", "https", 443, "https://example.com/%E4%B8%AD?q=%zz"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Target, r.Protocol, r.Port = tc.raw, tc.protocol, tc.port
			_, _, decoded := canonicalExecutionTestRequest(t, r)
			if decoded.Target != tc.want || decoded.Protocol != tc.protocol || decoded.Port != tc.port {
				t.Fatalf("got target=%q protocol=%q port=%d, want %q/%q/%d", decoded.Target, decoded.Protocol, decoded.Port, tc.want, tc.protocol, tc.port)
			}
		})
	}
}

func TestExecutionRequestCanonicalRejectsTargets(t *testing.T) {
	// [04] 复用 Scope 的严格主机策略；覆盖解释差异、端口欺骗和原始非 ASCII。
	cases := []string{
		"", " ", "/path", "//example.com", "https:example.com", "https:///example.com", "https:////example.com",
		"ftp://example.com", "file:///example.com", "http://", "https://?a=b", "https://#",
		"https://user@example.com", "https://user:pass@example.com", "https://@example.com",
		"https://example.com#fragment", "https://example.com#", "https://example.com/path?x=y#",
		"https://example.com..", "https://.example.com", "https://exa_mple.com", "https://example..com",
		"https://例子.example", "https://bücher.example", "https://example.com/中文", "https://example.com/?q=中文",
		"https://example.com:0", "https://example.com:65536", "https://example.com:-1", "https://example.com:+443",
		"https://example.com:abc", "https://example.com:", "https://example.com:443:80",
		" https://example.com", "https://example.com ", "https://example.com\n", "https://example.com/\x00", "https://example.com/\x7f",
		"https://example.com\\@evil.invalid", "https://example.com/a\\b", "https://example.com/?x=\\evil.invalid",
		"https://%65xample.com", "https://example.com/%zz", "https://example.com/%", "https://exam%00ple.com",
		"https://127.1", "https://2130706433", "https://0x7f000001", "https://0177.0.0.1", "https://192.0.2.01",
		"https://192.0.2.1.", "https://0xc0.0x00.0x02.0x01", "https://999.0.0.1", "https://example.123", "https://0x",
		"https://[::ffff:192.0.2.1]", "https://[fe80::1%25eth0]", "https://2001:db8::1", "https://2001:db8::1:443",
		"https://[example.com]", "https://[192.0.2.1]", "https://[v1.a]", "https://[2001:db8::1", "https://[::1]]",
		"https://-example.com", "https://example-.com", "https://*.example.com", "https://example.com\t/path",
		"https://" + strings.Repeat("a", 64) + ".example",
		"https://example.com/" + string([]byte{0xff}),
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Target = raw
			rejectExecutionTestRequest(t, r)
		})
	}
	for _, raw := range []string{"https://example.com:8443/", "https://[::1]:8443/", "http://example.com/"} {
		t.Run("effective port mismatch "+raw, func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Target = raw
			if strings.HasPrefix(raw, "http:") {
				r.Protocol = "http"
			}
			rejectExecutionTestRequest(t, r)
		})
	}
}

func TestExecutionRequestCanonicalQueryNotRewritten(t *testing.T) {
	queries := []string{"a=1&b=2", "b=2&a=1", "a=1&a=2", "a=2&a=1", "q=+", "q=%20", "q=%2F", "q=%2f", "flag", "flag=", "", "?"}
	seen := make(map[string]bool)
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			r := validExecutionTestRequest()
			if query != "" {
				if query == "?" {
					r.Target += "?"
				} else {
					r.Target += "?" + query
				}
			}
			_, hash, decoded := canonicalExecutionTestRequest(t, r)
			if decoded.Target != r.Target || seen[hash] {
				t.Fatalf("query semantics rewritten: %q -> %q", r.Target, decoded.Target)
			}
			seen[hash] = true
		})
	}
}

func TestExecutionRequestCanonicalArguments(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`{}`, `{}`},
		{" \n\t{}\r ", `{}`},
		{`{"z":[],"b":{},"a":null}`, `{"a":null,"b":{},"z":[]}`},
		{`{"z":[3,2,1,{"b":2,"a":1}],"a":true}`, `{"a":true,"z":[3,2,1,{"a":1,"b":2}]}`},
		{`{"值":"中文","a":"a","":"empty key"}`, `{"":"empty key","a":"a","值":"中文"}`},
		{`{"__proto__":{"constructor":true},"a":"<>&"}`, `{"__proto__":{"constructor":true},"a":"<>&"}`},
		{`{"n":9007199254740993}`, `{"n":9007199254740993}`},
		{`{"n":-9223372036854775809}`, `{"n":-9223372036854775809}`},
		{`{"n":12345678901234567890123456789012345678901234567890}`, `{"n":12345678901234567890123456789012345678901234567890}`},
		{`{"a":-0,"b":1.0,"c":1e+03,"d":1E-10000}`, `{"a":-0,"b":1.0,"c":1e+03,"d":1E-10000}`},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Arguments = json.RawMessage(tc.raw)
			_, _, decoded := canonicalExecutionTestRequest(t, r)
			var escaped bytes.Buffer
			json.HTMLEscape(&escaped, []byte(tc.want))
			if string(decoded.Arguments) != escaped.String() {
				t.Fatalf("arguments got %s, want %s", decoded.Arguments, escaped.String())
			}
		})
	}
	// [05] 语法合法的任意精度数字不经浮点转换；不同词法允许不同摘要。
	seen := make(map[string]bool)
	for _, number := range []string{"1", "1.0", "1e0", "1E+0", "0", "-0", "1e10000", strings.Repeat("9", 15000)} {
		t.Run("number "+number[:min(len(number), 40)], func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Arguments = json.RawMessage(`{"n":` + number + `}`)
			_, hash, decoded := canonicalExecutionTestRequest(t, r)
			if !bytes.Equal(decoded.Arguments, r.Arguments) || seen[hash] {
				t.Fatal("JSON number was rounded, collapsed or rewritten")
			}
			seen[hash] = true
		})
	}
}

func TestExecutionRequestCanonicalRejectsArguments(t *testing.T) {
	cases := []string{
		"", " ", "\n\t", "null", "true", "false", "1", "1.0", `"object"`, "[]", "[{}]",
		`{"a":1,"a":2}`, `{"a":1,"b":2,"a":3}`, `{"":1,"":2}`, `{"a":null,"a":null}`,
		`{"outer":{"key":1,"key":2}}`, `{"outer":[{"key":1,"key":2}]}`,
		`{"a":{"x":{"k":1,"k":2}}}`, `{"a":[[{"k":1,"k":2}]]}`,
		`{"n":NaN}`, `{"n":nan}`, `{"n":Infinity}`, `{"n":-Infinity}`, `{"n":+Infinity}`, `{"n":Inf}`,
		`{"n":01}`, `{"n":-01}`, `{"n":0x10}`, `{"n":+1}`, `{"n":.1}`, `{"n":1.}`, `{"n":1e}`, `{"n":1e+}`, `{"n":--1}`,
		`{"a":1,}`, `{"a":[1,]}`, `{"a" 1}`, `{"a":}`, `{"a":1`, `{"a":[1}`, `{"a":/*x*/1}`,
		`{1:"a"}`, `{'a':1}`, `{"a":undefined}`, `{"a":"\x41"}`, `{"a":"unterminated}`,
		`{} {}`, `{} []`, `{} null`, `{} true`, `{} 1`, `{} trailing`, `{} //comment`,
		"\xef\xbb\xbf{}", "{\"a\":\"\xff\"}", "{\"a\":\"\x00\"}",
		string(bytes.Repeat([]byte{' '}, 16*1024+1)),
	}
	for i, raw := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Arguments = json.RawMessage(raw)
			rejectExecutionTestRequest(t, r)
		})
	}
	r := validExecutionTestRequest()
	r.Arguments = nil
	rejectExecutionTestRequest(t, r)
}

func TestExecutionRequestCanonicalEscapedArgumentKeys(t *testing.T) {
	// [07] 按解码后的键拒绝转义别名；不同对象内的同名键则不构成重复。
	backslash := string(rune(92))
	for _, raw := range []string{
		`{"a":1,"` + backslash + `u0061":2}`,
		`{"nested":{"a":1,"` + backslash + `u0061":2}}`,
		`{"nested":[{"a":1,"` + backslash + `u0061":2}]}`,
		`{"中文":1,"` + backslash + `u4e2d` + backslash + `u6587":2}`,
	} {
		r := validExecutionTestRequest()
		r.Arguments = json.RawMessage(raw)
		rejectExecutionTestRequest(t, r)
	}
	a := validExecutionTestRequest()
	a.Arguments = json.RawMessage(`{"a":"a","nested":{"a":2},"array":[{"a":3},{"a":4}]}`)
	b := a
	b.Arguments = json.RawMessage(`{"array":[{"a":3},{"a":4}],"nested":{"a":2},"` + backslash + `u0061":"` + backslash + `u0061"}`)
	aj, ah, _ := canonicalExecutionTestRequest(t, a)
	bj, bh, _ := canonicalExecutionTestRequest(t, b)
	if !bytes.Equal(aj, bj) || ah != bh {
		t.Fatal("equivalent escaped keys or values produced different hashes")
	}
}

func TestExecutionRequestCanonicalArgumentLimits(t *testing.T) {
	// [06] 16 KiB 含边界；仅容器计深度，根对象占一层，数组不能绕过深度限制。
	for _, length := range []int{16*1024 - 1, 16 * 1024, 16*1024 + 1} {
		t.Run(fmt.Sprintf("bytes_%d", length), func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Arguments = json.RawMessage(`{"s":"` + strings.Repeat("a", length-8) + `"}`)
			if len(r.Arguments) != length {
				t.Fatal("incorrect size test fixture")
			}
			if length <= 16*1024 {
				canonicalExecutionTestRequest(t, r)
			} else {
				rejectExecutionTestRequest(t, r)
			}
		})
	}
	for _, count := range []int{2729, 2730} {
		t.Run(fmt.Sprintf("escaped_bytes_%d", count), func(t *testing.T) {
			r := validExecutionTestRequest()
			r.Arguments = json.RawMessage(`{"s":"` + strings.Repeat("<", count) + `"}`)
			if count == 2729 {
				canonicalExecutionTestRequest(t, r)
			} else {
				rejectExecutionTestRequest(t, r)
			}
		})
	}
	for _, depth := range []int{1, 15, 16, 17, 1000} {
		for _, arrays := range []bool{false, true} {
			t.Run(fmt.Sprintf("depth_%d_arrays_%v", depth, arrays), func(t *testing.T) {
				var raw string
				if arrays {
					raw = `{"v":` + strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1) + "}"
				} else {
					raw = strings.Repeat(`{"v":`, depth) + "0" + strings.Repeat("}", depth)
				}
				r := validExecutionTestRequest()
				r.Arguments = json.RawMessage(raw)
				if depth <= 16 {
					canonicalExecutionTestRequest(t, r)
				} else {
					rejectExecutionTestRequest(t, r)
				}
			})
		}
	}
}

func FuzzExecutionRequestCanonicalStable(f *testing.F) {
	f.Add("HTTPS://EXAMPLE.COM.:00443", `{"b":2,"a":1}`)
	f.Add("https://[2001:0DB8::1]/a%2fb?z=2&a=1", `{"n":9007199254740993}`)
	f.Add("https://example.com/", `{"a":1,"a":2}`)
	f.Add("https://127.1/", `{}`)
	f.Fuzz(func(t *testing.T, target, arguments string) {
		r := validExecutionTestRequest()
		r.Target, r.Arguments = target, json.RawMessage(arguments)
		before := bytes.Clone(r.Arguments)
		data, hash, err := r.Canonical()
		if !bytes.Equal(before, r.Arguments) || r.Target != target {
			t.Fatal("input mutated")
		}
		if err != nil {
			if data != nil || hash != "" {
				t.Fatal("error returned partial canonical output")
			}
			return
		}
		canonicalExecutionTestRequest(t, r)
	})
}
