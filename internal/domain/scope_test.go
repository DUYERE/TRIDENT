package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func validDomainTestScope() Scope {
	return Scope{
		Domains:          []string{"example.com"},
		IPRanges:         []string{"192.0.2.0/24", "2001:db8::/32"},
		Ports:            []uint16{80, 443},
		Protocols:        []string{"http", "https"},
		AllowedActions:   []string{"recon", "verify"},
		ForbiddenActions: []string{"destroy"},
		MaxRPS:           5,
		MaxConcurrency:   2,
		DataPolicy:       "redact",
		StopConditions:   []string{"authorization_revoked"},
	}
}

func TestScopeCanonicalGolden(t *testing.T) {
	// [01] 用固定 JSON 锁定字段、空数组、排序、去重和 CIDR 掩码语义。
	s := validDomainTestScope()
	s.Domains = []string{" Z.Example.COM. ", "example.com", "EXAMPLE.COM.", "2001:0DB8::1", "192.0.2.5"}
	s.IPRanges = []string{" 192.0.2.129/24 ", "2001:0DB8:1::1/32", "192.0.2.0/24"}
	s.Ports = []uint16{443, 80, 443}
	s.Protocols = []string{" HTTPS ", "http", "HTTP"}
	s.AllowedActions = []string{" verify ", "recon", "recon"}
	s.ForbiddenActions = []string{" destroy ", "destroy"}
	s.DataPolicy = " redact "
	s.StopConditions = []string{" budget ", "authorization_revoked", "budget"}
	want := `{"domains":["192.0.2.5","2001:db8::1","example.com","z.example.com"],"ip_ranges":["192.0.2.0/24","2001:db8::/32"],"ports":[80,443],"protocols":["http","https"],"allowed_actions":["recon","verify"],"forbidden_actions":["destroy"],"max_rps":5,"max_concurrency":2,"data_policy":"redact","stop_conditions":["authorization_revoked","budget"]}`
	got, hash, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical JSON\n got: %s\nwant: %s", got, want)
	}
	digest := sha256.Sum256(got)
	if hash != hex.EncodeToString(digest[:]) || len(hash) != 64 {
		t.Fatalf("hash %q does not match returned JSON", hash)
	}
	var decoded Scope
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	again, againHash, err := decoded.Canonical()
	if err != nil || !bytes.Equal(got, again) || hash != againHash {
		t.Fatalf("canonical round trip is unstable: %s, %q, %v", again, againHash, err)
	}
}

func TestScopeCanonicalDoesNotMutateInput(t *testing.T) {
	s := validDomainTestScope()
	s.Domains = []string{" B.Example.com. ", "example.com", "example.com"}
	s.IPRanges = []string{"2001:db8:1::/32", "192.0.2.3/24"}
	s.Ports = []uint16{443, 80, 443}
	s.Protocols = []string{" HTTPS ", "HTTP"}
	s.AllowedActions = []string{"verify", " recon "}
	s.ForbiddenActions = []string{"z", " destroy "}
	s.StopConditions = []string{"z", " authorization_revoked "}
	before, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Canonical(); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowsURL("https://example.com", "recon"); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("caller-owned slices mutated: before=%s after=%s", before, after)
	}
	// [02] 校验失败也不得排序或覆盖调用方的底层数组。
	s.MaxRPS = 0
	before, _ = json.Marshal(s)
	if _, _, err := s.Canonical(); err == nil {
		t.Fatal("invalid scope accepted")
	}
	after, _ = json.Marshal(s)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid input was mutated")
	}
}

func TestScopeCanonicalEquivalentInputs(t *testing.T) {
	a := validDomainTestScope()
	b := validDomainTestScope()
	b.Domains = []string{" EXAMPLE.COM. ", "example.com"}
	b.IPRanges = []string{"2001:0db8:ffff::1/32", "192.0.2.99/24", "192.0.2.0/24"}
	b.Ports = []uint16{443, 443, 80}
	b.Protocols = []string{" HTTPS ", " HTTP ", "http"}
	b.AllowedActions = []string{" verify ", "recon", "verify"}
	b.ForbiddenActions = []string{" destroy ", "destroy"}
	b.DataPolicy = " redact "
	b.StopConditions = []string{" authorization_revoked ", "authorization_revoked"}
	aj, ah, ae := a.Canonical()
	bj, bh, be := b.Canonical()
	if ae != nil || be != nil || !bytes.Equal(aj, bj) || ah != bh {
		t.Fatalf("equivalent scopes differ: %s/%s, %s/%s, errors=%v/%v", aj, ah, bj, bh, ae, be)
	}
	b.MaxRPS++
	_, changed, err := b.Canonical()
	if err != nil || changed == ah {
		t.Fatalf("changed policy did not change hash: %q, %v", changed, err)
	}
}

func TestScopeCanonicalEmptyArrays(t *testing.T) {
	s := validDomainTestScope()
	s.IPRanges = nil
	s.Ports = nil
	s.Protocols = nil
	s.ForbiddenActions = nil
	data, hash, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ip_ranges", "ports", "protocols", "forbidden_actions"} {
		if !strings.Contains(string(data), `"`+field+`":[]`) {
			t.Errorf("%s must encode as []: %s", field, data)
		}
	}
	s.IPRanges = []string{}
	s.Ports = []uint16{}
	s.Protocols = []string{}
	s.ForbiddenActions = []string{}
	again, againHash, err := s.Canonical()
	if err != nil || !bytes.Equal(data, again) || hash != againHash {
		t.Fatal("nil and empty slices differ")
	}
	if err := s.AllowsURL("https://example.com", "recon"); err == nil {
		t.Fatal("empty protocols/ports must not authorize a URL")
	}
}

func TestScopeCanonicalInvalidFields(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Scope)
	}{
		{"no targets", func(s *Scope) { s.Domains = nil; s.IPRanges = nil }},
		{"port zero", func(s *Scope) { s.Ports = []uint16{80, 0} }},
		{"unsupported protocol", func(s *Scope) { s.Protocols = []string{"ftp"} }},
		{"empty protocol", func(s *Scope) { s.Protocols = []string{" "} }},
		{"no allowed action", func(s *Scope) { s.AllowedActions = nil }},
		{"empty allowed action", func(s *Scope) { s.AllowedActions = []string{"recon", " "} }},
		{"empty forbidden action", func(s *Scope) { s.ForbiddenActions = []string{" "} }},
		{"overlapping actions", func(s *Scope) { s.ForbiddenActions = []string{" recon "} }},
		{"zero rps", func(s *Scope) { s.MaxRPS = 0 }},
		{"negative rps", func(s *Scope) { s.MaxRPS = -1 }},
		{"zero concurrency", func(s *Scope) { s.MaxConcurrency = 0 }},
		{"negative concurrency", func(s *Scope) { s.MaxConcurrency = -1 }},
		{"empty data policy", func(s *Scope) { s.DataPolicy = " \t\n" }},
		{"invalid UTF-8 data policy", func(s *Scope) { s.DataPolicy = string([]byte{0xff}) }},
		{"invalid UTF-8 allowed action", func(s *Scope) { s.AllowedActions = []string{string([]byte{0xff})} }},
		{"no stop conditions", func(s *Scope) { s.StopConditions = nil }},
		{"empty stop condition", func(s *Scope) { s.StopConditions = []string{"stop", " "} }},
		{"invalid UTF-8 stop condition", func(s *Scope) { s.StopConditions = []string{string([]byte{0xff})} }},
		{"empty CIDR", func(s *Scope) { s.IPRanges = []string{" "} }},
		{"bare CIDR address", func(s *Scope) { s.IPRanges = []string{"192.0.2.1"} }},
		{"IPv4 CIDR mask", func(s *Scope) { s.IPRanges = []string{"192.0.2.1/33"} }},
		{"IPv6 CIDR mask", func(s *Scope) { s.IPRanges = []string{"2001:db8::/129"} }},
		{"nonstandard CIDR", func(s *Scope) { s.IPRanges = []string{"192.000.2.1/24"} }},
		{"zoned CIDR", func(s *Scope) { s.IPRanges = []string{"fe80::1%eth0/64"} }},
		{"mapped CIDR", func(s *Scope) { s.IPRanges = []string{"::ffff:192.0.2.0/120"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validDomainTestScope()
			tc.edit(&s)
			data, hash, err := s.Canonical()
			if err == nil || data != nil || hash != "" {
				t.Fatalf("invalid scope returned data=%s hash=%q error=%v", data, hash, err)
			}
			if err := s.AllowsURL("https://example.com", "recon"); err == nil {
				t.Fatal("AllowsURL failed to validate scope first")
			}
		})
	}
}

func TestScopeCanonicalHosts(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{" Example.COM. ", "example.com"},
		{"localhost", "localhost"},
		{"a-b.example", "a-b.example"},
		{"123.example", "123.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"192.0.2.1", "192.0.2.1"},
		{"2001:0DB8:0000::1", "2001:db8::1"},
		{"::1", "::1"},
		{strings.Repeat("a", 63) + ".example", strings.Repeat("a", 63) + ".example"},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			s := validDomainTestScope()
			s.Domains = []string{tc.raw}
			data, _, err := s.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			var decoded Scope
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded.Domains, []string{tc.want}) {
				t.Fatalf("got %q, want %q", decoded.Domains, tc.want)
			}
		})
	}
}

func TestScopeCanonicalRejectsAmbiguousHosts(t *testing.T) {
	cases := []string{
		"", " ", ".", "*.example.com", "example.*", "例子.example", "bücher.example",
		"https://example.com", "user@example.com", "user:pass@example.com", "example.com:443",
		"[2001:db8::1]", "2001:db8::1%eth0", "::ffff:192.0.2.1", "192.0.2.1.",
		"127.1", "127.0.0.01", "0177.0.0.1", "2130706433", "0x7f000001", "0x7f.0x0.0x0.0x1",
		"0x", "0X.", "example.0x", "999.0.0.1", "127.0.0.1.2", "example.123", ".example.com", "example..com", "example.com..",
		"-example.com", "example-.com", "_service.example.com", "example/com", "example\\com",
		"example.com?x=1", "example.com#fragment", "exa mple.com", "example\n.com", "example\x00.com",
		"%65xample.com", "example.com\x7f", string([]byte{0xff}),
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			s := validDomainTestScope()
			s.Domains = []string{host}
			if _, _, err := s.Canonical(); err == nil {
				t.Fatalf("ambiguous host accepted: %q", host)
			}
		})
	}
}

func TestScopeAllowsURL(t *testing.T) {
	// [03] 覆盖精确域名、默认/显式端口、IPv4/IPv6、大小写和单个根尾点。
	cases := []struct {
		url    string
		action string
	}{
		{"http://example.com", "recon"},
		{"https://EXAMPLE.COM./path?next=https%3A%2F%2Fevil.invalid", "verify"},
		{"HTTPS://example.com/path", "recon"},
		{"https://example.com:443/", " recon "},
		{"http://example.com:443/", "recon"},
		{"https://example.com:80/", "recon"},
		{"https://example.com:00443/", "recon"},
		{"https://example.com/a%23b?q=%23", "recon"},
		{"http://192.0.2.0/", "recon"},
		{"http://192.0.2.255:80/", "recon"},
		{"https://[2001:DB8:1::1]/", "recon"},
		{"http://[2001:db8::1]:80/", "verify"},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			if err := validDomainTestScope().AllowsURL(tc.url, tc.action); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScopeAllowsURLRejectsInvalidURL(t *testing.T) {
	cases := []string{
		"", " ", "/path", "//example.com", "https:example.com", "https:///example.com",
		"ftp://example.com", "file:///example.com", "http://", "https://?a=b", "https://#",
		"https://user@example.com", "https://user:pass@example.com", "https://@example.com",
		"https://example.com#fragment", "https://example.com#", "https://example.com/path?x=y#",
		"https://sub.example.com", "https://example.com.evil.invalid", "https://notexample.com",
		"https://example.com..", "https://.example.com", "https://exa_mple.com", "https://例子.example",
		"https://example.com:0", "https://example.com:65536", "https://example.com:-1", "https://example.com:+443",
		"https://example.com:abc", "https://example.com:", "https://example.com:8443", "https://example.com:443:80",
		" https://example.com", "https://example.com ", "https://example.com\n", "https://example.com\\@evil.invalid",
		"https://%65xample.com", "https://example.com/%zz", "https://example.com/%",
		"http://127.1", "http://2130706433", "http://0x7f000001", "http://0177.0.0.1", "http://192.0.2.01",
		"http://192.0.2.1.", "http://0xc0.0x00.0x02.0x01", "http://999.0.0.1",
		"http://192.0.3.1", "http://[2001:db9::1]", "http://[::ffff:192.0.2.1]",
		"http://[fe80::1%25eth0]", "http://2001:db8::1", "http://2001:db8::1:80",
		"http://[example.com]", "http://[192.0.2.1]", "http://[v1.a]", "http://[2001:db8::1",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if err := validDomainTestScope().AllowsURL(raw, "recon"); err == nil {
				t.Fatalf("invalid or unauthorized URL accepted: %q", raw)
			}
		})
	}
}

func TestScopeAllowsURLPolicy(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*Scope)
		url    string
		action string
		allow  bool
	}{
		{"forbidden action", func(*Scope) {}, "https://example.com", "destroy", false},
		{"unknown action", func(*Scope) {}, "https://example.com", "scan", false},
		{"empty action", func(*Scope) {}, "https://example.com", " ", false},
		{"case-sensitive action", func(*Scope) {}, "https://example.com", "RECON", false},
		{"restricted protocol", func(s *Scope) { s.Protocols = []string{"http"} }, "https://example.com:80", "recon", false},
		{"restricted default port", func(s *Scope) { s.Ports = []uint16{80} }, "https://example.com", "recon", false},
		{"empty protocols", func(s *Scope) { s.Protocols = nil }, "https://example.com", "recon", false},
		{"empty ports", func(s *Scope) { s.Ports = nil }, "https://example.com", "recon", false},
		{"IP in domains without CIDR", func(s *Scope) { s.Domains = []string{"192.0.2.1"}; s.IPRanges = nil }, "http://192.0.2.1", "recon", false},
		{"IPv6 in domains without CIDR", func(s *Scope) { s.Domains = []string{"2001:db8::1"}; s.IPRanges = nil }, "http://[2001:db8::1]", "recon", false},
		{"CIDR only permits IP", func(s *Scope) { s.Domains = nil }, "http://192.0.2.1", "recon", true},
		{"CIDR does not authorize domain", func(s *Scope) { s.Domains = nil }, "https://example.com", "recon", false},
		{"domain without CIDR", func(s *Scope) { s.IPRanges = nil }, "https://example.com", "recon", true},
		{"IPv4 host prefix", func(s *Scope) { s.IPRanges = []string{"192.0.2.1/32"} }, "http://192.0.2.1", "recon", true},
		{"IPv4 host prefix excludes neighbor", func(s *Scope) { s.IPRanges = []string{"192.0.2.1/32"} }, "http://192.0.2.2", "recon", false},
		{"IPv6 host prefix", func(s *Scope) { s.IPRanges = []string{"2001:db8::1/128"} }, "http://[2001:db8::1]", "recon", true},
		{"IPv6 host prefix excludes neighbor", func(s *Scope) { s.IPRanges = []string{"2001:db8::1/128"} }, "http://[2001:db8::2]", "recon", false},
		{"no DNS at registration", func(s *Scope) { s.Domains = []string{"unresolvable.example.invalid"}; s.IPRanges = nil }, "https://unresolvable.example.invalid", "recon", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validDomainTestScope()
			tc.edit(&s)
			err := s.AllowsURL(tc.url, tc.action)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%v, got error=%v", tc.allow, err)
			}
		})
	}
}

func FuzzScopeCanonicalStable(f *testing.F) {
	f.Add("EXAMPLE.COM.")
	f.Add("192.0.2.1")
	f.Add("2001:db8::1")
	f.Add("*.example.com")
	// [04] 任意主机输入不得触发崩溃；成功规范化后必须能再次生成相同字节和摘要。
	f.Fuzz(func(t *testing.T, host string) {
		s := validDomainTestScope()
		s.Domains = []string{host}
		data, hash, err := s.Canonical()
		if err != nil {
			if data != nil || hash != "" {
				t.Fatal("error returned with partial canonical output")
			}
			return
		}
		var decoded Scope
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		again, againHash, err := decoded.Canonical()
		if err != nil || !bytes.Equal(data, again) || hash != againHash {
			t.Fatalf("unstable canonical output: %s %s %v", data, again, err)
		}
	})
}
