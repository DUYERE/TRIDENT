package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trident/internal/project"
)

func fixtureSnapshot(t *testing.T) *project.Snapshot {
	t.Helper()
	return fixtureSnapshotNamed(t, "java-authz")
}

func fixtureSnapshotNamed(t *testing.T, name string) *project.Snapshot {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "source")
	copyTree(t, source, copied)
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), copied, destination)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), destination, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/**", "/anything", true},
		{"/manager/**", "/manager", true},
		{"/manager/**", "/manager/update", true},
		{"/manager/**", "/staff/update", false},
		{"/*", "/login", true},
		{"/*", "/login/nested", false},
		{"/api/*/data", "/api/v1/data", true},
		{"/api/*/data", "/api/v1/other", false},
		{"/files/**/*.js", "/files/a/b/app.js", true},
	}
	for _, test := range cases {
		if got := matchPath(test.pattern, test.path); got != test.want {
			t.Fatalf("matchPath(%q, %q) = %v, want %v", test.pattern, test.path, got, test.want)
		}
	}
}

func TestRequirementParsing(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"permitAll", RequirementPublic},
		{"isAnonymous()", RequirementPublic},
		{"isAuthenticated()", RequirementAuthenticated},
		{"hasRole('ADMIN')", RequirementRole},
		{"ROLE_ADMIN", RequirementRole},
		{"denyAll", RequirementDeny},
		{"somethingCustom", RequirementUnknown},
	}
	for _, test := range cases {
		if got, _ := requirementFromAccess(test.value); got != test.want {
			t.Fatalf("requirementFromAccess(%q) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestAnalyzeFixtureDecisions(t *testing.T) {
	report, err := Analyze(context.Background(), fixtureSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	decisions := map[string]EndpointDecision{}
	for _, decision := range report.Endpoints {
		decisions[decision.Path] = decision
	}
	want := map[string]string{
		"/secure/admin":     "protected",
		"/secure/login":     "public",
		"/public/hello":     "unprotected",
		"/api/admin":        "protected",
		"/api/open":         "public",
		"/api/private/data": "protected",
		"/filtered/data":    "protected",
		"/xmlfilter/data":   "protected",
		"/xmlsecure/data":   "protected",
		"/manual/check":     "unknown",
		"/open/hello":       "unprotected",
	}
	for path, decision := range want {
		if decisions[path].Decision != decision {
			t.Fatalf("%s = %q (%s), want %q", path, decisions[path].Decision, decisions[path].Reason, decision)
		}
	}
	if report.Coverage.Protected != 6 || report.Coverage.Public != 2 || report.Coverage.Unprotected != 2 || report.Coverage.Unknown != 1 {
		t.Fatalf("coverage: %+v", report.Coverage)
	}
	if len(report.Findings) != 2 || report.Findings[0].Status != "inconclusive" {
		t.Fatalf("findings: %+v", report.Findings)
	}
	if report.RuntimeStatus != "not_run" || report.Coverage.RuntimeStatus != "not_run" {
		t.Fatalf("runtime status: %+v", report)
	}
	if report.Partial {
		t.Fatalf("fixture unexpectedly partial: %v", report.Limitations)
	}
}

func TestAnalyzeChainFixtureDecisions(t *testing.T) {
	report, err := Analyze(context.Background(), fixtureSnapshotNamed(t, "java-authz-chain"))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Chains) != 2 {
		t.Fatalf("chains: %+v", report.Chains)
	}
	first, second := report.Chains[0], report.Chains[1]
	if first.Order != 1 || first.OrderSource != "annotation" || len(first.SecurityMatchers) != 1 ||
		first.SecurityMatchers[0] != "/chain/api/**" || len(first.Rules) != 3 ||
		len(first.CustomFilters) != 1 {
		t.Fatalf("first chain: %+v", first)
	}
	if second.OrderSource != "default" || len(second.SecurityMatchers) != 0 || len(second.Rules) != 1 {
		t.Fatalf("second chain: %+v", second)
	}
	if report.Coverage.Chains != 2 || report.Coverage.MethodSecurity != "enabled" ||
		report.Coverage.ContextPath != "/app" {
		t.Fatalf("coverage: %+v", report.Coverage)
	}
	decisions := map[string]EndpointDecision{}
	for _, decision := range report.Endpoints {
		decisions[decision.Path] = decision
	}
	want := map[string]string{
		"/chain/api/hello":       "protected",
		"/chain/api/public/info": "public",
		"/chain/api/admin/panel": "protected",
		"/chain/web/open":        "public",
		"/chain/web/members":     "protected",
		"/chain/web/feature":     "protected",
		"/chain/web/denied":      "protected",
		"/chain/web/unknown":     "unknown",
		"/ctx/hello":             "public",
	}
	for path, decision := range want {
		if decisions[path].Decision != decision {
			t.Fatalf("%s = %q (%s), want %q", path, decisions[path].Decision, decisions[path].Reason, decision)
		}
	}
	if decisions["/chain/api/hello"].Chain != first.ID || decisions["/chain/web/open"].Chain != second.ID {
		t.Fatalf("chain attribution: %+v", decisions)
	}
	if got := decisions["/chain/api/admin/panel"].Roles; len(got) != 1 || got[0] != "ROLE_ADMIN" {
		t.Fatalf("chain role: %v", got)
	}
	if got := decisions["/chain/web/feature"].Roles; len(got) != 1 || got[0] != "ROLE_ADMIN" {
		t.Fatalf("method role: %v", got)
	}
	if decisions["/ctx/hello"].ExternalPath != "/app/ctx/hello" {
		t.Fatalf("external path: %+v", decisions["/ctx/hello"])
	}
	if report.Coverage.Protected != 5 || report.Coverage.Public != 3 || report.Coverage.Unknown != 1 ||
		report.Coverage.Unprotected != 0 {
		t.Fatalf("coverage: %+v", report.Coverage)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings: %+v", report.Findings)
	}
	if report.Partial {
		t.Fatalf("fixture unexpectedly partial: %v", report.Limitations)
	}
	if report.RuntimeStatus != "not_run" {
		t.Fatalf("runtime status: %q", report.RuntimeStatus)
	}
}
