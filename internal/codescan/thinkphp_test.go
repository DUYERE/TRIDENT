package codescan

import "testing"

func TestSQLURLConfigRowsAreParsed(t *testing.T) {
	sql := "INSERT INTO `urlconfig` (`aliases`, `url`, `status`) VALUES ('/news/:id', 'index/news/read', 1), ('/about', 'index/page/about', 1);"
	rows := urlConfigRowsFromSQL(sql)
	if len(rows) != 2 || rows[0].Alias != "/news/:id" || rows[0].URL != "index/news/read" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestJSONURLConfigRowsAreParsed(t *testing.T) {
	raw := []byte(`{"urlconfig":[{"aliases":"/a","url":"index/a"},{"alias":"/b","target":"index/b"}]}`)
	rows := urlConfigRowsFromJSON(raw)
	if len(rows) != 2 || rows[1].Alias != "/b" || rows[1].URL != "index/b" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestDynamicRouteIsExpandedFromDatabaseRows(t *testing.T) {
	report := &Report{Routes: []Route{{
		Language: "php", Path: "<dynamic>", PathStatus: "dynamic_unresolved",
		Symbol: `\think\Route.rule`, File: "app/route.php", Line: 17, Kind: "call",
	}}}
	applyURLConfigRows(report, []urlConfigRow{{Alias: "/a", URL: "index/a"}})
	if len(report.Routes) != 1 || report.Routes[0].Path != "/a" || report.Routes[0].PathStatus != "declared" || report.Routes[0].Source != "database" || report.Routes[0].Target != "index/a" {
		t.Fatalf("expanded route = %+v", report.Routes)
	}
}

func TestThinkPHPConventionCandidatesAreSeparate(t *testing.T) {
	report := &Report{
		Routes:  []Route{{Language: "php", File: "app/route.php", Symbol: `\think\Route.rule`}},
		Symbols: []Symbol{{Language: "php", Kind: "method", Name: "index", QualifiedName: "Index.index", File: "app/admin/controller/Index.php"}},
	}
	appendThinkPHPConventionRoutes(report)
	if len(report.Routes) != 2 || report.Routes[1].PathStatus != "convention_candidate" || report.Routes[1].Source != "convention" || report.Routes[1].Path != "/admin/index/index" {
		t.Fatalf("convention routes = %+v", report.Routes)
	}
}

func TestThinkPHPDynamicRouteWithoutSnapshotRowsIsExplicit(t *testing.T) {
	report := &Report{Routes: []Route{
		{Language: "php", Path: "<dynamic>", PathStatus: "dynamic_unresolved", Reason: "route_path_not_literal", Symbol: `\think\Route.rule`},
		{Language: "php", Path: "<dynamic>", PathStatus: "dynamic_unresolved", Reason: "route_path_not_literal", Symbol: `route(`},
	}}
	annotateURLConfigAbsent(report)
	if report.Routes[0].Reason != "database_urlconfig_absent" {
		t.Fatalf("thinkphp reason = %q", report.Routes[0].Reason)
	}
	if report.Routes[1].Reason != "route_path_not_literal" {
		t.Fatalf("plain route reason changed: %q", report.Routes[1].Reason)
	}
}
