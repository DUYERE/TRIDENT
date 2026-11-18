package codescan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scanSource(t *testing.T, language, source string, rules []RuleSpec) []Finding {
	t.Helper()
	spec, ok := specFor(language)
	if !ok {
		t.Fatalf("unsupported language %s", language)
	}
	tokens, err := lex([]byte(source), spec, MaxTokensPerFile)
	if err != nil {
		t.Fatalf("lex: %v", err)
	}
	statements, relations, err := splitStatements(tokens, spec, MaxStatementsPerFile)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return scanRules(statements, relations, spec, rulesForLanguage(rules, language), "sample.source", "sha256")
}

func ruleByID(id string) []RuleSpec {
	for _, rule := range builtinRules() {
		if rule.ID == id {
			return []RuleSpec{rule}
		}
	}
	return nil
}

func TestLexIgnoresCommentsAndStrings(t *testing.T) {
	spec, _ := specFor("php")
	source := "<?php // mysql_query($_GET['a']);\n/* system($_POST['b']); */\n$n = \"eval($_GET[x])\";\n"
	tokens, err := lex([]byte(source), spec, MaxTokensPerFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range tokens {
		if tok.kind == tokIdent && (tok.text == "mysql_query" || tok.text == "system" || tok.text == "eval") {
			t.Fatalf("comment/string code leaked into token IR: %q", tok.text)
		}
	}
	if strings.Join(tokenTexts(tokens), " ") == "" {
		t.Fatal("empty token stream")
	}
}

func tokenTexts(tokens []token) []string {
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		out = append(out, tok.text)
	}
	return out
}

func TestChainNormalization(t *testing.T) {
	spec, _ := specFor("php")
	chains := chainsIn(mustLex(t, "$request->input('host');", spec), spec)
	found := false
	for _, chain := range chains {
		if chain.full == "$request.input" && chain.short == "input" && chain.kind == "call" {
			found = true
		}
	}
	if !found {
		t.Fatal("member call chain was not normalized with the correct end/kind")
	}

	javaSpec, _ := specFor("java")
	javaChains := chainsIn(mustLex(t, "@GetMapping(\"/search\")", javaSpec), javaSpec)
	found = false
	for _, chain := range javaChains {
		if chain.short == "GetMapping" && chain.annotated && chain.kind == "call" {
			found = true
		}
	}
	if !found {
		t.Fatal("annotation prefix was not normalized")
	}
}

func mustLex(t *testing.T, source string, spec languageSpec) []token {
	t.Helper()
	tokens, err := lex([]byte(source), spec, MaxTokensPerFile)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestSplitStatementsHandlesSemicolonFreeLanguages(t *testing.T) {
	spec, _ := specFor("go")
	source := "func search(r *http.Request) {\n id := r.FormValue(\"id\")\n q := \"SELECT \" + id\n db.Query(q)\n}\n"
	statements, relations, err := splitStatements(mustLex(t, source, spec), spec, MaxStatementsPerFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) < 4 {
		t.Fatalf("Go body was not split into statements: %d", len(statements))
	}
	if relations[1].parent != 0 {
		t.Fatal("function scope parent is not the file scope")
	}
}

func TestAssignmentTargetAcrossLanguages(t *testing.T) {
	cases := []struct {
		language string
		source   string
		want     string
	}{
		{"typescript", "const name: string = req.query.name;", "name"},
		{"csharp", "string id = Request.QueryString[\"id\"];", "id"},
		{"go", "var x int = 1;", "x"},
		{"go", "id, _ := strconv.Atoi(raw);", "id"},
		{"java", "cmd.CommandText = sql;", "CommandText"},
	}
	for _, item := range cases {
		spec, _ := specFor(item.language)
		statements, _, err := splitStatements(mustLex(t, item.source, spec), spec, MaxStatementsPerFile)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, stmt := range statements {
			if stmt.assign != nil && stmt.assign.target == item.want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: expected assignment target %q", item.language, item.want)
		}
	}
}

func TestTaintSourceToSink(t *testing.T) {
	findings := scanSource(t, "php", "$id = $_GET['id'];\n$sql = \"SELECT \" . $id;\nmysql_query($sql);\n", ruleByID("php.sql.query"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 SQL finding, got %d", len(findings))
	}
	got := findings[0]
	if got.Status != "static_confirmed" || got.RuntimeStatus != "not_run" || got.Source == nil || got.Sink == nil {
		t.Fatalf("incomplete finding evidence: %+v", got)
	}
	if len(got.Flow) < 3 || got.Flow[0].Kind != "source" || got.Flow[len(got.Flow)-1].Kind != "sink" {
		t.Fatalf("expected source -> propagation -> sink flow, got %+v", got.Flow)
	}
	for _, step := range got.Flow {
		if step.SHA256 == "" || step.Line < 1 {
			t.Fatalf("flow step lacks pinned evidence: %+v", step)
		}
	}
}

func TestSanitizerAndArgIndexSuppressFalsePositives(t *testing.T) {
	cases := []struct {
		language string
		rule     string
		source   string
	}{
		{"php", "php.sql.query", "$page = intval($_GET['page']);\nmysql_query(\"SELECT \" . $page);\n"},
		{"php", "php.sql.query", "$stmt = $pdo->prepare('SELECT :id');\n$stmt->execute([':id' => $_GET['id']]);\n"},
		{"python", "python.sql.execute", "name = request.args.get('name')\ncursor.execute(\"SELECT * FROM t WHERE n = %s\", (name,))\n"},
		{"python", "python.xss.response", "title = request.args.get('title')\nsafe_title = html.escape(title)\nreturn render_template_string(\"<h1>\" + safe_title + \"</h1>\")\n"},
		{"javascript", "js.sql.query", "const id = parseInt(req.query.id, 10);\ndb.query('SELECT ?', [id]);\n"},
	}
	for _, item := range cases {
		findings := scanSource(t, item.language, item.source, ruleByID(item.rule))
		if len(findings) != 0 {
			t.Fatalf("%s/%s: expected no finding for negative case, got %d", item.language, item.rule, len(findings))
		}
	}
}

func TestCommentAndStringDecoysNeverMatch(t *testing.T) {
	source := "// mysql_query($_GET['id']);\n$note = \"mysql_query($_GET[id])\";\n"
	if got := scanSource(t, "php", source, ruleByID("php.sql.query")); len(got) != 0 {
		t.Fatalf("decoy produced %d findings", len(got))
	}
}

func TestReceiverSink(t *testing.T) {
	source := "ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nois.readObject();\n"
	findings := scanSource(t, "java", source, ruleByID("java.deserialization.readobject"))
	if len(findings) != 1 || findings[0].Sink.Detail != "receiver" {
		t.Fatalf("receiver sink was not detected: %+v", findings)
	}
}

func TestRoutesAreDeclarativeAndBounded(t *testing.T) {
	cases := []struct {
		language string
		source   string
		path     string
		method   string
	}{
		{"php", "Route::get('/search', function () {});", "/search", "GET"},
		{"php", "Route::rule('/rule', 'index/rule');", "/rule", ""},
		{"csharp", "[HttpPost(\"ping\")] public IActionResult Ping() {}", "ping", "POST"},
		{"python", "@app.route('/run', methods=['POST'])\ndef run(): pass", "/run", ""},
		{"javascript", "app.get('/xss', (req, res) => {});", "/xss", "GET"},
		{"java", "@GetMapping(\"/search\") public String search() {}", "/search", "GET"},
		{"go", "http.HandleFunc(\"/search\", search)", "/search", ""},
	}
	for _, item := range cases {
		spec, _ := specFor(item.language)
		statements, _, err := splitStatements(mustLex(t, item.source, spec), spec, MaxStatementsPerFile)
		if err != nil {
			t.Fatal(err)
		}
		routes := scanRoutes(statements, spec, "sample", "sha")
		found := false
		for _, route := range routes {
			if route.Path == item.path && (item.method == "" || contains(route.HTTPMethods, item.method)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: missing route %s %s (got %+v)", item.language, item.path, item.method, routes)
		}
	}
}

func TestDynamicRoutePathIsExplicitlyUnresolved(t *testing.T) {
	spec, _ := specFor("php")
	source := "Route::rule($aliases[$key], 'index/index');"
	statements, _, err := splitStatements(mustLex(t, source, spec), spec, MaxStatementsPerFile)
	if err != nil {
		t.Fatal(err)
	}
	routes := scanRoutes(statements, spec, "route.php", "sha")
	if len(routes) != 1 {
		t.Fatalf("routes = %+v", routes)
	}
	route := routes[0]
	if route.Path != "<dynamic>" || route.PathStatus != "dynamic_unresolved" || route.Reason != "route_path_not_literal" {
		t.Fatalf("dynamic route was not explicit: %+v", route)
	}
}

func TestNamespacedDynamicRoutePathIsExplicit(t *testing.T) {
	spec, _ := specFor("php")
	source := "\\think\\Route::rule($k,$val);"
	statements, _, err := splitStatements(mustLex(t, source, spec), spec, MaxStatementsPerFile)
	if err != nil {
		t.Fatal(err)
	}
	routes := scanRoutes(statements, spec, "route.php", "sha")
	if len(routes) != 1 || routes[0].PathStatus != "dynamic_unresolved" {
		t.Fatalf("namespaced dynamic route was not explicit: %+v", routes)
	}
}

func TestRouteAnnotationNameDoesNotCreateDynamicNoise(t *testing.T) {
	spec, _ := specFor("php")
	source := "$route = new Route(); $route->getName();"
	statements, _, err := splitStatements(mustLex(t, source, spec), spec, MaxStatementsPerFile)
	if err != nil {
		t.Fatal(err)
	}
	if routes := scanRoutes(statements, spec, "framework.php", "sha"); len(routes) != 0 {
		t.Fatalf("annotation name produced dynamic noise: %+v", routes)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRuleCatalogValidationFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"unknown_field.json": `{"schema_version":1,"rules":[{"id":"x","bogus":1}]}`,
		"bad_language.json":  `{"schema_version":1,"rules":[{"id":"x","languages":["cobol"],"category":"sql","cwe":"CWE-89","severity":"high","confidence":"high","title":"t","message":"m","sources":[{"kind":"access","names":["x"]}],"sinks":[{"kind":"call","names":["y"]}]}]}`,
		"duplicate_id.json":  `{"schema_version":1,"rules":[{"id":"x","languages":["php"],"category":"sql","cwe":"CWE-89","severity":"high","confidence":"high","title":"t","message":"m","sources":[{"kind":"access","names":["x"]}],"sinks":[{"kind":"call","names":["y"]}]},{"id":"x","languages":["php"],"category":"sql","cwe":"CWE-89","severity":"high","confidence":"high","title":"t","message":"m","sources":[{"kind":"access","names":["x"]}],"sinks":[{"kind":"call","names":["y"]}]}]}`,
		"wrong_schema.json":  `{"schema_version":99,"rules":[]}`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRuleFile(path); err == nil {
			t.Fatalf("%s should have been rejected", name)
		}
	}
	valid := filepath.Join(dir, "valid.json")
	body := `{"schema_version":1,"rules":[{"id":"caller.php.custom","languages":["php"],"category":"xss","cwe":"CWE-79","severity":"low","confidence":"medium","title":"t","message":"m","sources":[{"kind":"access","names":["$_GET"]}],"sinks":[{"kind":"call","names":["debug_log"]}]}]}`
	if err := os.WriteFile(valid, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRuleFile(valid)
	if err != nil || len(rules) != 1 {
		t.Fatalf("valid rules rejected: %v", err)
	}
	_, versionA, err := resolveRules(Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, versionB, err := resolveRules(Options{RulePath: valid})
	if err != nil {
		t.Fatal(err)
	}
	if versionA == versionB {
		t.Fatal("caller rules must change the rule-set version")
	}
}

func TestLanguageAliasesAndUnknown(t *testing.T) {
	selected, err := resolveLanguages(Options{Languages: []string{"dotnet", "js", "ts"}})
	if err != nil || !selected["csharp"] || !selected["javascript"] || !selected["typescript"] || selected["php"] {
		t.Fatalf("aliases resolved incorrectly: %+v %v", selected, err)
	}
	if _, err := resolveLanguages(Options{Languages: []string{"cobol"}}); err == nil {
		t.Fatal("unsupported language must fail closed")
	}
}

func TestAsFindingsReportKeepsStatusDeterministic(t *testing.T) {
	report := Report{
		SchemaVersion: SchemaVersion, ToolVersion: ToolVersion, SnapshotHash: "hash",
		AnalysisKind: AnalysisKind, RuleSetVersion: "rules",
		Findings: []Finding{{
			ID: "id", RuleID: "php.sql.query", Language: "php", Category: "sql", CWE: "CWE-89",
			Severity: "high", Confidence: "high", Status: "static_confirmed", RuntimeStatus: "not_run",
			Title: "t", File: "a.php", SHA256: "sha", StartLine: 1, EndLine: 3,
			Sink:     &Ref{Kind: "sink", Symbol: "mysql_query", File: "a.php", SHA256: "sha", Line: 3},
			Evidence: []Ref{{Kind: "source", Symbol: "$_GET", File: "a.php", SHA256: "sha", Line: 1}},
		}},
		Coverage: Coverage{RuntimeStatus: "not_run"},
	}
	first := AsFindingsReport(report)
	second := AsFindingsReport(report)
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) {
		t.Fatal("finding adaptation is not deterministic")
	}
	if len(first.Findings) != 1 || first.Findings[0].RuntimeStatus != "not_run" || first.Coverage.FindingsStaticConfirmed != 1 {
		t.Fatalf("unexpected adapted report: %+v", first)
	}
}

func TestInterpolatedStringSourcesAreExtracted(t *testing.T) {
	cases := []struct {
		language string
		rule     string
		source   string
	}{
		{"php", "php.sql.query", "$sql = \"SELECT * FROM t WHERE id=$_GET[id]\";\nmysql_query($sql);\n"},
		{"php", "php.sql.query", "$id = $_GET['id'];\n$sql = \"SELECT * FROM t WHERE id=$id\";\nmysql_query($sql);\n"},
		{"python", "python.sql.execute", "x = request.args.get('q')\ncursor.execute(f\"SELECT * FROM t WHERE u = {x}\")\n"},
		{"python", "python.sql.execute", "cursor.execute(f\"SELECT * FROM t WHERE u = {request.args.get('q')}\")\n"},
		{"javascript", "js.sql.query", "const q = `SELECT * FROM t WHERE u=${req.query.id}`;\ndb.query(q);\n"},
		{"csharp", "csharp.sql.command", "var id = Request.QueryString[\"id\"];\nvar cmd = new SqlCommand($\"SELECT * FROM t WHERE u={id}\", conn);\n"},
	}
	for _, item := range cases {
		findings := scanSource(t, item.language, item.source, ruleByID(item.rule))
		if len(findings) != 1 {
			t.Fatalf("%s: interpolated source not detected, got %d findings", item.language, len(findings))
		}
		if findings[0].Source == nil || findings[0].Sink == nil {
			t.Fatalf("%s: incomplete evidence %+v", item.language, findings[0])
		}
	}
}

func TestNonInterpolatedStringsStayOpaque(t *testing.T) {
	cases := []struct {
		language string
		rule     string
		source   string
	}{
		// PHP single quotes do not interpolate.
		{"php", "php.sql.query", "$sql = 'SELECT * FROM t WHERE id=$_GET[id]';\nmysql_query($sql);\n"},
		// Python plain strings and r-strings do not interpolate.
		{"python", "python.sql.execute", "sql = \"SELECT * FROM t WHERE u = {request.args.get('q')}\"\ncursor.execute(sql)\n"},
		{"python", "python.sql.execute", "sql = rf\"SELECT * FROM t WHERE u = {request.args.get('q')}\"\ncursor.execute(sql)\n"},
		// Go backticks are raw strings, never interpolation.
		{"go", "go.sql.query", "q := fmt.Sprintf(\"SELECT %s\", r.FormValue(\"id\"))\n"},
	}
	for _, item := range cases {
		if got := scanSource(t, item.language, item.source, ruleByID(item.rule)); len(got) != 0 {
			t.Fatalf("%s: non-interpolated literal produced %d findings", item.language, len(got))
		}
	}
}

func TestStringTextNeverCreatesSinksOrRoutes(t *testing.T) {
	// Sink-shaped text inside a string must not become a sink; interpolated
	// variables inside it may only act as sources.
	source := "$note = \"mysql_query($_GET[id])\";\n"
	if got := scanSource(t, "php", source, ruleByID("php.sql.query")); len(got) != 0 {
		t.Fatalf("string-embedded sink text produced %d findings", len(got))
	}
	// The variable itself is still a live source once it flows to a real sink.
	follow := "$note = \"mysql_query($_GET[id])\";\nmysql_query($note);\n"
	if got := scanSource(t, "php", follow, ruleByID("php.sql.query")); len(got) != 1 {
		t.Fatalf("interpolated source flow not detected: %d findings", len(got))
	}
}

func TestSameFileFunctionSummary(t *testing.T) {
	// Source wrapper: a helper returning untrusted input feeds a sink.
	wrapper := "function getInput() { return $_GET['x']; }\n$id = getInput();\nmysql_query($id);\n"
	if got := scanSource(t, "php", wrapper, ruleByID("php.sql.query")); len(got) != 1 {
		t.Fatalf("source wrapper not detected: %d findings", len(got))
	}
	// Sink wrapper: a tainted argument reaching a sink inside the function.
	sinkWrapper := "function runQuery($q) { mysql_query($q); }\nrunQuery($_GET['id']);\n"
	got := scanSource(t, "php", sinkWrapper, ruleByID("php.sql.query"))
	if len(got) != 1 {
		t.Fatalf("sink wrapper not detected: %d findings", len(got))
	}
	if !strings.Contains(got[0].Sink.Symbol, "mysql_query") {
		t.Fatalf("wrapper sink symbol mismatch: %+v", got[0].Sink)
	}
	foundWrapperLimitation := false
	for _, item := range got[0].Limitations {
		if strings.Contains(item, "cross_function_wrapper_sink") {
			foundWrapperLimitation = true
		}
	}
	if !foundWrapperLimitation {
		t.Fatalf("wrapper finding lacks cross-function limitation: %+v", got[0].Limitations)
	}
	// Taint-through helper: identity propagation through a function return.
	through := "function esc($x) { return $x; }\n$id = esc($_GET['id']);\nmysql_query($id);\n"
	if got := scanSource(t, "php", through, ruleByID("php.sql.query")); len(got) != 1 {
		t.Fatalf("taint-through helper not detected: %d findings", len(got))
	}
}

func TestFunctionSummaryNegativeCases(t *testing.T) {
	cases := []string{
		// Sanitizing wrapper: the sink inside the body only receives a
		// neutralized parameter, so the wrapper never becomes a sink summary.
		"function runQuery($q) { mysql_query(intval($q)); }\nrunQuery($_GET['id']);\n",
		// Untainted call argument never reaches the wrapped sink.
		"function runQuery($q) { mysql_query($q); }\nrunQuery('SELECT 1');\n",
		// Sink wrapper called with no arguments at all.
		"function runQuery($q) { mysql_query($q); }\nrunQuery();\n",
	}
	for _, source := range cases {
		if got := scanSource(t, "php", source, ruleByID("php.sql.query")); len(got) != 0 {
			t.Fatalf("negative summary case produced %d findings: %s", len(got), source)
		}
	}
}

func TestNewRedirectAndXPathRules(t *testing.T) {
	redirect := scanSource(t, "php", "$to = $_GET['url'];\nheader(\"Location: \" . $to);\n", ruleByID("php.redirect.header"))
	if len(redirect) != 1 || redirect[0].Category != "redirect" || redirect[0].CWE != "CWE-601" {
		t.Fatalf("open redirect not detected: %+v", redirect)
	}
	xpath := scanSource(t, "php", "$q = $_GET['q'];\n$nodes = $doc->xpath($q);\n", ruleByID("php.xpath.query"))
	if len(xpath) != 1 || xpath[0].Category != "xpath" || xpath[0].CWE != "CWE-643" {
		t.Fatalf("xpath injection not detected: %+v", xpath)
	}
	javaRedirect := scanSource(t, "java", "String to = request.getParameter(\"url\");\nresponse.sendRedirect(to);\n", ruleByID("java.redirect.response"))
	if len(javaRedirect) != 1 || javaRedirect[0].Category != "redirect" {
		t.Fatalf("java open redirect not detected: %+v", javaRedirect)
	}
}
