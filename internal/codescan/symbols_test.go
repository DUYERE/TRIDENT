package codescan

import (
	"testing"
)

func symbolIndexFor(t *testing.T, language, source string) ([]Symbol, []Call, []Unresolved) {
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
	return scanSymbolIndex(statements, relations, spec, "fixture."+language, "fixture-sha")
}

func hasSymbol(symbols []Symbol, name, kind string) bool {
	for _, symbol := range symbols {
		if symbol.Name == name && symbol.Kind == kind {
			return true
		}
	}
	return false
}

func findCall(calls []Call, name string) (Call, bool) {
	for _, call := range calls {
		if call.Name == name {
			return call, true
		}
	}
	return Call{}, false
}

func findUnresolved(items []Unresolved, expr string) bool {
	for _, item := range items {
		if item.Expr == expr {
			return true
		}
	}
	return false
}

func TestVariableAndStringConstantIndexAreBounded(t *testing.T) {
	spec, _ := specFor("php")
	source := `<?php
$x = "secret-value";
const TOKEN = "abc";
$obj->field = "not-a-variable";
`
	tokens, err := lex([]byte(source), spec, MaxTokensPerFile)
	if err != nil {
		t.Fatal(err)
	}
	statements, relations, err := splitStatements(tokens, spec, MaxStatementsPerFile)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = relations, statements
	variables, stringsIndex, _, _ := scanVariableIndex(statements, spec, "fixture.php", "sha")
	if len(variables) != 2 {
		t.Fatalf("variables = %+v", variables)
	}
	if variables[0].Name != "x" || variables[0].Kind != "variable" || variables[1].Name != "TOKEN" || variables[1].Kind != "constant" {
		t.Fatalf("variable kinds = %+v", variables)
	}
	if len(stringsIndex) != 3 || stringsIndex[0].Hash == "" || stringsIndex[0].Hash == "secret-value" {
		t.Fatalf("string constants = %+v", stringsIndex)
	}
}

func TestReceiverContainerDisambiguatesMethodCalls(t *testing.T) {
	userSymbols, userCalls, _ := symbolIndexFor(t, "php", `<?php
class User {
  public function save() {}
  public function run() {
    $u = new User();
    $u->save();
    $this->save();
  }
}
`)
	orderSymbols, orderCalls, _ := symbolIndexFor(t, "php", `<?php
class Order {
  public function save() {}
  public function run() {
    $o->save();
  }
}
`)
	report := &Report{Symbols: append(append([]Symbol{}, userSymbols...), orderSymbols...)}
	report.Calls = append(report.Calls, userCalls...)
	report.Calls = append(report.Calls, orderCalls...)
	for index := range report.Calls {
		report.Calls[index].Status = "external_or_unresolved"
	}
	report.Unresolved = []Unresolved{{Language: "php", Expr: "save", File: "fixture.php", Line: 1}}
	resolveCrossFileCalls(report)
	byReceiver := map[string]Call{}
	for _, call := range report.Calls {
		if call.Name == "save" {
			byReceiver[call.Receiver] = call
		}
	}
	if call := byReceiver["$u"]; call.Status != "same_project" || call.ResolvedSymbol != "User.save" {
		t.Fatalf("new-inferred receiver: %+v", call)
	}
	if call := byReceiver["$this"]; call.Status != "same_project" || call.ResolvedSymbol != "User.save" {
		t.Fatalf("this receiver: %+v", call)
	}
	if call := byReceiver["$o"]; call.Status != "ambiguous_symbol" {
		t.Fatalf("untyped receiver must stay ambiguous: %+v", call)
	}
}

func TestCrossFileCallResolution(t *testing.T) {
	report := &Report{
		Symbols: []Symbol{
			{Language: "php", Kind: "function", Name: "helper", QualifiedName: "helper", File: "a.php"},
			{Language: "php", Kind: "function", Name: "dup", QualifiedName: "One.dup", File: "b.php"},
			{Language: "php", Kind: "function", Name: "dup", QualifiedName: "Two.dup", File: "c.php"},
		},
		Calls: []Call{
			{Language: "php", Name: "helper", Callee: "helper", File: "x.php", Line: 1, Status: "external_or_unresolved"},
			{Language: "php", Name: "dup", Callee: "dup", File: "x.php", Line: 2, Status: "external_or_unresolved"},
		},
		Unresolved: []Unresolved{{Language: "php", Expr: "helper", File: "x.php", Line: 1}},
	}
	resolveCrossFileCalls(report)
	if report.Calls[0].Status != "same_project" || report.Calls[0].ResolvedFile != "a.php" {
		t.Fatalf("unique call not resolved: %+v", report.Calls[0])
	}
	if report.Calls[1].Status != "ambiguous_symbol" {
		t.Fatalf("ambiguous call not explicit: %+v", report.Calls[1])
	}
	if len(report.Unresolved) != 0 {
		t.Fatalf("resolved call left unresolved: %+v", report.Unresolved)
	}
}

func TestPHPFunctionClassAndCallStatus(t *testing.T) {
	symbols, calls, unresolved := symbolIndexFor(t, "php", `<?php
function helper($x) { return $x; }
class Demo {
  public function run($a) {
    helper($a);
    mysql_query($a);
  }
}
`)
	if !hasSymbol(symbols, "helper", "function") {
		t.Fatalf("missing PHP function symbol: %+v", symbols)
	}
	if !hasSymbol(symbols, "Demo", "class") {
		t.Fatalf("missing PHP class symbol: %+v", symbols)
	}
	if !hasSymbol(symbols, "run", "method") {
		t.Fatalf("missing PHP method symbol: %+v", symbols)
	}
	if call, ok := findCall(calls, "helper"); !ok || call.Status != "same_file" || call.Caller != "Demo.run" {
		t.Fatalf("local PHP call not attributed: %+v", calls)
	}
	if !findUnresolved(unresolved, "mysql_query") {
		t.Fatalf("external PHP call not unresolved: %+v", unresolved)
	}
}

func TestJavaClassMethodAndCall(t *testing.T) {
	symbols, calls, unresolved := symbolIndexFor(t, "java", `public class Demo {
  public void run(String input) { helper(input); }
  private void helper(String x) { }
}
`)
	if !hasSymbol(symbols, "Demo", "class") || !hasSymbol(symbols, "run", "method") || !hasSymbol(symbols, "helper", "method") {
		t.Fatalf("missing Java symbols: %+v", symbols)
	}
	call, ok := findCall(calls, "helper")
	if !ok || call.Status != "same_file" || call.Caller != "Demo.run" {
		t.Fatalf("Java call not attributed: %+v", calls)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unexpected Java unresolved calls: %+v", unresolved)
	}
}

func TestGoFunctionStructAndCall(t *testing.T) {
	symbols, calls, unresolved := symbolIndexFor(t, "go", `package main
type User struct { Name string }
func helper(x string) string { return x }
func run() { helper("x"); missing() }
func (u User) Greet() string { return u.Name }
`)
	if !hasSymbol(symbols, "User", "struct") || !hasSymbol(symbols, "helper", "function") || !hasSymbol(symbols, "run", "function") {
		t.Fatalf("missing Go symbols: %+v", symbols)
	}
	if !hasSymbol(symbols, "Greet", "method") {
		t.Fatalf("Go receiver method not indexed: %+v", symbols)
	}
	if call, ok := findCall(calls, "helper"); !ok || call.Status != "same_file" || call.Caller != "run" {
		t.Fatalf("Go call not attributed: %+v", calls)
	}
	if !findUnresolved(unresolved, "missing") {
		t.Fatalf("Go external call not unresolved: %+v", unresolved)
	}
}

func TestPythonFunctionsAndCalls(t *testing.T) {
	symbols, calls, unresolved := symbolIndexFor(t, "python", `def helper(x):
    return x
def run():
    helper(1)
    external(2)
`)
	if !hasSymbol(symbols, "helper", "function") || !hasSymbol(symbols, "run", "function") {
		t.Fatalf("missing Python symbols: %+v", symbols)
	}
	if call, ok := findCall(calls, "helper"); !ok || call.Status != "same_file" {
		t.Fatalf("Python local call not resolved: %+v", calls)
	}
	if !findUnresolved(unresolved, "external") {
		t.Fatalf("Python external call not unresolved: %+v", unresolved)
	}
}

func TestJavaScriptAndTypeScriptFunctions(t *testing.T) {
	for _, language := range []string{"javascript", "typescript"} {
		symbols, calls, unresolved := symbolIndexFor(t, language, `function helper(x) { return x; }
function run() { helper(1); window.fetch("/x"); }
class Service {
  helper(x) { return x; }
  run() { this.helper(1); }
}
`)
		if !hasSymbol(symbols, "helper", "function") || !hasSymbol(symbols, "run", "function") {
			t.Fatalf("%s symbols missing: %+v", language, symbols)
		}
		if !hasSymbol(symbols, "Service", "class") || !hasSymbol(symbols, "helper", "method") {
			t.Fatalf("%s class/method symbols missing: %+v", language, symbols)
		}
		if call, ok := findCall(calls, "helper"); !ok || call.Status != "same_file" || call.Caller != "run" {
			t.Fatalf("%s local call not attributed: %+v", language, calls)
		}
		if !findUnresolved(unresolved, "window.fetch") {
			t.Fatalf("%s external call not unresolved: %+v", language, unresolved)
		}
	}
}

func TestCSharpClassMethodAndCall(t *testing.T) {
	symbols, calls, unresolved := symbolIndexFor(t, "csharp", `class Demo {
  public void Run(string input) { Helper(input); External(input); }
  private void Helper(string x) { }
}
`)
	if !hasSymbol(symbols, "Demo", "class") || !hasSymbol(symbols, "Run", "method") || !hasSymbol(symbols, "Helper", "method") {
		t.Fatalf("missing C# symbols: %+v", symbols)
	}
	if call, ok := findCall(calls, "Helper"); !ok || call.Status != "same_file" || call.Caller != "Demo.Run" {
		t.Fatalf("C# local call not attributed: %+v", calls)
	}
	if !findUnresolved(unresolved, "External") {
		t.Fatalf("C# external call not unresolved: %+v", unresolved)
	}
}

func TestSymbolParametersAndEndLine(t *testing.T) {
	symbols, _, _ := symbolIndexFor(t, "java", `public class Demo {
  public void run(String input, int count) {
    helper(input);
  }
  private void helper(String x) { }
}
`)
	var run Symbol
	for _, symbol := range symbols {
		if symbol.Name == "run" && symbol.Kind == "method" {
			run = symbol
		}
	}
	if len(run.Parameters) != 2 || run.Parameters[0].Name != "input" || run.Parameters[1].Name != "count" {
		t.Fatalf("parameter names not extracted: %+v", run)
	}
	if run.Container != "Demo" || run.EndLine == 0 {
		t.Fatalf("container/end line not populated: %+v", run)
	}
}
