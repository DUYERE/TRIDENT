package dataflow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/project"
)

func fixtureSnapshot(t *testing.T) *project.Snapshot {
	t.Helper()
	return namedFixtureSnapshot(t, "java-maven")
}

func namedFixtureSnapshot(t *testing.T, name string) *project.Snapshot {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "source")
	copyTree(t, source, copied)
	return importSnapshot(t, copied)
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
			return fmt.Errorf("unexpected fixture entry %s", relative)
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

func importSnapshot(t *testing.T, source string) *project.Snapshot {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), source, destination)
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

func snapshotFromFiles(t *testing.T, files map[string]string) *project.Snapshot {
	t.Helper()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		target := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return importSnapshot(t, source)
}

func findingFor(report Report, path string) Finding {
	for _, finding := range report.Findings {
		if finding.Endpoint.Path == path {
			return finding
		}
	}
	return Finding{}
}

func TestAnalyzeFixtureJDBCSQLFlow(t *testing.T) {
	snapshot := fixtureSnapshot(t)
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 3 || report.Coverage.EndpointsAnalyzed != 3 || report.Partial {
		t.Fatalf("coverage: %+v findings=%+v partial=%v", report.Coverage, report.Findings, report.Partial)
	}
	if report.Coverage.FindingsConfirmed != 1 || report.Coverage.FindingsRefuted != 1 || report.Coverage.FindingsInconclusive != 1 {
		t.Fatalf("finding status counts: %+v", report.Coverage)
	}
	unsafe := findingFor(report, "/synthetic/customers/unsafe")
	if unsafe.Status != "static_confirmed" || unsafe.Severity != "high" || unsafe.CWE != "CWE-89" || unsafe.Sink == nil {
		t.Fatalf("unsafe finding: %+v", unsafe)
	}
	if unsafe.Sink.API != "statement.executeQuery" || !strings.HasSuffix(unsafe.Sink.File, "CustomerRepository.java") || unsafe.Sink.Line != 28 {
		t.Fatalf("unsafe sink: %+v", unsafe.Sink)
	}
	if len(unsafe.Sources) != 1 || unsafe.Sources[0].Parameter != "name" || unsafe.Sources[0].Binding != "name" {
		t.Fatalf("unsafe sources: %+v", unsafe.Sources)
	}
	flows := map[string]bool{}
	for _, step := range unsafe.Flow {
		flows[step.Kind] = true
	}
	if !flows["call"] || !flows["concat"] || !flows["sink"] {
		t.Fatalf("unsafe flow: %+v", unsafe.Flow)
	}
	anchors := map[string]bool{}
	for _, evidence := range unsafe.Evidence {
		anchors[evidence.Anchor] = true
	}
	if !anchors["fixture:unsafe-http-source"] || !anchors["fixture:sql-concatenation"] {
		t.Fatalf("unsafe evidence: %+v", unsafe.Evidence)
	}

	parameterized := findingFor(report, "/synthetic/customers/parameterized")
	if parameterized.Status != "refuted" || parameterized.Severity != "none" || parameterized.Sink != nil || parameterized.Protection == nil {
		t.Fatalf("parameterized finding: %+v", parameterized)
	}
	if parameterized.Protection.API != "statement.setString" || parameterized.Protection.Line != 39 {
		t.Fatalf("parameterized protection: %+v", parameterized.Protection)
	}

	dynamic := findingFor(report, "/synthetic/customers/dynamic")
	if dynamic.Status != "inconclusive" || dynamic.Boundary == nil || dynamic.Boundary.Kind != "dynamic_invocation" {
		t.Fatalf("dynamic finding: %+v", dynamic)
	}
	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
}

func TestAnalyzeDirectKnownAndUnknownPaths(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
@RestController
public class App {
    private Connection connection;
    @GetMapping("/direct")
    public void direct(@RequestParam("q") String q) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE a='" + q + "'");
    }
    @GetMapping("/safe")
    public void safe(@RequestParam("q") String q) throws Exception {
        String sql = "SELECT * FROM t WHERE a=?";
        PreparedStatement statement = connection.prepareStatement(sql);
        statement.setString(1, q);
        statement.executeQuery();
    }
    @GetMapping("/unknown")
    public void unknown(@RequestParam("q") String q) { external(q); }
    @GetMapping("/constant")
    public void constant(@RequestParam("q") String q) { log("fixed"); }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 4 {
		t.Fatalf("findings: %+v", report.Findings)
	}
	if finding := findingFor(report, "/direct"); finding.Status != "static_confirmed" || finding.Sink == nil || finding.Sink.Line != 10 {
		t.Fatalf("direct finding: %+v", finding)
	}
	if finding := findingFor(report, "/safe"); finding.Status != "refuted" || finding.Protection == nil {
		t.Fatalf("safe finding: %+v", finding)
	}
	if finding := findingFor(report, "/unknown"); finding.Status != "inconclusive" || finding.Boundary == nil || finding.Boundary.Kind != "unresolved_call" {
		t.Fatalf("unknown finding: %+v", finding)
	}
	if finding := findingFor(report, "/constant"); finding.Status != "inconclusive" || finding.Boundary != nil {
		t.Fatalf("constant finding: %+v", finding)
	}
}

func TestAnalyzePerParameterRecursionPreparedAndComments(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
@RestController
public class App {
    private Connection connection;
    @GetMapping("/multi")
    public void multi(@RequestParam("a") String a, @RequestParam("b") String b) throws Exception {
        String sql = "SELECT * FROM t WHERE a='" + b + "'";
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
        a.length();
    }
    @GetMapping("/prep")
    public void prep(@RequestParam("q") String q) throws Exception {
        String sql = "SELECT * FROM t WHERE a=" + q;
        PreparedStatement statement = connection.prepareStatement(sql);
        statement.executeQuery();
    }
    @GetMapping("/assign")
    public void assign(@RequestParam("q") String q) throws Exception {
        String sql = q;
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/rec")
    public void rec(@RequestParam("q") String q) { rec(q); }
    @GetMapping("/comment")
    public void comment(@RequestParam("q") String q) { log("statement.executeQuery(" + q + ")"); }
    @GetMapping("/none")
    public void none() { log("fixed"); }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 6 || report.Coverage.EndpointsAnalyzed != 5 {
		t.Fatalf("coverage: %+v findings=%+v", report.Coverage, report.Findings)
	}
	if report.Coverage.FindingsConfirmed != 3 || report.Coverage.FindingsInconclusive != 3 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}
	multiConfirmed := 0
	for _, finding := range report.Findings {
		if finding.Endpoint.Path != "/multi" {
			continue
		}
		if finding.Sources[0].Parameter == "b" {
			if finding.Status != "static_confirmed" || finding.Sink == nil {
				t.Fatalf("multi b: %+v", finding)
			}
			multiConfirmed++
		} else if finding.Sources[0].Parameter == "a" {
			if finding.Status != "inconclusive" || finding.Sink != nil {
				t.Fatalf("multi a: %+v", finding)
			}
		}
	}
	if multiConfirmed != 1 {
		t.Fatalf("multi findings: %+v", report.Findings)
	}
	if finding := findingFor(report, "/prep"); finding.Status != "static_confirmed" || finding.Sink == nil || finding.Sink.API != "connection.prepareStatement" {
		t.Fatalf("prepared sink: %+v", finding)
	}
	if finding := findingFor(report, "/assign"); finding.Status != "static_confirmed" || finding.Sink == nil || finding.Sink.API != "statement.executeQuery" {
		t.Fatalf("assign sink: %+v", finding)
	}
	if finding := findingFor(report, "/rec"); finding.Status != "inconclusive" || finding.Sink != nil {
		t.Fatalf("recursive finding: %+v", finding)
	}
	if finding := findingFor(report, "/comment"); finding.Status != "inconclusive" || finding.Sink != nil {
		t.Fatalf("comment/string false positive: %+v", finding)
	}
	if finding := findingFor(report, "/none"); finding.Status != "" {
		t.Fatalf("unbound endpoint produced finding: %+v", finding)
	}
}

func TestAnalyzeBuilderAndFormatFlows(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
@RestController
public class App {
    private Connection connection;
    @GetMapping("/builder")
    public void builder(@RequestParam("q") String q) throws Exception {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT * FROM t WHERE a='");
        sql.append(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }
    @GetMapping("/buffer-assign")
    public void bufferAssign(@RequestParam("q") String q) throws Exception {
        StringBuffer buffer = new StringBuffer();
        buffer.append(q);
        String sql = buffer.toString();
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/builder-constant")
    public void builderConstant(@RequestParam("q") String q) throws Exception {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT * FROM t WHERE a=?");
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }
    @GetMapping("/format")
    public void format(@RequestParam("q") String q) throws Exception {
        String sql = String.format("SELECT * FROM t WHERE a='%s'", q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/format-sink")
    public void formatSink(@RequestParam("q") String q) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery(String.format("SELECT * FROM t WHERE a='%s'", q));
    }
    @GetMapping("/format-constant")
    public void formatConstant(@RequestParam("q") String q) throws Exception {
        String sql = String.format("SELECT * FROM t WHERE a='100%%' AND b=?", q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/format-dynamic")
    public void formatDynamic(@RequestParam("q") String q, @RequestParam("fmt") String fmt) throws Exception {
        String sql = String.format(fmt, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/builder-boundary")
    public void builderBoundary(@RequestParam("q") String q) throws Exception {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT * FROM t WHERE a='");
        externalBuilder(sql, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 8 || len(report.Findings) != 9 {
		t.Fatalf("coverage: %+v findings=%+v", report.Coverage, report.Findings)
	}
	if report.Coverage.FindingsConfirmed != 4 || report.Coverage.FindingsInconclusive != 5 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}

	builder := findingFor(report, "/builder")
	if builder.Status != "static_confirmed" || builder.Sink == nil || builder.Sink.API != "statement.executeQuery" {
		t.Fatalf("builder finding: %+v", builder)
	}
	if !hasFlowKind(builder.Flow, "builder_append") || !hasFlowKind(builder.Flow, "sink") {
		t.Fatalf("builder flow: %+v", builder.Flow)
	}

	buffer := findingFor(report, "/buffer-assign")
	if buffer.Status != "static_confirmed" || buffer.Sink == nil {
		t.Fatalf("buffer finding: %+v", buffer)
	}
	if !hasFlowKind(buffer.Flow, "builder_append") || !hasFlowKind(buffer.Flow, "builder_to_string") {
		t.Fatalf("buffer flow: %+v", buffer.Flow)
	}

	constantBuilder := findingFor(report, "/builder-constant")
	if constantBuilder.Status != "inconclusive" || constantBuilder.Sink != nil || constantBuilder.Boundary != nil {
		t.Fatalf("constant builder finding: %+v", constantBuilder)
	}

	format := findingFor(report, "/format")
	if format.Status != "static_confirmed" || format.Sink == nil || !hasFlowKind(format.Flow, "string_format") {
		t.Fatalf("format finding: %+v", format)
	}

	formatSink := findingFor(report, "/format-sink")
	if formatSink.Status != "static_confirmed" || formatSink.Sink == nil {
		t.Fatalf("format sink finding: %+v", formatSink)
	}

	constantFormat := findingFor(report, "/format-constant")
	if constantFormat.Status != "inconclusive" || constantFormat.Sink != nil || constantFormat.Boundary != nil {
		t.Fatalf("constant format finding: %+v", constantFormat)
	}

	dynamic := findingsFor(report, "/format-dynamic")
	if len(dynamic) != 2 {
		t.Fatalf("dynamic format findings: %+v", dynamic)
	}
	for _, finding := range dynamic {
		if finding.Status != "inconclusive" || finding.Sink != nil || finding.Boundary == nil || finding.Boundary.Kind != "string_format_dynamic" {
			t.Fatalf("dynamic format finding: %+v", finding)
		}
	}

	boundary := findingFor(report, "/builder-boundary")
	if boundary.Status != "inconclusive" || boundary.Sink != nil || boundary.Boundary == nil || boundary.Boundary.Kind != "unresolved_call" {
		t.Fatalf("builder boundary finding: %+v", boundary)
	}

	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
}

func TestAnalyzeReturnAndBuilderMutationFlows(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
@RestController
public class App {
    private Connection connection;
    @GetMapping("/return")
    public void returnValue(@RequestParam("q") String q) throws Exception {
        String sql = buildQuery(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/return-sink")
    public void returnSink(@RequestParam("q") String q) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery(buildQuery(q));
    }
    @GetMapping("/return-constant")
    public void returnConstant(@RequestParam("q") String q) throws Exception {
        String sql = constantQuery(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/return-dynamic")
    public void returnDynamic(@RequestParam("q") String q, @RequestParam("fmt") String fmt) throws Exception {
        String sql = dynamicQuery(fmt, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/builder-helper")
    public void builderHelper(@RequestParam("q") String q) throws Exception {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT * FROM t WHERE a='");
        appendValue(sql, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }
    @GetMapping("/builder-helper-constant")
    public void builderHelperConstant(@RequestParam("q") String q) throws Exception {
        StringBuilder sql = new StringBuilder();
        appendConstant(sql, q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql.toString());
    }
    private String buildQuery(String value) {
        // fixture:return-concat
        return "SELECT * FROM t WHERE a='" + value + "'";
    }
    private String constantQuery(String value) {
        return "SELECT * FROM t WHERE a=?";
    }
    private String dynamicQuery(String pattern, String value) {
        return String.format(pattern, value);
    }
    private void appendValue(StringBuilder builder, String value) {
        // fixture:builder-mutation
        builder.append(value);
    }
    private void appendConstant(StringBuilder builder, String value) {
        builder.append("SELECT * FROM t WHERE a='100%%'");
    }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 6 || len(report.Findings) != 7 {
		t.Fatalf("coverage: %+v findings=%+v", report.Coverage, report.Findings)
	}
	if report.Coverage.FindingsConfirmed != 3 || report.Coverage.FindingsInconclusive != 4 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}

	returned := findingFor(report, "/return")
	if returned.Status != "static_confirmed" || returned.Sink == nil || returned.Sink.API != "statement.executeQuery" {
		t.Fatalf("return finding: %+v", returned)
	}
	if !hasFlowKind(returned.Flow, "return") || !hasFlowKind(returned.Flow, "sink") || !hasAnchor(returned, "fixture:return-concat") {
		t.Fatalf("return flow/evidence: %+v", returned)
	}

	returnSink := findingFor(report, "/return-sink")
	if returnSink.Status != "static_confirmed" || returnSink.Sink == nil {
		t.Fatalf("return sink finding: %+v", returnSink)
	}
	if !hasAnchor(returnSink, "fixture:return-concat") {
		t.Fatalf("return sink evidence: %+v", returnSink.Evidence)
	}

	returnConstant := findingFor(report, "/return-constant")
	if returnConstant.Status != "inconclusive" || returnConstant.Sink != nil {
		t.Fatalf("return constant finding: %+v", returnConstant)
	}

	returnDynamic := findingsFor(report, "/return-dynamic")
	if len(returnDynamic) != 2 {
		t.Fatalf("return dynamic findings: %+v", returnDynamic)
	}
	for _, finding := range returnDynamic {
		if finding.Status != "inconclusive" || finding.Sink != nil || finding.Boundary == nil || finding.Boundary.Kind != "string_format_dynamic" {
			t.Fatalf("return dynamic finding: %+v", finding)
		}
	}

	mutated := findingFor(report, "/builder-helper")
	if mutated.Status != "static_confirmed" || mutated.Sink == nil {
		t.Fatalf("builder mutation finding: %+v", mutated)
	}
	if !hasFlowKind(mutated.Flow, "builder_mutated") || !hasFlowKind(mutated.Flow, "sink") || !hasAnchor(mutated, "fixture:builder-mutation") {
		t.Fatalf("builder mutation flow/evidence: %+v", mutated)
	}

	mutationConstant := findingFor(report, "/builder-helper-constant")
	if mutationConstant.Status != "inconclusive" || mutationConstant.Sink != nil {
		t.Fatalf("builder mutation constant finding: %+v", mutationConstant)
	}

	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
}

func TestAnalyzeDispatchAndFieldTaint(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
interface Lookup {
    String find(String name);
}
interface Ambiguous {
    String find(String name);
}
class JdbcLookup implements Lookup {
    public String find(String name) {
        // fixture:interface-dispatch
        return "SELECT * FROM t WHERE a='" + name + "'";
    }
}
class FirstLookup implements Ambiguous {
    public String find(String name) { return "SELECT 1"; }
}
class SecondLookup implements Ambiguous {
    public String find(String name) { return "SELECT 2"; }
}
class BaseRepo {
    protected String inherited;
    public String build(String value) {
        // fixture:inherited-method
        return "SELECT * FROM t WHERE a='" + value + "'";
    }
    public String readInherited() {
        // fixture:inherited-field-read
        return this.inherited;
    }
}
class ChildRepo extends BaseRepo {
    public void save(String value) {
        // fixture:inherited-field-write
        this.inherited = value;
    }
}
class OverrideRepo extends BaseRepo {
    public String build(String value) {
        return "SELECT * FROM t WHERE b='" + value + "'";
    }
}
@RestController
public class App {
    private Connection connection;
    private Lookup lookup;
    private Ambiguous ambiguous;
    private ChildRepo child;
    private OverrideRepo override;
    private String stored;
    @GetMapping("/iface")
    public void iface(@RequestParam("q") String q) throws Exception {
        String sql = lookup.find(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/iface-ambiguous")
    public void ifaceAmbiguous(@RequestParam("q") String q) throws Exception {
        String sql = ambiguous.find(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/extends")
    public void extendsFlow(@RequestParam("q") String q) throws Exception {
        String sql = child.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/override")
    public void overrideFlow(@RequestParam("q") String q) throws Exception {
        String sql = override.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/field")
    public void field(@RequestParam("q") String q) throws Exception {
        store(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(this.stored);
    }
    @GetMapping("/field-copy")
    public void fieldCopy(@RequestParam("q") String q) throws Exception {
        store(q);
        String sql = this.stored;
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/field-constant")
    public void fieldConstant(@RequestParam("q") String q) throws Exception {
        storeConstant(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(this.stored);
    }
    @GetMapping("/field-inherited")
    public void fieldInherited(@RequestParam("q") String q) throws Exception {
        child.save(q);
        String sql = child.readInherited();
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    private void store(String value) {
        // fixture:field-write
        this.stored = value;
    }
    private void storeConstant(String value) {
        this.stored = "SELECT * FROM t WHERE a=?";
    }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 8 || len(report.Findings) != 8 {
		t.Fatalf("coverage: %+v findings=%+v", report.Coverage, report.Findings)
	}
	if report.Coverage.FindingsConfirmed != 6 || report.Coverage.FindingsInconclusive != 2 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}

	iface := findingFor(report, "/iface")
	if iface.Status != "static_confirmed" || iface.Sink == nil || !hasAnchor(iface, "fixture:interface-dispatch") {
		t.Fatalf("interface dispatch finding: %+v", iface)
	}

	ambiguous := findingFor(report, "/iface-ambiguous")
	if ambiguous.Status != "inconclusive" || ambiguous.Boundary == nil || ambiguous.Boundary.Kind != "ambiguous_dispatch" {
		t.Fatalf("ambiguous dispatch finding: %+v", ambiguous)
	}

	inherited := findingFor(report, "/extends")
	if inherited.Status != "static_confirmed" || inherited.Sink == nil || !hasAnchor(inherited, "fixture:inherited-method") {
		t.Fatalf("inherited method finding: %+v", inherited)
	}

	override := findingFor(report, "/override")
	if override.Status != "static_confirmed" || override.Sink == nil {
		t.Fatalf("override finding: %+v", override)
	}

	field := findingFor(report, "/field")
	if field.Status != "static_confirmed" || field.Sink == nil {
		t.Fatalf("field taint finding: %+v", field)
	}
	if !hasFlowKind(field.Flow, "field_write") || !hasAnchor(field, "fixture:field-write") {
		t.Fatalf("field taint flow/evidence: %+v", field)
	}

	fieldCopy := findingFor(report, "/field-copy")
	if fieldCopy.Status != "static_confirmed" || fieldCopy.Sink == nil || !hasFlowKind(fieldCopy.Flow, "field_read") {
		t.Fatalf("field copy finding: %+v", fieldCopy)
	}

	fieldConstant := findingFor(report, "/field-constant")
	if fieldConstant.Status != "inconclusive" || fieldConstant.Sink != nil {
		t.Fatalf("constant field finding: %+v", fieldConstant)
	}

	inheritedField := findingFor(report, "/field-inherited")
	if inheritedField.Status != "static_confirmed" || inheritedField.Sink == nil {
		t.Fatalf("inherited field finding: %+v", inheritedField)
	}
	if !hasFlowKind(inheritedField.Flow, "field_write") || !hasAnchor(inheritedField, "fixture:inherited-field-write") {
		t.Fatalf("inherited field flow/evidence: %+v", inheritedField)
	}

	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
}

func TestAnalyzeLambdaGenericVarargsOverloads(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.function.*;
class LambdaRepo {
    public String find(Function<String, String> mapper) {
        // fixture:lambda-overload
        return "SELECT * FROM t WHERE a='" + mapper.apply("x") + "'";
    }
    public String find(Integer id) {
        return "SELECT * FROM t WHERE id=" + id;
    }
}
class LambdaAmbiguous {
    public String find(Function<String, String> mapper) { return "SELECT 1"; }
    public String find(Consumer<String> consumer) { return "SELECT 2"; }
}
class VarRepo {
    public String join(String prefix, String... values) {
        // fixture:varargs-overload
        return "SELECT * FROM t WHERE a='" + prefix + values[0] + "'";
    }
    public String join(String prefix, Integer... values) {
        return "SELECT * FROM t WHERE id=" + values[0];
    }
}
class GenRepo {
    public <T> T pass(T value) {
        // fixture:generic-identity
        return value;
    }
    public String find(String name) {
        return "SELECT * FROM t WHERE a='" + name + "'";
    }
    public String find(Integer id) {
        return "SELECT * FROM t WHERE id=" + id;
    }
}
@RestController
public class App {
    private Connection connection;
    private LambdaRepo lambdaRepo;
    private LambdaAmbiguous lambdaAmbiguous;
    private VarRepo varRepo;
    private GenRepo genRepo;
    @GetMapping("/lambda")
    public void lambda(@RequestParam("q") String q) throws Exception {
        String sql = lambdaRepo.find(x -> q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/lambda-ambiguous")
    public void lambdaAmbiguousEndpoint(@RequestParam("q") String q) throws Exception {
        String sql = lambdaAmbiguous.find(x -> q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/varargs")
    public void varargs(@RequestParam("q") String q) throws Exception {
        String sql = varRepo.join("p", q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/varargs-ambiguous")
    public void varargsAmbiguous(@RequestParam("q") String q) throws Exception {
        String sql = varRepo.join(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/generic")
    public void generic(@RequestParam("q") String q) throws Exception {
        String sql = genRepo.find(genRepo.pass(q));
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/generic-direct")
    public void genericDirect(@RequestParam("q") String q) throws Exception {
        String sql = genRepo.pass(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 6 || len(report.Findings) != 6 {
		t.Fatalf("coverage: %+v findings=%+v", report.Coverage, report.Findings)
	}
	if report.Coverage.FindingsConfirmed != 4 || report.Coverage.FindingsInconclusive != 2 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}

	lambda := findingFor(report, "/lambda")
	if lambda.Status != "static_confirmed" || lambda.Sink == nil || !hasAnchor(lambda, "fixture:lambda-overload") {
		t.Fatalf("lambda finding: %+v", lambda)
	}

	lambdaAmbiguous := findingFor(report, "/lambda-ambiguous")
	if lambdaAmbiguous.Status != "inconclusive" || lambdaAmbiguous.Boundary == nil || lambdaAmbiguous.Boundary.Kind != "ambiguous_overload" {
		t.Fatalf("ambiguous lambda finding: %+v", lambdaAmbiguous)
	}

	varargs := findingFor(report, "/varargs")
	if varargs.Status != "static_confirmed" || varargs.Sink == nil || !hasAnchor(varargs, "fixture:varargs-overload") {
		t.Fatalf("varargs finding: %+v", varargs)
	}

	varargsAmbiguous := findingFor(report, "/varargs-ambiguous")
	if varargsAmbiguous.Status != "inconclusive" || varargsAmbiguous.Boundary == nil || varargsAmbiguous.Boundary.Kind != "ambiguous_overload" {
		t.Fatalf("ambiguous varargs finding: %+v", varargsAmbiguous)
	}

	generic := findingFor(report, "/generic")
	if generic.Status != "static_confirmed" || generic.Sink == nil || !hasAnchor(generic, "fixture:generic-identity") {
		t.Fatalf("generic finding: %+v", generic)
	}

	genericDirect := findingFor(report, "/generic-direct")
	if genericDirect.Status != "static_confirmed" || genericDirect.Sink == nil {
		t.Fatalf("generic identity finding: %+v", genericDirect)
	}

	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
}

func TestAnalyzeOverloadAndUnresolvedParent(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
interface TypedLookup {
    String find(String name);
    String find(Integer id);
}
class TypedImpl implements TypedLookup {
    public String find(String name) {
        // fixture:overload-string
        return "SELECT * FROM t WHERE a='" + name + "'";
    }
    public String find(Integer id) {
        return "SELECT * FROM t WHERE id=" + id;
    }
}
class TypedRepo {
    public String find(String name) { return "SELECT * FROM t WHERE a='" + name + "'"; }
    public String find(Integer id) { return "SELECT * FROM t WHERE id=" + id; }
}
class ExternalBase extends com.example.MissingBase {
}
class LocalParent extends com.example.MissingBase {
    public String build(String value) {
        // fixture:local-parent
        return "SELECT * FROM t WHERE a='" + value + "'";
    }
}
@RestController
public class App {
    private Connection connection;
    private TypedLookup typed;
    private TypedRepo repo;
    private ExternalBase external;
    private LocalParent local;
    @GetMapping("/overload-string")
    public void overloadString(@RequestParam("q") String q) throws Exception {
        String sql = typed.find(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/overload-int")
    public void overloadInt(@RequestParam("id") int id) throws Exception {
        String sql = repo.find(id);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/overload-object")
    public void overloadObject(@RequestParam("value") Object value) throws Exception {
        String sql = repo.find(value);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/unresolved-parent")
    public void unresolvedParent(@RequestParam("q") String q) throws Exception {
        String sql = external.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
    @GetMapping("/local-parent")
    public void localParent(@RequestParam("q") String q) throws Exception {
        String sql = local.build(q);
        Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 5 || len(report.Findings) != 5 {
		t.Fatalf("coverage: %+v findings=%+v", report.Coverage, report.Findings)
	}
	if report.Coverage.FindingsConfirmed != 3 || report.Coverage.FindingsInconclusive != 2 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}

	overloadString := findingFor(report, "/overload-string")
	if overloadString.Status != "static_confirmed" || overloadString.Sink == nil || !hasAnchor(overloadString, "fixture:overload-string") {
		t.Fatalf("string overload finding: %+v", overloadString)
	}

	overloadInt := findingFor(report, "/overload-int")
	if overloadInt.Status != "static_confirmed" || overloadInt.Sink == nil {
		t.Fatalf("int overload finding: %+v", overloadInt)
	}

	overloadObject := findingFor(report, "/overload-object")
	if overloadObject.Status != "inconclusive" || overloadObject.Boundary == nil || overloadObject.Boundary.Kind != "ambiguous_overload" {
		t.Fatalf("ambiguous overload finding: %+v", overloadObject)
	}

	unresolvedParent := findingFor(report, "/unresolved-parent")
	if unresolvedParent.Status != "inconclusive" || unresolvedParent.Boundary == nil || unresolvedParent.Boundary.Kind != "unresolved_parent" {
		t.Fatalf("unresolved parent finding: %+v", unresolvedParent)
	}

	localParent := findingFor(report, "/local-parent")
	if localParent.Status != "static_confirmed" || localParent.Sink == nil || !hasAnchor(localParent, "fixture:local-parent") {
		t.Fatalf("local parent finding: %+v", localParent)
	}

	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
}

func TestAnalyzeInjectionSinkCategories(t *testing.T) {
	snapshot := namedFixtureSnapshot(t, "java-injection-sinks")
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 12 || len(report.Findings) != 21 {
		t.Fatalf("coverage: %+v findings=%d", report.Coverage, len(report.Findings))
	}
	if report.Coverage.FindingsConfirmed != 8 || report.Coverage.FindingsInconclusive != 13 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}
	sqlFindings := 0
	for _, finding := range report.Findings {
		if finding.CWE == "CWE-89" {
			sqlFindings++
		}
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
		if finding.Status == "static_confirmed" && finding.Severity != "high" {
			t.Fatalf("confirmed severity: %+v", finding)
		}
	}
	if sqlFindings != 12 {
		t.Fatalf("sql findings: %d", sqlFindings)
	}

	command := findingForCWE(report, "/synthetic/inject/command", "CWE-78")
	if command == nil || command.Status != "static_confirmed" || command.Sink == nil || command.Sink.API != "Runtime.getRuntime().exec" {
		t.Fatalf("command finding: %+v", command)
	}
	if !hasFlowKind(command.Flow, "call") || !hasFlowKind(command.Flow, "command_sink") || !hasAnchor(*command, "fixture:command-exec") {
		t.Fatalf("command flow/evidence: %+v", command)
	}

	commandBuilder := findingForCWE(report, "/synthetic/inject/command-builder", "CWE-78")
	if commandBuilder == nil || commandBuilder.Status != "static_confirmed" || commandBuilder.Sink == nil || commandBuilder.Sink.API != "builder.start" {
		t.Fatalf("command builder finding: %+v", commandBuilder)
	}
	if !hasFlowKind(commandBuilder.Flow, "command_append") || !hasAnchor(*commandBuilder, "fixture:command-builder") {
		t.Fatalf("command builder flow/evidence: %+v", commandBuilder)
	}

	if constant := findingForCWE(report, "/synthetic/inject/command-constant", "CWE-78"); constant != nil {
		t.Fatalf("constant command must not be reported: %+v", constant)
	}

	commandDynamic := findingForCWE(report, "/synthetic/inject/command-dynamic", "CWE-78")
	if commandDynamic == nil || commandDynamic.Status != "inconclusive" || commandDynamic.Sink != nil ||
		commandDynamic.Boundary == nil || commandDynamic.Boundary.Kind != "unresolved_sink" {
		t.Fatalf("dynamic command finding: %+v", commandDynamic)
	}

	ssrf := findingForCWE(report, "/synthetic/inject/ssrf", "CWE-918")
	if ssrf == nil || ssrf.Status != "static_confirmed" || ssrf.Sink == nil || ssrf.Sink.API != "URL.openConnection" {
		t.Fatalf("ssrf finding: %+v", ssrf)
	}
	if !hasFlowKind(ssrf.Flow, "constructor") || !hasAnchor(*ssrf, "fixture:ssrf-url") {
		t.Fatalf("ssrf flow/evidence: %+v", ssrf)
	}

	ssrfRest := findingForCWE(report, "/synthetic/inject/ssrf-rest", "CWE-918")
	if ssrfRest == nil || ssrfRest.Status != "static_confirmed" || ssrfRest.Sink == nil || ssrfRest.Sink.API != "RestTemplate.getForObject" {
		t.Fatalf("rest ssrf finding: %+v", ssrfRest)
	}
	if constant := findingForCWE(report, "/synthetic/inject/ssrf-constant", "CWE-918"); constant != nil {
		t.Fatalf("constant ssrf must not be reported: %+v", constant)
	}

	path := findingForCWE(report, "/synthetic/inject/path", "CWE-22")
	if path == nil || path.Status != "static_confirmed" || path.Sink == nil || path.Sink.API != "new FileInputStream" {
		t.Fatalf("path finding: %+v", path)
	}
	if !hasFlowKind(path.Flow, "path_sink") || !hasAnchor(*path, "fixture:path-stream") {
		t.Fatalf("path flow/evidence: %+v", path)
	}

	pathFiles := findingForCWE(report, "/synthetic/inject/path-files", "CWE-22")
	if pathFiles == nil || pathFiles.Status != "static_confirmed" || pathFiles.Sink == nil || pathFiles.Sink.API != "Files.readAllBytes" {
		t.Fatalf("files path finding: %+v", pathFiles)
	}
	if constant := findingForCWE(report, "/synthetic/inject/path-constant", "CWE-22"); constant != nil {
		t.Fatalf("constant path must not be reported: %+v", constant)
	}

	template := findingForCWE(report, "/synthetic/inject/template", "CWE-1336")
	if template == nil || template.Status != "static_confirmed" || template.Sink == nil || template.Sink.API != "SpelExpressionParser.parseExpression" {
		t.Fatalf("template finding: %+v", template)
	}
	if !hasAnchor(*template, "fixture:template-spel") {
		t.Fatalf("template evidence: %+v", template)
	}

	templateEngine := findingForCWE(report, "/synthetic/inject/template-engine", "CWE-1336")
	if templateEngine == nil || templateEngine.Status != "static_confirmed" || templateEngine.Sink == nil || templateEngine.Sink.API != "SpringTemplateEngine.process" {
		t.Fatalf("template engine finding: %+v", templateEngine)
	}
}

func TestAnalyzeExtraSinkCategories(t *testing.T) {
	snapshot := namedFixtureSnapshot(t, "java-extra-sinks")
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 14 || len(report.Findings) != 24 {
		t.Fatalf("coverage: %+v findings=%d", report.Coverage, len(report.Findings))
	}
	if report.Coverage.FindingsConfirmed != 8 || report.Coverage.FindingsInconclusive != 16 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}
	sqlFindings := 0
	for _, finding := range report.Findings {
		if finding.CWE == "CWE-89" {
			sqlFindings++
		}
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
	if sqlFindings != 14 {
		t.Fatalf("sql findings: %d", sqlFindings)
	}

	xssChain := findingForCWE(report, "/synthetic/extra/xss-chain", "CWE-79")
	if xssChain == nil || xssChain.Status != "static_confirmed" || xssChain.Sink == nil || xssChain.Sink.API != "getWriter().write" {
		t.Fatalf("xss chain finding: %+v", xssChain)
	}
	if !hasFlowKind(xssChain.Flow, "xss_sink") || !hasAnchor(*xssChain, "fixture:xss-chain") {
		t.Fatalf("xss chain flow/evidence: %+v", xssChain)
	}

	xssWriter := findingForCWE(report, "/synthetic/extra/xss-writer", "CWE-79")
	if xssWriter == nil || xssWriter.Status != "static_confirmed" || xssWriter.Sink == nil || xssWriter.Sink.API != "PrintWriter.print" {
		t.Fatalf("xss writer finding: %+v", xssWriter)
	}
	if !hasAnchor(*xssWriter, "fixture:xss-writer") {
		t.Fatalf("xss writer evidence: %+v", xssWriter)
	}

	xssDynamic := findingForCWE(report, "/synthetic/extra/xss-dynamic", "CWE-79")
	if xssDynamic == nil || xssDynamic.Status != "inconclusive" || xssDynamic.Sink != nil ||
		xssDynamic.Boundary == nil || xssDynamic.Boundary.Kind != "unresolved_sink" {
		t.Fatalf("dynamic xss finding: %+v", xssDynamic)
	}

	if constant := findingForCWE(report, "/synthetic/extra/xss-constant", "CWE-79"); constant != nil {
		t.Fatalf("constant xss must not be reported: %+v", constant)
	}

	deserialization := findingForCWE(report, "/synthetic/extra/deserialization", "CWE-502")
	if deserialization == nil || deserialization.Status != "static_confirmed" || deserialization.Sink == nil || deserialization.Sink.API != "new ObjectInputStream" {
		t.Fatalf("deserialization finding: %+v", deserialization)
	}
	if !hasFlowKind(deserialization.Flow, "deserialization_sink") || !hasAnchor(*deserialization, "fixture:deserialization") {
		t.Fatalf("deserialization flow/evidence: %+v", deserialization)
	}

	xmlDecoder := findingForCWE(report, "/synthetic/extra/xml-decoder", "CWE-502")
	if xmlDecoder == nil || xmlDecoder.Status != "static_confirmed" || xmlDecoder.Sink == nil || xmlDecoder.Sink.API != "new XMLDecoder" {
		t.Fatalf("xml decoder finding: %+v", xmlDecoder)
	}

	if constant := findingForCWE(report, "/synthetic/extra/deserialization-constant", "CWE-502"); constant != nil {
		t.Fatalf("constant deserialization must not be reported: %+v", constant)
	}

	xxeDom := findingForCWE(report, "/synthetic/extra/xxe-dom", "CWE-611")
	if xxeDom == nil || xxeDom.Status != "static_confirmed" || xxeDom.Sink == nil || xxeDom.Sink.API != "DocumentBuilder.parse" {
		t.Fatalf("xxe dom finding: %+v", xxeDom)
	}
	if !hasFlowKind(xxeDom.Flow, "xxe_sink") || !hasAnchor(*xxeDom, "fixture:xxe-dom") {
		t.Fatalf("xxe dom flow/evidence: %+v", xxeDom)
	}

	xxeSax := findingForCWE(report, "/synthetic/extra/xxe-sax", "CWE-611")
	if xxeSax == nil || xxeSax.Status != "static_confirmed" || xxeSax.Sink == nil || xxeSax.Sink.API != "SAXParser.parse" {
		t.Fatalf("xxe sax finding: %+v", xxeSax)
	}

	xxeDynamic := findingForCWE(report, "/synthetic/extra/xxe-dynamic", "CWE-611")
	if xxeDynamic == nil || xxeDynamic.Status != "inconclusive" || xxeDynamic.Sink != nil ||
		xxeDynamic.Boundary == nil || xxeDynamic.Boundary.Kind != "unresolved_sink" {
		t.Fatalf("dynamic xxe finding: %+v", xxeDynamic)
	}

	if constant := findingForCWE(report, "/synthetic/extra/xxe-constant", "CWE-611"); constant != nil {
		t.Fatalf("constant xxe must not be reported: %+v", constant)
	}

	ldapSearch := findingForCWE(report, "/synthetic/extra/ldap-search", "CWE-90")
	if ldapSearch == nil || ldapSearch.Status != "static_confirmed" || ldapSearch.Sink == nil || ldapSearch.Sink.API != "InitialDirContext.search" {
		t.Fatalf("ldap search finding: %+v", ldapSearch)
	}
	if !hasFlowKind(ldapSearch.Flow, "ldap_sink") || !hasAnchor(*ldapSearch, "fixture:ldap-search") {
		t.Fatalf("ldap search flow/evidence: %+v", ldapSearch)
	}

	ldapLookup := findingForCWE(report, "/synthetic/extra/ldap-lookup", "CWE-90")
	if ldapLookup == nil || ldapLookup.Status != "static_confirmed" || ldapLookup.Sink == nil || ldapLookup.Sink.API != "LdapTemplate.lookup" {
		t.Fatalf("ldap lookup finding: %+v", ldapLookup)
	}

	if constant := findingForCWE(report, "/synthetic/extra/ldap-constant", "CWE-90"); constant != nil {
		t.Fatalf("constant ldap must not be reported: %+v", constant)
	}
}

func TestAnalyzeCollectionTaint(t *testing.T) {
	snapshot := namedFixtureSnapshot(t, "java-collections")
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.EndpointsAnalyzed != 8 || len(report.Findings) != 10 {
		t.Fatalf("coverage: %+v findings=%d", report.Coverage, len(report.Findings))
	}
	if report.Coverage.FindingsConfirmed != 4 || report.Coverage.FindingsInconclusive != 6 || report.Coverage.FindingsRefuted != 0 {
		t.Fatalf("status counts: %+v", report.Coverage)
	}
	sqlFindings := 0
	for _, finding := range report.Findings {
		if finding.CWE == "CWE-89" {
			sqlFindings++
		}
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime overclaim: %+v", finding)
		}
	}
	if sqlFindings != 8 {
		t.Fatalf("sql findings: %d", sqlFindings)
	}

	sqlList := findingForCWE(report, "/synthetic/collection/sql-list", "CWE-89")
	if sqlList == nil || sqlList.Status != "static_confirmed" || sqlList.Sink == nil || sqlList.Sink.API != "statement.executeQuery" {
		t.Fatalf("list collection sink: %+v", sqlList)
	}
	if !hasFlowKind(sqlList.Flow, "collection_add") || !hasFlowKind(sqlList.Flow, "collection_read") || !hasFlowKind(sqlList.Flow, "sink") {
		t.Fatalf("list collection flow: %+v", sqlList.Flow)
	}
	if !hasAnchor(*sqlList, "fixture:collection-sql-list") {
		t.Fatalf("list collection evidence: %+v", sqlList.Evidence)
	}

	sqlMap := findingForCWE(report, "/synthetic/collection/sql-map", "CWE-89")
	if sqlMap == nil || sqlMap.Status != "static_confirmed" || sqlMap.Sink == nil || sqlMap.Sink.API != "statement.executeQuery" {
		t.Fatalf("map collection sink: %+v", sqlMap)
	}
	if !hasFlowKind(sqlMap.Flow, "collection_add") || !hasFlowKind(sqlMap.Flow, "collection_read") || !hasAnchor(*sqlMap, "fixture:collection-sql-map") {
		t.Fatalf("map collection flow/evidence: %+v", sqlMap)
	}

	if constant := findingForCWE(report, "/synthetic/collection/sql-constant", "CWE-89"); constant == nil || constant.Status != "inconclusive" || constant.Sink != nil {
		t.Fatalf("constant collection negative control: %+v", constant)
	}

	command := findingForCWE(report, "/synthetic/collection/command-list", "CWE-78")
	if command == nil || command.Status != "static_confirmed" || command.Sink == nil || command.Sink.API != "Runtime.getRuntime().exec" {
		t.Fatalf("collection command sink: %+v", command)
	}
	if !hasFlowKind(command.Flow, "collection_add") || !hasFlowKind(command.Flow, "collection_read") || !hasFlowKind(command.Flow, "command_sink") {
		t.Fatalf("collection command flow: %+v", command.Flow)
	}
	if !hasAnchor(*command, "fixture:collection-command-list") {
		t.Fatalf("collection command evidence: %+v", command.Evidence)
	}
	commandSQL := findingForCWE(report, "/synthetic/collection/command-list", "CWE-89")
	if commandSQL == nil || commandSQL.Status != "inconclusive" || commandSQL.Boundary == nil || commandSQL.Boundary.Kind != "unresolved_call" {
		t.Fatalf("command list sql boundary: %+v", commandSQL)
	}

	if constantCommand := findingForCWE(report, "/synthetic/collection/command-constant", "CWE-78"); constantCommand != nil {
		t.Fatalf("constant command must not be reported: %+v", constantCommand)
	}

	xss := findingForCWE(report, "/synthetic/collection/xss-list", "CWE-79")
	if xss == nil || xss.Status != "static_confirmed" || xss.Sink == nil || xss.Sink.API != "PrintWriter.write" {
		t.Fatalf("collection xss sink: %+v", xss)
	}
	if !hasFlowKind(xss.Flow, "collection_read") || !hasFlowKind(xss.Flow, "xss_sink") || !hasAnchor(*xss, "fixture:collection-xss-list") {
		t.Fatalf("collection xss flow/evidence: %+v", xss)
	}

	dynamic := findingForCWE(report, "/synthetic/collection/dynamic", "CWE-89")
	if dynamic == nil || dynamic.Status != "inconclusive" || dynamic.Sink != nil {
		t.Fatalf("dynamic collection finding: %+v", dynamic)
	}
	if !containsString(dynamic.Limitations, "collection_dynamic") {
		t.Fatalf("dynamic collection limitation: %+v", dynamic.Limitations)
	}

	unknown := findingForCWE(report, "/synthetic/collection/unknown-receiver", "CWE-89")
	if unknown == nil || unknown.Status != "inconclusive" || unknown.Boundary == nil || unknown.Boundary.Kind != "unresolved_call" {
		t.Fatalf("unknown collection receiver: %+v", unknown)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func findingForCWE(report Report, path, cwe string) *Finding {
	for index := range report.Findings {
		if report.Findings[index].Endpoint.Path == path && report.Findings[index].CWE == cwe {
			return &report.Findings[index]
		}
	}
	return nil
}

func hasAnchor(finding Finding, anchor string) bool {
	for _, evidence := range finding.Evidence {
		if evidence.Anchor == anchor {
			return true
		}
	}
	return false
}

func findingsFor(report Report, path string) []Finding {
	var matches []Finding
	for _, finding := range report.Findings {
		if finding.Endpoint.Path == path {
			matches = append(matches, finding)
		}
	}
	return matches
}

func hasFlowKind(flow []FlowStep, kind string) bool {
	for _, step := range flow {
		if step.Kind == kind {
			return true
		}
	}
	return false
}

func TestHasFormatSpecifier(t *testing.T) {
	cases := []struct {
		literal string
		want    bool
	}{
		{`"SELECT %s"`, true},
		{`"percent 100%%"`, false},
		{`"LIKE '50%'"`, false},
		{`"a % 5"`, false},
		{`"%1$tm/%<te"`, true},
		{`"%-10.2f"`, true},
	}
	for _, item := range cases {
		if got := hasFormatSpecifier(item.literal); got != item.want {
			t.Fatalf("%s: got %v, want %v", item.literal, got, item.want)
		}
	}
}

func TestAnalyzeRejectsTextBlockSource(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
@RestController
public class App {
    private String sql = """
        SELECT 1
        """;
    @GetMapping("/x")
    public void x(@RequestParam("q") String q) throws Exception {
        statement.executeQuery(sql + q);
    }
}
`,
	})
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.Coverage.JavaFilesRejected != 1 || len(report.Findings) != 0 {
		t.Fatalf("text block handling: %+v", report)
	}
}
