package dataflow

import (
	"context"
	"encoding/json"
	"testing"
)

const mapperXMLSample = `<?xml version="1.0" encoding="UTF-8"?>
<mapper namespace="demo.UserMapper">
  <!-- #{} and ${} inside comments must not count -->
  <sql id="WhereClause">
    <if test="criterion.valid">and ${criterion.condition} #{criterion.value}</if>
  </sql>
  <select id="findByName" parameterType="String">
    SELECT * FROM users WHERE name = #{name}
  </select>
  <select id="orderBy" parameterType="String">
    SELECT * FROM users ORDER BY ${column}
  </select>
  <update id="rename" parameterType="map">
    UPDATE users SET name = #{name} WHERE id = #{id}
  </update>
</mapper>`

func TestParseMapperXMLAssessments(t *testing.T) {
	statements := parseMapperXML("mapper/UserMapper.xml", "sha256", mapperXMLSample)
	if len(statements) != 4 {
		t.Fatalf("expected 4 statements, got %d: %+v", len(statements), statements)
	}
	byID := map[string]OrmStatement{}
	for _, stmt := range statements {
		byID[stmt.ID] = stmt
	}
	cases := map[string]string{
		"WhereClause": "framework_fragment",
		"findByName":  "parameterized",
		"orderBy":     "substitution",
		"rename":      "parameterized",
	}
	for id, want := range cases {
		stmt, ok := byID[id]
		if !ok {
			t.Fatalf("missing statement %s", id)
		}
		if stmt.Assessment != want {
			t.Fatalf("%s assessment = %q, want %q", id, stmt.Assessment, want)
		}
		if stmt.File == "" || stmt.Line < 1 || stmt.SHA256 == "" {
			t.Fatalf("%s lacks pinned evidence: %+v", id, stmt)
		}
	}
	if byID["WhereClause"].SubstituteCount != 1 || byID["WhereClause"].BindCount != 1 {
		t.Fatal("comment text or nested tags were misparsed")
	}
}

func TestOrmIndexLookupAndAmbiguity(t *testing.T) {
	statements := []OrmStatement{
		{Namespace: "demo.UserMapper", ID: "findByName", Kind: "select", Assessment: "parameterized"},
		{Namespace: "demo.AdminMapper", ID: "findByName", Kind: "select", Assessment: "substitution"},
		{Namespace: "demo.OrderMapper", ID: "orderBy", Kind: "select", Assessment: "substitution"},
	}
	index := newOrmIndex(statements)
	if stmt, status := index.Lookup("", "orderBy"); status != "resolved" || stmt.Assessment != "substitution" {
		t.Fatalf("unique simple id not resolved: %v %+v", status, stmt)
	}
	if stmt, status := index.Lookup("UserMapper", "findByName"); status != "resolved" || stmt.Assessment != "parameterized" {
		t.Fatalf("receiver type did not disambiguate: %v %+v", status, stmt)
	}
	if _, status := index.Lookup("", "findByName"); status != "ambiguous" {
		t.Fatalf("ambiguous simple id should stay ambiguous, got %v", status)
	}
	if _, status := index.Lookup("", "missing"); status != "not_found" {
		t.Fatalf("unknown method should stay not_found, got %v", status)
	}
}

func TestDefaultEvidenceOnlyAndMyBatisEvidence(t *testing.T) {
	snapshot := namedFixtureSnapshot(t, "java-mybatis-sinks")
	ctx := context.Background()
	current, err := AnalyzeWithOptions(ctx, snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := AnalyzeWithOptions(ctx, snapshot, Options{EmitUnobserved: true})
	if err != nil {
		t.Fatal(err)
	}
	if current.AnalysisKind != "source_sink_multi_category_v2" || legacy.AnalysisKind != "source_sink_multi_category_v1" {
		t.Fatalf("analysis kinds not versioned: %q / %q", current.AnalysisKind, legacy.AnalysisKind)
	}
	if current.Coverage.UnobservedPaths == 0 || legacy.Coverage.UnobservedPaths != 0 {
		t.Fatalf("unobserved counting wrong: default=%d legacy=%d", current.Coverage.UnobservedPaths, legacy.Coverage.UnobservedPaths)
	}
	if current.Coverage.MyBatisStatements < 6 || current.Coverage.MyBatisRefuted != 1 || current.Coverage.MyBatisConfirmed != 1 {
		t.Fatalf("unexpected MyBatis coverage: %+v", current.Coverage)
	}
	for _, finding := range current.Findings {
		if finding.EvidenceStrength == "unobserved" {
			t.Fatalf("default report contains an unobserved finding: %+v", finding)
		}
	}
	hasParameterizedFinding := false
	for _, finding := range legacy.Findings {
		if finding.ID == "CWE-89:/users/find:name" {
			hasParameterizedFinding = true
			if finding.Status != "refuted" || finding.Orm == nil || finding.Orm.Assessment != "parameterized" {
				t.Fatalf("#{} binding was not refuted with ORM evidence: %+v", finding)
			}
		}
	}
	if !hasParameterizedFinding {
		t.Fatal("legacy mode lost the MyBatis refuted finding")
	}
	confirmed := false
	frameworkFragment := false
	for _, finding := range current.Findings {
		if finding.ID == "CWE-89:/users/order:column" {
			confirmed = finding.Status == "static_confirmed" && finding.Orm != nil &&
				finding.Orm.Assessment == "substitution" && finding.Sink != nil
		}
	}
	for _, stmt := range current.ORM.Statements {
		if stmt.Assessment == "framework_fragment" {
			frameworkFragment = true
		}
	}
	if !confirmed {
		t.Fatal("${} substitution was not confirmed with ORM evidence")
	}
	if !frameworkFragment {
		t.Fatal("framework-generated ${} fragment was not classified conservatively")
	}
	first, _ := json.Marshal(current)
	again, err := AnalyzeWithOptions(ctx, snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, _ := json.Marshal(again)
	if string(first) != string(second) {
		t.Fatal("dataflow report is not deterministic")
	}
}

func TestSinkAnchorsWithoutHTTP(t *testing.T) {
	snapshot := namedFixtureSnapshot(t, "java-mybatis-sinks")
	ctx := context.Background()
	report, err := InspectSinks(ctx, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.AnalysisKind != SinkAnchorKind || len(report.Anchors) < 2 {
		t.Fatalf("unexpected sink anchor report: %+v", report)
	}
	deserialization, command := false, false
	for _, anchor := range report.Anchors {
		if anchor.Status != "inconclusive" || anchor.RuntimeStatus != "not_run" {
			t.Fatalf("sink anchor overclaims status: %+v", anchor)
		}
		if anchor.File == "" || anchor.SHA256 == "" || anchor.Line < 1 {
			t.Fatalf("sink anchor lacks pinned evidence: %+v", anchor)
		}
		if anchor.API == "in.readObject" && anchor.Symbol == "OfflineJobs.main" {
			deserialization = true
		}
		if anchor.API == "exec" && anchor.Symbol == "OfflineJobs.scheduled" && anchor.ParameterReachable {
			command = true
		}
	}
	if !deserialization || !command {
		t.Fatalf("non-HTTP sinks were missed: deserialization=%v command=%v", deserialization, command)
	}
	first, _ := json.Marshal(report)
	again, err := InspectSinks(ctx, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := json.Marshal(again)
	if string(first) != string(second) {
		t.Fatal("sink anchor report is not deterministic")
	}
}

func TestLowNoiseKeepsLegacyFixtureEvidence(t *testing.T) {
	snapshot := fixtureSnapshot(t)
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 3 || report.Coverage.UnobservedPaths == 0 {
		t.Fatalf("java-maven evidence changed unexpectedly: %d findings, %d unobserved", len(report.Findings), report.Coverage.UnobservedPaths)
	}
	statuses := map[string]int{}
	for _, finding := range report.Findings {
		statuses[finding.Status]++
	}
	if statuses["static_confirmed"] != 1 || statuses["refuted"] != 1 || statuses["inconclusive"] != 1 {
		t.Fatalf("java-maven status distribution changed: %+v", statuses)
	}
}
