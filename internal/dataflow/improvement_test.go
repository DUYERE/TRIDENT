package dataflow

import (
	"context"
	"strings"
	"testing"
)

// A ternary that carries the request value loses taint today: the assignment
// falls into the "expression shape not modelled" branch, records a limitation
// under a misleading name and never reaches the sink. This pins the fix.
func TestTernaryAssignmentPropagatesTaint(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
@RestController
public class App {
    private Connection connection;
    @GetMapping("/ternary")
    public void ternary(@RequestParam("q") String q) throws Exception {
        String chosen = (q == null) ? "SELECT 1" : q;
        Statement statement = connection.createStatement();
        statement.executeQuery(chosen);
    }
}
`,
	})
	report, err := AnalyzeWithOptions(context.Background(), snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	finding := findingFor(report, "/ternary")
	if finding.Status != "static_confirmed" || finding.Sink == nil {
		t.Fatalf("ternary taint never reached the sink: %+v (coverage=%+v)", finding, report.Coverage)
	}
}

// A file that uses a Java text block used to be rejected wholesale, taking
// every endpoint in it out of the analysis. The block content is still not
// analysed, but the file must stay analysable and the skip must be visible.
func TestTextBlockFileStaysAnalyzable(t *testing.T) {
	source := `package demo;
public class Demo {
    private String query = """
        SELECT * FROM t WHERE id = #{id}
        """;
    public void run() { }
}
`
	model, err := parseJavaFile("Demo.java", strings.Repeat("a", 64), []byte(source))
	if err != nil {
		t.Fatalf("text block file rejected: %v", err)
	}
	if len(model.Classes) != 1 {
		t.Fatalf("class lost after text block handling: %+v", model.Classes)
	}
	if len(model.Notes) != 1 || model.Notes[0] != "text_block_content_not_analyzed" {
		t.Fatalf("text block skip is not disclosed: %+v", model.Notes)
	}
	for _, token := range model.Tokens {
		if token.Text == "query" && token.Line != 3 {
			t.Fatalf("line numbers shifted by the text block rewrite: %+v", token)
		}
	}
}
