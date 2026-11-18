package dataflow

import (
	"context"
	"strings"
	"testing"

	"trident/internal/javaast"
)

// B1: the lexer-based resolver cannot choose between two same-named methods in
// one package. The restricted AST call graph can, and the taint engine must use
// that target when it is available.
func TestJavaASTHintResolvesAmbiguousCall(t *testing.T) {
	const source = `package demo;
class First { void save() {} }
class Second { void save() {} }
class Controller {
  void run() {
    save();
  }
}
`
	snapshot := snapshotFromFiles(t, map[string]string{"src/demo/Controller.java": source})
	files, _, _, err := parseProject(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	index := newProjectModel(files)
	line := 0
	for number, text := range strings.Split(source, "\n") {
		if strings.Contains(text, "save();") {
			line = number + 1
		}
	}
	if line == 0 {
		t.Fatal("fixture call line not found")
	}
	index.applyJavaAST(javaast.Model{Calls: []javaast.CallEdge{{
		File: "src/demo/Controller.java", Line: line, API: "save",
		Status: javaast.CallResolved, Target: "demo.First#save()",
	}}})
	resolved, ambiguous, reason := index.resolveCallWithAST(
		"src/demo/Controller.java", line, "", "demo", "save", nil)
	if resolved == nil || ambiguous != 0 {
		t.Fatalf("AST hint did not resolve: target=%v ambiguous=%d reason=%s", resolved, ambiguous, reason)
	}
	if resolved.Class == nil || resolved.Class.Name != "First" {
		t.Fatalf("resolved wrong AST target: %+v", resolved.Class)
	}
}

func TestJavaASTAnalysisIsAttachedToTaintIndex(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{"src/demo/App.java": `package demo;
class First { void save() {} }
class App {
  void run() {
    new First().save();
  }
}
`})
	model, err := javaast.Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	files, _, _, err := parseProject(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	index := newProjectModel(files)
	index.applyJavaAST(model)
	if len(index.astHints) == 0 {
		t.Fatal("AST call edges were not attached to the taint index")
	}
}
