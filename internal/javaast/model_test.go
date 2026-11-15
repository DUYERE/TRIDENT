package javaast

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"trident/internal/project"
)

func fixtureSnapshot(t *testing.T) *project.Snapshot {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "java-ast-model"))
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

func TestAnalyzeSemanticModel(t *testing.T) {
	snapshot := fixtureSnapshot(t)
	report, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.Coverage.FilesScanned != 5 || report.Coverage.FilesRejected != 1 {
		t.Fatalf("unexpected file coverage: %+v partial=%v", report.Coverage, report.Partial)
	}
	broken := findFile(t, report, "src/main/java/com/example/model/Broken.java")
	if broken.ParseError == "" {
		t.Fatal("malformed file must record a parse error")
	}
	if len(broken.Boundaries) != 1 || broken.Boundaries[0] != "rejected_java_file" {
		t.Fatalf("unexpected rejected boundaries: %+v", broken.Boundaries)
	}

	nested := findType(t, report, "com.example.model.Outer.Inner")
	if nested.Kind != "class" || len(nested.Methods) != 1 || nested.Methods[0].Name != "describe" {
		t.Fatalf("nested class not indexed: %+v", nested)
	}
	outer := findType(t, report, "com.example.model.Outer")
	if len(outer.Nested) != 1 || outer.Nested[0] != "com.example.model.Outer.Inner" {
		t.Fatalf("outer nested reference mismatch: %+v", outer.Nested)
	}

	overloads := callsByAPI(report, "pick")
	if len(overloads) != 2 {
		t.Fatalf("expected two overload resolutions, got %+v", overloads)
	}
	if overloads[0].Target != "com.example.model.Overloads#pick(java.lang.String)" ||
		overloads[1].Target != "com.example.model.Overloads#pick(java.util.List)" {
		t.Fatalf("generic erasure overload resolution mismatch: %+v", overloads)
	}
	label := callsByAPI(report, "label")
	if len(label) != 1 || label[0].Status != CallResolved ||
		label[0].Target != "com.example.model.Outer#label()" {
		t.Fatalf("enclosing-class call not resolved: %+v", label)
	}
	save := callsByAPI(report, "save")
	if len(save) != 1 || save[0].Status != CallResolved ||
		save[0].Target != "com.example.model.JdbcStore#save(java.lang.String)" ||
		save[0].Reason != "interface_dispatch" {
		t.Fatalf("interface dispatch mismatch: %+v", save)
	}
	handle := callsByAPI(report, "handle")
	if len(handle) != 1 || handle[0].Status != CallAmbiguous || handle[0].Reason != "ambiguous_dispatch" {
		t.Fatalf("ambiguous dispatch mismatch: %+v", handle)
	}

	annotated := findType(t, report, "com.example.model.Annotated")
	route := annotationByName(t, annotated.Methods[0], "Route")
	if len(route.Args) != 2 || route.Args[0].Value.Kind != "string" || route.Args[0].Value.Text != "api/items" {
		t.Fatalf("annotation constant folding mismatch: %+v", route.Args)
	}
	if len(route.Args[1].Value.Elements) != 2 || route.Args[1].Value.Elements[0].Text != "api" {
		t.Fatalf("annotation array folding mismatch: %+v", route.Args[1].Value)
	}
	access := annotationByName(t, annotated.Methods[1], "Access")
	if len(access.Args) != 1 || access.Args[0].Value.Kind != "name" ||
		access.Args[0].Value.Text != "com.example.model.Role.ADMIN" {
		t.Fatalf("enum annotation constant mismatch: %+v", access.Args)
	}

	if report.Coverage.CallsResolved != 4 || report.Coverage.CallsAmbiguous != 1 ||
		report.Coverage.CallsUnresolved != 0 || report.Coverage.InterfaceDispatch != 1 {
		t.Fatalf("call coverage mismatch: %+v", report.Coverage)
	}
	if report.Coverage.AnnotationsIndexed != 2 || report.Coverage.ConstantsFolded != 1 {
		t.Fatalf("folding coverage mismatch: %+v", report.Coverage)
	}
	if report.Coverage.RuntimeStatus != "not_run" {
		t.Fatalf("runtime status must stay not_run: %+v", report.Coverage)
	}

	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(repeated)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("semantic model output is not deterministic")
	}
}

func findFile(t *testing.T, report Model, path string) FileInfo {
	t.Helper()
	for _, item := range report.Files {
		if item.Path == path {
			return item
		}
	}
	t.Fatalf("file %s not found", path)
	return FileInfo{}
}

func findType(t *testing.T, report Model, fqn string) TypeInfo {
	t.Helper()
	for _, item := range report.Types {
		if item.FQN == fqn {
			return item
		}
	}
	t.Fatalf("type %s not found", fqn)
	return TypeInfo{}
}

func callsByAPI(report Model, api string) []CallEdge {
	var out []CallEdge
	for _, edge := range report.Calls {
		if edge.API == api {
			out = append(out, edge)
		}
	}
	return out
}

func annotationByName(t *testing.T, method MethodInfo, name string) Annotation {
	t.Helper()
	for _, item := range method.Annotations {
		if item.Name == name {
			return item
		}
	}
	t.Fatalf("annotation %s not found on %s", name, method.Name)
	return Annotation{}
}

// TestUnbalancedAngleBracketsTerminate guards the scanner against a hang: a
// comparison operator inside a method body looks like an unclosed generic
// argument list, and a non-advancing skipAngles used to loop forever on real
// projects.
func TestUnbalancedAngleBracketsTerminate(t *testing.T) {
	source := `package demo;

public class Compare {
    public boolean less(int a, int b) {
        return a < b;
    }

    public boolean both(int a, int b, int c) {
        return a < b && b < c;
    }
}
`
	unit, err := ParseFile("Compare.java", "sha", []byte(source))
	if err != nil {
		t.Fatalf("comparison operators must not fail the parse: %v", err)
	}
	if len(unit.Types) != 1 || len(unit.Types[0].Methods) != 2 {
		t.Fatalf("unexpected declarations: %+v", unit.Types)
	}
}

func TestSkipAnglesAlwaysAdvances(t *testing.T) {
	tokens := []token{{text: "<"}, {text: "a"}, {text: "+"}, {text: "b"}}
	if next := skipAngles(tokens, 0); next <= 0 {
		t.Fatalf("unbalanced group must advance, got %d", next)
	}
	balanced := []token{{text: "<"}, {text: "String"}, {text: ">"}, {text: "x"}}
	if next := skipAngles(balanced, 0); next != 3 {
		t.Fatalf("balanced group must end after '>', got %d", next)
	}
}
