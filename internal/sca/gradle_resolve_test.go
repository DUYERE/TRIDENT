package sca

import (
	"strings"
	"testing"
)

func TestParseGradleDependencyReportSelectsRuntimeClasspath(t *testing.T) {
	output := `------------------------------------------------------------
Project ':jdbc-app'
------------------------------------------------------------

annotationProcessor - Annotation processors and their dependencies for source set 'main'.
No dependencies

compileClasspath - Compile classpath for source set 'main'.
+--- org.apache.commons:commons-text:1.9
|    \--- org.apache.commons:commons-lang3:3.11

runtimeClasspath - Runtime classpath of source set 'main'.
+--- project :common
+--- org.apache.commons:commons-text:1.9
|    \--- org.apache.commons:commons-lang3:3.11
\--- junit:junit:4.12
     \--- org.hamcrest:hamcrest-core:1.3

testRuntimeClasspath - Runtime classpath of source set 'test'.
\--- junit:junit:4.12
`
	report := parseGradleDependencyReport(output)
	dependencies, configurations, ok := report.selected()
	if !ok {
		t.Fatal("runtimeClasspath report was not selected")
	}
	if len(configurations) != 1 || configurations[0] != "runtimeClasspath" {
		t.Fatalf("selected configurations: %v", configurations)
	}
	if len(dependencies) != 5 {
		t.Fatalf("dependencies: %+v", dependencies)
	}
	byArtifact := map[string]EffectiveDependency{}
	for _, dependency := range dependencies {
		byArtifact[dependency.ArtifactID] = dependency
	}
	if project := byArtifact[":common"]; project.Type != "project" || project.Depth != 1 || !project.Direct {
		t.Fatalf("project dependency: %+v", project)
	}
	if hamcrest := byArtifact["hamcrest-core"]; hamcrest.Depth != 2 || hamcrest.Direct {
		t.Fatalf("transitive dependency: %+v", hamcrest)
	}
	if text := byArtifact["commons-text"]; text.Version != "1.9" || text.Scope != "runtimeClasspath" || !text.Direct {
		t.Fatalf("direct dependency: %+v", text)
	}
}

func TestParseGradleDependencyReportMarkers(t *testing.T) {
	output := `runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.foo:bar:1.0 -> 1.2
|    \--- org.foo:baz:2.0 (*)
+--- org.foo:qux:3.0 (c)
\--- org.foo:missing:1.0 FAILED
`
	report := parseGradleDependencyReport(output)
	dependencies, _, ok := report.selected()
	if !ok || len(dependencies) != 4 {
		t.Fatalf("dependencies: %+v", dependencies)
	}
	byArtifact := map[string]EffectiveDependency{}
	for _, dependency := range dependencies {
		byArtifact[dependency.ArtifactID] = dependency
	}
	if bar := byArtifact["bar"]; bar.Version != "1.2" || !strings.Contains(bar.Note, "requested 1.0") {
		t.Fatalf("version conflict: %+v", bar)
	}
	if baz := byArtifact["baz"]; !baz.Omitted || baz.Depth != 2 {
		t.Fatalf("omitted marker: %+v", baz)
	}
	if qux := byArtifact["qux"]; !strings.Contains(qux.Note, "constraint") {
		t.Fatalf("constraint marker: %+v", qux)
	}
	if missing := byArtifact["missing"]; !missing.Failed || !strings.Contains(missing.Note, "FAILED") {
		t.Fatalf("failed marker: %+v", missing)
	}
}

func TestParseGradleDependencyReportFallsBackToCompileClasspath(t *testing.T) {
	output := `compileClasspath - Compile classpath for source set 'main'.
\--- a:b:1.0
`
	report := parseGradleDependencyReport(output)
	dependencies, configurations, ok := report.selected()
	if !ok || len(configurations) != 1 || configurations[0] != "compileClasspath" {
		t.Fatalf("compile fallback: %v %v", configurations, ok)
	}
	if len(dependencies) != 1 || dependencies[0].Version != "1.0" {
		t.Fatalf("dependencies: %+v", dependencies)
	}
}

func TestParseGradleDependencyReportEmptyAndMissingConfigurations(t *testing.T) {
	empty := parseGradleDependencyReport("runtimeClasspath - Runtime classpath of source set 'main'.\nNo dependencies\n")
	dependencies, _, ok := empty.selected()
	if !ok || len(dependencies) != 0 {
		t.Fatalf("empty runtime classpath: %+v %v", dependencies, ok)
	}
	missing := parseGradleDependencyReport("No configurations\n")
	_, _, ok = missing.selected()
	if ok {
		t.Fatal("no configurations reported as selected")
	}
}

func TestParseGradleDependencyReportDepth(t *testing.T) {
	output := `runtimeClasspath - Runtime classpath of source set 'main'.
+--- a:one:1.0
|    +--- a:two:1.0
|    |    \--- a:three:1.0
|    \--- a:four:1.0
\--- a:five:1.0
`
	dependencies, _, _ := parseGradleDependencyReport(output).selected()
	depths := map[string]int{}
	for _, dependency := range dependencies {
		depths[dependency.ArtifactID] = dependency.Depth
	}
	want := map[string]int{"one": 1, "two": 2, "three": 3, "four": 2, "five": 1}
	for artifact, depth := range want {
		if depths[artifact] != depth {
			t.Fatalf("%s depth = %d, want %d (all: %v)", artifact, depths[artifact], depth, depths)
		}
	}
}
