package sca

import (
	"strings"
	"testing"
)

func TestParseMavenEffectiveTree(t *testing.T) {
	output := `[INFO] Scanning for projects...
[INFO] Building java-fixture-parent 1.0.0
[INFO] example.synthetic.trident:java-fixture-parent:pom:1.0.0
[INFO] +- org.apache.commons:commons-text:jar:1.9:compile
[INFO] |  \- org.apache.commons:commons-lang3:jar:3.11:compile
[INFO] \- org.junit.jupiter:junit-jupiter:jar:5.11.4:test
[INFO]    \- org.junit.platform:junit-platform-engine:jar:1.11.4:test
[INFO] Building jdbc-app 1.0.0
[INFO] example.synthetic.trident:jdbc-app:jar:1.0.0
[INFO] +- org.apache.commons:commons-text:jar:1.9:compile (version managed from 1.10.0)
[INFO] \- com.h2database:h2:jar:2.3.232:test (optional)
`
	modules := parseMavenTree(output)
	if len(modules) != 2 {
		t.Fatalf("modules: %+v", modules)
	}
	if modules[0].GroupID != "example.synthetic.trident" || modules[0].ArtifactID != "java-fixture-parent" || modules[0].Version != "1.0.0" {
		t.Fatalf("root module: %+v", modules[0])
	}
	dependencies := map[string]EffectiveDependency{}
	for _, module := range modules {
		for _, dependency := range module.Dependencies {
			dependencies[dependency.ArtifactID] = dependency
		}
	}
	if dependencies["commons-text"].Depth != 1 || !dependencies["commons-text"].Direct || dependencies["commons-text"].Scope != "compile" {
		t.Fatalf("direct dependency: %+v", dependencies["commons-text"])
	}
	if dependencies["commons-lang3"].Depth != 2 || dependencies["commons-lang3"].Direct {
		t.Fatalf("transitive dependency: %+v", dependencies["commons-lang3"])
	}
	if dependencies["junit-platform-engine"].Depth != 2 || !strings.Contains(dependencies["h2"].Note, "optional") {
		t.Fatalf("scope/notes: %+v", dependencies)
	}
}

func TestSplitCoordinateWithClassifier(t *testing.T) {
	coordinate, ok := splitCoordinate("g:a:jar:sources:1.2.3:runtime", true)
	if !ok || coordinate.Version != "1.2.3" || coordinate.Scope != "runtime" || coordinate.Classifier != "sources" {
		t.Fatalf("classifier coordinate: %+v", coordinate)
	}
}
