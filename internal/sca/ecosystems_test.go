package sca

import "testing"

func TestNPMLockResolvesDeclaredRange(t *testing.T) {
	manifest := ecosystemManifest{path: "package.json", ecosystem: "npm", kind: "npm_manifest"}
	lock := ecosystemManifest{path: "package-lock.json", ecosystem: "npm", kind: "npm_lock"}
	exact := map[string]string{}
	loadLockVersions(lock, []byte(`{"packages":{"node_modules/express":{"version":"4.18.2"}}}`), exact)
	deps, reason := parseEcosystemManifest(manifest, []byte(`{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29.0.0"}}`), exact)
	if reason != "" || len(deps) != 2 {
		t.Fatalf("deps=%+v reason=%q", deps, reason)
	}
	if deps[0].Version != "4.18.2" || deps[0].VersionStatus != "resolved" || deps[0].Ecosystem != "npm" {
		t.Fatalf("express = %+v", deps[0])
	}
	if deps[1].Scope != "dev" || deps[1].VersionStatus != "range" {
		t.Fatalf("jest = %+v", deps[1])
	}
}

func TestComposerNuGetPipGoManifests(t *testing.T) {
	composer := ecosystemManifest{path: "composer.json", ecosystem: "composer", kind: "composer_manifest"}
	composerDeps, _ := parseEcosystemManifest(composer, []byte(`{"require":{"monolog/monolog":"^2.0","php":">=7.4"},"require-dev":{"phpunit/phpunit":"^9.0"}}`), map[string]string{})
	if len(composerDeps) != 2 || composerDeps[0].GroupID != "monolog" || composerDeps[0].ArtifactID != "monolog" {
		t.Fatalf("composer = %+v", composerDeps)
	}

	nuget := ecosystemManifest{path: "App.csproj", ecosystem: "nuget", kind: "nuget_project"}
	nugetDeps, _ := parseEcosystemManifest(nuget, []byte(`<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`), map[string]string{})
	if len(nugetDeps) != 1 || nugetDeps[0].Name != "Newtonsoft.Json" || nugetDeps[0].Version != "13.0.3" {
		t.Fatalf("nuget = %+v", nugetDeps)
	}

	pip := ecosystemManifest{path: "requirements.txt", ecosystem: "pip", kind: "pip_requirements"}
	pipDeps, _ := parseEcosystemManifest(pip, []byte("requests==2.31.0\nflask>=2.0\n"), map[string]string{})
	if len(pipDeps) != 2 || pipDeps[0].VersionStatus != "resolved" || pipDeps[1].VersionStatus != "range" {
		t.Fatalf("pip = %+v", pipDeps)
	}

	goFile := ecosystemManifest{path: "go.mod", ecosystem: "go", kind: "go_mod"}
	goDeps, _ := parseEcosystemManifest(goFile, []byte("module example\nrequire (\n github.com/gin-gonic/gin v1.9.1\n)\n"), map[string]string{})
	if len(goDeps) != 1 || goDeps[0].Version != "1.9.1" || goDeps[0].ArtifactID != "gin" {
		t.Fatalf("go = %+v", goDeps)
	}
}
