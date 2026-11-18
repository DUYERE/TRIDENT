package reach

import (
	"testing"

	"trident/internal/sca"
)

func TestLanguageImportMatching(t *testing.T) {
	imports := []languageImport{
		{file: "app/controller/Home.php", line: 3, raw: `Monolog\Logger`},
		{file: "web/app.js", line: 2, raw: "express"},
		{file: "app/main.py", line: 1, raw: "requests"},
		{file: "api/main.go", line: 4, raw: "github.com/gin-gonic/gin"},
		{file: "dotnet/Home.cs", line: 2, raw: "Newtonsoft.Json"},
	}
	cases := []sca.Dependency{
		{Ecosystem: "composer", Name: "monolog/monolog"},
		{Ecosystem: "npm", Name: "express"},
		{Ecosystem: "pip", Name: "requests"},
		{Ecosystem: "go", Name: "github.com/gin-gonic/gin"},
		{Ecosystem: "nuget", Name: "Newtonsoft.Json"},
	}
	for _, dep := range cases {
		refs := matchLanguageImports(dep, imports)
		if len(refs) == 0 {
			t.Fatalf("no import matched for %+v", dep)
		}
	}
}

func TestLanguageEntryOnlyMarksBoundImportReachable(t *testing.T) {
	if languageForEcosystem("composer") != "php" || languageForEcosystem("pip") != "python" {
		t.Fatal("ecosystem-language mapping changed")
	}
	if !languageHasEntry("javascript", `router.get("/x", requireAuth)`) {
		t.Fatal("js entry pattern not recognized")
	}
}
