package sbom

import (
	"testing"

	"trident/internal/sca"
)

func TestEcosystemPURLs(t *testing.T) {
	cases := []struct {
		dep  sca.Dependency
		want string
	}{
		{sca.Dependency{Ecosystem: "npm", Name: "express", ArtifactID: "express", Version: "4.18.2"}, "pkg:npm/express@4.18.2"},
		{sca.Dependency{Ecosystem: "npm", Name: "@scope/pkg", GroupID: "@scope", ArtifactID: "pkg", Version: "1.0.0"}, "pkg:npm/%40scope/pkg@1.0.0"},
		{sca.Dependency{Ecosystem: "composer", GroupID: "monolog", ArtifactID: "monolog", Name: "monolog/monolog", Version: "2.9.1"}, "pkg:composer/monolog/monolog@2.9.1"},
		{sca.Dependency{Ecosystem: "nuget", ArtifactID: "Newtonsoft.Json", Name: "Newtonsoft.Json", Version: "13.0.3"}, "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{sca.Dependency{Ecosystem: "pip", ArtifactID: "Requests", Name: "Requests", Version: "2.31.0"}, "pkg:pypi/requests@2.31.0"},
		{sca.Dependency{Ecosystem: "go", GroupID: "github.com/gin-gonic", ArtifactID: "gin", Name: "github.com/gin-gonic/gin", Version: "1.9.1"}, "pkg:golang/github.com/gin-gonic/gin@1.9.1"},
	}
	for _, item := range cases {
		if got := purl(item.dep); got != item.want {
			t.Fatalf("purl(%+v) = %q, want %q", item.dep, got, item.want)
		}
	}
}
