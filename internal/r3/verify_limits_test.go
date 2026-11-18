package r3

import (
	"strings"
	"testing"
)

func TestProfileLimitationsCoverLanguageProfiles(t *testing.T) {
	cases := map[string]string{
		"php-lint":       "php_lint_syntax_only",
		"python-compile": "python_compile_syntax_only",
		"pytest":         "pytest_requires_project_dependencies",
		"node-check":     "node_check_syntax_only",
		"npm-test":       "npm_test_requires_project_runner",
		"go-test":        "go_test_requires_module",
		"dotnet-build":   "dotnet_build_compiles_only",
		"dotnet-test":    "dotnet_test_requires_project_runner",
	}
	for profile, want := range cases {
		got := strings.Join(profileLimitations(profile), " ")
		if !strings.Contains(got, want) {
			t.Fatalf("%s missing %s: %v", profile, want, got)
		}
	}
	if len(profileLimitations("maven")) != 0 {
		t.Fatalf("maven must not gain language-profile limitations")
	}
}
