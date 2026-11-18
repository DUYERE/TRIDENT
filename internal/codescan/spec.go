package codescan

import (
	"path"
	"sort"
	"strings"
)

// languageSpec is a tokenizer configuration. Everything after tokenization is
// language-independent: the same statement IR, chain normalization, taint
// engine, rule matcher and report shape are used for every language.
type languageSpec struct {
	Name              string
	Extensions        []string
	LineComments      []string
	BlockComments     [][2]string
	StringDelimiters  []string
	TripleDelimiters  []string
	VerbatimPrefix    string
	SkipTags          []string
	MemberOps         []string
	NewlineStatements bool
	Braces            bool
	HashLineComments  bool
	Routes            []routeSpec
	// Interpolation selects which string literals embed runtime-evaluated
	// expressions. "" keeps every string opaque. "brace" extracts {expr}
	// (Python f-strings, C# interpolated strings), "dollar_brace" extracts
	// ${expr} (JS/TS template literals) and "php_dollar" extracts $var,
	// $var->member, $var[idx] and {$expr} inside double-quoted PHP strings.
	// Extracted tokens carry fromString and may only act as taint sources or
	// sanitizers, never as sinks, routes or parameter bindings.
	Interpolation string
}

// routeSpec is a declarative HTTP entry point shape. Path is normally the first
// string literal argument; non-literal paths are ignored instead of guessed,
// except for explicitly dynamic route calls such as ThinkPHP Route::rule.
type routeSpec struct {
	Kind    string // call | annotation
	Names   []string
	Method  string // fixed method, or "" to infer from the matched name
	Dynamic bool   // emit an explicit dynamic_unresolved route for a variable path
}

var (
	commonSanitizerOps = []string{"->", "::", "."}
	blockC             = [2]string{"/*", "*/"}
	razorC             = [2]string{"@*", "*@"}
)

func languageSpecs() []languageSpec {
	phpRoutes := []routeSpec{
		{Kind: "call", Names: []string{"Route::get", "Route::post", "Route::put", "Route::delete", "Route::patch", "Route::any", "$router->get", "$router->post"}},
		{Kind: "call", Names: []string{"Route::rule"}, Dynamic: true},
		{Kind: "annotation", Names: []string{"Route"}},
	}
	csharpRoutes := []routeSpec{
		{Kind: "annotation", Names: []string{"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "Route", "AcceptVerbs"}},
		{Kind: "call", Names: []string{"MapGet", "MapPost", "MapPut", "MapDelete", "MapControllerRoute", "UseEndpoints"}},
	}
	pythonRoutes := []routeSpec{
		{Kind: "annotation", Names: []string{"app.route", "router.route", "blueprint.route"}},
		{Kind: "call", Names: []string{"path", "re_path", "url"}},
	}
	jsRoutes := []routeSpec{
		{Kind: "call", Names: []string{"app.get", "app.post", "app.put", "app.delete", "app.patch", "app.all", "app.use", "router.get", "router.post", "router.put", "router.delete", "router.patch", "server.get"}},
		{Kind: "annotation", Names: []string{"Get", "Post", "Put", "Delete", "Patch", "Controller"}},
	}
	javaRoutes := []routeSpec{
		{Kind: "annotation", Names: []string{"RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "Path"}},
	}
	goRoutes := []routeSpec{
		{Kind: "call", Names: []string{"http.HandleFunc", "HandleFunc", "GET", "POST", "PUT", "DELETE", "Group", "r.GET", "r.POST"}},
	}

	php := languageSpec{
		Name: "php", Extensions: []string{".php", ".phtml", ".php5"},
		LineComments: []string{"//", "#"}, BlockComments: [][2]string{blockC},
		StringDelimiters: []string{"\"", "'"}, TripleDelimiters: nil,
		SkipTags:  []string{"<?php", "<?=", "<?", "?>"},
		MemberOps: commonSanitizerOps, Braces: true, HashLineComments: true,
		Routes: phpRoutes, Interpolation: "php_dollar",
	}
	csharp := languageSpec{
		Name: "csharp", Extensions: []string{".cs"},
		LineComments: []string{"//"}, BlockComments: [][2]string{blockC, razorC},
		StringDelimiters: []string{"\"", "'"}, VerbatimPrefix: "@",
		MemberOps: commonSanitizerOps, Braces: true,
		Routes: csharpRoutes, Interpolation: "brace",
	}
	python := languageSpec{
		Name: "python", Extensions: []string{".py", ".pyw"},
		LineComments: []string{"#"}, BlockComments: [][2]string{},
		StringDelimiters: []string{"\"", "'"}, TripleDelimiters: []string{"\"\"\"", "'''"},
		MemberOps: []string{"."}, NewlineStatements: true, HashLineComments: true,
		Routes: pythonRoutes, Interpolation: "brace",
	}
	javascript := languageSpec{
		Name: "javascript", Extensions: []string{".js", ".jsx", ".mjs", ".cjs"},
		LineComments: []string{"//"}, BlockComments: [][2]string{blockC},
		StringDelimiters: []string{"\"", "'", "`"},
		MemberOps:        []string{"."}, Braces: true,
		Routes: jsRoutes, Interpolation: "dollar_brace",
	}
	typescript := javascript
	typescript.Name = "typescript"
	typescript.Extensions = []string{".ts", ".tsx"}
	java := languageSpec{
		Name: "java", Extensions: []string{".java"},
		LineComments: []string{"//"}, BlockComments: [][2]string{blockC},
		StringDelimiters: []string{"\"", "'"},
		MemberOps:        []string{"."}, Braces: true,
		Routes: javaRoutes,
	}
	goLang := languageSpec{
		Name: "go", Extensions: []string{".go"},
		LineComments: []string{"//"}, BlockComments: [][2]string{blockC},
		StringDelimiters: []string{"\"", "'", "`"},
		MemberOps:        []string{"."}, Braces: true,
		Routes: goRoutes,
	}
	return []languageSpec{php, csharp, python, javascript, typescript, java, goLang}
}

// SupportsFile reports whether a snapshot file is owned by a language front
// end. It lets callers bound the extra analysis pass without duplicating the
// extension table.
func SupportsFile(file string) bool {
	_, ok := languageForFile(file, languageSpecs())
	return ok
}

func specFor(name string) (languageSpec, bool) {
	for _, spec := range languageSpecs() {
		if spec.Name == name {
			return spec, true
		}
	}
	return languageSpec{}, false
}

func supportedLanguageNames() []string {
	out := make([]string, 0, 8)
	for _, spec := range languageSpecs() {
		out = append(out, spec.Name)
	}
	sort.Strings(out)
	return out
}

// languageForFile returns the single owning language of a file. Extension
// ownership is disjoint, so a file belongs to at most one front end.
func languageForFile(file string, specs []languageSpec) (languageSpec, bool) {
	ext := strings.ToLower(path.Ext(file))
	for _, spec := range specs {
		for _, candidate := range spec.Extensions {
			if candidate == ext {
				return spec, true
			}
		}
	}
	return languageSpec{}, false
}

func inferHTTPMethod(name, fallback string) []string {
	if fallback != "" {
		return []string{fallback}
	}
	lower := strings.ToLower(name)
	for _, method := range []string{"Get", "Post", "Put", "Delete", "Patch", "Head", "Options"} {
		if strings.Contains(lower, strings.ToLower(method)) {
			return []string{strings.ToUpper(method)}
		}
	}
	return []string{}
}
