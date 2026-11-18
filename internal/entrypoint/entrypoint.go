// Package entrypoint provides a bounded, read-only inventory of application
// entry files. It is deliberately filename-based: a detected file is evidence
// that a project has an application entry candidate, not proof that a route is
// deployed or reachable.
package entrypoint

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"trident/internal/project"
)

const (
	// SchemaVersion is the JSON schema version for Report.
	SchemaVersion = 1
	// MaxEntries bounds the candidate inventory. The scan stops after this many
	// entries and reports partial output.
	MaxEntries = 128
	// MaxCandidateBytes bounds content reads used only for framework evidence.
	MaxCandidateBytes = 1 << 20
)

var excludedSegments = map[string]struct{}{
	".git":          {},
	".next":         {},
	".nuxt":         {},
	"vendor":        {},
	"node_modules":  {},
	"tests":         {},
	"test":          {},
	"fixtures":      {},
	"examples":      {},
	"example":       {},
	"docs":          {},
	"doc":           {},
	"third_party":   {},
	"thirdparty":    {},
	"dist":          {},
	"build":         {},
	"target":        {},
	"obj":           {},
	"bin":           {},
	"packages":      {},
	"venv":          {},
	".venv":         {},
	"site-packages": {},
	"__pycache__":   {},
	"coverage":      {},
	"out":           {},
}

var phpInternalSegments = map[string]struct{}{
	"src":        {},
	"app":        {},
	"lib":        {},
	"libs":       {},
	"library":    {},
	"libraries":  {},
	"framework":  {},
	"system":     {},
	"core":       {},
	"config":     {},
	"routes":     {},
	"resources":  {},
	"storage":    {},
	"bootstrap":  {},
	"database":   {},
	"migrations": {},
	"extend":     {},
	"thinkphp":   {},
	"think":      {},
	"static":     {},
	"assets":     {},
	"includes":   {},
	"include":    {},
	"3rdparty":   {},
	"thirdparty": {},
}

var phpRequestMarkers = []string{
	"$_GET", "$_POST", "$_REQUEST", "$_FILES", "$_COOKIE",
	"php://input",
	`$_SERVER['REQUEST_METHOD']`, `$_SERVER["REQUEST_METHOD"]`,
	`$_SERVER['REQUEST_URI']`, `$_SERVER["REQUEST_URI"]`,
	`$_SERVER['QUERY_STRING']`, `$_SERVER["QUERY_STRING"]`,
	`$_SERVER['PATH_INFO']`, `$_SERVER["PATH_INFO"]`,
}

// Entry is one application entry candidate. It is not a route and has no
// authoritative URL.
type Entry struct {
	Language  string `json:"language"`
	Framework string `json:"framework,omitempty"`
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Line      int    `json:"line"`
	Reason    string `json:"reason"`
	SHA256    string `json:"sha256,omitempty"`
}

// Report is the deterministic result of an entrypoint scan.
type Report struct {
	SchemaVersion int      `json:"schema_version"`
	Entries       []Entry  `json:"entries"`
	Partial       bool     `json:"partial"`
	Limitations   []string `json:"limitations"`
}

type candidate struct {
	language  string
	framework string
	reason    string
	tokens    []string
}

// Inspect scans the pinned snapshot manifest and reads only recognized
// candidate files, within MaxCandidateBytes, to infer a framework label and
// evidence line. It never executes project code, invokes a build, or accesses
// the network.
func Inspect(ctx context.Context, snapshot *project.Snapshot) (Report, error) {
	if snapshot == nil {
		return Report{}, fmt.Errorf("entrypoint: nil snapshot")
	}
	if err := contextError(ctx); err != nil {
		return Report{}, err
	}
	manifest := snapshot.Manifest()
	report := Report{
		SchemaVersion: SchemaVersion,
		Entries:       []Entry{},
		Limitations: []string{
			"entrypoint_filename_heuristic",
			"entrypoint_candidate_not_deployed_route",
			"entrypoint_content_bounded_1mib",
			"php_request_script_candidate_not_route",
			"php_request_script_not_deployed",
			"php_request_script_content_bounded_1mib",
		},
	}
	seen := map[string]struct{}{}
	for _, file := range manifest.Entries {
		if len(report.Entries) >= MaxEntries {
			report.Partial = true
			report.Limitations = append(report.Limitations, "entrypoint_inventory_truncated")
			break
		}
		relative := normalize(file.Path)
		if relative == "" || excluded(relative) {
			continue
		}
		item, ok := classify(relative)
		if !ok {
			continue
		}
		seen[relative] = struct{}{}
		entry := Entry{
			Language:  item.language,
			Framework: item.framework,
			Path:      relative,
			Kind:      "application_entry",
			Line:      1,
			Reason:    item.reason,
			SHA256:    file.SHA256,
		}
		if file.Size <= MaxCandidateBytes {
			content, err := snapshot.ReadFile(ctx, relative)
			if err != nil {
				report.Partial = true
				report.Limitations = append(report.Limitations, "entrypoint_file_unreadable")
			} else {
				if framework := inferFramework(item.language, content); framework != "" {
					entry.Framework = framework
				}
				if line := evidenceLine(content, item.tokens); line > 0 {
					entry.Line = line
				}
			}
		} else {
			report.Partial = true
			report.Limitations = append(report.Limitations, "entrypoint_file_too_large")
		}
		report.Entries = append(report.Entries, entry)
	}
	if err := appendPHPRequestScripts(ctx, snapshot, &report, seen); err != nil {
		return Report{}, err
	}
	sort.Slice(report.Entries, func(i, j int) bool {
		if report.Entries[i].Language != report.Entries[j].Language {
			return report.Entries[i].Language < report.Entries[j].Language
		}
		if report.Entries[i].Path != report.Entries[j].Path {
			return report.Entries[i].Path < report.Entries[j].Path
		}
		return report.Entries[i].Kind < report.Entries[j].Kind
	})
	return report, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// appendPHPRequestScripts adds language-level candidates for plain PHP web
// scripts that read request data directly. This is deliberately independent of
// ThinkPHP/Laravel/etc. route declarations: a file-level candidate is evidence
// that a script can consume HTTP input, not proof that it is deployed at a URL.
func appendPHPRequestScripts(ctx context.Context, snapshot *project.Snapshot, report *Report, seen map[string]struct{}) error {
	for _, file := range snapshot.Manifest().Entries {
		if err := contextError(ctx); err != nil {
			return err
		}
		if len(report.Entries) >= MaxEntries {
			report.Partial = true
			addEntrypointLimitation(report, "entrypoint_inventory_truncated")
			return nil
		}
		relative := normalize(file.Path)
		if relative == "" || !phpRequestScriptPath(relative) {
			continue
		}
		if _, ok := seen[relative]; ok {
			continue
		}
		if file.Size > MaxCandidateBytes {
			report.Partial = true
			addEntrypointLimitation(report, "entrypoint_file_too_large")
			continue
		}
		content, err := snapshot.ReadFile(ctx, relative)
		if err != nil {
			report.Partial = true
			addEntrypointLimitation(report, "entrypoint_file_unreadable")
			continue
		}
		line, ok := phpRequestAccessLine(content)
		if !ok {
			continue
		}
		framework := inferFramework("php", content)
		if framework == "" {
			framework = "PHP"
		}
		report.Entries = append(report.Entries, Entry{
			Language: "php", Framework: framework, Path: relative,
			Kind: "request_script", Line: line, Reason: "php_request_superglobal_observed",
			SHA256: file.SHA256,
		})
		seen[relative] = struct{}{}
	}
	return nil
}

func addEntrypointLimitation(report *Report, limitation string) {
	for _, existing := range report.Limitations {
		if existing == limitation {
			return
		}
	}
	report.Limitations = append(report.Limitations, limitation)
}

func phpRequestScriptPath(relative string) bool {
	lower := strings.ToLower(relative)
	if !strings.HasSuffix(lower, ".php") && !strings.HasSuffix(lower, ".phtml") && !strings.HasSuffix(lower, ".php5") {
		return false
	}
	if excluded(relative) {
		return false
	}
	for _, segment := range strings.Split(lower, "/") {
		if _, ok := phpInternalSegments[segment]; ok {
			return false
		}
	}
	return true
}

func phpRequestAccessLine(content []byte) (int, bool) {
	for index, line := range strings.Split(string(content), "\n") {
		for _, marker := range phpRequestMarkers {
			if strings.Contains(line, marker) {
				return index + 1, true
			}
		}
	}
	return 0, false
}

// PHPRequestAccessLine exposes the same first-request-access line used by the
// entrypoint inventory. It is a lexical observation shared with the authz
// script pass so both capabilities bind to the same line.
func PHPRequestAccessLine(content []byte) (int, bool) {
	return phpRequestAccessLine(content)
}

func normalize(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	value = path.Clean(value)
	if value == "." || value == "" || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "/") {
		return ""
	}
	return value
}

func excluded(relative string) bool {
	for _, segment := range strings.Split(relative, "/") {
		if _, ok := excludedSegments[strings.ToLower(segment)]; ok {
			return true
		}
	}
	return false
}

func classify(relative string) (candidate, bool) {
	segments := strings.Split(relative, "/")
	base := strings.ToLower(segments[len(segments)-1])
	lower := strings.ToLower(relative)
	under := func(names ...string) bool {
		for _, name := range names {
			if strings.HasPrefix(lower, name+"/") || strings.Contains(lower, "/"+name+"/") {
				return true
			}
		}
		return false
	}
	first := ""
	if len(segments) > 1 {
		first = strings.ToLower(segments[0])
	}
	root := len(segments) == 1

	switch base {
	case "index.php":
		if root || first == "public" || first == "web" || first == "www" || first == "htdocs" {
			return candidate{language: "php", framework: "PHP", reason: "known_http_entry_filename", tokens: []string{"thinkphp/start.php", "think\\", "laravel", "symfony", "codeigniter"}}, true
		}
	case "router.php", "server.php":
		if root || first == "public" || first == "web" || first == "www" || first == "htdocs" {
			return candidate{language: "php", framework: "PHP built-in server router", reason: "known_http_entry_filename", tokens: []string{"PATH_INFO", "php -S", "request_uri"}}, true
		}
	case "program.cs", "startup.cs", "global.asax.cs":
		return candidate{language: "csharp", framework: ".NET", reason: "known_application_entry_filename", tokens: []string{"CreateBuilder", "Startup", "System.Web", "WebApplication"}}, true
	case "manage.py":
		return candidate{language: "python", framework: "Django", reason: "known_application_entry_filename", tokens: []string{"django", "DJANGO_SETTINGS_MODULE", "execute_from_command_line"}}, true
	case "wsgi.py", "asgi.py":
		return candidate{language: "python", framework: "WSGI/ASGI", reason: "known_application_entry_filename", tokens: []string{"get_wsgi_application", "get_asgi_application", "application"}}, true
	case "app.py", "main.py", "server.py":
		if root || under("src", "app", "server", "backend") {
			return candidate{language: "python", framework: "Python", reason: "known_application_entry_filename", tokens: []string{"Flask(", "from flask", "FastAPI(", "from fastapi", "aiohttp", "django"}}, true
		}
	case "server.js", "server.ts", "app.js", "app.ts", "main.js", "main.ts":
		if root || under("src", "server", "backend", "apps") {
			return candidate{language: languageForJS(base), framework: "Node.js", reason: "known_application_entry_filename", tokens: []string{"express", "NestFactory", "fastify", "koa", "http.createServer", "listen("}}, true
		}
	case "main.go":
		return candidate{language: "go", framework: "Go", reason: "known_application_entry_filename", tokens: []string{"gin.Default", "gin.New", "echo.New", "fiber.New", "http.ListenAndServe", "http.HandleFunc"}}, true
	case "application.java", "main.java":
		return candidate{language: "java", framework: "Java", reason: "known_application_entry_filename", tokens: []string{"SpringApplication", "@SpringBootApplication", "public static void main"}}, true
	}
	if strings.HasSuffix(base, "application.java") {
		return candidate{language: "java", framework: "Java", reason: "known_application_entry_filename", tokens: []string{"SpringApplication", "@SpringBootApplication"}}, true
	}
	return candidate{}, false
}

func languageForJS(base string) string {
	if strings.HasSuffix(base, ".ts") {
		return "typescript"
	}
	return "javascript"
}

func inferFramework(language string, content []byte) string {
	text := string(content)
	lower := strings.ToLower(text)
	switch language {
	case "php":
		switch {
		case strings.Contains(lower, "thinkphp/start.php"), strings.Contains(lower, "think\\"), strings.Contains(lower, "thinkphp"):
			return "ThinkPHP"
		case strings.Contains(lower, "laravel"), strings.Contains(lower, "illuminate\\"):
			return "Laravel"
		case strings.Contains(lower, "symfony\\"):
			return "Symfony"
		case strings.Contains(lower, "codeigniter\\"):
			return "CodeIgniter"
		}
	case "csharp":
		switch {
		case strings.Contains(text, "WebApplication.CreateBuilder"):
			return "ASP.NET Core"
		case strings.Contains(lower, "microsoft.aspnetcore"):
			return "ASP.NET Core"
		case strings.Contains(text, "System.Web"):
			return "ASP.NET MVC"
		}
	case "python":
		switch {
		case strings.Contains(text, "FastAPI("), strings.Contains(lower, "from fastapi"):
			return "FastAPI"
		case strings.Contains(text, "Flask("), strings.Contains(lower, "from flask"):
			return "Flask"
		case strings.Contains(lower, "django"):
			return "Django"
		case strings.Contains(lower, "aiohttp"):
			return "aiohttp"
		}
	case "javascript", "typescript":
		switch {
		case strings.Contains(lower, "nestjs"), strings.Contains(text, "NestFactory"):
			return "NestJS"
		case strings.Contains(lower, "express"):
			return "Express"
		case strings.Contains(lower, "fastify"):
			return "Fastify"
		case strings.Contains(lower, "koa"):
			return "Koa"
		case strings.Contains(lower, "http.createserver"):
			return "Node HTTP"
		}
	case "go":
		switch {
		case strings.Contains(text, "gin.Default"), strings.Contains(text, "gin.New"):
			return "Gin"
		case strings.Contains(text, "echo.New"):
			return "Echo"
		case strings.Contains(text, "fiber.New"):
			return "Fiber"
		case strings.Contains(text, "http.ListenAndServe"), strings.Contains(text, "http.HandleFunc"):
			return "net/http"
		}
	case "java":
		switch {
		case strings.Contains(text, "SpringApplication"), strings.Contains(text, "@SpringBootApplication"):
			return "Spring Boot"
		}
	}
	return ""
}

func evidenceLine(content []byte, tokens []string) int {
	if len(tokens) == 0 {
		return 0
	}
	lines := strings.Split(string(content), "\n")
	for index, line := range lines {
		lower := strings.ToLower(line)
		for _, token := range tokens {
			if token != "" && strings.Contains(lower, strings.ToLower(token)) {
				return index + 1
			}
		}
	}
	return 0
}
