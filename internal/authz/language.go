package authz

import (
	"context"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"trident/internal/entrypoint"
	"trident/internal/project"
)

const (
	MaxLanguageFiles    = 4000
	MaxLanguageBytes    = 2 << 20
	MaxLanguageAdapters = 4000
)

type languagePattern struct {
	language    string
	framework   string
	control     string
	requirement string
	re          *regexp.Regexp
	public      bool
}

type languageRoutePattern struct {
	language string
	re       *regexp.Regexp
}

var languagePatterns = []languagePattern{
	{language: "php", framework: "thinkphp/laravel", control: "middleware_or_login_check", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(middleware|beforeAction|checkLogin|isLogin|Auth::|authorize|permission|login_required)`)},
	{language: "php", framework: "thinkphp/laravel", control: "public_action", requirement: RequirementPublic, re: regexp.MustCompile(`(?i)(allowAnonymous|noAuth|skipAuth|public\s+function\s+login)`), public: true},
	{language: "csharp", framework: "aspnet-core", control: "authorize_attribute", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(\[Authorize|RequireAuthorization|UseAuthentication|AddAuthorization)`)},
	{language: "csharp", framework: "aspnet-core", control: "allow_anonymous", requirement: RequirementPublic, re: regexp.MustCompile(`(?i)\[AllowAnonymous`), public: true},
	{language: "python", framework: "django/flask/fastapi", control: "login_or_permission_dependency", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(login_required|requires_auth|permission_required|before_request|LoginRequiredMixin|Depends\s*\(|is_authenticated)`)},
	{language: "python", framework: "django/flask/fastapi", control: "public_route", requirement: RequirementPublic, re: regexp.MustCompile(`(?i)(allow_anonymous|public_route|no_auth)`), public: true},
	{language: "javascript", framework: "express/koa/nest", control: "auth_middleware", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(requireAuth|isAuthenticated|passport\.authenticate|ensureLoggedIn|authMiddleware|jwt|roles|canActivate|UseGuards)`)},
	{language: "javascript", framework: "express/koa/nest", control: "public_route", requirement: RequirementPublic, re: regexp.MustCompile(`(?i)(allowAnonymous|publicRoute|noAuth)`), public: true},
	{language: "typescript", framework: "express/koa/nest", control: "auth_middleware", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(requireAuth|isAuthenticated|passport\.authenticate|ensureLoggedIn|authMiddleware|jwt|roles|canActivate|UseGuards)`)},
	{language: "typescript", framework: "express/koa/nest", control: "public_route", requirement: RequirementPublic, re: regexp.MustCompile(`(?i)(allowAnonymous|publicRoute|noAuth)`), public: true},
	{language: "go", framework: "gin/echo/net-http", control: "auth_middleware", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(RequireAuth|AuthMiddleware|JWTAuth|BasicAuth|AuthRequired|middleware)`), public: false},
	{language: "go", framework: "gin/echo/net-http", control: "public_handler", requirement: RequirementPublic, re: regexp.MustCompile(`(?i)(AllowAnonymous|PublicHandler|NoAuth)`), public: true},
}

var languageRoutePatterns = []languageRoutePattern{
	{language: "php", re: regexp.MustCompile(`(?i)(Route::|route\(|->rule\(|\$this->fetch)`)},
	{language: "csharp", re: regexp.MustCompile(`(?i)(\[(?:HttpGet|HttpPost|Route)|Map(?:Get|Post)|AddEndpoint|ControllerBase|ApiController)`)},
	{language: "python", re: regexp.MustCompile(`(?i)(@(?:app|router)\.(get|post|route)|urlpatterns|path\s*\(|add_url_rule)`)},
	{language: "javascript", re: regexp.MustCompile(`(?i)(router\.(get|post|put|delete)|app\.(get|post|put|delete)|@(Get|Post|Controller)|defineEventHandler)`)},
	{language: "typescript", re: regexp.MustCompile(`(?i)(router\.(get|post|put|delete)|app\.(get|post|put|delete)|@(Get|Post|Controller)|defineEventHandler)`)},
	{language: "go", re: regexp.MustCompile(`(?i)(HandleFunc|\.GET\s*\(|\.POST\s*\(|\.GET\(|\.POST\(|gin\.Context|echo\.Context)`)},
}

// phpScriptPattern is a line-level control observation for a PHP script that
// directly reads request data. It is intentionally narrower than a framework
// auth model: only controls observed before the request-access line count as
// protection for that line.
type phpScriptPattern struct {
	name        string
	requirement string
	re          *regexp.Regexp
}

var phpScriptGuardPatterns = []phpScriptPattern{
	{name: "permission_check", requirement: RequirementRole, re: regexp.MustCompile(`(?i)\b(?:isActionAccessible|hasAccess|checkPermission|canAccess|requirePermission)\s*\(`)},
	{name: "role_check", requirement: RequirementRole, re: regexp.MustCompile(`(?i)\b(?:hasRole|hasPermission|isAdmin|is_admin|authorize\s*\(|Gate::|permission\s*\(|can\s*\(|in_array\s*\([^)]*(?:admin|role|permission))`)},
	{name: "session_guard", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(?:if\s*\(\s*!\s*(?:isset|empty)\s*\(\s*\$_(?:SESSION|COOKIE)|if\s*\(\s*empty\s*\(\s*\$_(?:SESSION|COOKIE)|if\s*\(\s*!\s*\$_(?:SESSION|COOKIE))`)},
	{name: "auth_call", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)\b(?:checkLogin|isLoggedIn|is_logged_in|requireLogin|require_login|isAuthenticated|is_authenticated|is_user_logged_in|current_user_can)(?:\s*\()|(?:Auth::check|auth\(\)\s*->\s*check|->\s*checkLogin|->\s*isLoggedIn)`)},
	{name: "auth_file", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)\b(?:require|require_once|include|include_once)\b[^;\n]*(?:auth|login|session|guard|permission|security)[^;\n]*;`)},
	{name: "middleware", requirement: RequirementAuthenticated, re: regexp.MustCompile(`(?i)(?:->\s*middleware\s*\(\s*['"]auth|middleware\s*\(\s*['"]auth|beforeAction\s*\(\s*['"]?auth)`)},
}

var phpScriptPublicPatterns = []phpScriptPattern{
	{name: "explicit_public", requirement: RequirementPublic, re: regexp.MustCompile(`(?i)(?:allowAnonymous|allow_anonymous|noAuth|no_auth|skipAuth|skip_auth|public_action|@public\b|//\s*(?:public|anonymous)\b)`)},
}

type phpScriptMatch struct {
	name        string
	requirement string
	line        int
}

func phpScriptAdapter(file, content string) (LanguageAdapter, bool) {
	requestLine, ok := entrypoint.PHPRequestAccessLine([]byte(content))
	if !ok {
		return LanguageAdapter{}, false
	}
	before, at, after := phpScriptMatches(content, requestLine, phpScriptGuardPatterns)
	publicBefore, publicAt, publicAfter := phpScriptMatches(content, requestLine, phpScriptPublicPatterns)
	matches := append(append([]phpScriptMatch{}, before...), publicBefore...)
	control := "none"
	requirement := RequirementUnknown
	controlLine := 0
	decision := "unprotected"
	reason := "php_script_no_recognized_guard_before_request_access"
	if len(before) > 0 && len(publicBefore) > 0 {
		decision = "unknown"
		reason = "php_script_conflicting_controls"
	} else if len(publicBefore) > 0 {
		decision = "public"
		reason = "php_script_explicit_public_marker"
		control = publicBefore[0].name
		requirement = RequirementPublic
		controlLine = publicBefore[0].line
	} else if len(before) > 0 {
		decision = "protected"
		reason = "php_script_guard_before_request_access"
		control = before[0].name
		controlLine = before[0].line
		requirement = RequirementAuthenticated
		for _, match := range before {
			if match.requirement == RequirementRole {
				requirement = RequirementRole
			}
		}
	} else if len(at) > 0 || len(publicAt) > 0 {
		decision = "unknown"
		reason = "php_script_guard_at_request_line"
		matches = append(matches, at...)
		matches = append(matches, publicAt...)
	} else if len(after) > 0 || len(publicAfter) > 0 {
		decision = "unknown"
		reason = "php_script_guard_after_request_access"
		matches = append(matches, after...)
		matches = append(matches, publicAfter...)
	}
	if decision == "unknown" && reason == "php_script_guard_after_request_access" {
		controlLine = 0
		if len(after) > 0 {
			controlLine = after[0].line
		}
	}
	if decision == "unknown" && reason == "php_script_guard_at_request_line" {
		controlLine = requestLine
	}
	matched := make([]string, 0, len(matches))
	for _, match := range matches {
		matched = append(matched, match.name+"@"+strconv.Itoa(match.line))
	}
	sort.Strings(matched)
	return LanguageAdapter{
		Language: "php", Framework: frameworkFor("php", content),
		File: file, Line: requestLine, Scope: "request_script", ControlLine: controlLine,
		Symbol: "request_script", Control: control, Requirement: requirement,
		Decision: decision, Reason: reason, MatchedControls: matched,
	}, true
}

func phpScriptMatches(content string, requestLine int, patterns []phpScriptPattern) (before, at, after []phpScriptMatch) {
	for _, pattern := range patterns {
		for _, location := range pattern.re.FindAllStringIndex(content, -1) {
			line := 1 + strings.Count(content[:location[0]], "\n")
			match := phpScriptMatch{name: pattern.name, requirement: pattern.requirement, line: line}
			switch {
			case line < requestLine:
				before = append(before, match)
			case line == requestLine:
				at = append(at, match)
			default:
				after = append(after, match)
			}
		}
	}
	sort.SliceStable(before, func(i, j int) bool { return before[i].line < before[j].line })
	sort.SliceStable(at, func(i, j int) bool { return at[i].line < at[j].line })
	sort.SliceStable(after, func(i, j int) bool { return after[i].line < after[j].line })
	return before, at, after
}

func scanLanguageAdapters(ctx context.Context, snapshot *project.Snapshot) ([]LanguageAdapter, Coverage) {
	coverage := Coverage{}
	if snapshot == nil {
		return nil, coverage
	}
	var entries []project.FileEntry
	for _, entry := range snapshot.Manifest().Entries {
		language := languageForPath(entry.Path)
		if language == "" || language == "java" || isVendorPath(entry.Path) {
			continue
		}
		entries = append(entries, entry)
	}
	if len(entries) > MaxLanguageFiles {
		coverage.LanguageFilesRejected += len(entries) - MaxLanguageFiles
		entries = entries[:MaxLanguageFiles]
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	adapters := make([]LanguageAdapter, 0, 64)
	langStats := map[string]*Coverage{}
	phpClasses := make([]phpClassInfo, 0, 64)
	for _, entry := range entries {
		data, err := snapshot.ReadFile(ctx, entry.Path)
		if err != nil || len(data) == 0 || len(data) > MaxLanguageBytes {
			coverage.LanguageFilesRejected++
			continue
		}
		content := string(data)
		language := languageForPath(entry.Path)
		stats := langStats[language]
		if stats == nil {
			stats = &Coverage{}
			langStats[language] = stats
		}
		stats.LanguageFilesScanned++
		coverage.LanguageFilesScanned++
		found := false
		for _, rule := range languagePatterns {
			if rule.language != language {
				continue
			}
			location := rule.re.FindStringIndex(content)
			if location == nil {
				continue
			}
			found = true
			line := 1 + strings.Count(content[:location[0]], "\n")
			adapter := LanguageAdapter{
				Language: language, Framework: frameworkFor(language, content),
				File: entry.Path, Line: line, Scope: "file",
				Control:     rule.control,
				Requirement: rule.requirement, Decision: "protected", Reason: "recognized_control",
			}
			if rule.public {
				adapter.Decision = "public"
				adapter.Reason = "explicit_public_marker"
			}
			adapters = append(adapters, adapter)
			if len(adapters) >= MaxLanguageAdapters {
				coverage.LanguageFilesRejected++
				break
			}
		}
		if !found && languageHasRoute(language, content) {
			adapters = append(adapters, LanguageAdapter{
				Language: language, Framework: frameworkFor(language, content),
				File: entry.Path, Line: 1, Scope: "file", Control: "none", Requirement: RequirementUnknown,
				Decision: "unprotected", Reason: "route_without_recognized_control",
			})
		}
		if language == "php" {
			if adapter, ok := phpScriptAdapter(entry.Path, content); ok {
				if len(adapters) >= MaxLanguageAdapters {
					coverage.LanguageFilesRejected++
				} else {
					adapters = append(adapters, adapter)
				}
			}
			if adapter, ok := phpRouteAdapter(entry.Path, content); ok {
				if len(adapters) >= MaxLanguageAdapters {
					coverage.LanguageFilesRejected++
				} else {
					adapters = append(adapters, adapter)
				}
			}
			if info, ok := parsePHPClassInfo(entry.Path, content); ok {
				phpClasses = append(phpClasses, info)
			}
		}
	}
	for _, adapter := range phpControllerAdapters(phpClasses) {
		if len(adapters) >= MaxLanguageAdapters {
			coverage.LanguageFilesRejected++
			break
		}
		adapters = append(adapters, adapter)
	}
	for _, stats := range langStats {
		coverage.LanguageControls += stats.LanguageFilesScanned
	}
	coverage.LanguageDecisions = len(adapters)
	sort.Slice(adapters, func(i, j int) bool {
		if adapters[i].Language != adapters[j].Language {
			return adapters[i].Language < adapters[j].Language
		}
		if adapters[i].File != adapters[j].File {
			return adapters[i].File < adapters[j].File
		}
		return adapters[i].Line < adapters[j].Line
	})
	return adapters, coverage
}

func languageForPath(file string) string {
	switch strings.ToLower(path.Ext(file)) {
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".go":
		return "go"
	case ".java":
		return "java"
	default:
		return ""
	}
}

func isVendorPath(file string) bool {
	lower := "/" + strings.ToLower(strings.ReplaceAll(file, "\\", "/")) + "/"
	for _, segment := range []string{
		"/vendor/", "/node_modules/", "/dist/", "/bin/", "/obj/",
		"/static/", "/assets/", "/extend/", "/third_party/", "/thirdparty/",
		"/3rdparty/", "/tests/", "/docs/", "/examples/",
		"/thinkphp/", "/library/", "/libraries/",
	} {
		if strings.Contains(lower, segment) {
			return true
		}
	}
	return false
}

func frameworkFor(language, content string) string {
	lower := strings.ToLower(content)
	switch language {
	case "php":
		if strings.Contains(lower, "think") || strings.Contains(lower, "\\\\think") {
			return "thinkphp"
		}
		if strings.Contains(lower, "laravel") || strings.Contains(lower, "illuminate") {
			return "laravel"
		}
	case "python":
		if strings.Contains(lower, "django") || strings.Contains(lower, "urlpatterns") {
			return "django"
		}
		if strings.Contains(lower, "fastapi") {
			return "fastapi"
		}
		return "flask"
	case "javascript", "typescript":
		if strings.Contains(lower, "@nestjs") || strings.Contains(lower, "nest") {
			return "nest"
		}
		if strings.Contains(lower, "koa") {
			return "koa"
		}
		return "express"
	case "go":
		if strings.Contains(lower, "gin.") {
			return "gin"
		}
		if strings.Contains(lower, "echo.") {
			return "echo"
		}
	case "csharp":
		return "aspnet-core"
	}
	return ""
}

func languageHasRoute(language, content string) bool {
	for _, pattern := range languageRoutePatterns {
		if pattern.language == language && pattern.re.MatchString(content) {
			return true
		}
	}
	return false
}

type phpClassInfo struct {
	File       string
	Name       string
	Base       string
	Line       int
	Framework  string
	Guard      string
	GuardLine  int
	GuardIndex int
}

var phpClassDeclaration = regexp.MustCompile(`(?im)^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+extends\s+([A-Za-z_\\][A-Za-z0-9_\\]*))?`)

var phpControllerGuardPatterns = []struct {
	control string
	re      *regexp.Regexp
}{
	{control: "middleware_property", re: regexp.MustCompile(`(?is)\$\s*(?:middleware|middlewares)\s*=\s*(?:array\s*\(|\[)[^;]{0,500}(?:auth|login|permission|checklogin|role)`)},
	{control: "before_action_list", re: regexp.MustCompile(`(?is)\$\s*beforeActionList\s*=\s*(?:array\s*\(|\[)[^;]{0,500}(?:auth|login|permission|checklogin|role)`)},
	{control: "middleware_call", re: regexp.MustCompile(`(?is)->\s*middleware\s*\(\s*['"][^'"]*(?:auth|login|permission|role)`)},
	{control: "auth_call", re: regexp.MustCompile(`(?i)(?:Auth::check|checkLogin|isLoggedIn|isLogin|requireLogin)`)},
}

var phpRouteMiddlewarePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)->\s*middleware\s*\(\s*['"][^'"]*(?:auth|login|permission|role)`),
	regexp.MustCompile(`(?is)Route::\s*(?:group|rule|get|post|any)\s*\([^;]{0,500}(?:middleware|beforeAction)[^;]{0,500}(?:auth|login|permission|role)`),
}

// parsePHPClassInfo keeps bounded metadata for controller inheritance. It does
// not parse PHP; it records only the class name, base class and the first guard
// observed in the file.
func parsePHPClassInfo(file, content string) (phpClassInfo, bool) {
	matches := phpClassDeclaration.FindAllStringSubmatchIndex(content, -1)
	if len(matches) == 0 {
		return phpClassInfo{}, false
	}
	match := matches[0]
	if len(match) < 4 || match[2] < 0 {
		return phpClassInfo{}, false
	}
	name := content[match[2]:match[3]]
	base := ""
	if len(match) >= 6 && match[4] >= 0 {
		base = strings.TrimPrefix(strings.TrimSpace(content[match[4]:match[5]]), `\`)
		if index := strings.LastIndexAny(base, `\`); index >= 0 {
			base = base[index+1:]
		}
	}
	info := phpClassInfo{
		File: file, Name: name, Base: base,
		Line: 1 + strings.Count(content[:match[0]], "\n"), Framework: frameworkFor("php", content),
	}
	for _, pattern := range phpControllerGuardPatterns {
		location := pattern.re.FindStringIndex(content)
		if location == nil {
			continue
		}
		info.Guard = pattern.control
		info.GuardIndex = location[0]
		info.GuardLine = 1 + strings.Count(content[:location[0]], "\n")
		break
	}
	return info, true
}

func phpRouteAdapter(file, content string) (LanguageAdapter, bool) {
	for _, pattern := range phpRouteMiddlewarePatterns {
		location := pattern.FindStringIndex(content)
		if location == nil {
			continue
		}
		line := 1 + strings.Count(content[:location[0]], "\n")
		return LanguageAdapter{
			Language: "php", Framework: frameworkFor("php", content), File: file,
			Line: line, Scope: "route", ControlLine: line, Control: "route_middleware",
			Requirement: RequirementAuthenticated, Decision: "protected", Reason: "php_route_middleware",
		}, true
	}
	return LanguageAdapter{}, false
}

func phpControllerAdapters(classes []phpClassInfo) []LanguageAdapter {
	byName := map[string]phpClassInfo{}
	for _, class := range classes {
		if class.Name == "" {
			continue
		}
		if _, ok := byName[class.Name]; !ok {
			byName[class.Name] = class
		}
	}
	adapters := make([]LanguageAdapter, 0, len(classes))
	for _, class := range classes {
		adapter := LanguageAdapter{
			Language: "php", Framework: class.Framework, File: class.File,
			Line: class.Line, Scope: "controller", Symbol: class.Name,
			Requirement: RequirementAuthenticated, Decision: "protected",
		}
		if class.Guard != "" {
			adapter.Control = class.Guard
			adapter.ControlLine = class.GuardLine
			adapter.Reason = "php_controller_declared_auth"
			adapters = append(adapters, adapter)
			continue
		}
		base, depth := byName[class.Base], 0
		for base.Name != "" && depth < 8 {
			if base.Guard != "" {
				adapter.Control = "controller_base_middleware"
				adapter.ControlFile = base.File
				adapter.ControlLine = base.GuardLine
				adapter.Reason = "php_controller_inherited_auth"
				adapter.MatchedControls = []string{"base=" + base.Name + "." + base.Guard}
				adapters = append(adapters, adapter)
				break
			}
			if base.Base == "" || base.Base == base.Name {
				break
			}
			base, depth = byName[base.Base], depth+1
		}
	}
	return adapters
}
