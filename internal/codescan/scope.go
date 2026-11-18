package codescan

import "strings"

// fileScope separates project-owned sources from third-party and generated
// artifacts. It is a display hint only: it does not change partial semantics.
func fileScope(path string) string {
	p := "/" + strings.TrimPrefix(strings.ToLower(strings.ReplaceAll(path, "\\", "/")), "/")
	switch {
	case strings.Contains(p, "/node_modules/"),
		strings.Contains(p, "/vendor/"),
		strings.Contains(p, "/vendors/"),
		strings.Contains(p, "/third_party/"),
		strings.Contains(p, "/third-party/"),
		strings.Contains(p, "/extend/phpexcel/"),
		strings.Contains(p, "/extend/phpmailer/"),
		strings.Contains(p, "/public/static/public/jquery/"),
		strings.Contains(p, "/public/static/public/layui/"),
		strings.Contains(p, "/public/static/public/ueditor/"):
		return "vendor"
	case strings.HasSuffix(p, ".min.js"),
		strings.HasSuffix(p, ".min.css"),
		strings.HasSuffix(p, ".bundle.js"),
		strings.Contains(p, "/dist/"):
		return "generated"
	default:
		return "project"
	}
}
