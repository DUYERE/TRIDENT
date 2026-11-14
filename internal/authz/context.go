package authz

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"trident/internal/audit"
	"trident/internal/project"
)

var (
	propertiesContextPath = regexp.MustCompile(`(?m)^\s*server\.servlet\.context-path\s*[=:]\s*(\S+)`)
	yamlContextPath       = regexp.MustCompile(`(?m)^\s{0,8}context-path\s*:\s*(\S+)`)
	xmlContextParamBlock  = regexp.MustCompile(`(?s)<context-param\b[^>]*>(.*?)</context-param>`)
	xmlParamName          = regexp.MustCompile(`(?s)<param-name>\s*([^<]+?)\s*</param-name>`)
	xmlParamValue         = regexp.MustCompile(`(?s)<param-value>\s*([^<]*?)\s*</param-value>`)
	xmlEnableMethodSec    = regexp.MustCompile(`<(?:[A-Za-z0-9_.-]+:)?global-method-security\b`)
)

// loadConfigFiles reads the bounded set of non-XML deployment descriptors used
// for context-path detection. Build files and arbitrary resources are ignored.
func loadConfigFiles(ctx context.Context, snapshot *project.Snapshot) (map[string]string, error) {
	files := map[string]string{}
	var paths []string
	for _, entry := range snapshot.Manifest().Entries {
		lower := strings.ToLower(entry.Path)
		if strings.HasSuffix(lower, ".properties") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
			paths = append(paths, entry.Path)
		}
	}
	sort.Strings(paths)
	if len(paths) > MaxFiles {
		return nil, audit.ErrLimit
	}
	for _, file := range paths {
		data, err := snapshot.ReadFile(ctx, file)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 || len(data) > MaxFileBytes || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
			continue
		}
		files[file] = string(data)
	}
	return files, nil
}

// detectContextPath returns a single declared context path, its source file and
// whether declarations conflict or are non-literal. The value is only used for
// the reported external_path; matching stays context-relative.
func detectContextPath(xmlFiles, configFiles map[string]string) (string, string, bool) {
	values := map[string]string{}
	conflict := false
	var files []string
	for file := range configFiles {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		content := configFiles[file]
		lower := strings.ToLower(file)
		var matches [][]string
		if strings.HasSuffix(lower, ".properties") {
			matches = propertiesContextPath.FindAllStringSubmatch(content, -1)
		} else {
			matches = yamlContextPath.FindAllStringSubmatch(content, -1)
		}
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			value, ok := normalizeContextPath(match[1])
			if !ok {
				conflict = true
				continue
			}
			if value != "" {
				values[value] = file
			}
		}
	}
	var xmlPaths []string
	for file := range xmlFiles {
		xmlPaths = append(xmlPaths, file)
	}
	sort.Strings(xmlPaths)
	for _, file := range xmlPaths {
		content := xmlFiles[file]
		for _, block := range xmlContextParamBlock.FindAllStringSubmatch(content, -1) {
			if len(block) < 2 {
				continue
			}
			name := firstSubmatch(xmlParamName, block[1])
			if name != "contextPath" && name != "server.servlet.context-path" && name != "app.context-path" {
				continue
			}
			value, ok := normalizeContextPath(firstSubmatch(xmlParamValue, block[1]))
			if !ok {
				conflict = true
				continue
			}
			if value != "" {
				values[value] = file
			}
		}
	}
	if len(values) > 1 {
		return "", "", true
	}
	for value, source := range values {
		return value, source, conflict
	}
	return "", "", conflict
}

func normalizeContextPath(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	value = strings.Trim(value, `"'`)
	if value == "" {
		return "", true
	}
	if strings.Contains(value, "${") || strings.ContainsAny(value, " \t") {
		return "", false
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	value = strings.TrimSuffix(value, "/")
	if value == "" || value == "/" {
		return "", true
	}
	return value, true
}

// methodSecurityState reports whether method security is globally enabled by
// @EnableMethodSecurity, @EnableGlobalMethodSecurity or XML. Annotation use is
// still honored when the enable flag is absent, but the report says so.
func methodSecurityState(sources map[string]javaSource, xmlFiles map[string]string) string {
	for _, source := range sources {
		if strings.Contains(source.Content, "@EnableMethodSecurity") || strings.Contains(source.Content, "@EnableGlobalMethodSecurity") {
			return "enabled"
		}
	}
	for _, content := range xmlFiles {
		if xmlEnableMethodSec.MatchString(content) {
			return "enabled"
		}
	}
	return "absent"
}
