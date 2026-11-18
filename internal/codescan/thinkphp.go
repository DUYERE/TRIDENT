package codescan

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"trident/internal/project"
)

const (
	MaxURLConfigFiles   = 32
	MaxDatabaseRoutes   = 500
	MaxConventionRoutes = 200
	MaxURLConfigRowSize = 4096
	MaxSQLiteBytes      = 32 << 20
)

type urlConfigRow struct {
	Alias string `json:"aliases"`
	URL   string `json:"url"`
}

var (
	urlConfigInsert = regexp.MustCompile("(?is)INSERT\\s+INTO\\s+[`\"\\[]?urlconfig\\b[^;]*?VALUES\\s*(.+?);")
)

// expandThinkPHPDatabaseRoutes resolves an otherwise dynamic ThinkPHP route
// only when the pinned snapshot itself contains urlconfig rows. SQL dumps and
// JSON fixtures are supported; live database access is never attempted.
func expandThinkPHPDatabaseRoutes(ctx context.Context, snapshot *project.Snapshot, report *Report) {
	if snapshot == nil || report == nil || len(report.Routes) == 0 {
		return
	}
	hasDynamic := false
	for _, route := range report.Routes {
		if route.PathStatus == "dynamic_unresolved" && isThinkPHPRule(route.Symbol) {
			hasDynamic = true
			break
		}
	}
	if !hasDynamic {
		return
	}
	rows := loadURLConfigRows(ctx, snapshot)
	if len(rows) == 0 {
		annotateURLConfigAbsent(report)
		return
	}
	if len(rows) > MaxDatabaseRoutes {
		rows = rows[:MaxDatabaseRoutes]
		markPartial(report, "database_route_limit")
	}
	applyURLConfigRows(report, rows)
}

func applyURLConfigRows(report *Report, rows []urlConfigRow) {
	expanded := make([]Route, 0, len(report.Routes)+len(rows))
	for _, route := range report.Routes {
		if route.PathStatus != "dynamic_unresolved" || !isThinkPHPRule(route.Symbol) {
			expanded = append(expanded, route)
			continue
		}
		for _, row := range rows {
			alias := strings.TrimSpace(row.Alias)
			if alias == "" || !routePathPattern.MatchString(alias) {
				continue
			}
			expanded = append(expanded, Route{
				Language: "php", Path: alias, Target: strings.TrimSpace(row.URL),
				PathStatus: "declared", Reason: "database_urlconfig_row", Source: "database",
				HTTPMethods: append([]string(nil), route.HTTPMethods...), Symbol: route.Symbol,
				File: route.File, SHA256: route.SHA256, Line: route.Line, Kind: "database",
			})
		}
	}
	report.Routes = expanded
}

func isThinkPHPRule(symbol string) bool {
	lower := strings.ToLower(symbol)
	return strings.Contains(lower, "route") && strings.Contains(lower, "rule")
}

// annotateURLConfigAbsent distinguishes "the snapshot carries no urlconfig
// rows" from "the path expression itself was not a literal". Both stay
// unresolved; only the first is expandable once such rows are available.
func annotateURLConfigAbsent(report *Report) {
	for index := range report.Routes {
		route := &report.Routes[index]
		if route.PathStatus == "dynamic_unresolved" && isThinkPHPRule(route.Symbol) {
			route.Reason = "database_urlconfig_absent"
		}
	}
}

func loadURLConfigRows(ctx context.Context, snapshot *project.Snapshot) []urlConfigRow {
	var candidates []project.FileEntry
	for _, entry := range snapshot.Manifest().Entries {
		lower := strings.ToLower(entry.Path)
		base := strings.ToLower(path.Base(lower))
		if !isURLConfigEntryPath(lower, base) {
			continue
		}
		candidates = append(candidates, entry)
	}
	if len(candidates) == 0 {
		for _, entry := range snapshot.Manifest().Entries {
			if strings.HasSuffix(strings.ToLower(entry.Path), ".sql") {
				candidates = append(candidates, entry)
			}
		}
	}
	if len(candidates) > MaxURLConfigFiles {
		candidates = candidates[:MaxURLConfigFiles]
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Path < candidates[j].Path })
	rows := make([]urlConfigRow, 0, 64)
	for _, entry := range candidates {
		content, err := snapshot.ReadFile(ctx, entry.Path)
		if err != nil || len(content) == 0 {
			continue
		}
		ext := strings.ToLower(path.Ext(entry.Path))
		if ext == ".db" || ext == ".sqlite" || ext == ".sqlite3" {
			if len(content) > MaxSQLiteBytes {
				continue
			}
			rows = append(rows, parseSQLiteSnapshot(ctx, content)...)
		} else {
			if len(content) > MaxFileBytes {
				continue
			}
			switch ext {
			case ".sql":
				rows = append(rows, parseURLConfigSQL(string(content))...)
			case ".json":
				rows = append(rows, parseURLConfigJSON(content)...)
			}
		}
		if len(rows) >= MaxDatabaseRoutes {
			break
		}
	}
	return dedupeURLConfigRows(rows)
}

func isURLConfigEntryPath(lower, base string) bool {
	switch path.Ext(lower) {
	case ".sql", ".json", ".db", ".sqlite", ".sqlite3":
	default:
		return false
	}
	return strings.Contains(base, "urlconfig") || strings.Contains(lower, "/database/") || strings.Contains(lower, "/db/")
}

func parseSQLiteSnapshot(ctx context.Context, content []byte) []urlConfigRow {
	file, err := os.CreateTemp("", "trident-urlconfig-*.sqlite")
	if err != nil {
		return nil
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(content); err != nil {
		file.Close()
		return nil
	}
	if err = file.Close(); err != nil {
		return nil
	}
	return parseSQLiteURLConfig(ctx, name)
}

func parseURLConfigSQL(text string) []urlConfigRow {
	matches := urlConfigInsert.FindAllStringSubmatch(text, -1)
	rows := make([]urlConfigRow, 0, len(matches)*2)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		columns := urlConfigColumns(match[0])
		for _, tuple := range splitSQLValueTuples(match[1]) {
			values := parseSQLTuple(tuple)
			if len(values) < 2 {
				continue
			}
			aliasIndex, urlIndex := 0, 1
			if len(columns) > 0 {
				aliasIndex, urlIndex = -1, -1
				for index, column := range columns {
					switch strings.ToLower(strings.TrimSpace(column)) {
					case "aliases", "alias":
						aliasIndex = index
					case "url", "target", "path":
						urlIndex = index
					}
				}
			}
			if aliasIndex < 0 || urlIndex < 0 || aliasIndex >= len(values) || urlIndex >= len(values) {
				continue
			}
			alias, target := strings.TrimSpace(values[aliasIndex]), strings.TrimSpace(values[urlIndex])
			if len(alias) > 256 || len(target) > 256 || alias == "" {
				continue
			}
			rows = append(rows, urlConfigRow{Alias: alias, URL: target})
		}
	}
	return rows
}

func urlConfigColumns(insert string) []string {
	values := strings.Index(strings.ToUpper(insert), "VALUES")
	if values < 0 {
		return nil
	}
	prefix := insert[:values]
	open := strings.Index(prefix, "(")
	close := strings.LastIndex(prefix, ")")
	if open < 0 || close <= open {
		return nil
	}
	parts := strings.Split(prefix[open+1:close], ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.Trim(strings.TrimSpace(part), "`\"'[]"))
	}
	return out
}

func splitSQLValueTuples(values string) []string {
	var out []string
	start, depth := -1, 0
	quote := rune(0)
	for index, char := range values {
		if quote != 0 {
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			quote = char
		case '(':
			if depth == 0 {
				start = index + 1
			}
			depth++
		case ')':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					out = append(out, values[start:index])
					start = -1
				}
			}
		}
	}
	return out
}

func parseSQLTuple(tuple string) []string {
	var out []string
	var current strings.Builder
	quote := rune(0)
	flush := func() {
		value := strings.TrimSpace(current.String())
		value = strings.Trim(value, "`\"'")
		out = append(out, value)
		current.Reset()
	}
	for _, char := range tuple {
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			quote = char
		case ',':
			flush()
		default:
			current.WriteRune(char)
		}
	}
	flush()
	return out
}

func parseURLConfigJSON(content []byte) []urlConfigRow {
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		return nil
	}
	rows := make([]urlConfigRow, 0, 32)
	var walk func(any)
	walk = func(node any) {
		switch item := node.(type) {
		case []any:
			for _, child := range item {
				walk(child)
			}
		case map[string]any:
			if aliases, ok := stringField(item, "aliases", "alias"); ok {
				if target, ok := stringField(item, "url", "target", "path"); ok && len(aliases) <= 256 && len(target) <= 256 {
					rows = append(rows, urlConfigRow{Alias: aliases, URL: target})
				}
			}
			for _, child := range item {
				walk(child)
			}
		}
	}
	walk(value)
	return rows
}

func stringField(item map[string]any, names ...string) (string, bool) {
	for _, name := range names {
		if raw, ok := item[name]; ok {
			if value, ok := raw.(string); ok && strings.TrimSpace(value) != "" {
				return value, true
			}
		}
	}
	return "", false
}

func dedupeURLConfigRows(rows []urlConfigRow) []urlConfigRow {
	seen := map[string]bool{}
	out := make([]urlConfigRow, 0, len(rows))
	for _, row := range rows {
		key := row.Alias + "\x00" + row.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, row)
	}
	return out
}

// appendThinkPHPConventionRoutes emits bounded convention candidates, never
// deployed URLs. They are marked separately so entry aggregation can exclude
// them from the authoritative entry table.
func appendThinkPHPConventionRoutes(report *Report) {
	if report == nil || !looksLikeThinkPHP(report) {
		return
	}
	seen := map[string]bool{}
	for _, route := range report.Routes {
		if route.PathStatus == "declared" || route.PathStatus == "dynamic_unresolved" {
			seen[route.Path] = true
		}
	}
	added := 0
	for _, symbol := range report.Symbols {
		if symbol.Kind != "method" || symbol.File == "" || simpleScope(symbol.File) != "project" {
			continue
		}
		lower := strings.ToLower(strings.ReplaceAll(symbol.File, "\\", "/"))
		controllerAt := strings.Index(lower, "/controller/")
		if controllerAt < 0 || !strings.HasSuffix(lower, ".php") {
			continue
		}
		parts := strings.Split(strings.Trim(lower, "/"), "/")
		module := "application"
		if controllerAt > 0 {
			before := strings.Split(strings.Trim(lower[:controllerAt], "/"), "/")
			if len(before) > 0 {
				module = before[len(before)-1]
			}
		}
		controller := strings.TrimSuffix(parts[len(parts)-1], ".php")
		if controller == "" || strings.EqualFold(symbol.Name, "__construct") || strings.EqualFold(symbol.Name, "_initialize") {
			continue
		}
		path := "/" + module + "/" + controller + "/" + symbol.Name
		if seen[path] || len(path) > 256 {
			continue
		}
		seen[path] = true
		report.Routes = append(report.Routes, Route{
			Language: symbol.Language, Path: path, PathStatus: "convention_candidate",
			Reason: "framework_convention_not_deployment", Source: "convention",
			HTTPMethods: []string{"ANY"}, Symbol: symbol.QualifiedName, File: symbol.File,
			SHA256: symbol.SHA256, Line: symbol.Line, Kind: "convention",
		})
		added++
		if added >= MaxConventionRoutes {
			markPartial(report, "convention_route_limit")
			break
		}
	}
}

func looksLikeThinkPHP(report *Report) bool {
	for _, route := range report.Routes {
		if isThinkPHPRule(route.Symbol) || strings.EqualFold(path.Base(route.File), "route.php") {
			return true
		}
	}
	for _, file := range report.Files {
		if strings.EqualFold(path.Base(file.File), "index.php") && strings.Contains(strings.ToLower(file.File), "public/") {
			return true
		}
	}
	return false
}

func simpleScope(file string) string {
	lower := strings.ToLower(strings.ReplaceAll(file, "\\", "/"))
	if strings.Contains(lower, "/vendor/") || strings.Contains(lower, "/node_modules/") {
		return "vendor"
	}
	return "project"
}

// Keep these available to tests and future DB adapters without exposing raw
// values through the JSON report.
func urlConfigRowsFromSQL(text string) []urlConfigRow { return parseURLConfigSQL(text) }

func urlConfigRowsFromJSON(content []byte) []urlConfigRow { return parseURLConfigJSON(content) }
