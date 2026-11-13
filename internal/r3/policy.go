package r3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// RemediationPolicy bounds AI-generated patches. It is caller configuration,
// never snapshot content, and cannot prove that a patch is secure.
type RemediationPolicy struct {
	SchemaVersion       int               `json:"schema_version"`
	MaxFiles            int               `json:"max_files"`
	MaxChangedLines     int               `json:"max_changed_lines"`
	ForbiddenPatterns   []string          `json:"forbidden_patterns"`
	PreferredStrategies map[string]string `json:"preferred_strategies"`
	RequireValidation   bool              `json:"require_validation"`
}

const MaxPolicyBytes = 64 << 10

func DefaultPolicy() RemediationPolicy {
	return RemediationPolicy{
		SchemaVersion:     1,
		MaxFiles:          4,
		MaxChangedLines:   200,
		RequireValidation: true,
		ForbiddenPatterns: []string{
			`(?i)Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`,
			`(?i)new\s+ObjectInputStream\s*\(`,
			`(?i)new\s+XMLDecoder\s*\(`,
		},
		PreferredStrategies: map[string]string{
			"sql":             "parameterized queries or prepared statements; never concatenate request data into SQL text",
			"command":         "fixed command plus allow-listed arguments; never pass request data to a shell",
			"ssrf":            "allow-list scheme/host/port and refuse redirects before the outbound request",
			"path":            "resolve under a fixed base directory and reject traversal after normalization",
			"template":        "use constant templates with data-only bindings",
			"xss":             "context-aware output encoding or a fixed content type",
			"upload":          "fixed storage root, generated filename, size/type checks and no executable extensions",
			"deserialization": "replace native deserialization with a schema-constrained format or strict allow-list",
			"xxe":             "disable external entities and DTDs on the parser",
			"ldap":            "escape LDAP filter values or use a parameterized filter builder",
		},
	}
}

func LoadPolicy(path string) (RemediationPolicy, error) {
	policy := RemediationPolicy{}
	if path == "" {
		return DefaultPolicy(), nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > MaxPolicyBytes {
		return policy, fmt.Errorf("policy must be a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return policy, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&policy); err != nil {
		return policy, fmt.Errorf("invalid policy JSON: %w", err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return policy, fmt.Errorf("trailing policy content")
	}
	return policy.normalized()
}

func (p RemediationPolicy) normalized() (RemediationPolicy, error) {
	if p.SchemaVersion != 1 {
		return p, fmt.Errorf("policy schema_version must be 1")
	}
	if p.MaxFiles < 1 || p.MaxFiles > 20 {
		return p, fmt.Errorf("policy max_files must be between 1 and 20")
	}
	if p.MaxChangedLines < 1 || p.MaxChangedLines > 2000 {
		return p, fmt.Errorf("policy max_changed_lines must be between 1 and 2000")
	}
	if len(p.ForbiddenPatterns) > 32 {
		return p, fmt.Errorf("policy has too many forbidden patterns")
	}
	for _, pattern := range p.ForbiddenPatterns {
		if len(pattern) > 256 {
			return p, fmt.Errorf("policy forbidden pattern is too long")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return p, fmt.Errorf("invalid policy forbidden pattern")
		}
	}
	return p, nil
}

// ValidatePatch scans added lines only so a forbidden API present in unchanged
// context does not block an unrelated fix.
func (p RemediationPolicy) ValidatePatch(patch string, result PatchResult) error {
	normalized, err := p.normalized()
	if err != nil {
		return err
	}
	if len(result.Files) == 0 {
		return fmt.Errorf("policy requires at least one changed file")
	}
	if len(result.Files) > normalized.MaxFiles {
		return fmt.Errorf("policy allows at most %d changed files", normalized.MaxFiles)
	}
	changed := 0
	for _, file := range result.Files {
		changed += file.Additions + file.Deletions
	}
	if changed > normalized.MaxChangedLines {
		return fmt.Errorf("policy allows at most %d changed lines", normalized.MaxChangedLines)
	}
	var added []string
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
			continue
		}
		if strings.HasPrefix(line, "+") {
			added = append(added, line[1:])
		}
	}
	addedText := strings.Join(added, "\n")
	for _, pattern := range normalized.ForbiddenPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("policy pattern failed to compile")
		}
		if compiled.MatchString(addedText) {
			return fmt.Errorf("policy forbids added pattern %q", pattern)
		}
	}
	return nil
}

func (p RemediationPolicy) prompt() string {
	normalized, err := p.normalized()
	if err != nil {
		normalized = DefaultPolicy()
	}
	var builder strings.Builder
	builder.WriteString("Remediation policy:\n")
	fmt.Fprintf(&builder, "- change at most %d files and %d lines\n", normalized.MaxFiles, normalized.MaxChangedLines)
	if normalized.RequireValidation {
		builder.WriteString("- prefer fixes that can be validated by the configured offline profile\n")
	}
	if len(normalized.PreferredStrategies) > 0 {
		keys := make([]string, 0, len(normalized.PreferredStrategies))
		for key := range normalized.PreferredStrategies {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder.WriteString("- preferred strategies: ")
		for i, key := range keys {
			if i > 0 {
				builder.WriteString("; ")
			}
			builder.WriteString(key)
			builder.WriteString("=")
			builder.WriteString(normalized.PreferredStrategies[key])
		}
		builder.WriteString("\n")
	}
	return builder.String()
}
