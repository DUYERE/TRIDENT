package codescan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	cwePattern      = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	selectorPattern = regexp.MustCompile(`^[A-Za-z0-9_$@.:*?>()\[\]&\-]{1,128}$`)
)

var allowedCategories = map[string]bool{
	"sql": true, "command": true, "code_exec": true, "deserialization": true,
	"path": true, "ssrf": true, "xss": true, "xxe": true, "template": true,
	"upload": true, "ldap": true, "redirect": true, "xpath": true,
}
var allowedSeverities = map[string]bool{"high": true, "medium": true, "low": true}
var allowedConfidences = map[string]bool{"high": true, "medium": true, "low": true}
var allowedKinds = map[string]bool{"call": true, "access": true, "identifier": true, "assign": true, "statement": true, "receiver": true, "any": true}

// LoadRuleFile reads a caller-supplied rule catalog. It is deliberately strict:
// unknown fields, duplicate IDs, unsupported languages and out-of-range values
// fail closed rather than silently changing analysis semantics.
func LoadRuleFile(path string) ([]RuleSpec, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: rules file: %v", ErrRule, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: rules path is not a regular file", ErrRule)
	}
	if info.Size() > MaxRuleBytes {
		return nil, fmt.Errorf("%w: rules file exceeds %d bytes", ErrRule, MaxRuleBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: rules file: %v", ErrRule, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file RuleFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("%w: invalid rules JSON: %v", ErrRule, err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		return nil, fmt.Errorf("%w: trailing JSON document", ErrRule)
	}
	if file.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported rules schema_version %d", ErrRule, file.SchemaVersion)
	}
	if len(file.Rules) == 0 || len(file.Rules) > MaxRules {
		return nil, fmt.Errorf("%w: rules count must be 1..%d", ErrRule, MaxRules)
	}
	if err := validateRules(file.Rules); err != nil {
		return nil, err
	}
	return file.Rules, nil
}

func validateRules(rules []RuleSpec) error {
	if len(rules) > MaxRules {
		return fmt.Errorf("%w: too many rules", ErrRule)
	}
	seen := map[string]bool{}
	supported := map[string]bool{}
	for _, name := range supportedLanguageNames() {
		supported[name] = true
	}
	for i := range rules {
		r := &rules[i]
		if !idPattern.MatchString(r.ID) || seen[r.ID] {
			return fmt.Errorf("%w: invalid or duplicate rule id %q", ErrRule, r.ID)
		}
		seen[r.ID] = true
		if len(r.Languages) == 0 || len(r.Languages) > len(supported) {
			return fmt.Errorf("%w: %s has invalid languages", ErrRule, r.ID)
		}
		for _, lang := range r.Languages {
			if !supported[lang] {
				return fmt.Errorf("%w: %s uses unsupported language %q", ErrRule, r.ID, lang)
			}
		}
		if !allowedCategories[r.Category] || !cwePattern.MatchString(r.CWE) {
			return fmt.Errorf("%w: %s has invalid category/CWE", ErrRule, r.ID)
		}
		if !allowedSeverities[r.Severity] || !allowedConfidences[r.Confidence] {
			return fmt.Errorf("%w: %s has invalid severity/confidence", ErrRule, r.ID)
		}
		if r.Title == "" || len(r.Title) > 256 || len(r.Message) > 1024 {
			return fmt.Errorf("%w: %s has invalid title/message", ErrRule, r.ID)
		}
		if len(r.Sources) == 0 || len(r.Sinks) == 0 {
			return fmt.Errorf("%w: %s needs sources and sinks", ErrRule, r.ID)
		}
		for _, group := range [][]PatternSpec{r.Sources, r.Sinks, r.Sanitizers} {
			for _, pattern := range group {
				if err := validatePattern(pattern); err != nil {
					return fmt.Errorf("%w: %s: %v", ErrRule, r.ID, err)
				}
			}
		}
		if len(r.SafeCalls) > MaxPatternNames {
			return fmt.Errorf("%w: %s has too many safe_calls", ErrRule, r.ID)
		}
		for _, name := range r.SafeCalls {
			if !selectorPattern.MatchString(name) {
				return fmt.Errorf("%w: %s has invalid safe call %q", ErrRule, r.ID, name)
			}
		}
	}
	return nil
}

func validatePattern(pattern PatternSpec) error {
	if !allowedKinds[pattern.Kind] {
		return fmt.Errorf("invalid pattern kind %q", pattern.Kind)
	}
	if len(pattern.Names) == 0 || len(pattern.Names) > MaxPatternNames {
		return fmt.Errorf("invalid pattern names count")
	}
	for _, name := range pattern.Names {
		if !selectorPattern.MatchString(name) {
			return fmt.Errorf("invalid selector %q", name)
		}
	}
	if pattern.ArgIndex < 0 || pattern.ArgIndex > 16 {
		return fmt.Errorf("arg_index must be 0..16")
	}
	return nil
}

// resolveRules merges built-in rules with in-memory and caller-file rules. The
// rule-set version always carries a digest of the exact rule data, so a report
// can never be silently reinterpreted by a later rule change.
func resolveRules(opts Options) ([]RuleSpec, string, error) {
	rules := builtinRules()
	if err := validateRules(rules); err != nil {
		return nil, "", fmt.Errorf("built-in rules invalid: %w", err)
	}
	if len(opts.Extra) > 0 {
		rules = append(rules, opts.Extra...)
	}
	if opts.RulePath != "" {
		extra, err := LoadRuleFile(opts.RulePath)
		if err != nil {
			return nil, "", err
		}
		rules = append(rules, extra...)
	}
	if err := validateRules(rules); err != nil {
		return nil, "", err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	encoded, err := json.Marshal(rules)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(encoded)
	return rules, RuleSetVersion + "+" + hex.EncodeToString(digest[:6]), nil
}

// activeRules returns rules that apply to the selected languages, preserving
// the deterministic ID ordering from resolveRules.
func activeRules(rules []RuleSpec, selected map[string]bool) []RuleSpec {
	out := make([]RuleSpec, 0, len(rules))
	for _, r := range rules {
		for _, lang := range r.Languages {
			if selected[lang] {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func resolveLanguages(opts Options) (map[string]bool, error) {
	specs := languageSpecs()
	selected := map[string]bool{}
	if len(opts.Languages) == 0 {
		for _, spec := range specs {
			selected[spec.Name] = true
		}
		return selected, nil
	}
	for _, raw := range opts.Languages {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			return nil, fmt.Errorf("%w: empty language filter", ErrUnsupported)
		}
		found := false
		for _, spec := range specs {
			if spec.Name == name || (name == "dotnet" && spec.Name == "csharp") || (name == "net" && spec.Name == "csharp") || (name == "js" && spec.Name == "javascript") || (name == "ts" && spec.Name == "typescript") {
				selected[spec.Name] = true
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: %q (supported: %s)", ErrUnsupported, raw, strings.Join(supportedLanguageNames(), ", "))
		}
	}
	return selected, nil
}
