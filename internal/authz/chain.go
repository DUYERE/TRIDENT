package authz

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// chainSpec is the scan-time model of one filter chain. ruleKeys point at
// controls by their internal scan key so IDs can be assigned after sorting.
type chainSpec struct {
	source         string
	file           string
	line           int
	order          int
	orderObserved  bool
	matchers       []string
	matcherUnknown bool
	customFilters  []string
	ruleKeys       []string
	note           string
}

type controlBatch struct {
	controls []Control
	chains   []*chainSpec
}

var (
	chainMethodSecurity     = regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|protected|private|static|final)\s+)+SecurityFilterChain\s+\w+\s*\([^)]*\)[^;{]*\{`)
	chainMethodHttpSecurity = regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|protected|private|static|final)\s+)+[A-Za-z_][\w<>\[\].]*\s+\w+\s*\([^)]*HttpSecurity[^)]*\)[^;{]*\{`)
	chainOrderPattern       = regexp.MustCompile(`@Order\s*\(\s*(?:value\s*=\s*)?([^)]*)\)`)
	chainSecurityMatcher    = regexp.MustCompile(`securityMatcher\s*\(([^()]*)\)`)
	chainCustomFilter       = regexp.MustCompile(`addFilter(?:Before|After)\s*\(((?:[^()]|\([^()]*\))*)\)`)
)

// chainSpecFor returns the chain that owns the configuration call at offset.
// The enclosing method (SecurityFilterChain or configure(HttpSecurity)) is the
// chain boundary; annotations and securityMatcher calls before the call belong
// to it.
func chainSpecFor(content, file string, offset int, specs map[string]*chainSpec, ordered *[]*chainSpec) *chainSpec {
	start := chainMethodStart(content, offset)
	key := file + "\x00" + strconv.Itoa(start)
	if existing, ok := specs[key]; ok {
		return existing
	}
	spec := &chainSpec{source: "java", file: file, line: lineOf(content, start), order: defaultChainOrder}
	annotationWindow := content[0:start]
	if start > 400 {
		annotationWindow = content[start-400 : start]
	}
	if matches := chainOrderPattern.FindAllStringSubmatch(annotationWindow, -1); len(matches) > 0 {
		if parsed, ok := parseChainOrder(matches[len(matches)-1][1]); ok {
			spec.order = parsed
			spec.orderObserved = true
		}
	}
	header := content[start:offset]
	for _, match := range chainSecurityMatcher.FindAllStringSubmatch(header, -1) {
		values := quotedValues(match[1])
		if len(values) == 0 {
			spec.matcherUnknown = true
			continue
		}
		spec.matchers = append(spec.matchers, values...)
	}
	spec.matchers = uniqueStrings(spec.matchers)
	for _, match := range chainCustomFilter.FindAllStringSubmatch(header, -1) {
		value := normalizeSpace(match[1])
		if value != "" {
			spec.customFilters = append(spec.customFilters, value)
		}
	}
	spec.customFilters = uniqueStrings(spec.customFilters)
	specs[key] = spec
	*ordered = append(*ordered, spec)
	return spec
}

func chainMethodStart(content string, offset int) int {
	if offset > len(content) {
		offset = len(content)
	}
	prefix := content[:offset]
	start := 0
	for _, pattern := range []*regexp.Regexp{chainMethodSecurity, chainMethodHttpSecurity} {
		if matches := pattern.FindAllStringIndex(prefix, -1); len(matches) > 0 {
			if last := matches[len(matches)-1][0]; last > start {
				start = last
			}
		}
	}
	return start
}

func parseChainOrder(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if index := strings.Index(value, "="); index >= 0 {
		value = strings.TrimSpace(value[index+1:])
	}
	switch value {
	case "Ordered.HIGHEST_PRECEDENCE", "HIGHEST_PRECEDENCE":
		return -2147483648, true
	case "Ordered.LOWEST_PRECEDENCE", "LOWEST_PRECEDENCE":
		return defaultChainOrder, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func normalizeSpace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func controlKey(file, prefix string, order int) string {
	return file + "\x00" + prefix + ":" + strconv.Itoa(order)
}

// buildChainReport orders chains by Spring's precedence (order, then source,
// file and line) and maps rule keys to the final control IDs. Java chains are
// evaluated before legacy XML intercept-url controls sharing the default
// order; without a securityMatcher such a chain abstains and evaluation falls
// through to the next one, which preserves the pre-chain inventory behavior.
func buildChainReport(specs []*chainSpec, controls []Control, idByKey map[string]string, indexByKey map[string]int) ([]FilterChain, map[string][]Control, map[string]string) {
	sorted := append([]*chainSpec{}, specs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].order != sorted[j].order {
			return sorted[i].order < sorted[j].order
		}
		if sourceRank(sorted[i].source) != sourceRank(sorted[j].source) {
			return sourceRank(sorted[i].source) < sourceRank(sorted[j].source)
		}
		if sorted[i].file != sorted[j].file {
			return sorted[i].file < sorted[j].file
		}
		return sorted[i].line < sorted[j].line
	})
	chains := make([]FilterChain, 0, len(sorted))
	rulesByChain := map[string][]Control{}
	chainIDByKey := map[string]string{}
	for index, spec := range sorted {
		chain := FilterChain{
			ID:            fmt.Sprintf("chn-%03d", index+1),
			Source:        spec.source,
			File:          spec.file,
			Line:          spec.line,
			Order:         spec.order,
			OrderSource:   "default",
			CustomFilters: spec.customFilters,
			Status:        "observed",
		}
		if spec.orderObserved {
			chain.OrderSource = "annotation"
		}
		chain.SecurityMatchers = spec.matchers
		if spec.matcherUnknown {
			chain.Status = "unresolved"
			chain.Note = "security_matcher_not_resolved"
		}
		if spec.note != "" {
			chain.Note = spec.note
		}
		for _, key := range spec.ruleKeys {
			id, ok := idByKey[key]
			if !ok {
				continue
			}
			chain.Rules = append(chain.Rules, id)
			if controlIndex, ok := indexByKey[key]; ok {
				rulesByChain[chain.ID] = append(rulesByChain[chain.ID], controls[controlIndex])
			}
			chainIDByKey[key] = chain.ID
		}
		chains = append(chains, chain)
	}
	return chains, rulesByChain, chainIDByKey
}

func sourceRank(source string) int {
	if source == "java" {
		return 0
	}
	return 1
}
