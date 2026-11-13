package r3

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxTestClasses     = 10
	MaxJUnitReportXMLs = 200
	MaxJUnitXMLBytes   = 2 << 20
	MaxJacocoBytes     = 8 << 20
)

var (
	junitOKPattern      = regexp.MustCompile(`OK \((\d+) tests?\)`)
	junitFailurePattern = regexp.MustCompile(`Tests run: (\d+),\s+Failures: (\d+)(?:,\s+Errors: (\d+))?(?:,\s+Skipped: (\d+))?`)
)

func junitTestClasses(legacy string, values []string) ([]string, error) {
	candidates := append([]string{}, values...)
	if legacy != "" {
		candidates = append(candidates, strings.FieldsFunc(legacy, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })...)
	}
	var classes []string
	seen := map[string]bool{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if !mainClassPattern.MatchString(candidate) || len(candidate) > 256 {
			return nil, fmt.Errorf("test class must be a dotted Java identifier")
		}
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		classes = append(classes, candidate)
		if len(classes) > MaxTestClasses {
			return nil, fmt.Errorf("junit profile accepts at most %d test classes", MaxTestClasses)
		}
	}
	if len(classes) == 0 {
		return nil, fmt.Errorf("junit profile requires at least one test class")
	}
	return classes, nil
}

func junitClasspathEntries(entries []string) ([]string, error) {
	if len(entries) == 0 || len(entries) > 20 {
		return nil, fmt.Errorf("junit profile requires 1 to 20 test classpath entries")
	}
	cleaned := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry == "" || len(entry) > 2048 || strings.ContainsAny(entry, "\x00\r\n") || !filepath.IsAbs(entry) {
			return nil, fmt.Errorf("test classpath entries must be absolute paths")
		}
		info, err := os.Stat(entry)
		if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
			return nil, fmt.Errorf("test classpath entry does not exist: %s", filepath.Base(entry))
		}
		cleaned = append(cleaned, entry)
	}
	return cleaned, nil
}

// junitContainerClasspath mounts each host classpath entry read-only under
// /trident-cp and returns the container-side classpath.
func junitContainerClasspath(entries []string) ([]SandboxMount, string, error) {
	if len(entries) == 0 || len(entries) > 20 {
		return nil, "", fmt.Errorf("junit profile requires 1 to 20 test classpath entries")
	}
	mounts := make([]SandboxMount, 0, len(entries))
	parts := make([]string, 0, len(entries))
	for i, entry := range entries {
		if !filepath.IsAbs(entry) {
			return nil, "", fmt.Errorf("test classpath entries must be absolute")
		}
		container := fmt.Sprintf("/trident-cp/%d", i)
		mounts = append(mounts, SandboxMount{Host: entry, Container: container, ReadOnly: true})
		parts = append(parts, container)
	}
	return mounts, strings.Join(parts, ":"), nil
}

// parseTestSummary reads JUnitCore's final console summary. Absence of a
// recognizable summary yields nil instead of a fabricated zero-test result.
func parseTestSummary(output string) *TestRunSummary {
	summary := &TestRunSummary{}
	if match := junitOKPattern.FindStringSubmatch(output); match != nil {
		summary.Tests, _ = strconv.Atoi(match[1])
		summary.Raw = match[0]
		return summary
	}
	matches := junitFailurePattern.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil
	}
	match := matches[len(matches)-1]
	summary.Tests, _ = strconv.Atoi(match[1])
	summary.Failures, _ = strconv.Atoi(match[2])
	if match[3] != "" {
		summary.Errors, _ = strconv.Atoi(match[3])
	}
	if match[4] != "" {
		summary.Skipped, _ = strconv.Atoi(match[4])
	}
	summary.Raw = match[0]
	return summary
}

type junitSuiteXML struct {
	XMLName  xml.Name `xml:"testsuite"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Errors   int      `xml:"errors,attr"`
	Skipped  int      `xml:"skipped,attr"`
}

func parseJUnitXMLDir(dir string) (*JUnitXMLSummary, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("junit report directory is not a directory")
	}
	var files []string
	walkErr := filepath.WalkDir(dir, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".xml") {
			return nil
		}
		if len(files) >= MaxJUnitReportXMLs {
			return fmt.Errorf("junit report directory exceeds %d XML files", MaxJUnitReportXMLs)
		}
		files = append(files, current)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, nil
	}
	summary := &JUnitXMLSummary{Files: []string{}}
	for _, file := range files {
		if info, statErr := os.Stat(file); statErr != nil || info.Size() > MaxJUnitXMLBytes {
			return nil, fmt.Errorf("junit XML file is outside supported bounds: %s", filepath.Base(file))
		}
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			return nil, readErr
		}
		decoder := xml.NewDecoder(strings.NewReader(string(data)))
		found := 0
		for {
			token, tokenErr := decoder.Token()
			if tokenErr != nil {
				break
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != "testsuite" {
				continue
			}
			var suite junitSuiteXML
			if err := decoder.DecodeElement(&suite, &start); err != nil {
				return nil, err
			}
			found++
			summary.Suites++
			summary.Tests += suite.Tests
			summary.Failures += suite.Failures
			summary.Errors += suite.Errors
			summary.Skipped += suite.Skipped
		}
		if found == 0 {
			return nil, fmt.Errorf("junit XML file has no testsuite element: %s", filepath.Base(file))
		}
		summary.Files = append(summary.Files, filepath.Base(file))
	}
	return summary, nil
}

type jacocoReportXML struct {
	XMLName  xml.Name           `xml:"report"`
	Counters []jacocoCounterXML `xml:"counter"`
}

type jacocoCounterXML struct {
	Type    string `xml:"type,attr"`
	Missed  int    `xml:"missed,attr"`
	Covered int    `xml:"covered,attr"`
}

func parseJacocoXML(path string) (*CoverageSummary, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("jacoco report does not exist")
	}
	if info.Size() > MaxJacocoBytes {
		return nil, fmt.Errorf("jacoco report exceeds supported size")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report jacocoReportXML
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("invalid jacoco XML: %w", err)
	}
	summary := &CoverageSummary{}
	for _, counter := range report.Counters {
		switch counter.Type {
		case "LINE":
			summary.LineCovered, summary.LineTotal = counter.Covered, counter.Covered+counter.Missed
		case "BRANCH":
			summary.BranchCovered, summary.BranchTotal = counter.Covered, counter.Covered+counter.Missed
		case "METHOD":
			summary.MethodCovered, summary.MethodTotal = counter.Covered, counter.Covered+counter.Missed
		}
	}
	summary.LinePercent = percent(summary.LineCovered, summary.LineTotal)
	summary.BranchPercent = percent(summary.BranchCovered, summary.BranchTotal)
	if summary.LineTotal == 0 && summary.BranchTotal == 0 && summary.MethodTotal == 0 {
		return nil, fmt.Errorf("jacoco report has no recognizable counters")
	}
	return summary, nil
}

func percent(covered, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(covered) * 100 / float64(total)
}
