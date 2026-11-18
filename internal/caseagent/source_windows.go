package caseagent

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"trident/internal/casework"
	"trident/internal/r3"
)

// sourceWindows turns Case source evidence into bounded snapshot windows. The
// windows keep the patch-generation prompt focused on the observed sink instead
// of dumping the first 200 lines of every candidate file.
func (r *Registry) sourceWindows(detail casework.CaseDetail) ([]r3.ProposeWindow, []string) {
	entries := map[string]bool{}
	for _, entry := range r.snapshot.Manifest().Entries {
		entries[entry.Path] = true
	}
	type candidate struct {
		window r3.ProposeWindow
		score  int
		order  int
	}
	seen := map[string]int{}
	var candidates []candidate
	for _, finding := range detail.Findings {
		for _, ev := range finding.SourceEvidence {
			pathValue := filepath.ToSlash(strings.TrimSpace(ev.File))
			pathValue = filepath.ToSlash(filepath.Clean(pathValue))
			if pathValue == "." || pathValue == "" || filepath.IsAbs(pathValue) || strings.HasPrefix(pathValue, "../") || !entries[pathValue] {
				continue
			}
			start, end := evidenceWindow(ev.Lines)
			score := 3
			obs := strings.ToLower(ev.Observation)
			for _, term := range []string{"sink", "executes", "include", "upload", "insert", "write"} {
				if strings.Contains(obs, term) {
					score = 1
					break
				}
			}
			if index, ok := seen[pathValue]; ok {
				if start < candidates[index].window.StartLine {
					candidates[index].window.StartLine = start
				}
				if end > candidates[index].window.EndLine {
					candidates[index].window.EndLine = end
				}
				if score < candidates[index].score {
					candidates[index].score = score
				}
				continue
			}
			seen[pathValue] = len(candidates)
			candidates = append(candidates, candidate{
				window: r3.ProposeWindow{Path: pathValue, StartLine: start, EndLine: end},
				score:  score,
				order:  len(candidates),
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score < candidates[j].score
		}
		return candidates[i].order < candidates[j].order
	})
	windows := make([]r3.ProposeWindow, 0, r3.MaxProposalFiles)
	omitted := []string{}
	for _, c := range candidates {
		if len(windows) < r3.MaxProposalFiles {
			windows = append(windows, c.window)
		} else {
			omitted = append(omitted, c.window.Path)
		}
	}
	return windows, omitted
}

func evidenceWindow(lines string) (int, int) {
	parts := strings.Split(strings.TrimSpace(lines), "-")
	parse := func(value string, fallback int) int {
		number, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || number < 1 {
			return fallback
		}
		return number
	}
	start := parse(parts[0], 1)
	end := start + 39
	if len(parts) > 1 {
		end = parse(parts[1], end)
	}
	if end < start {
		end = start
	}
	if end-start+1 > r3.MaxProposalWindowLines {
		end = start + r3.MaxProposalWindowLines - 1
	}
	return start, end
}
