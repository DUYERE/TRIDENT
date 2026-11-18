package caseagent

import "testing"

func TestEvidenceWindow(t *testing.T) {
	cases := []struct {
		lines      string
		start, end int
	}{
		{lines: "40-50", start: 40, end: 50},
		{lines: "445-457", start: 445, end: 457},
		{lines: "107", start: 107, end: 146},
		{lines: "", start: 1, end: 40},
		{lines: "bad", start: 1, end: 40},
		{lines: "50-40", start: 50, end: 50},
		{lines: "1-300", start: 1, end: 200},
	}
	for _, tc := range cases {
		start, end := evidenceWindow(tc.lines)
		if start != tc.start || end != tc.end {
			t.Fatalf("evidenceWindow(%q) = %d-%d; want %d-%d", tc.lines, start, end, tc.start, tc.end)
		}
	}
}
