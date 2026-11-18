package codescan

import "testing"

func TestMarkPartialClassifiesAxes(t *testing.T) {
	cases := []struct {
		limitation string
		file       bool
		symbol     bool
		finding    bool
	}{
		{limitation: "file_limit", file: true},
		{limitation: "file_too_large", file: true},
		{limitation: "lex_rejected", file: true},
		{limitation: "statement_limit", file: true},
		{limitation: "symbol_limit", symbol: true},
		{limitation: "call_limit", symbol: true},
		{limitation: "unresolved_limit", symbol: true},
		{limitation: "finding_limit", finding: true},
	}
	for _, tc := range cases {
		t.Run(tc.limitation, func(t *testing.T) {
			report := Report{}
			markPartial(&report, tc.limitation)
			if !report.Partial {
				t.Fatalf("partial aggregate not set for %s", tc.limitation)
			}
			if report.FilePartial != tc.file || report.SymbolPartial != tc.symbol || report.FindingPartial != tc.finding {
				t.Fatalf("%s classified as file=%v symbol=%v finding=%v; want %v/%v/%v",
					tc.limitation, report.FilePartial, report.SymbolPartial, report.FindingPartial,
					tc.file, tc.symbol, tc.finding)
			}
			if !contains(report.Limitations, tc.limitation) {
				t.Fatalf("%s not recorded: %+v", tc.limitation, report.Limitations)
			}
		})
	}
}
