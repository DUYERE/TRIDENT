package codescan

import (
	"fmt"
	"sort"

	"trident/internal/findings"
)

// AsFindingsReport adapts the multi-language audit report to TRIDENT's unified
// evidence model, so the existing deterministic SARIF exporter and evidence
// drawers can consume it without duplicating rule semantics. It does not
// upgrade status, add runtime evidence or invent hypotheses.
func AsFindingsReport(report Report) findings.Report {
	out := findings.Report{
		SchemaVersion: report.SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  report.SnapshotHash,
		AnalysisKind:  AnalysisKind,
		Partial:       report.Partial,
		Findings:      make([]findings.Finding, 0, len(report.Findings)),
		Limitations: append(append([]string(nil), report.Limitations...),
			"code_audit_only: this report contains multi-language rule findings only; SCA, Java annotation inventory and Java dataflow evidence are separate reports",
			"ruleset_version="+report.RuleSetVersion),
		Coverage: findings.Coverage{
			FindingsTotal:          len(report.Findings),
			RuntimeStatus:          "not_run",
			JavaAST:                "not_used",
			ScaResolution:          "not_run",
			TaintAnalysis:          "bounded_intrascope_lexical",
			DependencyReachability: "not_run",
		},
	}
	for _, item := range report.Findings {
		evidence := make([]findings.Evidence, 0, len(item.Evidence))
		for index, ref := range item.Evidence {
			evidence = append(evidence, findings.Evidence{
				ID: fmt.Sprintf("%s:e%d", item.ID, index), Kind: ref.Kind,
				File: ref.File, SHA256: ref.SHA256, StartLine: ref.Line, EndLine: ref.Line,
				Detail: ref.Detail, Origin: AnalysisKind, OriginRef: item.RuleID,
			})
		}
		out.Findings = append(out.Findings, findings.Finding{
			ID: "code:" + item.ID, Kind: item.RuleID,
			Category: item.Category, CWE: item.CWE, Severity: item.Severity,
			Status: item.Status, RuntimeStatus: item.RuntimeStatus,
			Title: item.Title, Evidence: evidence,
			Hypotheses:     []findings.Hypothesis{},
			SourceAnalyses: []string{AnalysisKind, "ruleset=" + report.RuleSetVersion, "language=" + item.Language},
			Limitations:    append([]string(nil), item.Limitations...),
		})
		switch item.Status {
		case "static_confirmed":
			out.Coverage.FindingsStaticConfirmed++
		case "refuted":
			out.Coverage.FindingsRefuted++
		default:
			out.Coverage.FindingsInconclusive++
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool { return out.Findings[i].ID < out.Findings[j].ID })
	sort.Strings(out.Limitations)
	return out
}

// MergeFindings appends code-audit findings to an existing unified report
// without reinterpreting any existing finding. It is only used when the caller
// explicitly opts in with --include-code-audit/--code-rules.
func MergeFindings(base *findings.Report, report Report) {
	extra := AsFindingsReport(report)
	if len(extra.Findings) == 0 {
		return
	}
	base.Findings = append(base.Findings, extra.Findings...)
	base.Partial = base.Partial || report.Partial
	base.Limitations = append(base.Limitations, "multi_language_code_audit_included: "+report.RuleSetVersion)
	base.Limitations = append(base.Limitations, report.Limitations...)
	base.Coverage.FindingsTotal += extra.Coverage.FindingsTotal
	base.Coverage.FindingsStaticConfirmed += extra.Coverage.FindingsStaticConfirmed
	base.Coverage.FindingsInconclusive += extra.Coverage.FindingsInconclusive
	base.Coverage.FindingsRefuted += extra.Coverage.FindingsRefuted
	sort.Slice(base.Findings, func(i, j int) bool { return base.Findings[i].ID < base.Findings[j].ID })
	base.Limitations = dedupeSorted(base.Limitations)
}
