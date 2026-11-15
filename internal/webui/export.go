package webui

import (
	"fmt"
	"html"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"trident/internal/project"
)

// handleExportReport serves the deterministic HTML review report. It renders
// only snapshot-pinned data from the cached analysis: no wall-clock time, no
// duration, no requester identity, and no external resource references, so two
// downloads over the same snapshot and binary are byte-identical.
func (c *Console) handleExportReport(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	manifest := c.snapshotRef().Manifest()
	short := c.snapshotRef().Hash()
	if len(short) > 12 {
		short = short[:12]
	}
	page := renderReportHTML(c.version, short, manifest, state)
	encoded := []byte(page)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="trident-report-%s.html"`, short))
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

// renderReportHTML builds the full page. All dynamic text goes through esc;
// iteration order is fixed by sorted finding IDs and the static category list.
func renderReportHTML(version, shortHash string, manifest project.Manifest, state *analysisState) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<title>TRIDENT 证据报告 · " + esc(shortHash) + "</title>\n")
	b.WriteString(styleBlock)
	b.WriteString("</head>\n<body>\n")
	b.WriteString("<h1>TRIDENT 静态证据报告</h1>\n")
	b.WriteString("<p class=\"sub\">只读控制台导出，与 trident audit findings 同源数据；runtime_status 恒为 not_run，静态证据不等于运行时可利用。</p>\n")

	b.WriteString("<h2>1. 快照</h2>\n<table><tbody>")
	kv := [][2]string{
		{"快照摘要", manifestHash(state)},
		{"来源", manifest.Source},
		{"清单版本", strconv.Itoa(manifest.Version)},
		{"策略版本", manifest.PolicyVersion},
		{"工具版本", manifest.ToolVersion},
		{"文件数", strconv.Itoa(manifest.TotalFiles)},
		{"字节数", strconv.FormatInt(manifest.TotalBytes, 10)},
		{"排除条目", strconv.Itoa(len(manifest.Excluded))},
		{"部分快照", boolText(manifest.Partial)},
	}
	if len(manifest.Warnings) > 0 {
		kv = append(kv, [2]string{"清单警告", strings.Join(manifest.Warnings, "；")})
	}
	for _, row := range kv {
		b.WriteString("<tr><th>" + esc(row[0]) + "</th><td>" + esc(row[1]) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString("<h2>2. 结论概要</h2>\n")
	counts := statusCounts{}
	for _, finding := range state.findings.Findings {
		counts.Total++
		switch finding.Status {
		case "static_confirmed":
			counts.Confirmed++
		case "refuted":
			counts.Refuted++
		default:
			counts.Inconclusive++
		}
	}
	b.WriteString("<table><tbody>")
	for _, row := range [][2]string{
		{"发现总数", strconv.Itoa(counts.Total)},
		{"静态确认", strconv.Itoa(counts.Confirmed)},
		{"证据不足", strconv.Itoa(counts.Inconclusive)},
		{"已驳倒", strconv.Itoa(counts.Refuted)},
		{"入口清单", strconv.Itoa(state.audit.Coverage.EndpointsFound)},
		{"数据流发现", strconv.Itoa(state.findings.Coverage.DataflowFindings)},
		{"声明级依赖", strconv.Itoa(state.findings.Coverage.ScaDependencies)},
		{"公告候选", strconv.Itoa(state.findings.Coverage.ScaCandidates)},
		{"假设支持/未支持/未验证", fmt.Sprintf("%d/%d/%d", state.findings.Coverage.HypothesesSupported, state.findings.Coverage.HypothesesUnsupported, state.findings.Coverage.HypothesesUnverified)},
		{"Java AST", state.findings.Coverage.JavaAST},
		{"污点分析", state.findings.Coverage.TaintAnalysis},
		{"SCA 解析", state.findings.Coverage.ScaResolution},
		{"依赖可达性", state.findings.Coverage.DependencyReachability},
		{"分析工具版本", state.findings.ToolVersion},
	} {
		b.WriteString("<tr><th>" + esc(row[0]) + "</th><td>" + esc(row[1]) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString("<h2>3. 类别分布</h2>\n<table><thead><tr><th>类别</th><th>CWE</th><th>总数</th><th>静态确认</th><th>证据不足</th><th>已驳倒</th></tr></thead><tbody>\n")
	for _, meta := range categoryOrder {
		total, confirmed, inconclusive, refuted := 0, 0, 0, 0
		for _, finding := range state.findings.Findings {
			if categoryKey(finding.Kind) != meta.Key {
				continue
			}
			total++
			switch finding.Status {
			case "static_confirmed":
				confirmed++
			case "refuted":
				refuted++
			default:
				inconclusive++
			}
		}
		b.WriteString("<tr><td>" + esc(meta.Label) + "</td><td>" + esc(meta.CWE) + "</td><td>" +
			strconv.Itoa(total) + "</td><td>" + strconv.Itoa(confirmed) + "</td><td>" +
			strconv.Itoa(inconclusive) + "</td><td>" + strconv.Itoa(refuted) + "</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString("<h2>4. 发现明细</h2>\n")
	sorted := make([]int, 0, len(state.findings.Findings))
	for i := range state.findings.Findings {
		sorted = append(sorted, i)
	}
	sort.Slice(sorted, func(a, z int) bool {
		return state.findings.Findings[sorted[a]].ID < state.findings.Findings[sorted[z]].ID
	})
	for position, index := range sorted {
		finding := state.findings.Findings[index]
		b.WriteString("<section class=\"finding\">\n")
		b.WriteString("<h3>4." + strconv.Itoa(position+1) + " " + esc(finding.ID) + "</h3>\n")
		b.WriteString("<p class=\"title\">" + esc(finding.Title) + "</p>\n<table><tbody>")
		rows := [][2]string{
			{"类型", finding.Kind},
			{"类别", finding.Category},
			{"CWE", finding.CWE},
			{"严重度", finding.Severity},
			{"状态", finding.Status},
			{"运行时状态", finding.RuntimeStatus},
		}
		if finding.Endpoint != nil {
			rows = append(rows,
				[2]string{"入口路径", finding.Endpoint.Path},
				[2]string{"HTTP 方法", strings.Join(finding.Endpoint.HTTPMethods, ", ")},
				[2]string{"控制器符号", finding.Endpoint.Symbol},
				[2]string{"文件", finding.Endpoint.File},
				[2]string{"行号", fmt.Sprintf("%d-%d", finding.Endpoint.StartLine, finding.Endpoint.EndLine)},
			)
		}
		if finding.Component != nil {
			rows = append(rows,
				[2]string{"模块", finding.Component.Module},
				[2]string{"依赖", finding.Component.Dependency},
				[2]string{"声明版本", finding.Component.DeclaredVersion},
				[2]string{"公告", finding.Component.AdvisoryID},
			)
		}
		for _, row := range rows {
			b.WriteString("<tr><th>" + esc(row[0]) + "</th><td>" + esc(row[1]) + "</td></tr>\n")
		}
		b.WriteString("</tbody></table>\n")
		if len(finding.Evidence) > 0 {
			b.WriteString("<h4>证据</h4>\n<ul>\n")
			for _, evidence := range finding.Evidence {
				item := evidence.Kind + " · " + evidence.Origin
				if evidence.File != "" {
					item += " · " + evidence.File + ":" + strconv.Itoa(evidence.StartLine) + "-" + strconv.Itoa(evidence.EndLine)
				}
				if evidence.Detail != "" {
					item += " — " + evidence.Detail
				}
				if evidence.OriginRef != "" {
					item += " [" + evidence.OriginRef + "]"
				}
				b.WriteString("<li>" + esc(item) + "</li>\n")
			}
			b.WriteString("</ul>\n")
		}
		if len(finding.Hypotheses) > 0 {
			b.WriteString("<h4>假设</h4>\n<ul>\n")
			for _, hypothesis := range finding.Hypotheses {
				item := hypothesis.ID + " [" + hypothesis.Status + "] " + hypothesis.Statement
				if hypothesis.Reason != "" {
					item += " — " + hypothesis.Reason
				}
				b.WriteString("<li>" + esc(item) + "</li>\n")
			}
			b.WriteString("</ul>\n")
		}
		if len(finding.Limitations) > 0 {
			b.WriteString("<h4>限制</h4>\n<ul>\n")
			for _, limitation := range finding.Limitations {
				b.WriteString("<li>" + esc(limitation) + "</li>\n")
			}
			b.WriteString("</ul>\n")
		}
		b.WriteString("</section>\n")
	}
	if len(sorted) == 0 {
		b.WriteString("<p>该快照没有发现。</p>\n")
	}

	b.WriteString("<h2>5. 统一限制</h2>\n<ul>\n")
	for _, limitation := range state.findings.Limitations {
		b.WriteString("<li>" + esc(limitation) + "</li>\n")
	}
	b.WriteString("</ul>\n")
	b.WriteString("<footer>" + esc(Product) + " · " + esc(version) + " · 确定性 HTML：无时间戳、无外部资源；同一快照与同一二进制的导出逐字节一致。</footer>\n")
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

func manifestHash(state *analysisState) string { return state.findings.SnapshotHash }

func boolText(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func esc(value string) string { return html.EscapeString(value) }

const styleBlock = `<style>
:root{color-scheme:light}
body{font:14px/1.55 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:0 auto;max-width:920px;padding:32px 24px 64px;color:#1d2430;background:#f6f7f9}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:36px 0 12px;border-bottom:1px solid #d9dee6;padding-bottom:6px}
h3{font-size:15px;margin:24px 0 8px}
h4{font-size:13px;margin:16px 0 6px;color:#4a5568}
p.sub,footer{color:#5a6472;font-size:12px}
table{border-collapse:collapse;width:100%;background:#fff;margin:8px 0 16px}
th,td{border:1px solid #d9dee6;padding:6px 10px;text-align:left;vertical-align:top;font-size:13px}
tbody th{width:190px;background:#eef1f5;font-weight:600}
thead th{background:#eef1f5}
ul{margin:4px 0 12px;padding-left:22px}
li{margin:3px 0}
.finding{background:#fff;border:1px solid #d9dee6;padding:4px 18px 14px;margin:14px 0}
footer{margin-top:48px;border-top:1px solid #d9dee6;padding-top:12px}
</style>
`
