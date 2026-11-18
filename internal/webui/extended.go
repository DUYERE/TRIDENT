package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"trident/internal/correlate"
	"trident/internal/reach"
	"trident/internal/sarif"
	"trident/internal/sca"
)

// 扩展只读视图：把 CLI 侧已生成的只读结论搬到 Web（观察模式）。
// 不新增分析语义，不提供任何执行/修复入口；Agent 数据是只读观察。

// runtimeReportMaxBytes bounds the caller-supplied correlation report file.
const runtimeReportMaxBytes = 64 << 20

// handleTree serves the declaration dependency tree from the cached SCA run.
func (c *Console) handleTree(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sca.Tree(state.sca))
}

// handleSARIF serves the same SARIF the CLI emits, derived from the cached
// findings report.
func (c *Console) handleSARIF(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	document, err := sarif.Build(state.findings, c.version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sarif_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"trident.sarif\"")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(document)
}

// handleReachability runs the bounded reachability engine over the snapshot
// when a package map is configured. Result is cached like the analysis state
// and dropped whenever the configuration or the snapshot changes.
func (c *Console) handleReachability(w http.ResponseWriter, r *http.Request) {
	cfg := c.currentConfig()
	c.reachMu.Lock()
	defer c.reachMu.Unlock()
	if c.reachState == nil {
		report, err := reach.Inspect(r.Context(), c.snapshotRef(), reach.Options{PackageMapPath: cfg.PackageMapPath})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "reachability_failed", err.Error())
			return
		}
		c.reachState = &report
	}
	writeJSON(w, http.StatusOK, *c.reachState)
}

// handleRuntimeReport serves a caller-supplied correlation report produced by
// `runtime http correlate --out`; the console never executes runtime checks.
func (c *Console) handleRuntimeReport(w http.ResponseWriter, _ *http.Request) {
	cfg := c.currentConfig()
	if cfg.RuntimeReport == "" {
		writeError(w, http.StatusPreconditionFailed, "runtime_report_missing",
			"未配置运行时关联报告：在设置页填写 correlate 报告路径后即可显示")
		return
	}
	data, err := os.ReadFile(cfg.RuntimeReport)
	if err != nil {
		writeError(w, http.StatusNotFound, "runtime_report_unreadable", err.Error())
		return
	}
	if len(data) > runtimeReportMaxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "runtime_report_too_large", "report exceeds 64 MiB")
		return
	}
	var report correlate.Report
	if err := json.Unmarshal(data, &report); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "runtime_report_invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// handleAgentSteps serves one run with its step timeline.
func (c *Console) handleAgentSteps(w http.ResponseWriter, r *http.Request) {
	if c.agentStore == nil {
		writeError(w, http.StatusPreconditionFailed, "agent_database_missing",
			"未连接 Agent 会话库：在「设置 → Agent 与编排」填写连接串并保存即可立即接入，无需重启")
		return
	}
	runID, err := strconv.ParseInt(r.URL.Query().Get("run_id"), 10, 64)
	if err != nil || runID < 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "run_id must be a positive integer")
		return
	}
	run, err := c.agentStore.GetAgentRunReadOnly(r.Context(), runID)
	if err != nil {
		writeError(w, http.StatusNotFound, "run_not_found", "no such run")
		return
	}
	limit := 500
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil && parsed >= 1 && parsed <= 1000 {
			limit = parsed
		}
	}
	steps, err := c.agentStore.ListAgentStepsReadOnly(r.Context(), runID, 0, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_query_failed", err.Error())
		return
	}
	// Usage is derived from committed provider usage, never invented. It is
	// returned alongside the timeline so the console can show a bounded cost
	// estimate without a second round trip.
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "steps": steps, "usage": c.runUsageOf(run, steps)})
}
