/* TRIDENT read-only console. No build step, no external dependencies. */
(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const state = {
    token: sessionStorage.getItem("trident.token") || "",
    overview: null,
    route: "overview",
    findings: { items: [], total: 0, filtered: 0, counts: null, offset: 0, limit: 50, status: "all", category: "all", q: "", seq: 0, loading: false },
    endpoints: { items: [], total: 0, offset: 0, limit: 50, q: "", coverage: null, seq: 0, loading: false },
    source: { mode: "files", prefix: "", files: [], cursor: "", total: 0, path: "", line: 0, file: null, search: null, searchQ: "" },
    agent: { runs: [], openId: null, steps: [] },
    drawerId: null,
  };

  const routeMeta = {
    overview: { title: "概览", eyebrow: "TRIDENT / OVERVIEW" },
    findings: { title: "安全发现", eyebrow: "TRIDENT / FINDINGS" },
    endpoints: { title: "HTTP 入口", eyebrow: "TRIDENT / ENDPOINTS" },
    dependencies: { title: "依赖与公告", eyebrow: "TRIDENT / DEPENDENCIES" },
    tree: { title: "依赖树", eyebrow: "TRIDENT / DEPENDENCY TREE" },
    reachability: { title: "可达性", eyebrow: "TRIDENT / REACHABILITY" },
    runtime: { title: "运行时关联", eyebrow: "TRIDENT / RUNTIME CORRELATION" },
    agent: { title: "Agent 活动", eyebrow: "TRIDENT / AGENT OBSERVATION" },
    source: { title: "源码浏览", eyebrow: "TRIDENT / SOURCE" },
    about: { title: "边界与关于", eyebrow: "TRIDENT / SYSTEM" },
  };

  const statusMeta = {
    static_confirmed: { label: "静态确认", cls: "ok", dot: "ok" },
    inconclusive: { label: "证据待定", cls: "warn", dot: "warn" },
    refuted: { label: "已反驳", cls: "muted", dot: "" },
  };

  const severityLabel = { high: "高", medium: "中", low: "低", unknown: "未知", none: "无" };
  const hypothesisMeta = {
    supported: { label: "支持", cls: "ok" },
    unsupported: { label: "已反驳", cls: "bad" },
    unverified: { label: "未验证", cls: "warn" },
  };
  const kindLabels = {
    sql_injection: "SQL 注入",
    command_injection: "命令注入",
    ssrf: "服务端请求伪造",
    path_traversal: "路径遍历",
    template_injection: "模板注入",
    xss: "跨站脚本",
    deserialization: "不安全反序列化",
    xxe: "XML 外部实体",
    ldap_injection: "LDAP 注入",
    missing_authentication_or_authorization: "认证/授权缺失",
    vulnerable_dependency: "依赖漏洞候选",
  };
  const evidenceLabels = {
    route: "入口路由",
    source: "参数源",
    flow_step: "传播",
    sink: "危险汇点",
    protection: "防护",
    boundary: "未决边界",
    control_absence: "控制缺失",
    method: "方法",
    pom: "POM 声明",
    advisory: "公告",
  };
  const valueText = {
    not_available: "未实现",
    not_run: "未运行",
    unverified: "未验证",
    declaration_only: "仅声明级",
    bounded_lexical_multi_category: "有界词法 · 9 类汇点",
    single_parameter_multi_category_v9: "单参数多类别 v9",
    maven_declaration_only: "Maven 声明级",
    spring_mvc_annotation_inventory: "Spring MVC 注解清单",
    unified_finding_evidence_v1: "统一 Finding/Hypothesis v1",
  };
  const limitationTitles = {
    static_runtime_separation: "静态与运行时分离",
    sca_declaration_only: "SCA 仅声明级",
    advisory_exact_version_only: "公告仅精确版本",
    dependency_reachability_unverified: "依赖可达性未验证",
    endpoint_inventory_annotation_only: "入口为注解级",
    dataflow_bounded_lexical: "数据流为有界词法",
    absence_is_not_safety: "未观察到不等于安全",
    correlation_not_exploitation: "关联不等于可利用",
    lexical_flow_not_ast: "词法流非 AST",
    bounded_cross_method: "跨方法深度上限 8",
    route_inventory_from_annotation_audit: "路由来自注解清单",
    runtime_status_not_run: "运行时未执行",
    collection_taint_bounds: "集合传播边界",
    builder_and_format_bounds: "builder/format 边界",
    return_value_bounds: "返回值摘要边界",
    interface_inheritance_bounds: "接口继承分派边界",
    overload_and_parent_bounds: "重载与父类型边界",
    lambda_generic_varargs_bounds: "lambda/泛型/可变参数边界",
    deserialization_and_xss_bounds: "反序列化/XSS 边界",
    field_taint_bounds: "字段污点边界",
    non_sql_sink_observed_only: "非 SQL 汇点按观测生成",
    sql_sink_scope: "SQL 汇点范围",
    multi_category_sinks: "多类别汇点范围",
    no_java_source_found: "未发现 Java 源码",
    endpoint_inventory_partial: "入口清单部分覆盖",
    dataflow_report_partial: "数据流报告部分覆盖",
    sca_report_partial: "SCA 报告部分覆盖",
    advisory_catalog_not_provided: "未提供公告目录",
    nested_classes_skipped: "嵌套类已跳过",
    maven_not_executed: "未执行 Maven",
    transitive_dependencies_unavailable: "无传递依赖树",
    artifact_hashes_unavailable: "无制品哈希",
    source_callsites_not_analyzed: "未分析调用点",
    advisory_matching_disabled: "公告匹配未启用",
    advisory_matching_exact_versions_only: "公告仅精确版本",
    no_maven_pom_found: "未发现 POM",
    rejected_pom: "POM 被拒绝",
    parent_unresolved: "父 POM 未解析",
    parent_missing: "父 POM 缺失",
    parent_cycle: "父 POM 环",
    parent_coordinates_mismatch: "父坐标不匹配",
    duplicate_declaration: "重复声明",
    version_unresolved: "版本未解析",
  };

  const esc = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
  const fmtBytes = (n) => {
    if (!Number.isFinite(n)) return "—";
    if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + " GB";
    if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MB";
    if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KB";
    return n + " B";
  };
  const fmtNum = (n) => (Number.isFinite(n) ? n.toLocaleString("en-US") : "—");
  const shortHash = (hash) => (hash ? String(hash).slice(0, 12) : "—");
  const catKey = (kind) =>
    ({ sql_injection: "sql", command_injection: "command", path_traversal: "path", template_injection: "template", ldap_injection: "ldap", missing_authentication_or_authorization: "authz", vulnerable_dependency: "dependency" }[kind] || kind);
  const statusPill = (status) => {
    const meta = statusMeta[status] || { label: status || "未知", cls: "muted", dot: "" };
    return `<span class="status ${meta.cls}">${meta.dot ? '<span class="dot ' + meta.dot + '"></span>' : ""}${esc(meta.label)}</span>`;
  };
  const sevPill = (severity) => `<span class="sev ${esc(severity || "unknown")}">${esc(severityLabel[severity] || severity || "未知")}</span>`;
  const methodBadge = (method) => {
    const cls = ["get", "post", "put", "delete", "patch"].includes(String(method).toLowerCase()) ? String(method).toLowerCase() : "any";
    return `<span class="method ${cls}">${esc(method)}</span>`;
  };
  const methodsBadges = (methods) => `<span class="methods">${(methods && methods.length ? methods : ["ANY"]).map(methodBadge).join("")}</span>`;
  const valueLabel = (value) => valueText[value] || value || "—";

  function limitationRow(item) {
    const at = String(item).indexOf(":");
    const key = at > 0 ? String(item).slice(0, at) : String(item);
    const text = at > 0 ? String(item).slice(at + 1).trim() : "";
    const title = limitationTitles[key];
    return `<li class="limit-row"><svg class="icon"><use href="#i-info"/></svg><span><span class="limit-key">${esc(key)}</span>${title ? ` <b>${esc(title)}</b>` : ""}${text ? ` <span class="limit-text">${esc(text)}</span>` : ""}</span></li>`;
  }

  function limitationList(items) {
    if (!items || !items.length) return `<div class="empty"><svg class="icon"><use href="#i-check"/></svg><h4>没有额外限制记录</h4><p>报告未返回限制项；这不等于覆盖完整。</p></div>`;
    return `<ul class="limits">${items.map(limitationRow).join("")}</ul>`;
  }

  function emptyState(icon, title, text) {
    return `<div class="empty"><svg class="icon"><use href="#${icon}"/></svg><h4>${esc(title)}</h4><p>${esc(text)}</p></div>`;
  }

  function skeletonView() {
    return `<div class="sk sk-title"></div><div class="sk sk-card"></div><div class="sk sk-row mt-14"></div>`;
  }

  function toast(message, kind) {
    const el = $("#toast");
    el.textContent = message;
    el.className = "toast" + (kind ? " " + kind : "");
    el.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { el.hidden = true; }, 3200);
  }

  async function api(path, options = {}) {
    const headers = { "X-Trident-Request": "console" };
    const token = options.token !== undefined ? options.token : state.token;
    if (token) headers["X-Trident-Token"] = token;
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      credentials: "same-origin",
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });
    if (!response.ok) {
      let message = response.statusText;
      try {
        const payload = await response.json();
        message = payload.error || message;
      } catch { /* non-JSON error body */ }
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    if (response.status === 204) return null;
    return response.json();
  }

  function installChrome() {
    $("#exportBtn").addEventListener("click", exportReport);
    $("#exportHtmlBtn").addEventListener("click", exportHtmlReport);
    $("#themeToggle").addEventListener("click", toggleTheme);
    applyTheme(localStorage.getItem("trident.theme") || "dark");
    $("#mobileNav").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
    document.addEventListener("click", (event) => {
      const sidebar = $("#sidebar");
      if (!sidebar.classList.contains("open")) return;
      if (sidebar.contains(event.target) || $("#mobileNav").contains(event.target)) return;
      sidebar.classList.remove("open");
    });
    $("#drawerBackdrop").addEventListener("click", closeDrawer);
    $("#drawer").addEventListener("click", (event) => {
      const target = event.target.closest("[data-src]");
      if (target) {
        const line = Number(target.dataset.line || 1);
        closeDrawer();
        go("source", { path: target.dataset.src, line: line > 0 ? line : 1 });
      }
    });
    $("#drawer").addEventListener("click", (event) => {
      const copy = event.target.closest("[data-copy]");
      if (copy) {
        navigator.clipboard.writeText(copy.dataset.copy).then(() => toast("已复制到剪贴板", "ok")).catch(() => toast("复制失败", "bad"));
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        if (!$("#drawerLayer").hidden) closeDrawer();
        else $("#sidebar").classList.remove("open");
      }
      if (event.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
        const search = $("[data-search]");
        if (search && search.offsetParent !== null) {
          event.preventDefault();
          search.focus();
        }
      }
    });
    window.addEventListener("hashchange", renderRoute);
  }

  async function downloadArtifact(path, fallback) {
    const response = await fetch(path, {
      headers: { "X-Trident-Request": "console", ...(state.token ? { "X-Trident-Token": state.token } : {}) },
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error("导出失败：HTTP " + response.status);
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = /filename="([^"]+)"/.exec(disposition);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = match ? match[1] : fallback;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 4000);
  }

  async function exportReport() {
    try {
      await downloadArtifact("/api/report", "trident-findings.json");
      toast("证据报告已导出", "ok");
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  async function exportSARIF() {
    try {
      await downloadArtifact("/api/sarif", "trident.sarif");
      toast("SARIF 已导出", "ok");
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  async function exportHtmlReport() {
    try {
      await downloadArtifact("/export/report", "trident-report.html");
      toast("HTML 审阅报告已导出", "ok");
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  async function exportSBOM() {
    try {
      await downloadArtifact("/api/sbom", "trident-sbom.cdx.json");
      toast("CycloneDX SBOM 已导出", "ok");
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  // ── routing ────────────────────────────────────────────────────────────

  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, "");
    const split = raw.split("?");
    const name = routeMeta[split[0]] ? split[0] : "overview";
    return { name, params: new URLSearchParams(split[1] || "") };
  }

  function go(name, params) {
    const query = params ? "?" + new URLSearchParams(params).toString() : "";
    location.hash = "#/" + name + query;
  }

  async function renderRoute() {
    const { name, params } = parseHash();
    state.route = name;
    closeDrawer();
    $("#sidebar").classList.remove("open");
    $("#pageTitle").textContent = routeMeta[name].title;
    $("#pageEyebrow").textContent = routeMeta[name].eyebrow;
    document.title = "TRIDENT · " + routeMeta[name].title;
    $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.route === name));
    const view = $("#view");
    view.innerHTML = skeletonView();
    view.scrollTop = 0;
    try {
      if (name === "overview") await viewOverview();
      else if (name === "findings") await viewFindings();
      else if (name === "endpoints") await viewEndpoints();
      else if (name === "dependencies") await viewDependencies();
      else if (name === "tree") await viewTree();
      else if (name === "reachability") await viewReachability();
      else if (name === "runtime") await viewRuntime();
      else if (name === "agent") await viewAgent();
      else if (name === "source") await viewSource(params);
      else if (name === "about") await viewAbout();
    } catch (error) {
      if (error.status === 401) {
        showLogin("会话已失效，请重新输入访问令牌。");
        return;
      }
      renderFailure(error);
    }
  }

  function renderFailure(error) {
    $("#view").innerHTML = `<div class="card"><div class="empty"><svg class="icon"><use href="#i-alert"/></svg><h4>无法加载该视图</h4><p>${esc(error.message || "未知错误")}</p><button class="btn" type="button" id="retryView">重试</button></div></div>`;
    $("#retryView").addEventListener("click", renderRoute);
  }

  async function ensureOverview(force) {
    if (!state.overview || force) {
      state.overview = await api("/api/overview");
      updateChrome();
    }
    return state.overview;
  }

  function updateChrome() {
    const overview = state.overview;
    if (!overview) return;
    const version = overview.tool_version || "";
    const semver = (version.match(/(\d+\.\d+\.\d+[^\s+]*)/) || [])[1] || version;
    $("#footVersion").textContent = semver;
    $("#footVersion").title = version;
    $("#snapHash").textContent = shortHash(overview.snapshot.hash);
    $("#snapChip").title = overview.snapshot.hash;
    $("#statusHash").textContent = overview.snapshot.hash;
    $("#statusHash").title = overview.snapshot.hash;
    $("#statusAnalysis").textContent = `分析 ${overview.analysis.duration_ms} ms · ${new Date(overview.analysis.generated_at).toLocaleTimeString("zh-CN", { hour12: false })}`;
    const findingsBadge = $("#navFindings");
    findingsBadge.textContent = overview.counts.total;
    findingsBadge.hidden = overview.counts.total === 0;
    const endpointsBadge = $("#navEndpoints");
    endpointsBadge.textContent = overview.analysis.endpoint_coverage.endpoints_found;
    endpointsBadge.hidden = overview.analysis.endpoint_coverage.endpoints_found === 0;
  }

  // ── overview ───────────────────────────────────────────────────────────

  async function viewOverview() {
    const overview = await ensureOverview();
    const snap = overview.snapshot;
    const counts = overview.counts;
    const coverage = overview.coverage;
    const analysis = overview.analysis;
    $("#view").innerHTML = `
      <section class="hero">
        <div class="hero-copy">
          <span class="eyebrow">READ-ONLY STATIC EVIDENCE</span>
          <h2>供应链与源码安全态势</h2>
          <p>${esc(snap.source)} · ${fmtNum(snap.total_files)} 个文件 / ${fmtBytes(snap.total_bytes)}。所有结论均为静态证据，运行时状态始终保持 not_run。</p>
          <div class="hero-meta">
            <span class="chip mono"><svg class="icon icon-xs"><use href="#i-hash"/></svg>${esc(shortHash(snap.hash))}</span>
            <span class="chip"><span class="dot ${snap.partial ? "warn" : "ok"}"></span>${snap.partial ? "部分覆盖" : "完整清单"}</span>
            <span class="chip">${analysis.advisory_configured ? "公告目录已加载" : "未配置公告目录"}</span>
            <span class="chip">Java AST · ${esc(valueLabel(coverage.java_ast))}</span>
          </div>
        </div>
        <div class="hero-side">
          <div class="hero-badge"><strong>${fmtNum(counts.total)}</strong><span>FINDINGS</span></div>
          <span class="chip"><svg class="icon icon-xs"><use href="#i-clock"/></svg>${fmtNum(analysis.duration_ms)} ms</span>
        </div>
      </section>

      <div class="tiles">
        ${tile("folder", "teal", fmtNum(snap.total_files), "文件清单", `排除 ${fmtNum(snap.excluded_count)} 项`)}
        ${tile("route", "blue", fmtNum(analysis.endpoint_coverage.endpoints_found), "HTTP 入口", `${fmtNum(analysis.endpoint_coverage.controllers_found)} 个控制器`)}
        ${tile("bug", "rose", fmtNum(counts.total), "安全发现", `静态确认 ${fmtNum(counts.static_confirmed)}`)}
        ${tile("alert", "amber", fmtNum(counts.inconclusive), "证据待定", `已反驳 ${fmtNum(counts.refuted)}`)}
        ${tile("package", "violet", fmtNum(analysis.sca_coverage.dependencies_declared), "依赖声明", `${fmtNum(analysis.sca_coverage.poms_scanned)} 个 POM`)}
        ${tile("flag", "amber", fmtNum(coverage.sca_advisory_candidates), "公告命中", `未命中 ${fmtNum(coverage.sca_advisory_not_affected)}`)}
        ${tile("shield", "teal", snap.partial ? "部分" : "完整", "清单状态", "应用层只读快照")}
        ${tile("clock", "blue", fmtNum(analysis.duration_ms) + "ms", "分析耗时", new Date(analysis.generated_at).toLocaleTimeString("zh-CN", { hour12: false }))}
      </div>

      <div class="grid-2">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-grid"/></svg>发现构成</h3><span class="card-sub">静态状态分布</span></div>
          <div class="card-body">
            <div class="bar" id="compositionBar"></div>
            <div class="legend">
              <span class="legend-item"><span class="swatch ok"></span>静态确认 <b>${fmtNum(counts.static_confirmed)}</b></span>
              <span class="legend-item"><span class="swatch warn"></span>证据待定 <b>${fmtNum(counts.inconclusive)}</b></span>
              <span class="legend-item"><span class="swatch muted"></span>已反驳 <b>${fmtNum(counts.refuted)}</b></span>
            </div>
            <div class="kv mt-14">
              ${kvRow("假设支持 / 反驳 / 未验证", `${coverage.hypotheses_supported} / ${coverage.hypotheses_unsupported} / ${coverage.hypotheses_unverified}`, "good")}
              ${kvRow("数据流 Finding", fmtNum(coverage.dataflow_findings))}
              ${kvRow("入口清单", fmtNum(coverage.endpoints_inventoried))}
              ${kvRow("公告候选 / 未知", `${coverage.sca_advisory_candidates} / ${coverage.sca_advisory_unknown}`)}
            </div>
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-shield"/></svg>覆盖与门槛</h3><span class="card-sub">不是运行时结论</span></div>
          <div class="card-body">
            <div class="kv">
              ${kvRow("Java AST", valueLabel(coverage.java_ast), "warn")}
              ${kvRow("污点分析", valueLabel(coverage.taint_analysis))}
              ${kvRow("SCA 解析", valueLabel(coverage.sca_resolution))}
              ${kvRow("依赖可达性", valueLabel(coverage.dependency_reachability), "warn")}
              ${kvRow("运行时状态", valueLabel(coverage.runtime_status), "warn")}
              ${kvRow("入口文件扫描 / 拒绝", `${analysis.endpoint_coverage.java_files_scanned} / ${analysis.endpoint_coverage.java_files_rejected}`)}
              ${kvRow("POM 扫描 / 拒绝", `${analysis.sca_coverage.poms_scanned} / ${analysis.sca_coverage.poms_rejected}`)}
            </div>
          </div>
        </section>
      </div>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>漏洞类别</h3><span class="card-sub">点击类别筛选发现</span></div>
        <div class="card-body">
          <div class="category-grid">
            ${overview.categories.map(categoryCard).join("")}
          </div>
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-alert"/></svg>限制与边界</h3><span class="card-sub">${overview.limitations.length} 项</span></div>
        <div class="card-body">${limitationList(overview.limitations)}</div>
      </section>
    `;
    const bar = $("#compositionBar");
    const segments = [["ok", counts.static_confirmed], ["warn", counts.inconclusive], ["muted", counts.refuted]];
    segments.forEach(([cls, value]) => {
      if (!value) return;
      const segment = document.createElement("span");
      segment.className = "bar-seg " + cls;
      segment.style.width = (value / Math.max(counts.total, 1)) * 100 + "%";
      segment.title = `${value} 条`;
      bar.appendChild(segment);
    });
    $$("[data-category]", $("#view")).forEach((card) => {
      const select = () => {
        state.findings.category = card.dataset.category;
        state.findings.offset = 0;
        go("findings");
      };
      card.addEventListener("click", select);
      card.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          select();
        }
      });
    });
  }

  function tile(icon, tone, value, label, sub) {
    return `<div class="tile"><span class="tile-icon ${tone}"><svg class="icon"><use href="#i-${icon}"/></svg></span><div class="tile-body"><div class="tile-val">${esc(value)}</div><div class="tile-label">${esc(label)}</div><div class="tile-sub">${esc(sub)}</div></div></div>`;
  }

  function kvRow(key, value, tone) {
    return `<div class="kv-row"><span class="kv-key">${esc(key)}</span><span class="kv-val ${tone || ""}">${esc(value)}</span></div>`;
  }

  function categoryCard(category) {
    return `<div class="category" data-category="${esc(category.key)}" role="button" tabindex="0">
      <span class="cat-dot cat-${esc(category.key)}"></span>
      <span class="cat-name"><strong>${esc(category.label)}</strong><span>${esc(category.cwe)}</span></span>
      <span class="cat-count">${category.total}<small>确认 ${category.static_confirmed}</small></span>
    </div>`;
  }

  // ── findings ───────────────────────────────────────────────────────────

  async function viewFindings() {
    const overview = await ensureOverview();
    const findings = state.findings;
    $("#view").innerHTML = `
      <section class="card">
        <div class="toolbar">
          <div class="seg" id="statusSeg">
            ${[["all", "全部"], ["static_confirmed", "静态确认"], ["inconclusive", "证据待定"], ["refuted", "已反驳"]].map(([value, label]) => `<button type="button" data-status="${value}" class="${findings.status === value ? "active" : ""}">${label}</button>`).join("")}
          </div>
          <select class="select" id="categorySelect" aria-label="类别筛选">
            <option value="all">全部类别</option>
            ${overview.categories.map((category) => `<option value="${esc(category.key)}">${esc(category.label)} · ${category.total}</option>`).join("")}
          </select>
          <input class="input wide" id="findingSearch" data-search placeholder="搜索路径、参数、依赖或 CWE…" value="${esc(findings.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="findingCount">—</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>状态</th><th>类别</th><th>严重度</th><th>入口 / 组件</th><th>文件</th><th class="right">证据</th></tr></thead>
            <tbody id="findingRows"></tbody>
          </table>
        </div>
        <div class="pager">
          <span id="findingRange">—</span>
          <div class="pager-actions">
            <button class="btn" type="button" id="findingPrev"><svg class="icon"><use href="#i-chev-left"/></svg>上一页</button>
            <button class="btn" type="button" id="findingNext">下一页<svg class="icon"><use href="#i-chev-right"/></svg></button>
          </div>
        </div>
      </section>
    `;
    $("#categorySelect").value = findings.category;
    $("#statusSeg").addEventListener("click", (event) => {
      const button = event.target.closest("[data-status]");
      if (!button) return;
      findings.status = button.dataset.status;
      findings.offset = 0;
      $$("#statusSeg button").forEach((item) => item.classList.toggle("active", item === button));
      loadFindings();
    });
    $("#categorySelect").addEventListener("change", (event) => {
      findings.category = event.target.value;
      findings.offset = 0;
      loadFindings();
    });
    let timer = null;
    $("#findingSearch").addEventListener("input", (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        findings.q = event.target.value.trim();
        findings.offset = 0;
        loadFindings();
      }, 240);
    });
    $("#findingPrev").addEventListener("click", () => {
      findings.offset = Math.max(0, findings.offset - findings.limit);
      loadFindings();
    });
    $("#findingNext").addEventListener("click", () => {
      if (findings.offset + findings.limit < findings.filtered) {
        findings.offset += findings.limit;
        loadFindings();
      }
    });
    $("#findingRows").addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-id]");
      if (row) openFinding(row.dataset.id);
    });
    await loadFindings();
  }

  async function loadFindings() {
    const findings = state.findings;
    const seq = ++findings.seq;
    const rows = $("#findingRows");
    if (!rows) return;
    rows.innerHTML = Array.from({ length: 6 }, () => `<tr><td colspan="6"><div class="sk sk-row"></div></td></tr>`).join("");
    const params = new URLSearchParams({ limit: findings.limit, offset: findings.offset });
    if (findings.status !== "all") params.set("status", findings.status);
    if (findings.category !== "all") params.set("category", findings.category);
    if (findings.q) params.set("q", findings.q);
    try {
      const data = await api("/api/findings?" + params.toString());
      if (seq !== findings.seq) return;
      findings.items = data.items;
      findings.filtered = data.filtered;
      findings.total = data.total;
      $("#findingCount").textContent = `${fmtNum(data.filtered)} / ${fmtNum(data.total)} 条 · 静态确认 ${data.counts.static_confirmed}`;
      if (!data.items.length) {
        rows.innerHTML = `<tr><td colspan="6">${emptyState("i-bug", "没有匹配的发现", "调整状态、类别或搜索条件。未观察到路径不代表目标安全。")}</td></tr>`;
      } else {
        rows.innerHTML = data.items.map(findingRow).join("");
      }
      const start = data.filtered === 0 ? 0 : data.offset + 1;
      const end = Math.min(data.offset + data.items.length, data.filtered);
      $("#findingRange").textContent = `第 ${start}–${end} 条 / 共 ${fmtNum(data.filtered)} 条`;
      $("#findingPrev").disabled = data.offset === 0;
      $("#findingNext").disabled = data.offset + findings.limit >= data.filtered;
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      if (seq === findings.seq) {
        rows.innerHTML = `<tr><td colspan="6">${emptyState("i-alert", "加载失败", error.message)}</td></tr>`;
      }
    }
  }

  function findingRow(finding) {
    const where = finding.endpoint
      ? `<div class="id-cell"><strong class="mono">${esc(finding.endpoint.path)}</strong><span>${esc(finding.endpoint.symbol)}</span></div>`
      : `<div class="id-cell"><strong class="mono">${esc(finding.component ? finding.component.dependency : finding.category)}</strong><span>${esc(finding.component ? finding.component.advisory_id : finding.title)}</span></div>`;
    const location = finding.endpoint
      ? `${finding.endpoint.file}:${finding.endpoint.start_line}`
      : finding.component
        ? finding.component.declaration_pom
        : "—";
    return `<tr class="clickable" data-id="${esc(finding.id)}">
      <td>${statusPill(finding.status)}</td>
      <td><div class="id-cell"><strong>${esc(kindLabels[finding.kind] || finding.category)}</strong><span>${esc(finding.cwe)}</span></div></td>
      <td>${sevPill(finding.severity)}</td>
      <td>${where}</td>
      <td class="file" title="${esc(location)}">${esc(location)}</td>
      <td class="num">${finding.evidence_count}</td>
    </tr>`;
  }

  function displayTitle(finding) {
    const label = kindLabels[finding.kind] || finding.category;
    if (finding.kind === "vulnerable_dependency" && finding.component) {
      return `${finding.component.dependency} ${finding.component.declared_version || ""} 命中 ${finding.component.advisory_id}`.trim();
    }
    if (finding.endpoint) {
      const parameter = /parameter "([^"]+)"/.exec(finding.title || "");
      return `${label} · ${finding.endpoint.path}${parameter ? " 参数 " + parameter[1] : ""}`;
    }
    return finding.title;
  }

  async function openFinding(id) {
    state.drawerId = id;
    const layer = $("#drawerLayer");
    const drawer = $("#drawer");
    layer.hidden = false;
    drawer.innerHTML = `<div class="drawer-head"><div class="drawer-head-main"><span class="eyebrow">FINDING</span><h2>加载证据中…</h2></div><button class="icon-btn" type="button" data-close-drawer><svg class="icon"><use href="#i-x"/></svg></button></div><div class="drawer-body">${skeletonView()}</div>`;
    $("[data-close-drawer]", drawer).addEventListener("click", closeDrawer);
    try {
      const finding = await api("/api/finding?id=" + encodeURIComponent(id));
      if (state.drawerId !== id) return;
      drawer.innerHTML = drawerContent(finding);
      $("[data-close-drawer]", drawer).addEventListener("click", closeDrawer);
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      drawer.innerHTML = `<div class="drawer-head"><div class="drawer-head-main"><span class="eyebrow">FINDING</span><h2>无法加载详情</h2></div><button class="icon-btn" type="button" data-close-drawer><svg class="icon"><use href="#i-x"/></svg></button></div><div class="drawer-body">${emptyState("i-alert", "请求失败", error.message)}</div>`;
      $("[data-close-drawer]", drawer).addEventListener("click", closeDrawer);
    }
  }

  function closeDrawer() {
    state.drawerId = null;
    $("#drawerLayer").hidden = true;
    $("#drawer").innerHTML = "";
  }

  function drawerContent(finding) {
    const flow = finding.evidence.filter((item) => ["route", "source", "flow_step", "sink", "protection", "boundary"].includes(item.kind));
    return `
      <div class="drawer-head">
        <div class="drawer-head-main">
          <span class="eyebrow">${esc(finding.cwe)} · ${esc(kindLabels[finding.kind] || finding.kind)}</span>
          <h2>${esc(displayTitle(finding))}</h2>
          <div class="drawer-badges">
            ${statusPill(finding.status)}
            ${sevPill(finding.severity)}
            <span class="status muted">runtime ${esc(finding.runtime_status)}</span>
            ${finding.source_analyses.map((item) => `<span class="chip mono">${esc(item)}</span>`).join("")}
          </div>
        </div>
        <button class="icon-btn" type="button" data-close-drawer aria-label="关闭"><svg class="icon"><use href="#i-x"/></svg></button>
      </div>
      <div class="drawer-body">
        ${finding.endpoint ? `<section class="drawer-section"><h4><svg class="icon"><use href="#i-route"/></svg>入口</h4>
          <div class="evidence">
            <span class="evidence-kind">route</span>
            <span class="evidence-main">
              <div class="evidence-detail"><span class="mono">${esc(finding.endpoint.path)}</span> ${methodsBadges(finding.endpoint.http_methods)}</div>
              <div class="evidence-loc">${esc(finding.endpoint.symbol)}</div>
            </span>
            <button class="btn" type="button" data-src="${esc(finding.endpoint.file)}" data-line="${finding.endpoint.start_line}">打开源码</button>
          </div>
        </section>` : ""}
        ${finding.component ? `<section class="drawer-section"><h4><svg class="icon"><use href="#i-package"/></svg>依赖</h4>
          <div class="evidence">
            <span class="evidence-kind">component</span>
            <span class="evidence-main">
              <div class="evidence-detail mono">${esc(finding.component.dependency)} <b>${esc(finding.component.declared_version || "—")}</b></div>
              <div class="evidence-loc">advisory ${esc(finding.component.advisory_id)} · module ${esc(finding.component.module)}</div>
            </span>
          </div>
        </section>` : ""}
        <section class="drawer-section">
          <h4><svg class="icon"><use href="#i-route"/></svg>数据流</h4>
          ${flow.length ? `<ol class="flow">${flow.map((item) => `<li><div class="flow-kind">${esc(evidenceLabels[item.kind] || item.kind)}</div><div class="flow-detail">${esc(item.detail || "")}</div>${item.file ? `<div class="flow-loc">${esc(item.file)}${item.start_line ? ":" + item.start_line : ""}</div>` : ""}</li>`).join("")}</ol>` : emptyState("i-info", "没有结构化传播步骤", "该类发现只携带入口与组件证据，或传播步骤未进入统一模型。")}
        </section>
        <section class="drawer-section">
          <h4><svg class="icon"><use href="#i-bug"/></svg>证据</h4>
          <div class="evidence-list">${finding.evidence.map((item) => evidenceRow(item)).join("") || emptyState("i-info", "无证据", "报告未返回证据项。")}</div>
        </section>
        <section class="drawer-section">
          <h4><svg class="icon"><use href="#i-check"/></svg>假设</h4>
          ${finding.hypotheses.map(hypothesisCard).join("") || emptyState("i-info", "没有假设", "报告未返回假设项。")}
        </section>
        <section class="drawer-section">
          <h4><svg class="icon"><use href="#i-alert"/></svg>限制</h4>
          ${finding.limitations.length ? `<ul class="point-list">${finding.limitations.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>` : `<div class="card-sub">没有额外限制记录。</div>`}
        </section>
      </div>
      <div class="drawer-foot">
        <span class="mono">${esc(finding.id)}</span>
        <span class="flex-1"></span>
        <button class="btn ghost" type="button" data-copy="${esc(finding.id)}"><svg class="icon"><use href="#i-copy"/></svg>复制 ID</button>
      </div>`;
  }

  function evidenceRow(item) {
    const loc = item.file ? `${item.file}${item.start_line ? ":" + item.start_line + (item.end_line && item.end_line !== item.start_line ? "–" + item.end_line : "") : ""}` : item.origin;
    const attrs = item.file && item.start_line ? ` class="evidence clickable" data-src="${esc(item.file)}" data-line="${item.start_line}"` : ` class="evidence"`;
    return `<div${attrs}>
      <span class="evidence-kind">${esc(evidenceLabels[item.kind] || item.kind)}</span>
      <span class="evidence-main">
        <div class="evidence-detail">${esc(item.detail || item.kind)}</div>
        <div class="evidence-loc">${esc(loc)}${item.sha256 ? " · sha " + esc(item.sha256.slice(0, 12)) : ""}${item.anchor ? " · " + esc(item.anchor) : ""}</div>
      </span>
      ${item.file && item.start_line ? `<span class="evidence-arrow"><svg class="icon"><use href="#i-chev-right"/></svg></span>` : ""}
    </div>`;
  }

  function hypothesisCard(hypothesis) {
    const meta = hypothesisMeta[hypothesis.status] || { label: hypothesis.status, cls: "muted" };
    return `<div class="hypo">
      <div class="hypo-top"><p>${esc(hypothesis.statement)}</p><span class="status ${meta.cls}">${esc(meta.label)}</span></div>
      ${hypothesis.reason ? `<div class="hypo-meta">${esc(hypothesis.reason)}</div>` : ""}
      ${hypothesis.required_evidence && hypothesis.required_evidence.length ? `<div class="hypo-req">${hypothesis.required_evidence.map((item) => `<span class="req">${esc(item)}</span>`).join("")}</div>` : ""}
    </div>`;
  }

  // ── endpoints ──────────────────────────────────────────────────────────

  async function viewEndpoints() {
    const endpoints = state.endpoints;
    $("#view").innerHTML = `
      <section class="card">
        <div class="toolbar">
          <input class="input wide" id="endpointSearch" data-search placeholder="搜索路径、控制器、方法或文件…" value="${esc(endpoints.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="endpointCount">—</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>方法</th><th>路径</th><th>控制器方法</th><th>文件</th><th>参数绑定</th><th>路径状态</th></tr></thead>
            <tbody id="endpointRows"></tbody>
          </table>
        </div>
        <div class="pager">
          <span id="endpointRange">—</span>
          <div class="pager-actions">
            <button class="btn" type="button" id="endpointPrev"><svg class="icon"><use href="#i-chev-left"/></svg>上一页</button>
            <button class="btn" type="button" id="endpointNext">下一页<svg class="icon"><use href="#i-chev-right"/></svg></button>
          </div>
        </div>
      </section>
    `;
    let timer = null;
    $("#endpointSearch").addEventListener("input", (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        endpoints.q = event.target.value.trim();
        endpoints.offset = 0;
        loadEndpoints();
      }, 240);
    });
    $("#endpointPrev").addEventListener("click", () => {
      endpoints.offset = Math.max(0, endpoints.offset - endpoints.limit);
      loadEndpoints();
    });
    $("#endpointNext").addEventListener("click", () => {
      if (endpoints.offset + endpoints.limit < endpoints.total) {
        endpoints.offset += endpoints.limit;
        loadEndpoints();
      }
    });
    $("#endpointRows").addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-file]");
      if (row) go("source", { path: row.dataset.file, line: row.dataset.line });
    });
    await loadEndpoints();
  }

  async function loadEndpoints() {
    const endpoints = state.endpoints;
    const seq = ++endpoints.seq;
    const rows = $("#endpointRows");
    if (!rows) return;
    rows.innerHTML = Array.from({ length: 6 }, () => `<tr><td colspan="6"><div class="sk sk-row"></div></td></tr>`).join("");
    const params = new URLSearchParams({ limit: endpoints.limit, offset: endpoints.offset });
    if (endpoints.q) params.set("q", endpoints.q);
    try {
      const data = await api("/api/endpoints?" + params.toString());
      if (seq !== endpoints.seq) return;
      endpoints.items = data.items;
      endpoints.total = data.total;
      endpoints.coverage = data.coverage;
      $("#endpointCount").textContent = `${fmtNum(data.total)} 个入口 · 控制器 ${data.coverage.controllers_found}`;
      if (!data.items.length) {
        rows.innerHTML = `<tr><td colspan="6">${emptyState("i-route", "没有匹配的入口", "调整检索条件。注解级清单不证明路由已部署。")}</td></tr>`;
      } else {
        rows.innerHTML = data.items.map(endpointRow).join("");
      }
      const start = data.total === 0 ? 0 : data.offset + 1;
      const end = Math.min(data.offset + data.items.length, data.total);
      $("#endpointRange").textContent = `第 ${start}–${end} 条 / 共 ${fmtNum(data.total)} 条`;
      $("#endpointPrev").disabled = data.offset === 0;
      $("#endpointNext").disabled = data.offset + endpoints.limit >= data.total;
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      if (seq === endpoints.seq) rows.innerHTML = `<tr><td colspan="6">${emptyState("i-alert", "加载失败", error.message)}</td></tr>`;
    }
  }

  function endpointRow(endpoint) {
    const params = endpoint.parameters || [];
    const chips = params.slice(0, 3).map((parameter) => `<span class="param ${parameter.bindings && parameter.bindings.length ? "" : "unbound"}">${esc(parameter.name)}<b>${esc((parameter.bindings || []).join("/") || "unbound")}</b></span>`).join("");
    const more = params.length > 3 ? `<span class="param">+${params.length - 3}</span>` : "";
    const pathTone = endpoint.path_status === "resolved" ? "muted" : "warn";
    return `<tr class="clickable" data-file="${esc(endpoint.file)}" data-line="${endpoint.method_line || endpoint.start_line}">
      <td>${methodsBadges(endpoint.http_methods)}</td>
      <td class="path">${esc(endpoint.path)}</td>
      <td class="strong">${esc(endpoint.symbol)}</td>
      <td class="file" title="${esc(endpoint.file)}">${esc(endpoint.file)}:${endpoint.start_line}</td>
      <td>${chips}${more}</td>
      <td><span class="status ${pathTone}">${esc(endpoint.path_status || "—")}</span></td>
    </tr>`;
  }

  // ── dependencies ───────────────────────────────────────────────────────

  async function viewDependencies() {
    const data = await api("/api/dependencies");
    const report = data.report;
    const coverage = report.coverage;
    const project = report.project;
    const advisories = report.advisories || [];
    const matches = report.advisory_matches || [];
    const candidates = matches.filter((item) => item.finding_status === "candidate");
    $("#view").innerHTML = `
      ${coverage.advisories_loaded === 0 ? `<div class="banner warn"><svg class="icon"><use href="#i-alert"/></svg><span>未加载公告目录。依赖声明仍会被解析，但不会产生候选漏洞匹配。使用 <code>trident web --advisories &lt;file&gt;</code> 或 <code>audit findings --advisories</code> 显式指定本地固定公告。</span></div>` : ""}
      <div class="tiles">
        ${tile("package", "violet", fmtNum(coverage.dependencies_declared), "直接依赖声明", `${fmtNum(project.module_count)} 个模块`)}
        ${tile("layer", "blue", fmtNum(project.pom_count), "POM 文件", `${project.build_system}`)}
        ${tile("flag", "amber", fmtNum(candidates.length), "公告候选", `${fmtNum(advisories.length)} 条公告`)}
        ${tile("alert", "teal", fmtNum(coverage.dependencies_unresolved), "未解析版本", `拒绝 POM ${coverage.poms_rejected}`)}
      </div>
      <div class="grid-2">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>模块</h3><span class="card-sub">${fmtNum(project.module_count)} modules</span></div>
          <div class="card-body">
            ${report.modules.length ? `<div class="module-grid">${report.modules.map((module) => `<div class="module"><div class="module-top"><strong>${esc(module.artifact_id || module.directory)}</strong><span class="chip mono">${esc(module.packaging || "jar")}</span></div><div class="module-meta">${esc(module.group_id)} · ${esc(module.version || "未解析")}<br>${esc(module.pom)}${module.aggregator ? " · aggregator" : ""}</div></div>`).join("")}</div>` : emptyState("i-package", "未发现 Maven 模块", "快照中没有可解析的 pom.xml。")}
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-alert"/></svg>公告匹配</h3><span class="card-sub">精确版本 · 非可达性</span></div>
          <div class="card-body">
            ${matches.length ? matches.map((match) => `<div class="advisory ${match.finding_status === "candidate" ? "candidate" : ""}">
              <span class="status ${match.finding_status === "candidate" ? "warn" : "muted"}">${esc(match.finding_status)}</span>
              <span class="advisory-main"><strong>${esc(match.advisory_id)} · ${esc(match.dependency)} ${esc(match.declared_version || "—")}</strong><span>${esc(match.module)} · version ${esc(match.version_status)} · runtime ${esc(match.runtime_status)}</span></span>
            </div>`).join("") : emptyState("i-check", "没有公告匹配", "未加载公告目录、没有精确版本命中，或快照中没有 Maven 依赖。")}
          </div>
        </section>
      </div>
      <section class="card section-gap">
        <div class="card-head">
          <h3><svg class="icon"><use href="#i-package"/></svg>依赖声明</h3>
          <div class="card-head-actions">
            <span class="card-sub">仅 POM 声明级 · CycloneDX 1.5</span>
            <button class="btn sm ghost" id="exportSarifBtn" type="button" title="与 trident audit sarif 相同的 SARIF 2.1.0"><svg class="icon"><use href="#i-download"/></svg>SARIF</button>
            <button class="btn sm ghost" id="exportSbomBtn" type="button"><svg class="icon"><use href="#i-download"/></svg>导出 SBOM</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>模块</th><th>依赖</th><th>版本</th><th>Scope</th><th>版本状态</th><th>声明 POM</th></tr></thead>
            <tbody>
              ${report.dependencies.length ? report.dependencies.map((dependency) => `<tr>
                <td class="mono">${esc(dependency.module)}</td>
                <td class="strong mono">${esc(dependency.group_id)}:${esc(dependency.artifact_id)}</td>
                <td class="mono">${esc(dependency.version || "—")}</td>
                <td>${esc(dependency.scope || "—")}</td>
                <td><span class="status ${dependency.version_status === "resolved" ? "ok" : "warn"}">${esc(dependency.version_status)}</span></td>
                <td class="file">${esc(dependency.declaration_pom)}</td>
              </tr>`).join("") : `<tr><td colspan="6">${emptyState("i-package", "没有依赖声明", "快照中没有解析到 Maven dependency。")}</td></tr>`}
            </tbody>
          </table>
        </div>
      </section>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-shield"/></svg>SCA 边界</h3><span class="card-sub">transitive_tree = ${esc(coverage.transitive_tree)}</span></div>
        <div class="card-body">${limitationList(report.limitations)}</div>
      </section>
    `;
    $("#exportSbomBtn").addEventListener("click", exportSBOM);
    $("#exportSarifBtn").addEventListener("click", exportSARIF);
  }

  // ── tree / reachability / runtime / agent（只读扩展视图）────────────────

  async function viewTree() {
    const tree = await api("/api/tree");
    const renderNode = (node) => {
      if (node.external) {
        return `<li class="tree-leaf"><span class="chip mono" title="${esc(node.pom || "")}">${esc(node.name)}${node.version ? "@" + esc(node.version) : ""}</span>${node.cycle ? '<span class="status warn">环</span>' : ""}</li>`;
      }
      const children = (node.children || []).map(renderNode).join("");
      return `<li><div class="tree-node"><strong>${esc(node.name)}</strong>${node.version ? `<span class="chip mono">${esc(node.version)}</span>` : ""}${node.scope ? `<span class="chip">${esc(node.scope)}</span>` : ""}${node.cycle ? '<span class="status warn">循环依赖</span>' : ""}</div>${children ? `<ul class="tree-children">${children}</ul>` : ""}</li>`;
    };
    const cov = tree.coverage || {};
    $("#view").innerHTML = `
      <div class="card"><div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>声明级依赖树</h3>
        <span class="card-sub">${fmtNum(cov.modules || 0)} 模块 · ${fmtNum(cov.nodes || 0)} 节点 · ${fmtNum(cov.external_leaves || 0)} 外部依赖</span></div>
        <div class="card-body tight"><ul class="tree">${(tree.roots || []).map(renderNode).join("") || '<li class="code-empty">没有模块。</li>'}</ul></div></div>
      <div class="card section-gap"><div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>树覆盖与限制</h3></div><div class="card-body">
        <div class="kv">
          <div class="kv-row"><span class="kv-key">传递依赖树</span><span class="kv-val">${esc(cov.transitive_tree || "not_available")}</span></div>
          <div class="kv-row"><span class="kv-key">制品哈希</span><span class="kv-val">${esc(cov.artifact_hashes || "unavailable")}</span></div>
          <div class="kv-row"><span class="kv-key">循环依赖</span><span class="kv-val ${cov.cycles ? "warn" : "good"}">${fmtNum(cov.cycles || 0)}</span></div>
          <div class="kv-row"><span class="kv-key">runtime_status</span><span class="kv-val">${esc(tree.runtime_status || "not_run")}</span></div>
        </div>
        ${limitationList(tree.limitations || [])}
      </div></div>`;
  }

  async function viewReachability() {
    let report;
    try {
      report = await api("/api/reachability");
    } catch (error) {
      if (error.status === 412) {
        $("#view").innerHTML = `<div class="card"><div class="empty"><svg class="icon"><use href="#i-info"/></svg><h4>可达性视图未启用</h4><p>${esc(error.message)}</p><code class="mono">trident web ... --package-map package-map.json</code></div></div>`;
        return;
      }
      throw error;
    }
    const cov = report.coverage || {};
    const rows = (report.dependencies || []).map((item) => `
      <tr><td class="strong">${esc(item.module)}</td><td class="mono">${esc(item.dependency)}${item.version ? "@" + esc(item.version) : ""}</td>
      <td><span class="status ${item.reachability === "reachable" ? "ok" : item.reachability === "unreachable" ? "muted" : "warn"}">${esc(item.reachability)}</span></td>
      <td class="wrap">${esc(item.reason || "")}${(item.paths || []).length ? ` · ${item.paths.length} 条路径` : ""}</td></tr>`).join("");
    $("#view").innerHTML = `
      <div class="hero"><div class="hero-copy"><span class="eyebrow">BOUNDED ENTRY CALL GRAPH</span>
        <h2>依赖到入口有界可达性</h2>
        <p>入口 ${fmtNum(cov.entrypoints || 0)} · 类 ${fmtNum(cov.classes_indexed || 0)} · reachable ${fmtNum(cov.reachable || 0)} / unreachable ${fmtNum(cov.unreachable || 0)} / unknown ${fmtNum(cov.unknown || 0)}。三态都不证明类加载或运行时利用。</p></div></div>
      <div class="card section-gap"><div class="card-body tight"><div class="table-wrap"><table>
        <thead><tr><th>模块</th><th>依赖</th><th>可达性</th><th>依据</th></tr></thead><tbody>${rows}</tbody>
      </table></div></div></div>
      <div class="card section-gap"><div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>限制</h3></div><div class="card-body">${limitationList(report.limitations || [])}</div></div>`;
  }

  async function viewRuntime() {
    let report;
    try {
      report = await api("/api/runtime-report");
    } catch (error) {
      if (error.status === 412 || error.status === 404 || error.status === 422) {
        $("#view").innerHTML = `<div class="card"><div class="empty"><svg class="icon"><use href="#i-info"/></svg><h4>暂无运行时关联报告</h4><p>${esc(error.message)}</p><code class="mono">trident runtime http correlate --findings findings.json --runtime runtime.json --out correlate.json</code><p>然后在启动控制台时附加 --runtime-report correlate.json</p></div></div>`;
        return;
      }
      throw error;
    }
    const cov = report.coverage || {};
    $("#view").innerHTML = `
      <div class="hero"><div class="hero-copy"><span class="eyebrow">RUNTIME CORRELATION</span>
        <h2>静态发现 × 运行时结果关联</h2>
        <p>runtime_status=${esc(report.runtime_status || "not_run")} · 发现 ${fmtNum(cov.findings_total || 0)} · 运行时结果 ${fmtNum(cov.runtime_results || 0)} · 已关联 ${fmtNum(cov.correlated || 0)} / 歧义 ${fmtNum(cov.ambiguous || 0)} / 未关联 ${fmtNum(cov.not_correlated || 0)}。</p></div></div>
      <div class="card section-gap"><div class="card-head"><h3><svg class="icon"><use href="#i-hash"/></svg>关联报告原文</h3>
        <div class="card-head-actions"><button class="btn sm ghost" id="copyRuntimeJson" type="button"><svg class="icon"><use href="#i-copy"/></svg>复制 JSON</button></div></div>
        <div class="card-body"><pre class="code-view mono p-12" style="max-height:520px">${esc(JSON.stringify(report, null, 2))}</pre></div></div>`;
    $("#copyRuntimeJson").addEventListener("click", async () => {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      toast("报告 JSON 已复制", "ok");
    });
  }

  async function viewAgent() {
    let payload;
    try {
      payload = await api("/api/agent/runs");
    } catch (error) {
      if (error.status === 412) {
        $("#view").innerHTML = `<div class="card"><div class="empty"><svg class="icon"><use href="#i-server"/></svg><h4>Agent 观察未启用</h4><p>${esc(error.message)}</p><code class="mono">trident web ... --agent-dsn "postgres://trident_readonly:...@127.0.0.1:5432/trident?sslmode=disable"</code><p>Run 仍通过 CLI 启动；控制台只读观察，无执行入口。</p></div></div>`;
        return;
      }
      throw error;
    }
    const runState = (value) => ({cls: value === "running" ? "ok" : value === "done" ? "info" : value === "failed" || value === "timeout" ? "bad" : "muted", label: value});
    state.agent = {runs: payload.runs || [], openId: state.agent && state.agent.openId, steps: null};
    const rows = state.agent.runs.map((run) => `
      <tr class="clickable" data-run="${run.id}"><td class="strong mono">#${run.id}</td>
      <td class="wrap">${esc((run.goal || "").slice(0, 120))}</td>
      <td><span class="status ${runState(run.state).cls}">${esc(run.state)}</span></td>
      <td class="num">${fmtNum(run.model_calls)}/${fmtNum(run.limits && run.limits.max_model_calls)}</td>
      <td class="num">${fmtNum(run.tool_calls)}/${fmtNum(run.limits && run.limits.max_tool_calls)}</td>
      <td class="num">${fmtNum(run.tokens_used)}/${fmtNum(run.limits && run.limits.max_tokens)}</td>
      <td class="file">${esc((run.updated_at || "").replace("T", " ").slice(0, 19))}</td></tr>`).join("");
    $("#view").innerHTML = `
      <div class="hero"><div class="hero-copy"><span class="eyebrow">AGENT OBSERVATION (READ-ONLY)</span>
        <h2>Agent 活动时间线</h2>
        <p>最近 ${fmtNum(payload.total)} 个 Run 的只读观察视图；Run 通过 CLI 启动，控制台无任何执行入口。点击行查看 step 时间线。</p></div></div>
      <div class="card section-gap"><div class="card-body tight"><div class="table-wrap"><table>
        <thead><tr><th>Run</th><th>目标</th><th>状态</th><th class="right">模型调用</th><th class="right">工具调用</th><th class="right">Token</th><th>更新时间</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="code-empty">暂无 Agent Run。先用 CLI 启动一个：trident agent run --goal ... --snapshot ...</td></tr>'}</tbody>
      </table></div></div></div>
      <div id="agentRunDetail"></div>`;
    $$("tr[data-run]").forEach((row) => row.addEventListener("click", () => openAgentRun(Number(row.dataset.run))));
    if (state.agent.openId) await openAgentRun(state.agent.openId);
  }

  async function openAgentRun(runID) {
    const payload = await api("/api/agent/steps?run_id=" + runID);
    state.agent.openId = runID;
    state.agent.steps = payload.steps || [];
    const run = payload.run || {};
    const steps = state.agent.steps.map((step) => `
      <li><div class="tree-node"><span class="status info mono">#${step.seq}</span>
        <span class="chip mono">${esc(String(step.kind))}</span>
        <span class="chip">${esc((step.created_at || "").replace("T", " ").slice(0, 19))}</span></div>
      <div class="flow-detail mono" style="margin-top:4px">${esc(JSON.stringify(step.payload).slice(0, 300))}${JSON.stringify(step.payload).length > 300 ? "…" : ""}</div></li>`).join("");
    $("#agentRunDetail").innerHTML = `
      <div class="card mt-14"><div class="card-head"><h3><svg class="icon"><use href="#i-clock"/></svg>Run #${run.id} 时间线</h3>
        <span class="card-sub">${esc((run.goal || "").slice(0, 90))}</span></div>
        <div class="card-body"><div class="kv">
          <div class="kv-row"><span class="kv-key">状态 / 原因</span><span class="kv-val">${esc(run.state)} ${esc(run.reason || "")}</span></div>
          <div class="kv-row"><span class="kv-key">快照</span><span class="kv-val">${esc(shortHash(run.snapshot_hash || ""))}</span></div>
          <div class="kv-row"><span class="kv-key">预算消耗（模型/工具/Token）</span><span class="kv-val">${fmtNum(run.model_calls)}/${fmtNum(run.tool_calls)}/${fmtNum(run.tokens_used)}</span></div>
          <div class="kv-row"><span class="kv-key">最后事件序号</span><span class="kv-val">${fmtNum(run.last_seq)}</span></div>
        </div>
        <ul class="flow mt-14">${steps || '<li class="code-empty">该 Run 还没有 step。</li>'}</ul></div></div>`;
    const row = $(`tr[data-run="${runID}"]`);
    if (row) { $$("tr[data-run]").forEach((r) => r.classList.remove("active-row")); row.classList.add("active-row"); }
    $("#agentRunDetail").scrollIntoView({behavior: "smooth"});
  }

  // ── source workspace ───────────────────────────────────────────────────

  async function viewSource(params) {
    const path = params.get("path") || "";
    const line = Number(params.get("line") || 0);
    const source = state.source;
    if (path) {
      source.path = path;
      source.line = Number.isFinite(line) && line > 0 ? line : 1;
    }
    $("#view").innerHTML = `
      <div class="source-grid">
        <section class="panel files">
          <div class="panel-head">
            <h3>快照文件</h3>
            <div class="panel-tabs" id="sourceTabs">
              <button type="button" data-mode="files" class="${source.mode === "files" ? "active" : ""}">文件</button>
              <button type="button" data-mode="search" class="${source.mode === "search" ? "active" : ""}">检索</button>
            </div>
          </div>
          <div id="sourceLeft" class="source-left"></div>
        </section>
        <section class="panel code">
          <div id="codePanel" class="code-panel"></div>
        </section>
      </div>
    `;
    $("#sourceTabs").addEventListener("click", (event) => {
      const button = event.target.closest("[data-mode]");
      if (!button || button.dataset.mode === source.mode) return;
      source.mode = button.dataset.mode;
      $$("#sourceTabs button").forEach((item) => item.classList.toggle("active", item === button));
      renderSourceLeft();
    });
    $("#sourceLeft").addEventListener("click", (event) => {
      const file = event.target.closest("[data-file-path]");
      if (file) {
        openFile(file.dataset.filePath, 1);
        return;
      }
      const hit = event.target.closest("[data-hit-path]");
      if (hit) {
        openFile(hit.dataset.hitPath, Number(hit.dataset.hitLine));
        return;
      }
      const more = event.target.closest("[data-more]");
      if (more) loadMoreFiles();
    });
    renderSourceLeft();
    $("#codePanel").addEventListener("click", (event) => {
      const nav = event.target.closest("[data-page]");
      if (nav) {
        loadFileWindow(source.path, Number(nav.dataset.page));
        return;
      }
      const jump = event.target.closest("[data-jump]");
      if (jump) {
        const input = $("#jumpInput");
        const value = Number(input.value);
        if (Number.isFinite(value) && value > 0) openFile(source.path, value);
        return;
      }
      const searchShortcut = event.target.closest("[data-goto-search]");
      if (searchShortcut) {
        source.mode = "search";
        $$("#sourceTabs button").forEach((item) => item.classList.toggle("active", item.dataset.mode === "search"));
        renderSourceLeft();
      }
    });
    if (!source.files.length) await loadFiles();
    if (source.path) await openFile(source.path, source.line);
    else renderCodeEmpty();
  }

  function renderSourceLeft() {
    const source = state.source;
    const left = $("#sourceLeft");
    if (!left) return;
    if (source.mode === "search") {
      left.innerHTML = `
        <div class="panel-form">
          <input class="input" id="contentSearch" data-search placeholder="区分大小写的源码字面量…" value="${esc(source.searchQ)}" />
          <button class="btn" type="button" id="contentSearchBtn">搜索</button>
        </div>
        <div class="panel-body" id="searchBody">${source.search ? searchResults(source.search) : emptyState("i-search", "检索快照源码", "输入 1–256 字节的字面量。检索在已校验摘要的快照内进行，不会读取原目录。")}</div>
      `;
      $("#contentSearchBtn").addEventListener("click", runSearch);
      $("#contentSearch").addEventListener("keydown", (event) => { if (event.key === "Enter") runSearch(); });
      if (source.search) {
        const more = $("#searchMore");
        if (more) more.addEventListener("click", loadMoreSearch);
      }
    } else {
      left.innerHTML = `
        <div class="panel-form">
          <input class="input" id="filePrefix" placeholder="路径前缀，例如 src/main/java" value="${esc(source.prefix)}" />
          <button class="btn" type="button" id="fileRefresh">刷新</button>
        </div>
        <div class="panel-body" id="fileBody">${fileRows()}</div>
      `;
      $("#fileRefresh").addEventListener("click", () => {
        state.source.prefix = $("#filePrefix").value.trim();
        loadFiles(true);
      });
      $("#filePrefix").addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          state.source.prefix = event.target.value.trim();
          loadFiles(true);
        }
      });
    }
  }

  function fileRows() {
    const source = state.source;
    if (!source.files.length) return emptyState("i-folder", "没有文件", "快照清单为空或路径前缀无匹配。");
    return source.files.map((file) => `<button class="file-row ${file.path === source.path ? "active" : ""}" type="button" data-file-path="${esc(file.path)}" title="${esc(file.path)}">
      <svg class="icon"><use href="#i-file"/></svg><span>${esc(file.path)}</span><em class="mono">${fmtBytes(file.size)}</em>
    </button>`).join("") + (source.cursor ? `<div class="panel-form"><button class="btn block" type="button" data-more="1">加载更多（已 ${source.files.length} / ${source.total}）</button></div>` : `<div class="card-sub list-note">共 ${fmtNum(source.total)} 个文件</div>`);
  }

  async function loadFiles(reset) {
    const source = state.source;
    if (reset) {
      source.files = [];
      source.cursor = "";
      source.total = 0;
    }
    try {
      const params = new URLSearchParams({ limit: 100 });
      if (source.prefix) params.set("prefix", source.prefix);
      if (source.cursor) params.set("cursor", source.cursor);
      const data = await api("/api/files?" + params.toString());
      source.files = source.files.concat(data.entries || []);
      source.cursor = data.next_cursor || "";
      source.total = data.total;
      renderSourceLeft();
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      const left = $("#sourceLeft");
      if (left) left.innerHTML = emptyState("i-alert", "文件清单加载失败", error.message);
    }
  }

  function loadMoreFiles() {
    loadFiles(false);
  }

  async function openFile(path, line) {
    const start = line > 1 ? Math.max(1, line - 40) : 1;
    await fetchFile(path, start, line);
  }

  async function loadFileWindow(path, start) {
    await fetchFile(path, Math.max(1, start), Math.max(1, start));
    const code = $("#codeView");
    if (code) code.scrollTop = 0;
  }

  async function fetchFile(path, start, highlightLine) {
    const source = state.source;
    source.path = path;
    source.line = highlightLine;
    const panel = $("#codePanel");
    if (panel) panel.innerHTML = `<div class="p-18">${skeletonView()}</div>`;
    try {
      const data = await api(`/api/file?path=${encodeURIComponent(path)}&start_line=${start}&limit=200`);
      source.file = data;
      renderCode();
      $$(".file-row").forEach((row) => row.classList.toggle("active", row.dataset.filePath === path));
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      if (panel) panel.innerHTML = emptyState("i-alert", "读取失败", error.message);
    }
  }

  function renderCodeEmpty() {
    $("#codePanel").innerHTML = emptyState("i-code", "选择文件开始浏览", "左侧文件来自已校验摘要的快照清单，读取时再次校验大小与 SHA-256。");
  }

  function renderCode() {
    const source = state.source;
    const file = source.file;
    const panel = $("#codePanel");
    if (!panel || !file) return;
    if (file.binary) {
      panel.innerHTML = `<div class="code-head"><span class="code-path">${esc(file.path)}</span><span class="chips"><span class="chip mono">binary</span></span></div>${emptyState("i-file", "二进制文件", "二进制内容不进入源码视图；文件摘要仍通过清单校验。")}`;
      return;
    }
    const start = file.start_line || 1;
    const end = file.end_line || start;
    const lines = (file.lines || []).map((item) => `<div class="code-line ${item.number === source.line ? "hl" : ""}"><span class="code-ln">${item.number}</span><span class="code-lc">${esc(item.text)}</span></div>`).join("");
    panel.innerHTML = `
      <div class="code-head">
        <span class="code-path" title="${esc(file.path)}">${esc(file.path)}</span>
        <span class="chips">
          <span class="chip mono">${esc(file.sha256.slice(0, 12))}</span>
          <span class="chip">${fmtBytes(file.size)}</span>
          ${file.partial ? `<span class="chip"><span class="dot warn"></span>partial</span>` : ""}
        </span>
      </div>
      <div class="code-toolbar">
        <button class="btn" type="button" data-page="${Math.max(1, start - 200)}" ${start <= 1 ? "disabled" : ""}>上一页</button>
        <button class="btn" type="button" data-page="${Math.min(file.total_lines || end + 1, end + 1)}" ${end >= (file.total_lines || 0) ? "disabled" : ""}>下一页</button>
        <span class="spacer"></span>
        <span class="card-sub mono">${start}–${end} / ${file.total_lines}</span>
        <span class="jump"><input class="input" id="jumpInput" type="number" min="1" placeholder="行号"><button class="btn" type="button" data-jump="1">跳转</button></span>
        <button class="btn ghost" type="button" data-goto-search="1"><svg class="icon"><use href="#i-search"/></svg>检索</button>
      </div>
      <div class="code-view" id="codeView">${lines || `<div class="code-empty">文件为空。</div>`}</div>
    `;
    const view = $("#codeView");
    if (view && source.line >= start && source.line <= end) {
      const line = $(".code-line.hl", view);
      if (line) {
        const delta = line.getBoundingClientRect().top - view.getBoundingClientRect().top;
        view.scrollTop += delta - view.clientHeight / 2;
      }
    }
  }

  async function runSearch() {
    const input = $("#contentSearch");
    if (!input) return;
    const query = input.value.trim();
    if (!query) { toast("请输入检索字面量", "bad"); return; }
    if (query.length > 256) { toast("检索字面量最多 256 字节", "bad"); return; }
    state.source.searchQ = query;
    state.source.search = null;
    const body = $("#searchBody");
    if (body) body.innerHTML = `<div class="p-12">${skeletonView()}</div>`;
    try {
      const data = await api(`/api/search?q=${encodeURIComponent(query)}&limit=50`);
      state.source.search = data;
      state.source.searchCursor = data.next_cursor || "";
      renderSourceLeft();
      $("#contentSearch").value = query;
      $("#contentSearch").focus();
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      const body = $("#searchBody");
      if (body) body.innerHTML = emptyState("i-alert", "检索失败", error.message);
      toast(error.message, "bad");
    }
  }

  function searchResults(data) {
    if (!data.matches.length) return emptyState("i-search", "没有匹配", `未在 ${fmtNum(data.scanned_files)} 个文件中找到该字面量。部分或跳过结果不证明不存在。`);
    return `<div class="card-sub list-note">${fmtNum(data.matches.length)} 条命中 · 扫描 ${fmtNum(data.scanned_files)} 文件</div>` +
      data.matches.map((match) => `<button class="search-hit" type="button" data-hit-path="${esc(match.path)}" data-hit-line="${match.line}">
        <span class="hit-path"><svg class="icon icon-xs"><use href="#i-file"/></svg>${esc(match.path)}<span class="hit-line">:${match.line}</span></span>
        <span class="hit-text">${highlight(match.text, state.source.searchQ)}</span>
      </button>`).join("") +
      (data.next_cursor ? `<div class="panel-form"><button class="btn block" type="button" id="searchMore">加载更多</button></div>` : "");
  }

  async function loadMoreSearch() {
    const data = state.source.search;
    if (!data || !data.next_cursor) return;
    try {
      const next = await api(`/api/search?q=${encodeURIComponent(state.source.searchQ)}&limit=50&cursor=${encodeURIComponent(data.next_cursor)}`);
      next.matches = data.matches.concat(next.matches);
      next.scanned_files += data.scanned_files;
      state.source.search = next;
      renderSourceLeft();
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  function highlight(text, query) {
    const index = query ? text.indexOf(query) : -1;
    if (index < 0) return esc(text);
    return esc(text.slice(0, index)) + "<mark>" + esc(text.slice(index, index + query.length)) + "</mark>" + esc(text.slice(index + query.length));
  }

  // ── about ──────────────────────────────────────────────────────────────

  async function viewAbout() {
    const overview = await ensureOverview();
    const snap = overview.snapshot;
    const analysis = overview.analysis;
    const tools = analysis.tool_versions;
    $("#view").innerHTML = `
      <div class="about-grid">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-shield"/></svg>产品与构建</h3><span class="card-sub">${esc(overview.product)}</span></div>
          <div class="card-body">
            <div class="kv">
              ${kvRow("构建版本", overview.tool_version)}
              ${kvRow("报告 Schema", "v" + overview.schema_version)}
              ${kvRow("进程启动", new Date(overview.started_at).toLocaleString("zh-CN", { hour12: false }))}
              ${kvRow("分析生成", new Date(analysis.generated_at).toLocaleString("zh-CN", { hour12: false }) + " · " + analysis.duration_ms + "ms")}
              ${kvRow("分析类型", valueLabel(analysis.analysis_kind))}
            </div>
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-hash"/></svg>固定快照</h3><span class="card-sub">应用层只读</span></div>
          <div class="card-body">
            <div class="kv">
              ${kvRow("SHA-256", snap.hash)}
              ${kvRow("源目录", snap.source)}
              ${kvRow("Manifest / Policy", "v" + snap.manifest + " / " + snap.policy_version)}
              ${kvRow("文件 / 字节", fmtNum(snap.total_files) + " / " + fmtBytes(snap.total_bytes))}
              ${kvRow("排除项", fmtNum(snap.excluded_count))}
              ${kvRow("清单状态", snap.partial ? "partial" : "complete", snap.partial ? "warn" : "good")}
            </div>
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>分析工具链</h3><span class="card-sub">全部离线</span></div>
          <div class="card-body">
            <div class="kv">
              ${kvRow("findings（证据模型）", tools.findings)}
              ${kvRow("sca（声明级）", tools.sca)}
              ${kvRow("audit（入口清单）", tools.audit)}
              ${kvRow("dataflow（有界流）", tools.dataflow)}
              ${kvRow("Java AST", valueLabel(analysis.java_ast), "warn")}
              ${kvRow("依赖可达性", valueLabel(analysis.dependency_reachability), "warn")}
              ${kvRow("运行时验证", valueLabel(analysis.runtime_status), "warn")}
            </div>
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-alert"/></svg>安全边界</h3><span class="card-sub">控制台不做什么</span></div>
          <div class="card-body">
            <ul class="about-list">
              <li><svg class="icon"><use href="#i-check"/></svg><span>只读已 pin 的快照；不导入源码、不写原目录、不执行 Java/Maven。</span></li>
              <li><svg class="icon"><use href="#i-check"/></svg><span>不调用任何模型、不访问网络目标；没有 Agent 控制或审批 API。</span></li>
              <li><svg class="icon"><use href="#i-check"/></svg><span>静态 finding 与 runtime_status 分离：所有结论保持 not_run。</span></li>
              <li><svg class="icon"><use href="#i-check"/></svg><span>缺少证据只表示 inconclusive；absence_is_not_safety。</span></li>
              <li><svg class="icon"><use href="#i-check"/></svg><span>仅监听 loopback；访问令牌 + SameSite=Strict Cookie + CSP + nosniff。</span></li>
            </ul>
          </div>
        </section>
      </div>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-server"/></svg>只读 API</h3><span class="card-sub">需要 console header 与令牌</span></div>
        <div class="card-body">
          ${apiRow("GET", "/api/overview", "快照、覆盖与类别统计")}
          ${apiRow("GET", "/api/findings", "筛选与分页的发现摘要")}
          ${apiRow("GET", "/api/finding?id=", "单一发现完整证据")}
          ${apiRow("GET", "/api/endpoints", "Spring MVC 注解入口")}
          ${apiRow("GET", "/api/dependencies", "Maven 声明与公告匹配")}
          ${apiRow("GET", "/api/files · /api/file", "清单与逐行源码读取")}
          ${apiRow("GET", "/api/search", "快照内字面量检索")}
          ${apiRow("GET", "/api/report", "下载统一证据 JSON")}
          ${apiRow("GET", "/api/sbom", "下载 CycloneDX 1.5 JSON")}
          ${apiRow("GET", "/api/tree", "声明级依赖树")}
          ${apiRow("GET", "/api/reachability", "有界可达性（需 --package-map）")}
          ${apiRow("GET", "/api/sarif", "下载 SARIF 2.1.0")}
          ${apiRow("GET", "/api/runtime-report", "运行时关联报告（需 --runtime-report）")}
          ${apiRow("GET", "/api/agent/runs", "Agent Run 列表（需 --agent-dsn，只读观察）")}
          ${apiRow("GET", "/api/agent/steps", "Run step 时间线（只读观察）")}
          ${apiRow("GET", "/api/metrics", "只读运维计数器")}
          ${apiRow("GET", "/metrics", "Prometheus 文本格式抓取端点")}
          ${apiRow("GET", "/export/report", "下载确定性 HTML 审阅报告")}
        </div>
      </section>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>限制</h3><span class="card-sub">${overview.limitations.length} 项</span></div>
        <div class="card-body">${limitationList(overview.limitations)}</div>
      </section>
      <div class="card-sub about-foot">${esc(overview.product)} · ${esc(overview.tool_version)}</div>
    `;
  }

  function apiRow(method, path, description) {
    return `<div class="api-row"><span class="api-method">${esc(method)}</span><span class="api-path">${esc(path)}</span><span class="api-desc">${esc(description)}</span></div>`;
  }

  // ── login & boot ───────────────────────────────────────────────────────

  function showLogin(message, hint) {
    $("#app").hidden = true;
    $("#login").hidden = false;
    const error = $("#loginError");
    if (message) {
      error.textContent = message;
      error.className = "login-error" + (hint ? " hint" : "");
      error.hidden = false;
    } else {
      error.hidden = true;
    }
    setTimeout(() => $("#tokenInput").focus(), 30);
  }

  async function submitLogin() {
    const input = $("#tokenInput");
    const token = input.value.trim();
    const error = $("#loginError");
    if (!token) {
      error.textContent = "请输入访问令牌。";
      error.hidden = false;
      return;
    }
    const button = $("#loginBtn");
    button.disabled = true;
    button.textContent = "验证中…";
    try {
      await api("/api/session", { method: "POST", body: { token }, token: "" });
      state.token = token;
      sessionStorage.setItem("trident.token", token);
      $("#login").hidden = true;
      $("#app").hidden = false;
      input.value = "";
      await ensureOverview(true);
      if (!location.hash) location.hash = "#/overview";
      else await renderRoute();
    } catch (failure) {
      error.textContent = failure.status === 401 ? "令牌不正确，请检查终端输出。" : failure.message;
      error.hidden = false;
      input.select();
    } finally {
      button.disabled = false;
      button.textContent = "进入控制台";
    }
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    localStorage.setItem("trident.theme", next);
    applyTheme(next);
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const toggle = $("#themeToggle");
    if (toggle) {
      toggle.title = theme === "light" ? "切换到暗色主题" : "切换到亮色主题";
      toggle.innerHTML = `<svg class="icon"><use href="#${theme === "light" ? "i-moon" : "i-sun"}"/></svg>`;
    }
  }

  async function boot() {
    installChrome();
    $("#toggleToken").addEventListener("click", () => {
      const input = $("#tokenInput");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("#toggleToken").innerHTML = `<svg class="icon"><use href="#${show ? "i-eye-off" : "i-eye"}"/></svg>`;
    });
    $("#loginBtn").addEventListener("click", submitLogin);
    $("#tokenInput").addEventListener("keydown", (event) => { if (event.key === "Enter") submitLogin(); });
    try {
      await api("/api/health");
      $("#login").hidden = true;
      $("#app").hidden = false;
      await ensureOverview();
      if (!location.hash) {
        location.hash = "#/overview";
      } else {
        await renderRoute();
      }
    } catch (error) {
      if (error.status === 401) showLogin("输入启动 trident web 时打印的访问令牌。", true);
      else showLogin("控制台服务不可用：" + error.message);
    }
  }

  boot();
})();
