/* TRIDENT read-only console. No build step, no external dependencies. */
(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const state = {
    token: sessionStorage.getItem("trident.token") || "",
    overview: null,
    route: "overview",
    findings: { items: [], total: 0, filtered: 0, counts: null, severities: [], offset: 0, limit: 50, status: "all", category: "all", severity: "all", q: "", seq: 0, loading: false },
    endpoints: { items: [], total: 0, offset: 0, limit: 50, q: "", authz: "all", authzMap: {}, authzCounts: null, coverage: null, seq: 0, loading: false },
    authz: { items: [], total: 0, offset: 0, limit: 50, q: "", decision: "all", limitations: [], seq: 0 },
    model: { items: [], total: 0, offset: 0, limit: 50, q: "", seq: 0 },
    config: null,
    modelSettings: null,
    browse: { path: "", parent: "", entries: [], roots: [], pick: "" },
    source: { mode: "files", prefix: "", files: [], cursor: "", total: 0, path: "", line: 0, file: null, search: null, searchQ: "" },
    agent: { chat: null, threads: [], openId: 0, steps: [], run: null, busy: false, timer: null, lastSeq: 0 },
    drawerId: null,
  };

  const routeMeta = {
    projects: { title: "项目", eyebrow: "TRIDENT / PROJECTS" },
    overview: { title: "概览", eyebrow: "TRIDENT / OVERVIEW" },
    findings: { title: "安全发现", eyebrow: "TRIDENT / FINDINGS" },
    endpoints: { title: "HTTP 入口", eyebrow: "TRIDENT / ENDPOINTS" },
    dependencies: { title: "依赖与公告", eyebrow: "TRIDENT / DEPENDENCIES" },
    tree: { title: "依赖树", eyebrow: "TRIDENT / DEPENDENCY TREE" },
    reachability: { title: "可达性", eyebrow: "TRIDENT / REACHABILITY" },
    authz: { title: "权限清单", eyebrow: "TRIDENT / AUTHORIZATION" },
    model: { title: "代码模型", eyebrow: "TRIDENT / JAVA MODEL" },
    runtime: { title: "运行时关联", eyebrow: "TRIDENT / RUNTIME CORRELATION" },
    agent: { title: "Agent 对话", eyebrow: "TRIDENT / AGENT CHAT" },
    source: { title: "源码浏览", eyebrow: "TRIDENT / SOURCE" },
    settings: { title: "设置", eyebrow: "TRIDENT / SETTINGS" },
    "settings-model": { title: "模型", eyebrow: "TRIDENT / SETTINGS / MODEL" },
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
    context_path_unknown: "上下文路径未知",
    custom_auth_not_modeled: "自定义鉴权未建模",
    filter_chain_order_bounded: "过滤器链顺序有界",
    filter_chain_rule_order_bounded: "链内规则顺序有界",
    lexical_control_inventory_not_ast: "控制清单为词法级",
    manual_session_checks_are_unknown: "手工会话检查记为未知",
    spel_subset_only: "SpEL 仅支持子集",
    unprotected_is_inconclusive: "无控制不等于可未授权访问",
    unresolved_controls_present: "存在未解析控制",
    annotation_arguments_bounded: "注解参数有界",
    java_subset_parser: "受限 Java 子集解析",
    java_declarations_only: "仅声明级语义",
    constant_folding_bounded: "常量折叠有界",
    reflection_not_resolved: "反射未解析",
    dynamic_proxy_and_aop_not_resolved: "动态代理/AOP 未解析",
    external_types_not_resolved: "外部类型未解析",
    classpath_not_resolved: "classpath 未解析",
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
    if (title) {
      return `<li class="limit-row"><svg class="icon"><use href="#i-info"/></svg><span><b>${esc(title)}</b>${text ? ` <span class="limit-text trunc" title="${esc(text)}">${esc(text)}</span>` : ""}<span class="limit-key">${esc(key)}</span></span></li>`;
    }
    return `<li class="limit-row"><svg class="icon"><use href="#i-info"/></svg><span><span class="limit-key">${esc(key)}</span>${text ? ` <span class="limit-text">${esc(text)}</span>` : ""}</span></li>`;
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
    // Collapsible rail: icon-only mode persists across reloads.
    const applyNav = (mode) => {
      document.body.dataset.nav = mode;
      const toggle = $("#navCollapse");
      if (toggle) {
        toggle.title = mode === "collapsed" ? "展开侧边栏" : "收起侧边栏";
        toggle.setAttribute("aria-label", toggle.title);
      }
    };
    applyNav(localStorage.getItem("trident.nav") === "collapsed" ? "collapsed" : "expanded");
    $("#navCollapse").addEventListener("click", () => {
      const next = document.body.dataset.nav === "collapsed" ? "expanded" : "collapsed";
      localStorage.setItem("trident.nav", next);
      applyNav(next);
    });
    // Settings group: parent only toggles; navigation goes through its children.
    const applySettings = (open) => {
      document.body.dataset.settings = open ? "open" : "closed";
      localStorage.setItem("trident.settings", open ? "open" : "closed");
    };
    applySettings(localStorage.getItem("trident.settings") !== "closed");
    // Collapsed rail keeps icons only, so each item needs a hover label.
    $$(".nav-item").forEach((item) => {
      const label = $("span", item);
      if (label) item.title = label.textContent.trim();
    });
    $$(".nav-parent").forEach((parent) => {
      parent.addEventListener("click", (event) => {
        event.preventDefault();
        applySettings(document.body.dataset.settings !== "open");
      });
    });
    $("#projectSwitcher").addEventListener("change", async (event) => {
      const hash = event.target.value;
      if (!hash || hash === (state.config && state.config.project.hash)) return;
      try {
        await api("/api/projects/select", { method: "POST", body: { hash } });
        resetAnalysisState();
        await ensureConfig(true);
        await refreshProjectSwitcher();
        toast("已切换项目", "ok");
        await renderRoute();
      } catch (error) {
        toast(error.message, "bad");
        await refreshProjectSwitcher();
      }
    });
    $("#exportBtn").addEventListener("click", exportReport);
    $("#exportHtmlBtn").addEventListener("click", exportHtmlReport);
    $("#themeToggle").addEventListener("click", toggleTheme);
    const loginTheme = $("#loginThemeToggle") || $(".login-theme");
    if (loginTheme) loginTheme.addEventListener("click", toggleTheme);
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
    // The chat view renders [data-copy] outside the drawer; delegate once.
    document.addEventListener("click", (event) => {
      const copy = event.target.closest("[data-copy]");
      if (!copy || copy.closest("#drawer")) return;
      navigator.clipboard.writeText(copy.dataset.copy).then(() => toast("已复制到剪贴板", "ok")).catch(() => toast("复制失败", "bad"));
    });
    document.addEventListener("keydown", (event) => {
      if ((event.key === "Enter" || event.key === " ") && event.target.matches && event.target.matches("tr.clickable")) {
        event.preventDefault();
        event.target.click();
        return;
      }
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
    let name = split[0];
    if (!routeMeta[name] && routeMeta[name.replace(/\//g, "-")]) name = name.replace(/\//g, "-");
    if (!routeMeta[name]) name = "overview";
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
    $$(".nav-item").forEach((item) => {
      const route = item.dataset.route;
      const active = route === name || (route === "settings" && name === "settings-model" && !item.classList.contains("nav-parent"));
      item.classList.toggle("active", active);
    });
    const settingsParent = $(".nav-parent[data-group=settings]");
    if (settingsParent) settingsParent.classList.toggle("active", name === "settings" || name === "settings-model");
    const view = $("#view");
    view.innerHTML = skeletonView();
    view.scrollTop = 0;
    try {
      if (name !== "projects") {
        const config = await ensureConfig();
        if (!config.project.hash) {
          go("projects");
          return;
        }
      }
      if (name === "projects") await viewProjects();
      else if (name === "overview") await viewOverview();
      else if (name === "findings") await viewFindings();
      else if (name === "endpoints") await viewEndpoints();
      else if (name === "dependencies") await viewDependencies();
      else if (name === "tree") await viewTree();
      else if (name === "authz") await viewAuthz();
      else if (name === "model") await viewModel();
      else if (name === "reachability") await viewReachability();
      else if (name === "runtime") await viewRuntime();
      else if (name === "agent") await viewAgent();
      else if (name === "source") await viewSource(params);
      else if (name === "settings") await viewSettings();
      else if (name === "settings-model") await viewSettingsModel();
      else if (name === "about") await viewAbout();
    } catch (error) {
      if (error.status === 401) {
        showLogin("会话已失效，请重新输入访问令牌。");
        return;
      }
      if (error.status === 409 && /no_project|项目/.test(error.message)) {
        await ensureConfig(true);
        go("projects");
        return;
      }
      renderFailure(error);
    }
  }

  function renderFailure(error) {
    $("#view").innerHTML = `<div class="card"><div class="empty"><svg class="icon"><use href="#i-alert"/></svg><h4>无法加载该视图</h4><p>${esc(error.message || "未知错误")}</p><button class="btn" type="button" id="retryView">重试</button></div></div>`;
    $("#retryView").addEventListener("click", renderRoute);
  }

  async function refreshProjectSwitcher() {
    const select = $("#projectSwitcher");
    if (!select) return;
    let projects = [];
    try {
      const payload = await api("/api/projects");
      projects = payload.projects || [];
    } catch (error) {
      projects = [];
    }
    const current = (state.config && state.config.project && state.config.project.hash) || "";
    if (!projects.length) {
      select.innerHTML = `<option value="">未选择项目</option>`;
      return;
    }
    select.innerHTML = projects.map((entry) => {
      const name = String(entry.source || "").split(/[\\/]/).filter(Boolean).pop() || entry.hash.slice(0, 12);
      return `<option value="${esc(entry.hash)}"${entry.hash === current ? " selected" : ""}>${esc(name)}</option>`;
    }).join("");
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
    // The thread list is optional: a console without an Agent database must
    // still render the static overview.
    let recent = [];
    try {
      const payload = await api("/api/agent/threads");
      recent = (payload.threads || []).slice(0, 4);
    } catch (error) {
      recent = [];
    }
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
        ${tile("folder", "teal", fmtNum(snap.total_files), "文件清单", `排除 ${fmtNum(snap.excluded_count)} 项`, { route: "source" })}
        ${tile("route", "blue", fmtNum(analysis.endpoint_coverage.endpoints_found), "HTTP 入口", `${fmtNum(analysis.endpoint_coverage.controllers_found)} 个控制器`, { route: "endpoints" })}
        ${tile("bug", "rose", fmtNum(counts.total), "安全发现", `静态确认 ${fmtNum(counts.static_confirmed)}`, { route: "findings", status: "all" })}
        ${tile("alert", "amber", fmtNum(counts.inconclusive), "证据待定", `已反驳 ${fmtNum(counts.refuted)}`, { route: "findings", status: "inconclusive" })}
        ${tile("package", "violet", fmtNum(analysis.sca_coverage.dependencies_declared), "依赖声明", `${fmtNum(analysis.sca_coverage.poms_scanned)} 个 POM`, { route: "dependencies" })}
        ${tile("flag", "amber", fmtNum(coverage.sca_advisory_candidates), "公告命中", `未命中 ${fmtNum(coverage.sca_advisory_not_affected)}`, { route: "dependencies" })}
        ${tile("lock", "rose", fmtNum(overview.authz.unprotected), "无控制入口", `受保护 ${fmtNum(overview.authz.protected)} · 未知 ${fmtNum(overview.authz.unknown)}`, { route: "authz", decision: "unprotected" })}
        ${tile("code", "blue", overview.model.enabled ? fmtNum(overview.model.types) : "—", "代码模型", overview.model.enabled ? `${fmtNum(overview.model.methods)} 个方法 · 调用 ${fmtNum(overview.model.calls_resolved)}/${fmtNum(overview.model.calls_total)}` : (overview.model.reason || "未生成"), { route: "model" })}
        ${tile("shield", "teal", snap.partial ? "部分" : "完整", "清单状态", "应用层只读快照", { route: "about" })}
        ${tile("clock", "blue", fmtNum(analysis.duration_ms) + "ms", "分析耗时", new Date(analysis.generated_at).toLocaleTimeString("zh-CN", { hour12: false }), { route: "about" })}
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
            <div class="sev-block">
              <div class="sev-head"><span>严重度</span><span class="card-sub">排除已反驳</span></div>
              ${(overview.severities || []).map((item) => `
                <div class="sev-row actionable" role="link" tabindex="0" data-action="${esc(JSON.stringify({ route: "findings", severity: item.key }))}">
                  <span class="sev-label">${esc(item.label)}</span>
                  <span class="sev-track"><span class="sev-fill ${esc(item.key)}" data-pct="${counts.total ? Math.round((item.total / Math.max(counts.total - counts.refuted, 1)) * 100) : 0}"></span></span>
                  <b class="sev-count">${fmtNum(item.total)}</b>
                </div>`).join("")}
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

      ${recent.length ? `
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-clock"/></svg>最近会话</h3><a class="card-link" href="#/agent">查看全部<svg class="icon"><use href="#i-chev-right"/></svg></a></div>
        <div class="card-body tight">
          <ul class="recent-threads">
            ${recent.map((thread) => `
              <li class="recent-thread actionable" role="link" tabindex="0" data-run="${thread.id}">
                ${runStatePill(thread.state)}
                <span class="recent-goal" title="${esc(thread.goal)}">${esc(thread.goal || "(无目标)")}</span>
                <span class="recent-meta mono">#${thread.id} · ${thread.model_calls}M/${thread.tool_calls}T · ${fmtNum(thread.tokens_used)} tok</span>
                <span class="recent-time">${esc((thread.updated_at || "").slice(5, 16).replace("T", " "))}</span>
              </li>`).join("")}
          </ul>
        </div>
      </section>` : ""}

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
    const activate = (element) => {
      if (element.dataset.run) {
        // Selecting a thread before routing reuses the chat view's own state.
        state.agent = state.agent || {};
        state.agent.openId = Number(element.dataset.run);
        go("agent");
        return;
      }
      let action = null;
      try {
        action = JSON.parse(element.dataset.action || "null");
      } catch (error) {
        action = null;
      }
      if (!action || !action.route) return;
      if (action.route === "findings") {
        state.findings.status = action.status || "all";
        state.findings.category = action.category || "all";
        state.findings.severity = action.severity || "all";
        state.findings.offset = 0;
      }
      if (action.route === "authz") {
        state.authz.decision = action.decision || "all";
        state.authz.offset = 0;
      }
      go(action.route);
    };
    $$("[data-action], [data-run]", $("#view")).forEach((element) => {
      element.addEventListener("click", () => activate(element));
      element.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          activate(element);
        }
      });
    });
    // CSP forbids inline style attributes; widths are applied through CSSOM.
    $$(".sev-fill", $("#view")).forEach((fill) => {
      const pct = Math.max(0, Math.min(100, Number(fill.dataset.pct) || 0));
      fill.style.width = pct + "%";
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

  function tile(icon, tone, value, label, sub, action) {
    const attrs = action
      ? ` class="tile actionable" role="link" tabindex="0" data-action="${esc(JSON.stringify(action))}"`
      : ` class="tile"`;
    return `<div${attrs}><span class="tile-icon ${tone}"><svg class="icon"><use href="#i-${icon}"/></svg></span><div class="tile-body"><div class="tile-val">${esc(value)}</div><div class="tile-label">${esc(label)}</div><div class="tile-sub">${esc(sub)}</div></div></div>`;
  }

  // The build string carries every shipped capability after " + ". Showing it
  // raw turns the value column into a wall of text, so split it: short version
  // in the row, tags behind a disclosure.
  function describeBuild(raw) {
    const text = String(raw || "").trim();
    if (!text) return { short: "—", tags: [], note: "" };
    const note = (text.match(/\s*\(([^()]*)\)\s*$/) || [])[1] || "";
    const body = note ? text.slice(0, text.lastIndexOf("(")).trim() : text;
    const parts = body.split(" + ").map((item) => item.trim()).filter(Boolean);
    return { short: parts[0] || body, tags: parts.slice(1), note };
  }

  // Build identifiers are joined with "+"; allow a break there so the value
  // wraps at a segment boundary instead of splitting a capability name.
  const versionText = (value) => String(value ?? "").replace(/\+/g, "+\u200b");

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
          <select class="select" id="severitySelect" aria-label="严重度筛选">
            <option value="all">全部严重度</option>
            ${["high", "medium", "low", "unknown"].map((key) => `<option value="${key}">${esc(severityLabel[key] || key)}</option>`).join("")}
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
    $("#severitySelect").value = findings.severity;
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
    $("#severitySelect").addEventListener("change", (event) => {
      findings.severity = event.target.value;
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
    if (findings.severity !== "all") params.set("severity", findings.severity);
    if (findings.q) params.set("q", findings.q);
    try {
      const data = await api("/api/findings?" + params.toString());
      if (seq !== findings.seq) return;
      findings.items = data.items;
      findings.filtered = data.filtered;
      findings.total = data.total;
      findings.severities = data.severities || [];
      // Faceted counts arrive with the page; label the options so a bucket with
      // zero hits is obvious before selecting it.
      $$("#severitySelect option").forEach((option) => {
        const bucket = findings.severities.find((item) => item.key === option.value);
        if (option.value === "all") {
          const sum = findings.severities.reduce((total, item) => total + item.total, 0);
          option.textContent = `全部严重度 · ${sum}`;
        } else if (bucket) {
          option.textContent = `${severityLabel[bucket.key] || bucket.key} · ${bucket.total}`;
        }
      });
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
    return `<tr class="clickable" tabindex="0" data-id="${esc(finding.id)}">
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
          <div class="seg" id="endpointAuthzSeg">
            ${[["all", "全部"], ["unprotected", "无控制"], ["unknown", "未知"], ["public", "公开"], ["protected", "受保护"]].map(([value, label]) => `<button type="button" data-authz="${value}" class="${endpoints.authz === value ? "active" : ""}">${label}</button>`).join("")}
          </div>
          <input class="input wide" id="endpointSearch" data-search placeholder="搜索路径、控制器、方法或文件…" value="${esc(endpoints.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="endpointCount">—</span>
        </div>
        <div class="table-wrap">
          <table class="grid-fixed cols-endpoints">
            <thead><tr><th>方法</th><th>路径</th><th>控制器方法</th><th>权限</th><th>文件</th><th>参数绑定</th></tr></thead>
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
    $("#endpointAuthzSeg").addEventListener("click", (event) => {
      const button = event.target.closest("[data-authz]");
      if (!button) return;
      endpoints.authz = button.dataset.authz;
      endpoints.offset = 0;
      $$("#endpointAuthzSeg button").forEach((item) => item.classList.toggle("active", item === button));
      loadEndpoints();
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
    if (endpoints.authz && endpoints.authz !== "all") params.set("authz", endpoints.authz);
    try {
      const data = await api("/api/endpoints?" + params.toString());
      if (seq !== endpoints.seq) return;
      endpoints.items = data.items;
      endpoints.total = data.total;
      endpoints.coverage = data.coverage;
      endpoints.authzMap = data.authz || {};
      endpoints.authzCounts = data.authz_counts || null;
      const counts = data.authz_counts || {};
      $("#endpointCount").textContent = `${fmtNum(data.total)} 个入口 · 控制器 ${data.coverage.controllers_found} · 无控制 ${fmtNum(counts.unprotected || 0)}`;
      if (!data.items.length) {
        rows.innerHTML = `<tr><td colspan="6">${emptyState("i-route", "没有匹配的入口", "调整检索条件。注解级清单不证明路由已部署。")}</td></tr>`;
      } else {
        rows.innerHTML = data.items.map((item) => endpointRow(item, data.authz ? data.authz[item.symbol] : null)).join("");
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

  const bindingLabels = {
    RequestParam: "@QP",
    PathVariable: "@PV",
    RequestBody: "@Body",
    RequestHeader: "@Hdr",
    ModelAttribute: "@Model",
    CookieValue: "@Cookie",
    RequestPart: "@Part",
  };
  function bindingShort(bindings) {
    if (!bindings || !bindings.length) return "";
    return bindings.map((item) => bindingLabels[item] || item).join("/");
  }

  function endpointRow(endpoint, authz) {
    const params = endpoint.parameters || [];
    const chips = params.slice(0, 1).map((parameter) => {
      const bindings = (parameter.bindings || []).join("/") || "unbound";
      const tag = bindingShort(parameter.bindings);
      return `<span class="param ${tag ? "" : "unbound"}" title="${esc(parameter.name + " · " + bindings)}">${esc(parameter.name)}${tag ? `<b>${esc(tag)}</b>` : ""}</span>`;
    }).join("");
    const more = params.length > 1 ? `<span class="param" title="${esc(params.map((item) => item.name).join("、"))}">+${params.length - 1}</span>` : "";
    const pathTone = endpoint.path_status === "resolved" ? "muted" : "warn";
    return `<tr class="clickable" tabindex="0" data-file="${esc(endpoint.file)}" data-line="${endpoint.method_line || endpoint.start_line}" title="${esc((authz && authz.reason) || "")}">
      <td>${methodsBadges(endpoint.http_methods)}</td>
      <td class="path" title="路径状态 ${esc(endpoint.path_status || "unknown")}">${esc(endpoint.path)}${endpoint.path_status && endpoint.path_status !== "resolved" ? ` <span class="status ${pathTone}">${esc(endpoint.path_status)}</span>` : ""}</td>
      <td class="strong">${esc(endpoint.symbol)}</td>
      <td>${authz ? decisionPill(authz.decision) : '<span class="status muted">未评估</span>'}</td>
      <td class="file" title="${esc(endpoint.file)}">${esc(endpoint.file)}:${endpoint.start_line}</td>
      <td><div class="param-cell">${chips}${more}</div></td>
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

  const runtimeReasonLabels = {
    no_runtime_result_with_matching_route_and_method: "没有同路径同方法的运行时结果",
    no_runtime_result_with_matching_route: "没有同路径的运行时结果",
    runtime_result_ambiguous: "多条运行时结果对应同一条发现",
    matched_route_and_method: "路径与方法均匹配",
  };

  const matchMeta = {
    correlated: { label: "已关联", cls: "ok" },
    not_correlated: { label: "未关联", cls: "muted" },
    ambiguous: { label: "歧义", cls: "warn" },
  };

  async function viewRuntime() {
    let report;
    try {
      report = await api("/api/runtime-report");
    } catch (error) {
      if (error.status === 412 || error.status === 404 || error.status === 422) {
        $("#view").innerHTML = `<div class="card"><div class="empty"><svg class="icon"><use href="#i-flag"/></svg><h4>暂无运行时关联报告</h4><p>${esc(error.message)}</p><code class="mono">trident runtime http --plan plan.json --approve-target https://target</code><code class="mono">trident runtime correlate --findings findings.json --runtime runtime.json --out correlate.json</code><p>然后在「设置 → 路径与分析」里填写该报告路径，或启动时加 --runtime-report。</p></div></div>`;
        return;
      }
      throw error;
    }
    const cov = report.coverage || {};
    const results = report.results || [];
    const unmatched = report.unmatched_runtime || [];
    const rows = results.map((item) => {
      const meta = matchMeta[item.match] || { label: item.match || "未知", cls: "muted" };
      const endpoint = item.endpoint || {};
      return `<tr>
        <td><span class="status ${meta.cls}">${esc(meta.label)}</span></td>
        <td>${esc(kindLabels[item.kind] || item.kind)}</td>
        <td class="path" title="${esc(endpoint.file || "")}">${esc(endpoint.path || "—")}</td>
        <td>${methodsBadges(endpoint.http_methods || [])}</td>
        <td>${statusPill(item.finding_status === "static_confirmed" ? "static_confirmed" : item.finding_status === "refuted" ? "refuted" : "inconclusive")}</td>
        <td class="file" title="${esc(item.reason || "")}">${esc(runtimeReasonLabels[item.reason] || item.reason || "")}</td>
      </tr>`;
    }).join("");
    const unmatchedRows = unmatched.map((item) => `<tr>
      <td class="strong mono">${esc(item.id || "—")}</td>
      <td>${methodsBadges([item.method || "GET"])}</td>
      <td class="path">${esc(item.path || "")}</td>
      <td>${item.status ? `<span class="status ${item.status === "passed" ? "ok" : "bad"}">${esc(item.status)}</span>` : "—"}</td>
      <td class="num">${item.observed_status || "—"}</td>
    </tr>`).join("");
    $("#view").innerHTML = `
      <section class="hero">
        <div class="hero-copy">
          <span class="eyebrow">RUNTIME CORRELATION</span>
          <h2>静态发现 × 运行时结果关联</h2>
          <p>关联只说明某条静态发现在本次运行时观测中有对应结果，不会把 finding 升级为已确认；runtime_status=${esc(report.runtime_status || "not_run")}。</p>
          <div class="hero-meta">
            <span class="chip">发现 ${fmtNum(cov.findings_total || 0)}</span>
            <span class="chip">运行时结果 ${fmtNum(cov.runtime_results || 0)}</span>
            <span class="chip"><span class="dot ok"></span>已关联 ${fmtNum(cov.correlated || 0)}</span>
            <span class="chip">未关联 ${fmtNum(cov.not_correlated || 0)}</span>
            <span class="chip">歧义 ${fmtNum(cov.ambiguous || 0)}</span>
          </div>
        </div>
        <div class="hero-side">
          <span class="chip mono">${esc(shortHash((report.findings_source || {}).sha256 || ""))}</span>
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-bug"/></svg>发现关联结果</h3><span class="card-sub">${fmtNum(results.length)} 条</span></div>
        <div class="card-body tight">
          <div class="table-wrap"><table class="grid-fixed cols-runtime">
            <thead><tr><th>关联</th><th>类型</th><th>入口</th><th>方法</th><th>静态状态</th><th>说明</th></tr></thead>
            <tbody>${rows || `<tr><td colspan="6">${emptyState("i-bug", "没有发现条目", "关联报告的发现来源为空。")}</td></tr>`}</tbody>
          </table></div>
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-server"/></svg>未被引用的运行时结果</h3><span class="card-sub">${fmtNum(unmatched.length)} 条</span></div>
        <div class="card-body tight">
          <div class="table-wrap"><table class="grid-fixed cols-runtime">
            <thead><tr><th>请求</th><th>方法</th><th>路径</th><th>断言</th><th class="right">HTTP</th></tr></thead>
            <tbody>${unmatchedRows || `<tr><td colspan="5">${emptyState("i-server", "没有运行时结果", "本次运行时校验没有产生可关联的结果。")}</td></tr>`}</tbody>
          </table></div>
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>限制与边界</h3><span class="card-sub">关联不等于可利用</span></div>
        <div class="card-body">${limitationList(report.limitations)}</div>
      </section>

      <details class="card section-gap raw-report">
        <summary><svg class="icon"><use href="#i-hash"/></svg>关联报告原文（JSON）</summary>
        <div class="card-body"><pre class="code-view mono">${esc(JSON.stringify(report, null, 2))}</pre></div>
      </details>`;
  }

  // ── agent chat ─────────────────────────────────────────────────────────

  const runStates = {
    ready: { label: "待执行", cls: "muted" },
    running: { label: "执行中", cls: "ok" },
    completed: { label: "已完成", cls: "ok" },
    failed: { label: "失败", cls: "bad" },
    budget_exhausted: { label: "预算耗尽", cls: "warn" },
    paused: { label: "已暂停", cls: "warn" },
    unknown: { label: "状态不明", cls: "bad" },
    cancelled: { label: "已取消", cls: "muted" },
  };
  const terminalStates = ["completed", "failed", "budget_exhausted", "paused", "unknown", "cancelled"];

  function runStatePill(value) {
    const meta = runStates[value] || { label: value || "未知", cls: "muted" };
    const dot = meta.cls === "ok" ? "ok" : meta.cls === "bad" ? "bad" : meta.cls === "warn" ? "warn" : "";
    return `<span class="status ${meta.cls}">${dot ? `<span class="dot ${dot}"></span>` : ""}${esc(meta.label)}</span>`;
  }

  // Local aliases only: renaming must never rewrite the durable run record, so
  // the mapping lives in this browser's localStorage.
  const aliasStoreKey = "trident.thread.aliases";
  function loadAliases() {
    try {
      const value = JSON.parse(localStorage.getItem(aliasStoreKey) || "{}");
      return value && typeof value === "object" ? value : {};
    } catch (error) {
      return {};
    }
  }
  function threadAlias(thread) {
    return String(loadAliases()[`${thread.snapshot_hash || ""}:${thread.id}`] || "");
  }
  function saveThreadAlias(thread, value) {
    const all = loadAliases();
    const key = `${thread.snapshot_hash || ""}:${thread.id}`;
    const text = String(value || "").trim();
    if (!text || text === thread.goal) delete all[key];
    else all[key] = text;
    try {
      localStorage.setItem(aliasStoreKey, JSON.stringify(all));
    } catch (error) {
      /* renaming is a convenience; a full quota must not break the page */
    }
  }

  async function viewAgent() {
    const [chat, threadsPayload] = await Promise.all([
      api("/api/agent/chat/state").catch((error) => ({ enabled: false, reason: error.message })),
      api("/api/agent/threads").catch((error) => ({ threads: [], active_run: 0, error: error.message })),
    ]);
    const threads = threadsPayload.threads || [];
    const openId = state.agent && state.agent.openId && threads.some((item) => item.id === state.agent.openId)
      ? state.agent.openId
      : (threadsPayload.active_run || (threads[0] && threads[0].id) || 0);
    const query = (state.agent && state.agent.query) || "";
    state.agent = { chat, threads, openId, steps: [], run: null, busy: Boolean(threadsPayload.active_run), timer: null, lastSeq: 0, query };

    $("#view").innerHTML = `
      <div class="chat-shell">
        <aside class="chat-rail">
          <div class="chat-rail-head">
            <h3>会话</h3>
            <button class="btn sm primary" type="button" id="newThread"><svg class="icon"><use href="#i-plus"/></svg>新建</button>
          </div>
          <div class="chat-rail-filter">
            <svg class="icon"><use href="#i-search"/></svg>
            <input id="chatSearch" class="input" placeholder="筛选会话…" autocomplete="off" value="${esc(state.agent.query)}">
          </div>
          <div class="chat-threads" id="chatThreads"></div>
          <div class="chat-rail-foot">
            <span class="chip mono">${esc(shortHash(chat.project_hash || state.config?.project?.hash || ""))}</span>
            <span class="form-hint">仅显示当前项目的会话</span>
          </div>
        </aside>
        <section class="chat-main">
          <div class="chat-head" id="chatHead"></div>
          <div class="chat-stream" id="chatStream"></div>
          <form class="composer" id="composer">
            ${chat.enabled ? `<div class="goal-presets">${[
              ["未授权访问", "检查全部 HTTP 入口的访问控制：列出无控制与无法解析的入口，逐条给出文件、行号与依据；不要浏览无关目录。"],
              ["SQL 注入", "追踪 HTTP 参数到 SQL 执行的数据流，列出可达的拼接点并引用实际读到的行号；无法验证的标注 UNVERIFIED INFERENCE。"],
              ["路径遍历", "检查文件读取类入口的路径拼接与规范化，列出可被外部输入影响的调用点并给出行号证据。"],
              ["依赖风险", "结合依赖声明与公告目录，检查是否存在命中已知漏洞的依赖，给出声明 POM 与公告编号。"],
            ].map(([label, text]) => `<button type="button" class="chip chip-btn" data-preset="${esc(text)}">${esc(label)}</button>`).join("")}</div>` : ""}
            <textarea id="chatGoal" rows="3" placeholder="${chat.enabled ? "描述这次分析目标，例如：审计 SQL 注入与未授权访问风险" : esc(chat.reason || "对话未启用")}" ${chat.enabled ? "" : "disabled"}></textarea>
            <div class="composer-bar">
              <label class="profile-pick">模型
                <select id="chatProfile" ${chat.enabled ? "" : "disabled"}>
                  ${(chat.profiles || []).map((profile) => `<option value="${esc(profile.id)}"${profile.default ? " selected" : ""}>${esc(profile.label || profile.model)}${profile.key_present ? "" : "（缺密钥）"}</option>`).join("")}
                </select>
              </label>
              <label class="check"><input type="checkbox" id="chatEgress" ${chat.enabled ? "" : "disabled"}>批准把当前项目快照与本条目标发送给所选模型端点</label>
              <span class="spacer"></span>
              <span class="composer-status" id="composerStatus"></span>
              <button class="btn primary" type="submit" id="chatSend" ${chat.enabled ? "" : "disabled"}>发送<svg class="icon"><use href="#i-chev-right"/></svg></button>
            </div>
          </form>
        </section>
      </div>`;

    renderThreadList();
    $("#newThread").addEventListener("click", () => {
      state.agent.openId = 0;
      state.agent.steps = [];
      state.agent.run = null;
      renderThreadList();
      renderThread();
      $("#chatGoal").focus();
    });
    $("#chatThreads").addEventListener("click", (event) => {
      const row = event.target.closest("[data-thread]");
      if (!row) return;
      openThread(Number(row.dataset.thread));
    });
    $("#chatSearch").addEventListener("input", (event) => {
      state.agent.query = event.target.value;
      renderThreadList();
    });
    $("#composer").addEventListener("submit", (event) => {
      event.preventDefault();
      sendChat();
    });
    $("#chatGoal").addEventListener("keydown", (event) => {
      if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        sendChat();
      }
    });
    $$("#view [data-preset]").forEach((button) => {
      button.addEventListener("click", () => {
        const goal = $("#chatGoal");
        if (!goal) return;
        goal.value = button.dataset.preset;
        goal.focus();
      });
    });
    if (!chat.enabled) {
      $("#composerStatus").textContent = chat.reason || "";
      $("#composerStatus").className = "composer-status warn-text";
    } else if (!chat.key_present) {
      $("#composerStatus").textContent = "服务端未找到模型密钥";
      $("#composerStatus").className = "composer-status warn-text";
    }
    if (openId) await openThread(openId);
    else renderThread();
  }

  function startThreadRename(run) {
    const head = $("#chatHead");
    const title = head && head.querySelector("h2");
    if (!head || !title) return;
    const input = document.createElement("input");
    input.className = "input";
    input.value = threadAlias(run) || run.goal || "";
    input.maxLength = 160;
    title.replaceWith(input);
    input.focus();
    input.select();
    let done = false;
    const commit = () => {
      if (done) return;
      done = true;
      saveThreadAlias(run, input.value);
      renderThreadList();
      renderThread();
    };
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        commit();
      } else if (event.key === "Escape") {
        done = true;
        renderThread();
      }
    });
    input.addEventListener("blur", commit);
  }

  function renderThreadList() {
    const host = $("#chatThreads");
    if (!host) return;
    const all = state.agent.threads || [];
    const query = String(state.agent.query || "").trim().toLowerCase();
    const items = query
      ? all.filter((thread) => `${threadAlias(thread)} ${thread.goal || ""}`.toLowerCase().includes(query))
      : all;
    if (!all.length) {
      host.innerHTML = `<div class="chat-empty">当前项目还没有会话。写下目标并发送，第一轮分析就会出现在这里。</div>`;
      return;
    }
    if (!items.length) {
      host.innerHTML = `<div class="chat-empty">没有匹配的会话。</div>`;
      return;
    }
    host.innerHTML = items.map((thread) => {
      const alias = threadAlias(thread);
      const title = alias || (thread.goal || "(无目标)");
      return `<button class="chat-thread${thread.id === state.agent.openId ? " active" : ""}" type="button" data-thread="${thread.id}" title="${esc(alias ? `目标：${thread.goal}` : title)}">
        <span class="chat-thread-title">${esc(title.length > 60 ? `${title.slice(0, 60)}…` : title)}</span>
        <span class="chat-thread-meta">
          ${runStatePill(thread.state)}
          <span class="mono">#${thread.id}</span>
          <span>${thread.model_calls}M/${thread.tool_calls}T</span>
          <span class="chat-thread-time">${esc((thread.updated_at || "").slice(5, 16).replace("T", " "))}</span>
        </span>
      </button>`;
    }).join("");
  }

  async function openThread(runID) {
    stopPolling();
    state.agent.openId = runID;
    renderThreadList();
    $("#chatStream").innerHTML = `<div class="chat-loading">${skeletonView()}</div>`;
    try {
      const payload = await api("/api/agent/steps?run_id=" + runID + "&limit=1000");
      state.agent.steps = payload.steps || [];
      state.agent.run = payload.run || null;
      state.agent.lastSeq = state.agent.steps.length ? state.agent.steps[state.agent.steps.length - 1].seq : 0;
      renderThread();
      if (state.agent.run && !terminalStates.includes(state.agent.run.state)) startPolling();
    } catch (error) {
      $("#chatStream").innerHTML = emptyState("i-alert", "无法加载会话", error.message);
    }
  }

  function startPolling() {
    stopPolling();
    state.agent.busy = true;
    updateComposerState();
    state.agent.timer = setInterval(async () => {
      if (!state.agent.openId) return stopPolling();
      try {
        const payload = await api("/api/agent/steps?run_id=" + state.agent.openId + "&limit=1000");
        const steps = payload.steps || [];
        if (steps.length !== state.agent.steps.length) {
          state.agent.steps = steps;
          state.agent.run = payload.run || state.agent.run;
          state.agent.lastSeq = steps.length ? steps[steps.length - 1].seq : 0;
          renderThread();
          renderThreadList();
        } else if (payload.run) {
          state.agent.run = payload.run;
        }
        if (state.agent.run && terminalStates.includes(state.agent.run.state)) {
          stopPolling();
          renderThread();
          await refreshThreads();
        }
      } catch (error) {
        stopPolling();
      }
    }, 1500);
  }

  function stopPolling() {
    if (state.agent && state.agent.timer) {
      clearInterval(state.agent.timer);
      state.agent.timer = null;
    }
    if (state.agent) {
      state.agent.busy = false;
      updateComposerState();
    }
  }

  function updateComposerState() {
    const send = $("#chatSend");
    const status = $("#composerStatus");
    if (!send || !status) return;
    if (!state.agent.chat.enabled) return;
    send.disabled = state.agent.busy;
    status.className = "composer-status" + (state.agent.busy ? "" : "");
    status.textContent = state.agent.busy ? "执行中…" : "";
  }

  async function sendChat() {
    const goal = $("#chatGoal").value.trim();
    if (!goal) {
      toast("先写下目标", "bad");
      $("#chatGoal").focus();
      return;
    }
    if (!$("#chatEgress").checked) {
      toast("需要勾选外发批准：快照与目标会发送到模型端点", "bad");
      $("#chatEgress").focus();
      return;
    }
    const button = $("#chatSend");
    button.disabled = true;
    button.textContent = "启动中…";
    try {
      const result = await api("/api/agent/chat", {
        method: "POST",
        body: {
          goal,
          approve_egress: true,
          // Limits come from the selected profile; the page never overrides them.
          profile_id: ($("#chatProfile") && $("#chatProfile").value) || "",
        },
      });
      $("#chatGoal").value = "";
      state.agent.busy = true;
      await refreshThreads();
      await openThread(result.run_id);
      toast(`Run #${result.run_id} 已启动`, "ok");
    } catch (error) {
      toast(error.message, "bad");
    } finally {
      button.textContent = "发送";
      button.disabled = false;
      updateComposerState();
    }
  }

  async function refreshThreads() {
    try {
      const payload = await api("/api/agent/threads");
      state.agent.threads = payload.threads || [];
      renderThreadList();
    } catch (error) {
      /* the thread list is not critical for sending */
    }
  }

  function renderThread() {
    const run = state.agent.run;
    const head = $("#chatHead");
    const stream = $("#chatStream");
    if (!head || !stream) return;
    if (!run) {
      head.innerHTML = `<div class="chat-head-main"><h2>新的分析会话</h2><span class="form-hint">写入目标并批准外发后，Agent 会用只读工具读取当前项目快照。</span></div>`;
      stream.innerHTML = `<div class="chat-intro">${emptyState("i-server", "还没有开始", "描述一个分析目标即可。Agent 只能读取快照，不会执行项目代码。")}</div>`;
      return;
    }
    const alias = threadAlias(run);
    head.innerHTML = `
      <div class="chat-head-main">
        <div class="chat-head-line">
          ${runStatePill(run.state)}
          <span class="mono chat-run-id">#${run.id}</span>
          <span class="chip">${run.model_calls} 模型 / ${run.tool_calls} 工具</span>
          <span class="chip">${fmtNum(run.tokens_used)} tokens</span>
        </div>
        <h2 title="${esc(run.goal)}">${esc(alias || (run.goal || "").slice(0, 120))}</h2>
        ${alias ? `<p class="chat-goal-raw">目标：${esc(run.goal)}</p>` : ""}
      </div>
      <div class="chat-actions">
        <button class="btn sm ghost" type="button" data-chat-action="rename" title="别名只保存在本机浏览器">重命名</button>
        <button class="btn sm ghost" type="button" data-copy="${esc(run.goal || "")}">复制目标</button>
        <button class="btn sm ghost" type="button" data-chat-action="rerun" title="用同一目标开一轮新会话">以此目标新建</button>
      </div>`;
    $$("[data-chat-action]", head).forEach((button) => {
      button.addEventListener("click", () => {
        if (button.dataset.chatAction === "rename") startThreadRename(run);
        if (button.dataset.chatAction === "rerun") {
          state.agent.openId = 0;
          state.agent.steps = [];
          state.agent.run = null;
          renderThreadList();
          renderThread();
          const goal = $("#chatGoal");
          if (goal) {
            goal.value = run.goal || "";
            goal.focus();
          }
        }
      });
    });
    const blocks = buildBlocks(state.agent.steps);
    stream.innerHTML = blocks.map(renderBlock).join("") || emptyState("i-clock", "等待第一个事件", "Run 刚创建，step 正在写入。");
    stream.scrollTop = stream.scrollHeight;
  }

  // buildBlocks turns the append-only step log into readable messages: one
  // assistant bubble per model turn, with its tool calls folded into a summary.
  function buildBlocks(steps) {
    const blocks = [];
    let tools = null;
    let pending = new Map();
    steps.forEach((step) => {
      const payload = step.payload || {};
      switch (step.kind) {
        case "run.created":
          blocks.push({ type: "meta", text: `Run 创建 · 快照 ${shortHash(payload.snapshot_hash || "")}`, at: step.created_at });
          break;
        case "model.completed": {
          tools = null;
          const message = payload.message || {};
          if (message.content) blocks.push({ type: "assistant", text: message.content, at: step.created_at });
          const calls = message.calls || [];
          if (calls.length) {
            tools = { type: "tools", items: calls.map((call) => ({ name: call.name, args: call.arguments, result: null, status: "pending" })) };
            blocks.push(tools);
            pending = new Map(calls.map((call, index) => [call.id, { block: tools, index }]));
          }
          break;
        }
        case "tool.completed": {
          const slot = pending.get(payload.id);
          if (slot) {
            const item = slot.block.items[slot.index];
            item.result = payload.result;
            item.status = "done";
            item.name = payload.name || item.name;
            pending.delete(payload.id);
          } else {
            blocks.push({ type: "tools", items: [{ name: payload.name || "tool", args: {}, result: payload.result, status: "done" }] });
          }
          break;
        }
        case "run.completed":
          blocks.push({ type: "final", data: payload, at: step.created_at });
          break;
        case "run.failed":
        case "run.paused":
        case "run.budget_exhausted":
        case "run.cancelled": {
          const reason = payload.reason || payload.message || step.kind;
          blocks.push({ type: "state", kind: step.kind, reason: String(reason), at: step.created_at });
          break;
        }
        default:
          break;
      }
    });
    // One "过程" per stretch of tool work keeps the thread readable.
    const merged = [];
    blocks.forEach((block) => {
      const previous = merged[merged.length - 1];
      if (block.type === "tools" && previous && previous.type === "tools") {
        previous.items.push(...block.items);
        return;
      }
      merged.push(block);
    });
    return merged;
  }

  function renderBlock(block) {
    if (block.type === "meta") {
      return `<div class="chat-meta">${esc(block.text)}</div>`;
    }
    if (block.type === "assistant") {
      // Models sometimes emit a JSON fragment as "content"; folding it keeps
      // the readable answer separate from raw structured output.
      if (looksStructured(block.text)) {
        const raw = String(block.text).trim();
        return `<details class="tool-block json-block"><summary><svg class="icon"><use href="#i-code"/></svg>模型结构化输出 · ${fmtNum(raw.length)} 字节</summary><pre class="json-pre">${esc(raw.slice(0, 4000))}${raw.length > 4000 ? "\n…" : ""}</pre></details>`;
      }
      return `<div class="msg msg-assistant"><div class="msg-body">${renderText(block.text)}</div></div>`;
    }
    if (block.type === "tools") {
      const run = state.agent.run || {};
      const terminal = terminalStates.includes(run.state);
      const done = block.items.filter((item) => item.status === "done").length;
      const waiting = block.items.length - done;
      const note = terminal && waiting ? ` · ${waiting} 未执行` : waiting ? ` · ${waiting} 执行中` : "";
      return `<details class="tool-block"${!terminal && waiting ? " open" : ""}>
        <summary><svg class="icon"><use href="#i-code"/></svg>过程 · ${block.items.length} 次工具调用${note}</summary>
        <ul>${block.items.map((item) => renderToolItem(item, terminal)).join("")}</ul>
      </details>`;
    }
    if (block.type === "final") {
      const data = block.data || {};
      const hypotheses = data.hypotheses || [];
      const limits = data.limitations || [];
      const conclusionText = [
        data.summary || "",
        ...hypotheses.map((item) => `- ${stripInferenceLabel(item.statement || "")}`),
        limits.length ? `限制：${limits.slice(0, 8).map((item) => String(item)).join("；")}` : "",
      ].filter(Boolean).join("\n");
      return `<div class="final-card">
        <div class="final-head"><svg class="icon"><use href="#i-check"/></svg>分析结论<button class="btn sm ghost" type="button" data-copy="${esc(conclusionText)}"><svg class="icon"><use href="#i-copy"/></svg>复制结论</button></div>
        <p class="final-summary">${renderText(data.summary || "")}</p>
        ${hypotheses.length ? `<ol class="final-hypotheses">${hypotheses.map((item) => `
          <li>
            <p>${renderText(stripInferenceLabel(item.statement || ""))}</p>
            ${(item.evidence || []).length ? `<div class="final-cites">${item.evidence.map((cite) => `<button class="cite" type="button" data-src="${esc(cite.path)}" data-line="${cite.start_line || 1}">${esc(String(cite.path).split("/").pop())}:${cite.start_line}-${cite.end_line}</button>`).join("")}</div>` : ""}
          </li>`).join("")}</ol>` : ""}
        ${limits.length ? `<div class="final-limits"><b>限制</b><ul>${limits.slice(0, 8).map((item) => `<li>${esc(String(item))}</li>`).join("")}</ul></div>` : ""}
      </div>`;
    }
    if (block.type === "state") {
      const checkpoint = /checkpoint/i.test(block.reason);
      const hint = checkpoint
        ? "会话上下文超过 48 KiB 检查点上限：拆成更小的目标再开一轮，或在「设置 → 模型」里提高该配置的默认上限后重试。"
        : "";
      return `<div class="state-card"><b>${esc(block.kind)}</b><p>${esc(block.reason)}</p>${hint ? `<p class="state-hint">${esc(hint)}</p>` : ""}</div>`;
    }
    return "";
  }

  function looksStructured(text) {
    const value = String(text || "").trim();
    if (!value) return false;
    if (value.startsWith("{") || value.startsWith("[")) return true;
    return /"(summary|hypotheses|limitations)"\s*:/.test(value) && value.length > 80;
  }

  // validateFinal prepends a label; the model sometimes writes its own. Keep one.
  function stripInferenceLabel(text) {
    return String(text).replace(/^\s*(\[UNVERIFIED INFERENCE[^\]]*\]\s*)+/i, "");
  }

  function renderToolItem(item, terminal) {
    const args = item.args && Object.keys(item.args).length ? JSON.stringify(item.args) : "{}";
    let summary = terminal ? "未执行（Run 已停止）" : "等待结果";
    if (item.status === "done") {
      const json = JSON.stringify(item.result);
      summary = json.length > 140 ? json.slice(0, 140) + "…" : json;
    }
    return `<li class="${item.status === "done" ? "done" : terminal ? "skipped" : "pending"}">
      <span class="tool-name">${esc(item.name)}</span>
      <span class="tool-args mono">${esc(args.length > 90 ? args.slice(0, 90) + "…" : args)}</span>
      <span class="tool-result mono">${esc(summary)}</span>
    </li>`;
  }

  // renderText keeps the console XSS-safe: escape first, then apply a very small
  // subset of markdown (paragraphs, bullet lists, inline code, bold).
  function renderText(raw) {
    const text = String(raw || "").trim();
    if (!text) return "";
    const lines = text.split(/\n{2,}/);
    return lines.map((chunk) => {
      const items = chunk.split(/\n/).filter((line) => /^\s*[-*]\s+/.test(line));
      if (items.length && items.length === chunk.split(/\n/).filter(Boolean).length) {
        return `<ul>${items.map((line) => `<li>${inline(line.replace(/^\s*[-*]\s+/, ""))}</li>`).join("")}</ul>`;
      }
      return `<p>${inline(chunk).replace(/\n/g, "<br>")}</p>`;
    }).join("");
  }

  function inline(value) {
    return esc(value)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
  }

  // ── model settings ─────────────────────────────────────────────────────

  async function viewSettingsModel() {
    const [library, chat] = await Promise.all([
      api("/api/agent/models").catch((error) => ({ profiles: [], default: "", error: error.message })),
      api("/api/agent/chat/state").catch((error) => ({ enabled: false, reason: error.message })),
    ]);
    state.modelSettings = { library, chat, probes: (state.modelSettings && state.modelSettings.probes) || {} };
    $("#view").innerHTML = `
      <section class="card">
        <div class="card-head model-head">
          <div class="model-head-main">
            <span class="model-icon"><svg class="icon"><use href="#i-server"/></svg></span>
            <div>
              <h3>模型</h3>
              <p class="form-hint">模型库描述端点和模型；密钥只从服务端环境变量读取，配置文件里只记录变量名。</p>
            </div>
          </div>
        </div>
        <div class="tabs" id="modelTabs">
          <button type="button" data-tab="library" class="active">模型库 <em>${(library.profiles || []).length}</em></button>
          <button type="button" data-tab="budget">运行上限</button>
        </div>
        <div class="card-body" id="modelTabBody"></div>
      </section>`;
    const renderTab = (tab) => {
      $$("#modelTabs button").forEach((button) => button.classList.toggle("active", button.dataset.tab === tab));
      $("#modelTabBody").innerHTML = tab === "budget" ? modelBudgetPanel(library) : modelLibraryPanel(library, chat);
      if (tab === "library") wireModelLibrary();
    };
    $("#modelTabs").addEventListener("click", (event) => {
      const button = event.target.closest("[data-tab]");
      if (button) renderTab(button.dataset.tab);
    });
    renderTab("library");
  }

  function modelLibraryPanel(library, chat) {
    const profiles = library.profiles || [];
    const probes = state.modelSettings.probes || {};
    const rows = profiles.map((profile) => {
      const isDefault = profile.id === library.default;
      const probe = probes[profile.id];
      const available = probe ? (probe.error ? `<span class="status bad">${esc(probe.error.slice(0, 40))}</span>` : `<span class="status ok">${fmtNum((probe.models || []).length)} 个可用</span>`) : '<span class="status muted">未测试</span>';
      return `<tr class="${isDefault ? "active-row" : ""}">
        <td><div class="id-cell"><strong>${esc(profile.label || profile.id)}</strong><span class="mono">${esc(profile.model)}</span></div></td>
        <td class="mono file" title="${esc(profile.endpoint)}">${esc(profile.endpoint)}</td>
        <td>${profile.key_present
          ? '<span class="status ok"><span class="dot ok"></span>密钥已配置</span>'
          : `<span class="status bad" title="设置环境变量 ${esc(profile.key_env)}"><span class="dot bad"></span>缺少 ${esc(profile.key_env)}</span>`}</td>
        <td>${available}</td>
        <td>${isDefault ? '<span class="status info">默认</span>' : '<span class="status muted">备用</span>'}</td>
        <td class="right">
          <div class="row-actions">
            <button class="btn sm" type="button" data-probe="${esc(profile.id)}">测试</button>
            ${isDefault ? "" : `<button class="btn sm" type="button" data-default="${esc(profile.id)}">设为默认</button>`}
            <button class="btn sm ghost" type="button" data-edit="${esc(profile.id)}">编辑</button>
            ${profiles.length > 1 ? `<button class="btn sm ghost" type="button" data-remove="${esc(profile.id)}">删除</button>` : ""}
          </div>
        </td>
      </tr>`;
    }).join("");
    return `
      <div class="model-summary">
        <span>${fmtNum(profiles.length)} 个配置</span>
        <span class="foot-sep"></span>
        <span>默认 <b class="mono">${esc(profileLabel(library.default))}</b></span>
        <span class="foot-sep"></span>
        <span>${chat.enabled ? '<span class="status ok"><span class="dot ok"></span>对话可用</span>' : `<span class="status bad"><span class="dot bad"></span>${esc(chat.reason || "对话未启用")}</span>`}</span>
      </div>
      <div class="toolbar mt-14">
        <span class="form-hint">密钥只存在环境变量里：例如 <code>TRIDENT_MODEL_API_KEY</code>、<code>TRIDENT_MODEL_API_KEY_BACKUP</code>。</span>
        <span class="spacer"></span>
        <button class="btn primary" type="button" id="newProfile"><svg class="icon"><use href="#i-plus"/></svg>新建配置</button>
      </div>
      <div class="table-wrap mt-14">
        <table class="grid-fixed cols-models">
          <thead><tr><th>配置</th><th>端点</th><th>密钥</th><th>端点探测</th><th>角色</th><th class="right">操作</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="6">${emptyState("i-server", "模型库是空的", "新建一个配置：填端点、模型和保存密钥的环境变量名。")}</td></tr>`}</tbody>
        </table>
      </div>
      <div id="profileForm"></div>`;
  }

  function profileLabel(id) {
    const profiles = (state.modelSettings && state.modelSettings.library.profiles) || [];
    const found = profiles.find((item) => item.id === id);
    return found ? (found.label || found.model) : (id || "—");
  }

  function modelBudgetPanel(library) {
    const profiles = library.profiles || [];
    return `
      <div class="table-wrap">
        <p class="form-hint mb-12">对话不再逐轮设置预算：每次 Run 直接使用所选配置的默认上限，可按配置分别调整。</p>
        <table class="grid-fixed cols-budget">
          <thead><tr><th>配置</th><th class="right">模型调用</th><th class="right">工具调用</th><th class="right">Token</th></tr></thead>
          <tbody>${profiles.map((profile) => `<tr>
            <td>${esc(profile.label || profile.id)}${profile.id === library.default ? ' <span class="status info">默认</span>' : ""}</td>
            <td class="num">${fmtNum(profile.defaults.model_calls)}</td>
            <td class="num">${fmtNum(profile.defaults.tool_calls)}</td>
            <td class="num">${fmtNum(profile.defaults.tokens)}</td>
          </tr>`).join("") || `<tr><td colspan="4">${emptyState("i-server", "没有配置", "先在模型库添加一个配置。")}</td></tr>`}</tbody>
        </table>
      </div>
      <div class="kv mt-14">
        ${kvRow("硬上限（配置值只能更低）", `${ChatLimits.modelCalls} / ${ChatLimits.toolCalls} / ${fmtNum(ChatLimits.tokens)}`)}
        ${kvRow("并发", "同一控制台一次一个 Run", "warn")}
        ${kvRow("检查点上限", "48 KiB；超限即停止，需拆分目标", "warn")}
      </div>`;
  }

  const ChatLimits = { modelCalls: 32, toolCalls: 64, tokens: 400000 };

  function wireModelLibrary() {
    const newButton = $("#newProfile");
    if (newButton) newButton.addEventListener("click", () => openProfileForm(null));
    $$("[data-probe]").forEach((button) => {
      button.addEventListener("click", async () => {
        const id = button.dataset.probe;
        button.disabled = true;
        button.textContent = "测试中…";
        try {
          const result = await api("/api/agent/models/probe", { method: "POST", body: { id } });
          state.modelSettings.probes[id] = result;
          toast(result.error ? result.error : `端点可用，返回 ${result.models.length} 个模型`, result.error ? "bad" : "ok");
          await viewSettingsModel();
        } catch (error) {
          toast(error.message, "bad");
          button.disabled = false;
          button.textContent = "测试";
        }
      });
    });
    $$("[data-default]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await api("/api/agent/models/default", { method: "POST", body: { id: button.dataset.default } });
          toast("已设为默认模型", "ok");
          await viewSettingsModel();
        } catch (error) {
          toast(error.message, "bad");
        }
      });
    });
    $$("[data-edit]").forEach((button) => {
      button.addEventListener("click", () => {
        const profile = (state.modelSettings.library.profiles || []).find((item) => item.id === button.dataset.edit);
        if (profile) openProfileForm(profile);
      });
    });
    $$("[data-remove]").forEach((button) => {
      button.addEventListener("click", async () => {
        const id = button.dataset.remove;
        if (!window.confirm(`删除配置「${profileLabel(id)}」？密钥本身在环境变量里，不受影响。`)) return;
        try {
          await api("/api/agent/models/remove", { method: "POST", body: { id } });
          toast("已删除", "ok");
          await viewSettingsModel();
        } catch (error) {
          toast(error.message, "bad");
        }
      });
    });
  }

  function openProfileForm(profile) {
    const editing = Boolean(profile);
    const value = profile || { id: "", label: "", endpoint: "", model: "", key_env: "TRIDENT_MODEL_API_KEY", defaults: { model_calls: 12, tool_calls: 24, tokens: 131072 } };
    $("#profileForm").innerHTML = `
      <section class="profile-form">
        <div class="profile-form-head">
          <h4>${editing ? "编辑配置" : "新建配置"}</h4>
          <button class="icon-btn" type="button" id="closeProfileForm"><svg class="icon"><use href="#i-x"/></svg></button>
        </div>
        <div class="form-grid">
          <label class="field"><span>显示名称</span><input class="input" id="pfLabel" value="${esc(value.label)}" placeholder="例如 DeepSeek 主模型"></label>
          <label class="field"><span>端点（https）</span><input class="input" id="pfEndpoint" value="${esc(value.endpoint)}" placeholder="https://api.deepseek.com/v1"></label>
          <label class="field"><span>模型 ID</span><input class="input" id="pfModel" value="${esc(value.model)}" placeholder="deepseek-v4-pro"></label>
          <label class="field"><span>密钥环境变量</span><input class="input" id="pfKeyEnv" value="${esc(value.key_env)}" placeholder="TRIDENT_MODEL_API_KEY"></label>
          <label class="field"><span>模型调用上限</span><input class="input" id="pfModels" type="number" min="1" max="32" value="${value.defaults.model_calls}"></label>
          <label class="field"><span>工具调用上限</span><input class="input" id="pfTools" type="number" min="1" max="64" value="${value.defaults.tool_calls}"></label>
          <label class="field"><span>Token 上限</span><input class="input" id="pfTokens" type="number" min="4096" max="400000" step="1024" value="${value.defaults.tokens}"></label>
        </div>
        <div class="form-row">
          <button class="btn primary" type="button" id="saveProfile">${editing ? "保存" : "创建"}</button>
          <span class="form-hint">配置里不会写入密钥；只记录从哪个环境变量读取。</span>
        </div>
      </section>`;
    $("#closeProfileForm").addEventListener("click", () => { $("#profileForm").innerHTML = ""; });
    $("#saveProfile").addEventListener("click", async () => {
      const payload = {
        id: editing ? profile.id : "",
        label: $("#pfLabel").value.trim(),
        endpoint: $("#pfEndpoint").value.trim(),
        model: $("#pfModel").value.trim(),
        key_env: $("#pfKeyEnv").value.trim(),
        defaults: {
          model_calls: Number($("#pfModels").value || 12),
          tool_calls: Number($("#pfTools").value || 24),
          tokens: Number($("#pfTokens").value || 131072),
        },
      };
      const button = $("#saveProfile");
      button.disabled = true;
      button.textContent = "保存中…";
      try {
        await api("/api/agent/models", { method: "POST", body: payload });
        toast(editing ? "已保存" : "已创建", "ok");
        await viewSettingsModel();
      } catch (error) {
        toast(error.message, "bad");
        button.disabled = false;
        button.textContent = editing ? "保存" : "创建";
      }
    });
    $("#pfLabel").focus();
  }

  // ── source workspace ───────────────────────────────────────────────────

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
    const build = describeBuild(overview.tool_version);
    // The card header already names the product; keep the row to the version.
    const buildShort = build.short.startsWith(overview.product + " ") ? build.short.slice(overview.product.length + 1) : build.short;
    $("#view").innerHTML = `
      <div class="about-grid">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-shield"/></svg>产品与构建</h3><span class="card-sub">${esc(overview.product)}</span></div>
          <div class="card-body">
            <div class="kv">
              <div class="kv-row"><span class="kv-key">构建版本</span><span class="kv-val" title="${esc(overview.tool_version)}">${esc(buildShort)}</span></div>
              ${build.tags.length ? `<details class="build-detail"><summary>能力标记 ${build.tags.length} 项</summary><div class="build-tags">${build.tags.map((tag) => `<span class="chip mono">${esc(tag)}</span>`).join("")}</div>${build.note ? `<p class="form-hint">${esc(build.note)}</p>` : ""}</details>` : ""}
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
              ${kvRow("Manifest / Policy", "v" + snap.manifest_version + " / " + snap.policy_version)}
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
              ${kvRow("findings（证据模型）", versionText(tools.findings))}
              ${kvRow("sca（声明级）", versionText(tools.sca))}
              ${kvRow("audit（入口清单）", versionText(tools.audit))}
              ${kvRow("dataflow（有界流）", versionText(tools.dataflow))}
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
      const config = await ensureConfig(true);
      if (!config.project.hash) {
        // A fresh workspace has no project yet: land on the picker instead of
        // firing analysis requests that can only return 409.
        if (location.hash !== "#/projects") location.hash = "#/projects";
        await renderRoute();
        return;
      }
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
    // Both the login screen and the console topbar carry a toggle.
    $$(".theme-toggle").forEach((toggle) => {
      toggle.title = theme === "light" ? "切换到暗色主题" : "切换到亮色主题";
      toggle.innerHTML = `<svg class="icon"><use href="#${theme === "light" ? "i-moon" : "i-sun"}"/></svg>`;
    });
  }

  // ── authorization inventory ────────────────────────────────────────────

  const decisionMeta = {
    protected: { label: "受保护", cls: "ok" },
    public: { label: "公开", cls: "muted" },
    unprotected: { label: "无控制", cls: "bad" },
    unknown: { label: "未知", cls: "warn" },
  };

  const decisionReasonLabels = {
    no_authentication_or_authorization_control_observed: "未发现任何访问控制",
    login_endpoint_without_observed_control: "登录入口，未发现控制",
    public_control_observed: "显式公开声明",
    explicit_permit_with_protected_global_control: "显式放行，覆盖全局保护",
    control_requirement_unresolved: "控制存在但要求无法解析",
    control_class_not_recognized_as_auth_control: "控制类未被识别为鉴权控制",
    control_class_has_no_observed_auth_token: "控制类未观察到鉴权判定",
    control_class_unresolved: "控制类源码不在快照内",
    authentication_control_not_entry_level: "控制不作用于该入口",
    method_annotation_control_observed: "方法注解声明控制",
    class_annotation_control_observed: "类注解声明控制",
    servlet_filter_control_observed: "Servlet 过滤器声明控制",
    interceptor_control_observed: "MVC 拦截器声明控制",
    security_chain_rule_observed: "Security 过滤器链规则",
    xml_intercept_url_observed: "XML 拦截规则",
  };
  const decisionReason = (reason) => decisionReasonLabels[reason] || reason || "—";
  const controlKindLabels = {
    method_annotation: "方法注解",
    class_annotation: "类注解",
    servlet_filter: "Servlet 过滤器",
    web_xml_constraint: "web.xml 约束",
    mvc_interceptor: "MVC 拦截器",
    security_chain: "Security 过滤器链",
    security_matcher: "Security matcher",
    intercept_url: "XML 拦截规则",
    webfilter_annotation: "@WebFilter",
    jaxrs_roles: "JAX-RS 角色注解",
  };
  const controlKindLabel = (kind) => controlKindLabels[kind] || kind;
  const requirementLabel = (requirement) => {
    if (!requirement || requirement === "none") return "—";
    if (requirement === "public") return "显式公开";
    return requirement;
  };

  function decisionPill(decision) {
    const meta = decisionMeta[decision] || { label: decision || "未知", cls: "warn" };
    return `<span class="status ${meta.cls}"><span class="dot ${meta.cls === "bad" ? "bad" : meta.cls === "ok" ? "ok" : "warn"}"></span>${esc(meta.label)}</span>`;
  }

  async function viewAuthz() {
    const authz = state.authz;
    $("#view").innerHTML = `
      <section class="card">
        <div class="toolbar">
          <div class="seg" id="authzSeg">
            ${[["all", "全部"], ["unprotected", "无控制"], ["unknown", "未知"], ["public", "公开"], ["protected", "受保护"]].map(([value, label]) => `<button type="button" data-decision="${value}" class="${authz.decision === value ? "active" : ""}">${label}</button>`).join("")}
          </div>
          <input class="input wide" id="authzSearch" data-search placeholder="搜索路径、控制器方法或访问要求…" value="${esc(authz.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="authzCount">—</span>
        </div>
        <div class="table-wrap">
          <table class="grid-fixed cols-authz">
            <thead><tr><th>决策</th><th>路径</th><th>控制器方法</th><th>访问要求</th><th>依据</th></tr></thead>
            <tbody id="authzRows"></tbody>
          </table>
        </div>
        <div class="pager">
          <span id="authzRange">—</span>
          <div class="pager-actions">
            <button class="btn" type="button" id="authzPrev"><svg class="icon"><use href="#i-chev-left"/></svg>上一页</button>
            <button class="btn" type="button" id="authzNext">下一页<svg class="icon"><use href="#i-chev-right"/></svg></button>
          </div>
        </div>
      </section>
      <div class="grid-2 section-gap">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-lock"/></svg>过滤器链</h3><span class="card-sub">声明顺序即优先级</span></div>
          <div class="card-body" id="authzChains"></div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-shield"/></svg>已识别控制</h3><span class="card-sub">注解 / XML / 配置链</span></div>
          <div class="card-body" id="authzControls"></div>
        </section>
      </div>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>限制与边界</h3><span class="card-sub">无控制不等于可未授权访问</span></div>
        <div class="card-body" id="authzLimits">${limitationList(authz.limitations)}</div>
      </section>
    `;
    $("#authzSeg").addEventListener("click", (event) => {
      const button = event.target.closest("[data-decision]");
      if (!button) return;
      authz.decision = button.dataset.decision;
      authz.offset = 0;
      $$("#authzSeg button").forEach((item) => item.classList.toggle("active", item === button));
      loadAuthz();
    });
    let timer = null;
    $("#authzSearch").addEventListener("input", (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        authz.q = event.target.value.trim();
        authz.offset = 0;
        loadAuthz();
      }, 240);
    });
    $("#authzPrev").addEventListener("click", () => {
      authz.offset = Math.max(0, authz.offset - authz.limit);
      loadAuthz();
    });
    $("#authzNext").addEventListener("click", () => {
      if (authz.offset + authz.limit < authz.total) {
        authz.offset += authz.limit;
        loadAuthz();
      }
    });
    $("#authzRows").addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-file]");
      if (row) go("source", { path: row.dataset.file, line: row.dataset.line });
    });
    await loadAuthz();
  }

  function authzRow(endpoint) {
    const controls = (endpoint.matched_controls || []).join("、");
    return `<tr class="clickable" tabindex="0" data-file="${esc(endpoint.file)}" data-line="${endpoint.method_line || endpoint.start_line}" title="${esc(endpoint.reason || "")}">
      <td>${decisionPill(endpoint.decision)}</td>
      <td class="path">${esc(endpoint.external_path || endpoint.path)}</td>
      <td class="strong">${esc(endpoint.symbol)}</td>
      <td>${esc(requirementLabel(endpoint.requirement))}</td>
      <td class="file" title="${esc(endpoint.reason || "")}">${esc(controls || decisionReason(endpoint.reason))}</td>
    </tr>`;
  }

  async function loadAuthz() {
    const authz = state.authz;
    const seq = ++authz.seq;
    const rows = $("#authzRows");
    if (!rows) return;
    rows.innerHTML = Array.from({ length: 6 }, () => `<tr><td colspan="5"><div class="sk sk-row"></div></td></tr>`).join("");
    const params = new URLSearchParams({ limit: authz.limit, offset: authz.offset });
    if (authz.q) params.set("q", authz.q);
    if (authz.decision && authz.decision !== "all") params.set("decision", authz.decision);
    try {
      const data = await api("/api/authz?" + params.toString());
      if (seq !== authz.seq) return;
      authz.total = data.total;
      authz.limitations = data.limitations || [];
      $("#authzCount").textContent = `无控制 ${fmtNum(data.counts.unprotected)} · 未知 ${fmtNum(data.counts.unknown)} · 受保护 ${fmtNum(data.counts.protected)} · 公开 ${fmtNum(data.counts.public)}`;
      if (!data.endpoints.length) {
        rows.innerHTML = `<tr><td colspan="5">${emptyState("i-lock", "没有匹配的入口", "调整决策筛选或检索条件。缺少已识别控制不代表可未授权访问。")}</td></tr>`;
      } else {
        rows.innerHTML = data.endpoints.map(authzRow).join("");
      }
      const start = data.total === 0 ? 0 : data.offset + 1;
      const end = Math.min(data.offset + data.endpoints.length, data.total);
      $("#authzRange").textContent = `第 ${start}–${end} 条 / 共 ${fmtNum(data.total)} 条`;
      $("#authzPrev").disabled = data.offset === 0;
      $("#authzNext").disabled = data.offset + authz.limit >= data.total;
      renderAuthzChains(data.chains || []);
      renderAuthzControls(data.controls || []);
      const limits = $("#authzLimits");
      if (limits) limits.innerHTML = limitationList(data.limitations);
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      if (seq === authz.seq) rows.innerHTML = `<tr><td colspan="5">${emptyState("i-alert", "加载失败", error.message)}</td></tr>`;
    }
  }

  function renderAuthzChains(chains) {
    const host = $("#authzChains");
    if (!host) return;
    if (!chains.length) {
      host.innerHTML = emptyState("i-lock", "未识别过滤器链", "项目可能使用自定义拦截器、外部网关或运行时配置；这类控制不在静态清单范围内。");
      return;
    }
    host.innerHTML = `<ul class="limits">${chains.map((chain) => `<li class="limit-row"><svg class="icon"><use href="#i-lock"/></svg><span><b>${esc(chain.id)}</b> <span class="limit-text">order=${esc(chain.order)} · ${esc((chain.security_matchers || []).join(" ") || "全部路径")} · 规则 ${(chain.rules || []).length}</span></span></li>`).join("")}</ul>`;
  }

  function renderAuthzControls(controls) {
    const host = $("#authzControls");
    if (!host) return;
    if (!controls.length) {
      host.innerHTML = emptyState("i-shield", "未识别访问控制", "注解、XML 与常见配置链均未命中。这是清单结论，不是漏洞结论。");
      return;
    }
    host.innerHTML = `<ul class="limits">${controls.slice(0, 40).map((control) => `<li class="limit-row"><svg class="icon"><use href="#i-shield"/></svg><span><b>${esc(controlKindLabel(control.kind))}</b> <span class="limit-text">${esc((control.paths || []).join(" ") || requirementLabel(control.requirement))} · ${esc(control.file)}:${control.line}</span></span></li>`).join("")}</ul>`;
  }

  // ── java semantic model ────────────────────────────────────────────────

  async function viewModel() {
    const model = state.model;
    $("#view").innerHTML = `
      <section class="card">
        <div class="toolbar">
          <input class="input wide" id="modelSearch" data-search placeholder="搜索类型全限定名或文件…" value="${esc(model.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="modelCount">—</span>
        </div>
        <div class="table-wrap">
          <table class="grid-fixed cols-model">
            <thead><tr><th>类型</th><th>种类</th><th class="right">方法</th><th class="right">字段</th><th>继承</th><th>文件</th></tr></thead>
            <tbody id="modelRows"></tbody>
          </table>
        </div>
        <div class="pager">
          <span id="modelRange">—</span>
          <div class="pager-actions">
            <button class="btn" type="button" id="modelPrev"><svg class="icon"><use href="#i-chev-left"/></svg>上一页</button>
            <button class="btn" type="button" id="modelNext">下一页<svg class="icon"><use href="#i-chev-right"/></svg></button>
          </div>
        </div>
      </section>
    `;
    let timer = null;
    $("#modelSearch").addEventListener("input", (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        model.q = event.target.value.trim();
        model.offset = 0;
        loadModel();
      }, 240);
    });
    $("#modelPrev").addEventListener("click", () => {
      model.offset = Math.max(0, model.offset - model.limit);
      loadModel();
    });
    $("#modelNext").addEventListener("click", () => {
      if (model.offset + model.limit < model.total) {
        model.offset += model.limit;
        loadModel();
      }
    });
    $("#modelRows").addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-fqn]");
      if (row) openModelType(row.dataset.fqn);
    });
    $("#modelRows").addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const row = event.target.closest("tr[data-fqn]");
      if (row) {
        event.preventDefault();
        openModelType(row.dataset.fqn);
      }
    });
    await loadModel();
  }

  function modelRow(item) {
    const kind = { class: "类", interface: "接口", enum: "枚举", record: "记录", annotation: "注解" }[item.kind] || item.kind;
    return `<tr class="clickable" tabindex="0" data-fqn="${esc(item.fqn)}">
      <td><div class="id-cell"><strong class="mono">${esc(item.name)}</strong><span>${esc(item.fqn)}</span></div></td>
      <td><span class="status muted">${esc(kind)}</span></td>
      <td class="num">${fmtNum(item.methods)}</td>
      <td class="num">${fmtNum(item.fields)}</td>
      <td class="file">${esc(item.extends || "—")}</td>
      <td class="file" title="${esc(item.file)}">${esc(item.file)}:${item.line}</td>
    </tr>`;
  }

  async function loadModel() {
    const model = state.model;
    const seq = ++model.seq;
    const rows = $("#modelRows");
    if (!rows) return;
    rows.innerHTML = Array.from({ length: 6 }, () => `<tr><td colspan="6"><div class="sk sk-row"></div></td></tr>`).join("");
    const params = new URLSearchParams({ limit: model.limit, offset: model.offset });
    if (model.q) params.set("q", model.q);
    try {
      const data = await api("/api/model?" + params.toString());
      if (seq !== model.seq) return;
      if (!data.enabled) {
        $("#modelCount").textContent = "未启用";
        $("#modelRange").textContent = "—";
        rows.innerHTML = `<tr><td colspan="6">${emptyState("i-code", "代码模型未启用", data.reason || "该快照未生成 Java 语义模型。")}</td></tr>`;
        $("#modelPrev").disabled = true;
        $("#modelNext").disabled = true;
        return;
      }
      model.total = data.total;
      $("#modelCount").textContent = `${fmtNum(data.total)} 个类型 · 方法 ${fmtNum(data.coverage.methods_indexed)} · 调用 ${fmtNum(data.coverage.calls_resolved)}/${fmtNum(data.coverage.calls_observed)}`;
      if (!data.types.length) {
        rows.innerHTML = `<tr><td colspan="6">${emptyState("i-code", "没有匹配的类型", "调整检索条件；受限子集解析失败的文件会记录在边界中。")}</td></tr>`;
      } else {
        rows.innerHTML = data.types.map(modelRow).join("");
      }
      const start = data.total === 0 ? 0 : data.offset + 1;
      const end = Math.min(data.offset + data.types.length, data.total);
      $("#modelRange").textContent = `第 ${start}–${end} 条 / 共 ${fmtNum(data.total)} 条`;
      $("#modelPrev").disabled = data.offset === 0;
      $("#modelNext").disabled = data.offset + model.limit >= data.total;
    } catch (error) {
      if (error.status === 401) { showLogin("会话已失效，请重新输入访问令牌。"); return; }
      if (seq === model.seq) rows.innerHTML = `<tr><td colspan="6">${emptyState("i-alert", "加载失败", error.message)}</td></tr>`;
    }
  }

  async function openModelType(fqn) {
    const layer = $("#drawerLayer");
    const drawer = $("#drawer");
    layer.hidden = false;
    drawer.innerHTML = `<div class="drawer-head"><div class="drawer-head-main"><span class="eyebrow">TYPE</span><h2>加载类型…</h2></div><button class="icon-btn" type="button" data-close-drawer><svg class="icon"><use href="#i-x"/></svg></button></div><div class="drawer-body">${skeletonView()}</div>`;
    $("[data-close-drawer]", drawer).addEventListener("click", closeDrawer);
    try {
      const data = await api("/api/model/type?fqn=" + encodeURIComponent(fqn));
      if (layer.hidden) return;
      drawer.innerHTML = modelTypeDrawer(data);
      $("[data-close-drawer]", drawer).addEventListener("click", closeDrawer);
    } catch (error) {
      drawer.innerHTML = `<div class="drawer-head"><div class="drawer-head-main"><span class="eyebrow">TYPE</span><h2>无法加载类型</h2></div><button class="icon-btn" type="button" data-close-drawer><svg class="icon"><use href="#i-x"/></svg></button></div><div class="drawer-body">${emptyState("i-alert", "请求失败", error.message)}</div>`;
      $("[data-close-drawer]", drawer).addEventListener("click", closeDrawer);
    }
  }

  function modelTypeDrawer(data) {
    const item = data.type;
    const methods = (item.methods || []).map((method) => `<li class="limit-row"><svg class="icon"><use href="#i-code"/></svg><span><b class="mono">${esc(method.name)}</b> <span class="limit-text">${esc(method.symbol)} · ${esc(item.file)}:${method.line}</span></span></li>`).join("");
    const fields = (item.fields || []).map((field) => `<li class="limit-row"><svg class="icon"><use href="#i-hash"/></svg><span><b class="mono">${esc(field.name)}</b> <span class="limit-text">${esc(field.type || field.type_raw)}${field.constant ? " = " + esc(field.constant) : ""}</span></span></li>`).join("");
    const edge = (call) => `<li class="limit-row"><svg class="icon"><use href="#i-route"/></svg><span><b class="mono">${esc(call.api || call.caller)}</b> <span class="limit-text">${esc(call.target || call.status)} · ${esc(call.file)}:${call.line}</span></span></li>`;
    return `<div class="drawer-head"><div class="drawer-head-main"><span class="eyebrow">${esc((item.kind || "type").toUpperCase())}</span><h2>${esc(item.name)}</h2><div class="drawer-meta"><span class="chip mono">${esc(item.fqn)}</span><span class="chip" data-src="${esc(item.file)}" data-line="${item.line}">${esc(item.file)}:${item.line}</span></div></div><button class="icon-btn" type="button" data-close-drawer><svg class="icon"><use href="#i-x"/></svg></button></div>
      <div class="drawer-body">
        <div class="drawer-section"><div class="drawer-section-head"><svg class="icon"><use href="#i-code"/></svg>方法 · ${(item.methods || []).length}</div><ul class="limits">${methods || '<li class="limit-row"><span class="limit-text">无方法声明</span></li>'}</ul></div>
        <div class="drawer-section"><div class="drawer-section-head"><svg class="icon"><use href="#i-hash"/></svg>字段 · ${(item.fields || []).length}</div><ul class="limits">${fields || '<li class="limit-row"><span class="limit-text">无字段声明</span></li>'}</ul></div>
        <div class="drawer-section"><div class="drawer-section-head"><svg class="icon"><use href="#i-route"/></svg>出向调用 · ${data.outgoing.length}</div><ul class="limits">${data.outgoing.map(edge).join("") || '<li class="limit-row"><span class="limit-text">未观察到调用</span></li>'}</ul></div>
        <div class="drawer-section"><div class="drawer-section-head"><svg class="icon"><use href="#i-chev-left"/></svg>入向调用 · ${data.incoming.length}</div><ul class="limits">${data.incoming.map(edge).join("") || '<li class="limit-row"><span class="limit-text">未观察到调用</span></li>'}</ul></div>
      </div>`;
  }

  // ── settings ───────────────────────────────────────────────────────────

  async function viewSettings() {
    const config = await api("/api/config");
    state.config = config;
    const paths = config.paths;
    const features = config.features;
    $("#view").innerHTML = `
      <section class="card">
        <div class="card-head"><h3><svg class="icon"><use href="#i-folder"/></svg>当前项目</h3><span class="card-sub">${config.mode === "workspace" ? "工作区模式" : "固定快照模式"}</span></div>
        <div class="card-body">
          <div class="kv">
            ${kvRow("源码目录", config.project.source || "—")}
            ${kvRow("快照摘要", config.project.hash, "good")}
            ${kvRow("文件 / 字节", `${fmtNum(config.project.files)} / ${fmtBytes(config.project.bytes)}`)}
            ${kvRow("工作区", config.workspace || "未启用（以 --workspace 启动后可在界面切换项目）")}
          </div>
          ${features.project_import ? `
          <div class="form-row mt-14">
            <button class="btn primary" type="button" id="gotoProjects"><svg class="icon"><use href="#i-folder"/></svg>选择 / 导入项目</button>
            <span class="form-hint">在「项目」页浏览目录、切换已导入项目。</span>
          </div>` : `<p class="form-hint warn-text">当前以固定快照启动，无法切换项目。使用 <code>trident web --workspace &lt;dir&gt;</code> 重新启动后即可在界面选择项目。</p>`}
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-package"/></svg>分析配置</h3><span class="card-sub">保存后立即重新分析</span></div>
        <div class="card-body">
          <div class="form-grid">
            <label class="field" for="cfgAdvisories"><span>公告目录 / 文件</span><input class="input" id="cfgAdvisories" value="${esc(paths.advisories_path || paths.advisories_dir)}" placeholder="目录或单个 JSON 目录文件" autocomplete="off" spellcheck="false"></label>
            <label class="field" for="cfgPackageMap"><span>Package map（依赖 → 包前缀）</span><input class="input" id="cfgPackageMap" value="${esc(paths.package_map_path)}" placeholder="JSON 文件路径；留空关闭可达性" autocomplete="off" spellcheck="false"></label>
            <label class="field" for="cfgRuntime"><span>运行时关联报告</span><input class="input" id="cfgRuntime" value="${esc(paths.runtime_report)}" placeholder="runtime http correlate --out 产物" autocomplete="off" spellcheck="false"></label>
          </div>
          <div class="form-row mt-14">
            <button class="btn primary" type="button" id="saveConfigBtn"><svg class="icon"><use href="#i-check"/></svg>保存并重新分析</button>
            <button class="btn" type="button" id="rerunBtn"><svg class="icon"><use href="#i-clock"/></svg>仅重新分析</button>
            <span class="spacer"></span>
            <span class="toolbar-count">公告 ${fmtNum(paths.advisories_count)} 个${paths.advisories_error ? " · " + esc(paths.advisories_error) : ""}</span>
          </div>
          ${features.workspace_editable ? "" : `<p class="form-hint warn-text">固定快照模式只读：路径配置需要以 --workspace 启动后才能修改。</p>`}
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-download"/></svg>导出</h3><span class="card-sub">确定性输出</span></div>
        <div class="card-body">
          <div class="form-row">
            <button class="btn" type="button" id="settingsSbom">导出 CycloneDX SBOM</button>
            <button class="btn" type="button" id="settingsSarif">导出 SARIF</button>
            <button class="btn" type="button" id="settingsEvidence">导出证据 JSON</button>
            <button class="btn" type="button" id="settingsReport">导出 HTML 报告</button>
          </div>
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>能力状态</h3><span class="card-sub">由本次启动参数决定</span></div>
        <div class="card-body">
          <div class="kv">
            ${kvRow("项目导入", features.project_import ? "可用" : "不可用", features.project_import ? "good" : "warn")}
            ${kvRow("路径配置", features.workspace_editable ? "可用" : "不可用", features.workspace_editable ? "good" : "warn")}
            ${kvRow("代码模型", features.java_model ? "已生成" : "未生成", features.java_model ? "good" : "warn")}
            ${kvRow("Agent 观测", features.agent_store ? "已连接只读库" : "未配置 --agent-dsn", features.agent_store ? "good" : "warn")}
            ${kvRow("分析状态", config.analysis.ready ? `完成 · ${fmtNum(config.analysis.duration_ms)} ms` : (config.analysis.error || "尚未运行"))}
          </div>
          ${config.java_model_reason ? `<p class="form-hint warn-text">${esc(config.java_model_reason)}</p>` : ""}
        </div>
      </section>
    `;
    $("#settingsSbom").addEventListener("click", exportSBOM);
    $("#settingsSarif").addEventListener("click", exportSARIF);
    $("#settingsEvidence").addEventListener("click", exportReport);
    $("#settingsReport").addEventListener("click", exportHtmlReport);
    if (features.workspace_editable) {
      $("#saveConfigBtn").addEventListener("click", saveConsoleConfig);
      $("#rerunBtn").addEventListener("click", rerunAnalysis);
    } else {
      $("#saveConfigBtn").disabled = true;
      $("#rerunBtn").disabled = true;
      $$("#cfgAdvisories, #cfgPackageMap, #cfgRuntime").forEach((input) => { input.disabled = true; });
    }
    if (features.project_import) {
      $("#gotoProjects").addEventListener("click", () => go("projects"));
    }
  }

  async function saveConsoleConfig() {
    const button = $("#saveConfigBtn");
    button.disabled = true;
    button.textContent = "保存中…";
    try {
      await api("/api/config", {
        method: "POST",
        body: {
          advisories_path: $("#cfgAdvisories").value.trim(),
          package_map_path: $("#cfgPackageMap").value.trim(),
          runtime_report: $("#cfgRuntime").value.trim(),
        },
      });
      toast("配置已保存，开始重新分析…", "ok");
      await rerunAnalysis();
    } catch (error) {
      toast(error.message, "bad");
      button.disabled = false;
      button.innerHTML = `<svg class="icon"><use href="#i-check"/></svg>保存并重新分析`;
    }
  }

  async function rerunAnalysis() {
    const button = $("#rerunBtn");
    if (button) {
      button.disabled = true;
      button.textContent = "分析中…";
    }
    try {
      const result = await api("/api/analysis/rerun", { method: "POST", body: {} });
      toast(`分析完成 · ${result.analysis.findings} 条发现 · ${result.analysis.duration_ms} ms`, "ok");
      await ensureOverview(true);
      await viewSettings();
    } catch (error) {
      toast(error.message, "bad");
      if (button) {
        button.disabled = false;
        button.innerHTML = `<svg class="icon"><use href="#i-clock"/></svg>仅重新分析`;
      }
    }
  }


  // ── project selection ──────────────────────────────────────────────────

  async function ensureConfig(force) {
    if (!state.config || force) state.config = await api("/api/config");
    return state.config;
  }

  function projectName(entry) {
    if (!entry || !entry.source) return "未命名项目";
    const parts = String(entry.source).split(/[\\/]/).filter(Boolean);
    return parts.length ? parts[parts.length - 1] : entry.source;
  }

  function setProjectChrome(hasProject) {
    const chip = $("#snapHash");
    if (chip) chip.textContent = hasProject ? shortHash(state.config.project.hash) : "未选择项目";
    const statusHash = $("#statusHash");
    if (statusHash) statusHash.textContent = hasProject ? state.config.project.hash : "—";
    const status = $("#statusAnalysis");
    if (status) status.textContent = hasProject ? status.textContent : "等待选择项目";
    ["#exportBtn", "#exportHtmlBtn"].forEach((selector) => {
      const button = $(selector);
      if (button) button.disabled = !hasProject;
    });
    const pill = $(".pill.runtime");
    if (pill) pill.hidden = !hasProject;
    if (!hasProject) {
      [$("#navFindings"), $("#navEndpoints")].forEach((badge) => {
        if (badge) badge.hidden = true;
      });
    }
  }

  async function viewProjects() {
    const [config, list] = await Promise.all([ensureConfig(true), api("/api/projects")]);
    const current = config.project.hash;
    const hasProject = Boolean(current);
    setProjectChrome(hasProject);
    const items = list.projects || [];
    $("#view").innerHTML = `
      ${hasProject ? `
      <section class="hero">
        <div class="hero-copy">
          <span class="eyebrow">CURRENT PROJECT</span>
          <h2>${esc(projectName({ source: config.project.source }))}</h2>
          <p class="mono hero-path">${esc(config.project.source || "—")}</p>
          <div class="hero-meta">
            <span class="chip mono"><svg class="icon icon-xs"><use href="#i-hash"/></svg>${esc(shortHash(current))}</span>
            <span class="chip">${fmtNum(config.project.files)} 个文件</span>
            <span class="chip">${fmtBytes(config.project.bytes)}</span>
            <span class="chip"><span class="dot ok"></span>分析完成 ${fmtNum(config.analysis.duration_ms)} ms</span>
          </div>
        </div>
        <div class="hero-side">
          <button class="btn primary" type="button" id="gotoOverview">查看分析结果<svg class="icon"><use href="#i-chev-right"/></svg></button>
        </div>
      </section>` : `
      <section class="card welcome-card">
        <div class="empty">
          <svg class="icon"><use href="#i-folder"/></svg>
          <h4>先选择一个要审计的项目</h4>
          <p>在下方浏览本地目录，或直接粘贴源码路径。导入只读取源码，快照保存在工作区，原目录不会被写入。</p>
        </div>
      </section>`}

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-folder"/></svg>导入本地项目</h3><span class="card-sub">只读导入 · 不执行代码</span></div>
        <div class="card-body">
          ${config.features.project_import ? `
          <div class="form-row">
            <label class="field grow" for="importSource"><span>源码目录</span><input class="input" id="importSource" placeholder="例如 D:\\Code\\Java\\market" autocomplete="off" spellcheck="false" value="${esc(state.browse.pick || "")}"></label>
            <button class="btn" type="button" id="browseToggle"><svg class="icon"><use href="#i-folder"/></svg>浏览目录</button>
            <button class="btn primary" type="button" id="importBtn"><svg class="icon"><use href="#i-download"/></svg>导入并分析</button>
          </div>
          <div id="browser" class="browser" hidden>
            <div class="browser-bar">
              <button class="btn sm" type="button" id="browseUp" title="上级目录">↑ 上级</button>
              <span class="browser-path mono" id="browsePath">—</span>
            </div>
            <div class="browser-roots" id="browseRoots"></div>
            <ul class="dir-list" id="browseList"></ul>
            <div class="browser-foot">
              <button class="btn sm primary" type="button" id="pickDir">选择当前目录</button>
              <span class="form-hint">只会列出目录，不读取文件内容，不跟随符号链接。</span>
            </div>
          </div>` : `<p class="form-hint warn-text">当前以固定快照启动，无法导入项目。使用 <code>trident web --workspace .trident</code> 启动后即可在界面选择项目。</p>`}
        </div>
      </section>

      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>已导入项目</h3><span class="card-sub">${fmtNum(items.length)} 个</span></div>
        <div class="card-body">
          ${items.length ? `<ul class="project-list">${items.map((entry) => projectRow(entry, current)).join("")}</ul>` : `<div class="empty"><svg class="icon"><use href="#i-folder"/></svg><h4>还没有导入任何项目</h4><p>从上面的目录选择器挑一个源码目录即可开始。</p></div>`}
        </div>
      </section>
    `;

    if (!config.features.project_import) return;

    const input = $("#importSource");
    const browser = $("#browser");
    $("#importBtn").addEventListener("click", () => importProject(input.value.trim()));
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") importProject(input.value.trim());
    });
    $("#browseToggle").addEventListener("click", async () => {
      browser.hidden = !browser.hidden;
      if (!browser.hidden && !state.browse.path) await browseTo("");
    });
    $("#browseUp").addEventListener("click", () => {
      if (state.browse.parent) browseTo(state.browse.parent);
    });
    $("#pickDir").addEventListener("click", () => {
      if (!state.browse.path) return;
      input.value = state.browse.path;
      state.browse.pick = state.browse.path;
      toast("已选择目录：" + state.browse.path, "ok");
    });
    $("#browseList").addEventListener("click", (event) => {
      const row = event.target.closest("li[data-path]");
      if (row) browseTo(row.dataset.path);
    });
    $("#browseRoots").addEventListener("click", (event) => {
      const chip = event.target.closest("[data-root]");
      if (chip) browseTo(chip.dataset.root);
    });
    $("#view").addEventListener("click", (event) => {
      const action = event.target.closest("[data-project-action]");
      if (!action) return;
      const hash = action.dataset.hash;
      if (action.dataset.projectAction === "select") selectProject(hash);
      if (action.dataset.projectAction === "forget") forgetProject(hash);
    });
    const overview = $("#gotoOverview");
    if (overview) overview.addEventListener("click", () => go("overview"));
    if (!browser.hidden) await browseTo(state.browse.path || "");
  }

  function projectRow(entry, current) {
    const active = entry.hash === current;
    return `<li class="project-row${active ? " active" : ""}">
      <span class="project-icon"><svg class="icon"><use href="#i-${active ? "check" : "folder"}"/></svg></span>
      <span class="project-main">
        <strong>${esc(projectName(entry))}</strong>
        <span class="mono project-path" title="${esc(entry.source)}">${esc(entry.source)}</span>
      </span>
      <span class="project-meta">
        <span class="chip mono">${esc(shortHash(entry.hash))}</span>
        <span class="chip">${fmtNum(entry.files)} 文件</span>
      </span>
      <span class="project-actions">
        ${active
          ? '<span class="status ok"><span class="dot ok"></span>当前</span>'
          : `<button class="btn sm" type="button" data-project-action="select" data-hash="${esc(entry.hash)}">切换</button>
             <button class="btn sm ghost" type="button" data-project-action="forget" data-hash="${esc(entry.hash)}" title="只从列表移除，不删除快照文件">移除</button>`}
      </span>
    </li>`;
  }

  async function browseTo(path) {
    const browse = state.browse;
    try {
      const data = await api("/api/fs" + (path ? "?path=" + encodeURIComponent(path) : ""));
      browse.path = data.path;
      browse.parent = data.parent || "";
      browse.entries = data.entries || [];
      browse.roots = data.roots || [];
      $("#browsePath").textContent = data.path;
      $("#browseUp").disabled = !data.parent;
      $("#browseRoots").innerHTML = browse.roots.map((root) => `<button class="chip chip-btn" type="button" data-root="${esc(root)}">${esc(root)}</button>`).join("");
      $("#browseList").innerHTML = browse.entries.length
        ? browse.entries.map((entry) => `<li class="dir-row${entry.looks_like_project ? " project" : ""}" data-path="${esc(entry.path)}">
            <svg class="icon"><use href="#i-folder"/></svg>
            <span class="dir-name">${esc(entry.name)}</span>
            ${entry.looks_like_project ? '<span class="status info">项目</span>' : ""}
          </li>`).join("")
        : `<li class="dir-empty">该目录下没有可进入的子目录</li>`;
      if (data.truncated) $("#browseList").insertAdjacentHTML("beforeend", `<li class="dir-empty">条目过多，仅显示前 ${500} 项</li>`);
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  async function selectProject(hash) {
    try {
      await api("/api/projects/select", { method: "POST", body: { hash } });
      resetAnalysisState();
      await ensureConfig(true);
      await refreshProjectSwitcher();
      await ensureOverview(true);
      toast("已切换项目，重新分析完成", "ok");
      go("overview");
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  async function forgetProject(hash) {
    try {
      await api("/api/projects/forget", { method: "POST", body: { hash } });
      toast("已从列表移除（快照文件保留）", "ok");
      await viewProjects();
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  async function importProject(source) {
    if (!source) {
      toast("请填写或选择一个源码目录", "bad");
      return;
    }
    const button = $("#importBtn");
    button.disabled = true;
    button.textContent = "导入中…";
    try {
      const result = await api("/api/projects", { method: "POST", body: { source } });
      state.browse.pick = source;
      resetAnalysisState();
      await ensureConfig(true);
      await refreshProjectSwitcher();
      await ensureOverview(true);
      toast(`已导入 ${result.project.files} 个文件 · ${shortHash(result.project.hash)}`, "ok");
      go("overview");
    } catch (error) {
      toast(error.message, "bad");
      button.disabled = false;
      button.innerHTML = `<svg class="icon"><use href="#i-download"/></svg>导入并分析`;
    }
  }

  function resetAnalysisState() {
    state.overview = null;
    state.findings = { ...state.findings, items: [], total: 0, filtered: 0, offset: 0, counts: null };
    state.endpoints = { ...state.endpoints, items: [], total: 0, offset: 0, authzMap: {}, authzCounts: null };
    state.authz = { ...state.authz, items: [], total: 0, offset: 0 };
    state.model = { ...state.model, items: [], total: 0, offset: 0 };
    state.source = { ...state.source, files: [], cursor: "", path: "", file: null, search: null };
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
    if (!state.token) {
      showLogin("");
      return;
    }
    try {
      await api("/api/health");
      $("#login").hidden = true;
      $("#app").hidden = false;
      const config = await ensureConfig(true);
      await refreshProjectSwitcher();
      if (!config.project.hash) {
        if (location.hash !== "#/projects") location.hash = "#/projects";
        await renderRoute();
        return;
      }
      await refreshProjectSwitcher();
      await ensureOverview();
      if (!location.hash) {
        location.hash = "#/overview";
      } else {
        await renderRoute();
      }
    } catch (error) {
      if (error.status === 401) showLogin("");
      else showLogin("控制台服务不可用：" + error.message);
    }
  }

  boot();
})();
