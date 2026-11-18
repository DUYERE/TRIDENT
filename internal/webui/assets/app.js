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
    cases: { items: [], available: false, root: "cases", q: "", status: "all", loading: false, seq: 0 },
    caseDetail: null,
    endpoints: { items: [], total: 0, offset: 0, limit: 50, q: "", authz: "all", authzMap: {}, authzCounts: null, coverage: null, entries: [], entryCoverage: [], entryPartial: false, entryLimitations: [], seq: 0, loading: false },
    authz: { items: [], total: 0, offset: 0, limit: 50, q: "", decision: "all", limitations: [], seq: 0 },
    code: { items: [], total: 0, offset: 0, limit: 50, q: "", language: "all", category: "all", severity: "all", limitations: [], seq: 0 },
    symbols: { items: [], total: 0, offset: 0, limit: 50, q: "", language: "all", kind: "all", seq: 0 },
    model: { items: [], total: 0, offset: 0, limit: 50, q: "", seq: 0 },
    config: null,
    modelSettings: null,
    browse: { path: "", parent: "", entries: [], roots: [], pick: "" },
    source: { mode: "files", prefix: "", files: [], cursor: "", total: 0, path: "", line: 0, file: null, search: null, searchQ: "" },
    agent: { chat: null, conversations: [], conversationId: 0, conversation: null, runs: [], tasks: [], openId: 0, steps: [], run: null, busy: false, timer: null, lastSeq: 0 },
    pendingRepair: false,
    drawerId: null,
  };

  const routeMeta = {
    projects: { title: "项目", eyebrow: "TRIDENT / PROJECTS" },
    overview: { title: "概览", eyebrow: "TRIDENT / OVERVIEW" },
    findings: { title: "安全发现", eyebrow: "TRIDENT / FINDINGS" },
    cases: { title: "Case 工作台", eyebrow: "TRIDENT / CASES" },
    case: { title: "Case 详情", eyebrow: "TRIDENT / CASES / DETAIL" },
    endpoints: { title: "HTTP 入口", eyebrow: "TRIDENT / ENDPOINTS" },
    dependencies: { title: "依赖与公告", eyebrow: "TRIDENT / DEPENDENCIES" },
    tree: { title: "依赖树", eyebrow: "TRIDENT / DEPENDENCY TREE" },
    reachability: { title: "可达性", eyebrow: "TRIDENT / REACHABILITY" },
    authz: { title: "权限清单", eyebrow: "TRIDENT / AUTHORIZATION" },
    code: { title: "代码审计", eyebrow: "TRIDENT / MULTI-LANGUAGE CODE AUDIT" },
    model: { title: "代码模型", eyebrow: "TRIDENT / CODE MODEL" },
    runtime: { title: "运行时关联", eyebrow: "TRIDENT / RUNTIME CORRELATION" },
    agent: { title: "Agent 对话", eyebrow: "TRIDENT / AGENT CHAT" },
    tasks: { title: "编排任务", eyebrow: "TRIDENT / ORCHESTRATION" },
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
    const projectMenu = $("#projectMenu");
    const projectPanel = $("#projectMenuPanel");
    const projectBtn = $("#projectSwitchBtn");
    const closeProjectMenu = () => {
      if (!projectPanel) return;
      projectPanel.hidden = true;
      if (projectBtn) projectBtn.setAttribute("aria-expanded", "false");
    };
    if (projectBtn && projectPanel) {
      projectBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        const open = projectPanel.hidden;
        projectPanel.hidden = !open;
        projectBtn.setAttribute("aria-expanded", String(open));
        if (open) refreshProjectSwitcher();
      });
      document.addEventListener("click", (event) => {
        if (projectMenu && !projectMenu.contains(event.target)) closeProjectMenu();
      });
      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeProjectMenu();
      });
    }
    const manageProjects = $("#manageProjects");
    if (manageProjects) {
      manageProjects.addEventListener("click", () => {
        closeProjectMenu();
        go("projects");
      });
    }
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
      const createCase = event.target.closest("[data-create-case]");
      if (createCase) {
        createCaseFromFinding(createCase.dataset.createCase);
        return;
      }
      const ask = event.target.closest("[data-ask-agent]");
      if (ask) {
        const finding = state.drawerFinding;
        const location = finding && finding.location ? `（${finding.location}）` : "";
        state.pendingAgentGoal = `请复核发现 ${ask.dataset.askAgent}${location}：先引用它给出的证据行确认可达性，再给出利用前提与修复建议；只引用实际读到的行，无法验证的部分标注 UNVERIFIED INFERENCE。`;
        closeDrawer();
        go("agent");
        return;
      }
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
      if (name !== "projects" && name !== "cases" && name !== "case") {
        const config = await ensureConfig();
        if (!config.project.hash) {
          go("projects");
          return;
        }
      }
      if (name === "projects") await viewProjects();
      else if (name === "overview") await viewOverview();
      else if (name === "findings") await viewFindings();
      else if (name === "cases") await viewCases();
      else if (name === "case") await viewCase(params);
      else if (name === "endpoints") await viewEndpoints();
      else if (name === "dependencies") await viewDependencies();
      else if (name === "tree") await viewTree();
      else if (name === "authz") await viewAuthz();
      else if (name === "code") await viewCode();
      else if (name === "model") await viewModel();
      else if (name === "reachability") await viewReachability();
      else if (name === "runtime") await viewRuntime();
      else if (name === "agent") await viewAgent(params);
      else if (name === "tasks") await viewOrchTasks(params);
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

  async function selectProject(hash) {
    if (!hash || hash === (state.config && state.config.project.hash)) return;
    const panel = $("#projectMenuPanel");
    if (panel) panel.hidden = true;
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
  }

  async function refreshProjectSwitcher() {
    const label = $("#projectSwitchLabel");
    const list = $("#projectMenuList");
    if (!label || !list) return;
    let projects = [];
    try {
      const payload = await api("/api/projects");
      projects = payload.projects || [];
    } catch (error) {
      projects = [];
    }
    const current = (state.config && state.config.project && state.config.project.hash) || "";
    if (!projects.length) {
      label.textContent = "未选择项目";
      list.innerHTML = `<div class="project-menu-empty">${emptyState("i-folder", "还没有项目", "到「项目」页导入本地源码目录后，这里会列出全部快照。")}</div>`;
      return;
    }
    const active = projects.find((entry) => entry.hash === current) || projects[0];
    label.textContent = String(active.source || "").split(/[\\/]/).filter(Boolean).pop() || active.hash.slice(0, 12);
    list.innerHTML = projects.map((entry) => {
      const name = String(entry.source || "").split(/[\\/]/).filter(Boolean).pop() || entry.hash.slice(0, 12);
      const isCurrent = entry.hash === current;
      return `<button class="project-option${isCurrent ? " current" : ""}" type="button" role="option" aria-selected="${isCurrent}" data-hash="${esc(entry.hash)}" title="${esc(entry.source || "")}">
        <span class="project-option-main">
          <strong>${esc(name)}</strong>
          <span class="mono">${esc(entry.hash.slice(0, 10))} · ${fmtNum(entry.files)} 文件 · ${fmtBytes(entry.bytes)}</span>
        </span>
        ${isCurrent ? '<span class="project-current"><span class="dot ok"></span>当前</span>' : '<span class="project-current muted">切换</span>'}
      </button>`;
    }).join("");
    $$("#projectMenuList .project-option").forEach((option) => {
      option.addEventListener("click", () => selectProject(option.dataset.hash));
    });
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
    const applicationEntries = overview.analysis.application_entries || 0;
    const entryTotal = overview.analysis.endpoint_coverage.endpoints_found + applicationEntries;
    endpointsBadge.textContent = entryTotal;
    endpointsBadge.hidden = entryTotal === 0;
  }

  // ── overview ───────────────────────────────────────────────────────────

  async function viewOverview() {
    const overview = await ensureOverview();
    // Keep the overview in sync with the findings page: when the lazy
    // multi-language audit has not run yet, warm it in the background and
    // re-render so the finding counts land without a manual refresh.
    if (overview.code && !overview.code.available && String(overview.code.reason || "").startsWith("analysis_pending") && !state.codeWarm) {
      state.codeWarm = true;
      api("/api/code-audit?limit=1").then(() => {
        state.codeWarm = false;
        return ensureOverview(true);
      }).then(() => {
        if (state.route === "overview") renderRoute();
      }).catch(() => {
        state.codeWarm = false;
      });
    }
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
        ${tile("route", "blue", fmtNum(analysis.endpoint_coverage.endpoints_found + (analysis.application_entries || 0)), "HTTP 入口", `${fmtNum(analysis.endpoint_coverage.controllers_found)} 个控制器 · ${fmtNum(analysis.application_entries || 0)} 个应用入口`, { route: "endpoints" })}
        ${tile("bug", "rose", fmtNum(counts.total), "安全发现", `静态确认 ${fmtNum(counts.static_confirmed)}`, { route: "findings", status: "all" })}
        ${tile("alert", "amber", fmtNum(counts.inconclusive), "证据待定", `已反驳 ${fmtNum(counts.refuted)}`, { route: "findings", status: "inconclusive" })}
        ${tile("package", "violet", fmtNum(analysis.sca_coverage.dependencies_declared), "依赖声明", `${fmtNum(analysis.sca_coverage.poms_scanned)} 个 POM`, { route: "dependencies" })}
        ${tile("flag", "amber", fmtNum(coverage.sca_advisory_candidates), "公告命中", `未命中 ${fmtNum(coverage.sca_advisory_not_affected)}`, { route: "dependencies" })}
        ${tile("lock", "rose", fmtNum(overview.authz.unprotected), "无控制入口", `受保护 ${fmtNum(overview.authz.protected)} · 未知 ${fmtNum(overview.authz.unknown)}`, { route: "authz", decision: "unprotected" })}
        ${tile("bug", "violet", overview.code && overview.code.available ? fmtNum(overview.code.findings) : "…", "多语言审计", overview.code && overview.code.available ? `${fmtNum(overview.code.languages)} 种语言 · ${fmtNum(overview.code.findings)} 条发现` : (overview.code && String(overview.code.reason || "").startsWith("analysis_pending") ? "正在后台运行，完成后本页自动同步" : (overview.code ? (overview.code.reason || "未运行") : "未运行")), { route: "code" })}
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
              ${kvRow("应用入口候选 / 语言", `${fmtNum(analysis.application_entries || 0)} / ${fmtNum(analysis.application_entry_languages || 0)}`, "warn")}
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

  // ── cases ───────────────────────────────────────────────────────────────

  const caseStatusMeta = {
    verified: { label: "已验证", cls: "ok" },
    ready: { label: "补丁就绪", cls: "warn" },
    in_progress: { label: "进行中", cls: "info" },
    blocked: { label: "受阻", cls: "bad" },
    failed: { label: "验证失败", cls: "bad" },
    draft: { label: "草稿", cls: "muted" },
    pending: { label: "未开始", cls: "muted" },
    missing: { label: "缺失", cls: "bad" },
  };
  const caseStatusPill = (status) => {
    const meta = caseStatusMeta[status] || { label: status || "未知", cls: "muted" };
    return `<span class="status ${meta.cls}">${esc(meta.label)}</span>`;
  };
  const caseTime = (value) => {
    const time = new Date(value);
    return Number.isNaN(time.getTime()) ? "—" : time.toLocaleString("zh-CN", { hour12: false });
  };
  const caseStage = (stage) => {
    const meta = caseStatusMeta[stage.status] || caseStatusMeta.pending;
    return `<div class="case-stage ${esc(stage.status || "pending")}" title="${esc(stage.detail || stage.label || "")}">
      <span class="case-stage-dot"></span>
      <span class="case-stage-label">${esc(stage.label || stage.key)}</span>
      <span class="case-stage-state">${esc(meta.label)}</span>
    </div>`;
  };
  const caseStageStrip = (stages) => `<div class="case-stages">${(stages || []).map(caseStage).join("")}</div>`;

  function caseRow(item) {
    const stages = item.stages || [];
    return `<a class="case-row" href="#/case?id=${esc(encodeURIComponent(item.id))}">
      <div class="case-row-main">
        <div class="case-row-title">
          <strong>${esc(item.title || item.id)}</strong>
          ${item.severity ? sevPill(item.severity) : ""}
          ${caseStatusPill(item.status)}
        </div>
        <div class="case-row-meta">
          <span class="mono">${esc(item.id)}</span>
          ${item.repository ? `<span>·</span><span>${esc(item.repository)}</span>` : ""}
          ${item.vulnerable_version ? `<span>·</span><span>${esc(item.vulnerable_version)}</span>` : ""}
          <span>·</span><span>${fmtNum(item.finding_count)} Finding</span>
        </div>
        ${caseStageStrip(stages)}
      </div>
      <div class="case-row-side">
        <span class="case-row-updated">${esc(caseTime(item.updated_at))}</span>
        <svg class="icon"><use href="#i-chev-right"/></svg>
      </div>
    </a>`;
  }

  async function viewCases() {
    const data = await api("/api/cases");
    const store = state.cases;
    store.items = data.cases || [];
    store.available = Boolean(data.available);
    store.root = data.root || "cases";
    const count = $("#navCases");
    if (count) {
      count.textContent = store.items.length;
      count.hidden = store.items.length === 0;
    }
    const statuses = [
      ["all", "全部"],
      ["verified", "已验证"],
      ["ready", "补丁就绪"],
      ["in_progress", "进行中"],
      ["blocked", "受阻"],
    ];
    $("#view").innerHTML = `
      <section class="card case-hero">
        <div class="card-head">
          <h3><svg class="icon"><use href="#i-flag"/></svg>证据驱动的 Case 工作台</h3>
          <span class="card-sub">Finding → PoC → 补丁 → 验证 → 上游</span>
        </div>
        <div class="card-body case-hero-body">
          <div class="case-hero-copy">
            <p>只展示已落盘的证据与产物。阶段状态不是进度条：没有运行证明的 Case 会保持未开始，不能写成已验证。</p>
            <div class="case-hero-stats">
              <span><b>${fmtNum(store.items.length)}</b> Case</span>
              <span><b>${fmtNum(store.items.filter((item) => item.status === "verified").length)}</b> 已验证</span>
              <span><b>${fmtNum(store.items.reduce((sum, item) => sum + (item.finding_count || 0), 0))}</b> Finding</span>
            </div>
          </div>
          <div class="case-hero-actions">
            <button class="btn" type="button" id="caseRefresh"><svg class="icon"><use href="#i-refresh"/></svg>刷新</button>
            <a class="btn" href="#/findings"><svg class="icon"><use href="#i-bug"/></svg>从 Finding 创建</a>
          </div>
        </div>
      </section>
      <section class="card section-gap">
        <div class="toolbar">
          <div class="seg" id="caseStatusSeg">
            ${statuses.map(([value, label]) => `<button type="button" data-case-status="${value}" class="${store.status === value ? "active" : ""}">${label}</button>`).join("")}
          </div>
          <input class="input wide" id="caseSearch" data-search placeholder="搜索 Case、仓库、CVE 或 Finding…" value="${esc(store.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="caseCount">—</span>
        </div>
        ${store.available ? `<div class="case-list" id="caseList"></div>` : `<div class="empty"><svg class="icon"><use href="#i-folder"/></svg><h4>没有发现 Case 目录</h4><p>控制台默认扫描 &lt;工作目录&gt;/cases。启动时传 <span class="mono">--cases &lt;dir&gt;</span>，或从安全发现抽屉创建 Case。</p></div>`}
      </section>`;

    const renderList = () => {
      const query = store.q.trim().toLowerCase();
      const filtered = store.items.filter((item) => {
        if (store.status !== "all" && item.status !== store.status) return false;
        if (!query) return true;
        return [item.id, item.title, item.repository, item.vulnerable_version, item.fixed_version, item.severity].some((value) => String(value || "").toLowerCase().includes(query));
      });
      const list = $("#caseList");
      if (list) list.innerHTML = filtered.length ? filtered.map(caseRow).join("") : emptyState("i-flag", "没有匹配的 Case", "换个状态筛选或搜索词再试。");
      $("#caseCount").textContent = `${fmtNum(filtered.length)} / ${fmtNum(store.items.length)}`;
    };

    const statusSeg = $("#caseStatusSeg");
    if (statusSeg) {
      statusSeg.addEventListener("click", (event) => {
        const button = event.target.closest("[data-case-status]");
        if (!button) return;
        store.status = button.dataset.caseStatus;
        $$("#caseStatusSeg button").forEach((item) => item.classList.toggle("active", item === button));
        renderList();
      });
    }
    const search = $("#caseSearch");
    if (search) {
      let timer = null;
      search.addEventListener("input", (event) => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          store.q = event.target.value;
          renderList();
        }, 220);
      });
    }
    const refresh = $("#caseRefresh");
    if (refresh) refresh.addEventListener("click", () => viewCases());
    renderList();
  }

  async function viewCase(params) {
    const id = params.get("id") || "";
    if (!id) {
      go("cases");
      return;
    }
    const detail = await api("/api/case?id=" + encodeURIComponent(id));
    state.caseDetail = detail;
    const stages = detail.stages || [];
    const findings = detail.findings || [];
    const evidence = detail.evidence || [];
    const patch = detail.patch;
    const validation = detail.validation;
    const upstream = detail.upstream;
    $("#view").innerHTML = `
      <section class="card case-detail-head">
        <div class="card-head">
          <div class="case-detail-title">
            <span class="eyebrow">${esc(detail.repository || "CASE")}${detail.vulnerable_version ? " · " + esc(detail.vulnerable_version) : ""}</span>
            <h2>${esc(detail.title || detail.id)}</h2>
            <div class="case-detail-badges">
              ${caseStatusPill(detail.status)}
              ${detail.severity ? sevPill(detail.severity) : ""}
              <span class="chip mono">${esc(detail.id)}</span>
              <span class="status muted">${esc(detail.source || "directory")}</span>
            </div>
          </div>
          <div class="row-actions">
            <button class="btn sm" type="button" data-case-action="patch" title="读取已落盘的 patch.diff；不在 Web 请求内重新生成"><svg class="icon"><use href="#i-code"/></svg>生成补丁</button>
            <button class="btn sm" type="button" data-case-action="verify" title="读取已落盘的 verify.log / patch_meta.json"><svg class="icon"><use href="#i-check"/></svg>验证补丁</button>
            <button class="btn sm" type="button" data-case-action="export"><svg class="icon"><use href="#i-download"/></svg>导出 JSON</button>
            <button class="btn sm primary" type="button" data-ask-repair="${esc(detail.id)}"><svg class="icon"><use href="#i-bug"/></svg>让 Agent 修复</button>
            <button class="btn sm" type="button" id="caseDetailRefresh"><svg class="icon"><use href="#i-refresh"/></svg></button>
          </div>
        </div>
        <div class="card-body">
          <div class="case-detail-meta">
            ${kvRow("仓库", detail.repository || "—")}
            ${kvRow("漏洞版本", detail.vulnerable_version || "—")}
            ${kvRow("修复参考", detail.fixed_version || "—")}
            ${kvRow("更新", caseTime(detail.updated_at))}
            ${kvRow("Finding 数", fmtNum(detail.finding_count))}
          </div>
          ${caseStageStrip(stages)}
        </div>
      </section>
      <div class="grid-2 section-gap">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-bug"/></svg>Findings</h3><span class="card-sub">${fmtNum(findings.length)} 个</span></div>
          <div class="card-body case-block">
            ${findings.length ? findings.map((finding) => `<div class="case-finding">
              <div class="case-finding-head"><strong>${esc(finding.title || finding.id)}</strong>${finding.severity ? sevPill(finding.severity) : ""}</div>
              <div class="case-finding-meta"><span class="mono">${esc(finding.id)}</span>${finding.cve ? `<span class="mono">${esc(finding.cve)}</span>` : ""}${finding.runtime_result ? `<span class="status ${finding.runtime_result === "VULNERABLE" ? "warn" : "info"}">runtime ${esc(finding.runtime_result)}</span>` : ""}</div>
              ${(finding.source_evidence || []).map((source) => `<div class="case-source"><span class="mono">${esc(source.file)}${source.lines ? ":" + esc(source.lines) : ""}</span>${source.observation ? `<span>${esc(source.observation)}</span>` : ""}${source.sha256 ? `<span class="mono">sha ${esc(source.sha256.slice(0, 12))}</span>` : ""}</div>`).join("")}
            </div>`).join("") : emptyState("i-info", "没有 Finding", "Case 目录里没有可解析的 finding 文档。")}
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>补丁与验证</h3><span class="card-sub">只读已落盘产物</span></div>
          <div class="card-body">
            ${patch ? `<div class="kv">
              ${kvRow("补丁文件", patch.file)}
              ${kvRow("大小 / 文件数", fmtBytes(patch.bytes) + " / " + fmtNum((patch.files || []).length))}
              ${kvRow("SHA-256", shortHash(patch.sha256))}
              ${kvRow("apply check", patch.apply_check || "—", patch.apply_check ? "good" : "warn")}
              ${(patch.files || []).map((file) => `<div class="case-file mono">${esc(file)}</div>`).join("")}
            </div>` : emptyState("i-code", "还没有补丁产物", "先生成 patch.diff，再让 Case 读取真实补丁。")}
            ${validation ? `<div class="case-validation">
              <div class="case-validation-head"><span>${esc(validation.result)}</span><span class="status ${String(validation.result || "").includes("VERIFIED") ? "ok" : "warn"}">${esc(validation.source || "recorded")}</span></div>
              <div class="case-validation-meta">${esc(validation.log || "—")}${validation.verified_at ? " · " + esc(caseTime(validation.verified_at)) : ""}</div>
              ${validation.checks ? `<div class="case-checks">${Object.entries(validation.checks).map(([key, value]) => `<span class="case-check ${value === true ? "ok" : value === false ? "bad" : ""}">${esc(key)}: ${esc(value === null || value === undefined ? "—" : value)}</span>`).join("")}</div>` : ""}
            </div>` : `<div class="case-note warn">没有验证记录；不能把未执行写成已验证。</div>`}
          </div>
        </section>
      </div>
      <div class="grid-2 section-gap">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-hash"/></svg>证据产物</h3><span class="card-sub">${fmtNum(evidence.length)} 个</span></div>
          <div class="card-body">
            ${evidence.length ? `<div class="case-evidence-list">${evidence.map((item) => `<div class="case-evidence">
              <div><strong>${esc(item.name)}</strong><span class="status ${item.result === "VULNERABLE" ? "warn" : "muted"}">${esc(item.result || "recorded")}</span></div>
              <div class="case-evidence-meta">${fmtBytes(item.bytes)}${item.sha256 ? " · sha " + esc(item.sha256.slice(0, 12)) : ""}${item.detail ? " · " + esc(item.detail) : ""}</div>
            </div>`).join("")}</div>` : emptyState("i-info", "没有证据产物", "evidence/ 目录没有可解析的 JSON。")}
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-package"/></svg>上游 Bundle</h3><span class="card-sub">${upstream && upstream.present ? "本地草稿" : "未准备"}</span></div>
          <div class="card-body">
            ${upstream && upstream.present ? `<div class="case-upstream">
              <div class="case-upstream-state"><span class="status ${upstream.submitted ? "ok" : "warn"}">${upstream.submitted ? "已提交" : "DRAFT · 未提交"}</span></div>
              ${(upstream.files || []).map((file) => `<div class="case-file mono">upstream/${esc(file)}</div>`).join("")}
              <div class="case-note">上游提交需要明确批准；当前只准备本地材料。</div>
            </div>` : emptyState("i-package", "还没有上游材料", "advisory、repro、test-plan 与 PR body 尚未落盘。")}
          </div>
        </section>
      </div>
      ${(detail.limitations || []).length ? `<section class="card section-gap"><div class="card-head"><h3><svg class="icon"><use href="#i-alert"/></svg>限制</h3><span class="card-sub">不能从状态推断安全</span></div><div class="card-body"><ul class="point-list">${detail.limitations.map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div></section>` : ""}
    `;

    $$("[data-case-action]").forEach((button) => {
      button.addEventListener("click", () => runCaseAction(button.dataset.caseAction, detail.id));
    });
    $$("[data-ask-repair]").forEach((button) => {
      button.addEventListener("click", () => {
        state.pendingAgentGoal = `请以 Case ${detail.id}（${detail.title || "未命名 Case"}）为唯一目标：先读取 finding 的源码证据确认可达性；如果本轮已获批准，调用 propose_patch(case_id="${detail.id}") 生成补丁，再用 verify_patch 验证；任何失败、未批准或 source_not_in_snapshot 都必须原样报告，不要把语法检查写成漏洞已修复。`;
        state.pendingRepair = true;
        go("agent");
      });
    });
    const refresh = $("#caseDetailRefresh");
    if (refresh) refresh.addEventListener("click", () => viewCase(new URLSearchParams({ id: detail.id })));
  }

  async function runCaseAction(action, id) {
    try {
      if (action === "patch") {
        const payload = await api("/api/case/propose", { method: "POST", body: { id } });
        toast(payload.message || "已读取补丁产物", "ok");
        await viewCase(new URLSearchParams({ id }));
        return;
      }
      if (action === "verify") {
        const payload = await api("/api/case/verify", { method: "POST", body: { id } });
        toast(payload.message || "已读取验证记录", "ok");
        await viewCase(new URLSearchParams({ id }));
        return;
      }
      if (action === "export") {
        await downloadArtifact("/api/case/export?id=" + encodeURIComponent(id), `trident-case-${id}.json`);
        toast("Case 已导出", "ok");
      }
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  async function createCaseFromFinding(findingID) {
    try {
      const payload = await api("/api/cases", { method: "POST", body: { finding_id: findingID } });
      closeDrawer();
      if (payload.case && payload.case.id) {
        toast(payload.created ? "Case 已创建" : "Case 已存在", "ok");
        go("case", { id: payload.case.id });
      }
    } catch (error) {
      toast(error.message, "bad");
    }
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
    rows.innerHTML = `<tr><td colspan="6" class="muted">正在合并统一证据与多语言代码审计；大项目首次可能需要数十秒…</td></tr>` + Array.from({ length: 6 }, () => `<tr><td colspan="6"><div class="sk sk-row"></div></td></tr>`).join("");
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
        rows.innerHTML = `<tr><td colspan="6"><div class="empty"><svg class="icon"><use href="#i-bug"/></svg><h4>统一证据模型没有匹配的发现</h4><p>本页只覆盖 Java/Spring 数据流、依赖公告与访问控制。若快照含 PHP / .NET / Python / JS-TS / Go 源码，多语言规则发现在「代码审计」页单独呈现；0 条不代表安全。</p><a class="btn" href="#/code">打开代码审计页</a></div></td></tr>`;
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
    const isCode = String(finding.id || "").startsWith("code:");
    const where = finding.endpoint
      ? `<div class="id-cell"><strong class="mono">${esc(finding.endpoint.path)}</strong><span>${esc(finding.endpoint.symbol)}</span></div>`
      : isCode && finding.location
        ? `<div class="id-cell"><strong class="mono">${esc(finding.location)}</strong><span>${esc(finding.kind || "")}</span></div>`
        : `<div class="id-cell"><strong class="mono">${esc(finding.component ? finding.component.dependency : finding.category)}</strong><span>${esc(finding.component ? finding.component.advisory_id : finding.title)}</span></div>`;
    const location = finding.endpoint
      ? `${finding.endpoint.file}:${finding.endpoint.start_line}`
      : isCode && finding.location
        ? finding.location
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
      state.drawerFinding = finding;
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
        <div class="row-actions">
          <button class="btn sm" type="button" data-create-case="${esc(finding.id)}"><svg class="icon"><use href="#i-flag"/></svg>创建 Case</button>
          <button class="btn sm" type="button" data-ask-agent="${esc(finding.id)}"><svg class="icon"><use href="#i-bug"/></svg>问 Agent</button>
          <button class="icon-btn" type="button" data-close-drawer aria-label="关闭"><svg class="icon"><use href="#i-x"/></svg></button>
        </div>
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
      <section class="card section-gap" id="endpointEntrySection" hidden>
        <div class="card-head">
          <div>
            <div class="eyebrow">ENTRY EVIDENCE</div>
            <h3>统一入口证据</h3>
          </div>
          <span class="card-sub" id="endpointEntryCount">—</span>
        </div>
        <div class="table-wrap">
          <table class="cols-unified">
            <thead><tr><th>语言 / 来源</th><th>方法</th><th>路径 / 文件</th><th>证据类型</th><th>权限</th><th>置信度</th></tr></thead>
            <tbody id="endpointEntryRows"></tbody>
          </table>
        </div>
        <div class="card-body entry-note" id="endpointEntryNote"></div>
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
    $("#endpointEntryRows").addEventListener("click", (event) => {
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
      const entries = data.entries || [];
      endpoints.entries = entries;
      endpoints.entryCoverage = data.entry_coverage || [];
      endpoints.entryPartial = Boolean(data.entry_partial);
      endpoints.entryLimitations = data.entry_limitations || [];
      const entrySection = $("#endpointEntrySection");
      if (entrySection) {
        entrySection.hidden = entries.length === 0;
        const languageCount = new Set(entries.map((entry) => entry.language).filter(Boolean)).size;
        const sourceCount = new Set(entries.map((entry) => entry.source).filter(Boolean)).size;
        $("#endpointEntryCount").textContent = entries.length ? `${fmtNum(entries.length)} 条 · ${fmtNum(languageCount)} 语言 / ${fmtNum(sourceCount)} 来源` : "";
        $("#endpointEntryRows").innerHTML = entries.map((entry) => endpointUnifiedRow(entry)).join("");
        const limitations = endpoints.entryLimitations
          .map((item) => endpointLimitationLabel(item))
          .filter(Boolean)
          .slice(0, 3);
        $("#endpointEntryNote").textContent = entries.length
          ? `Java 注解入口、codescan 路由声明、应用入口文件候选已统一为本视图。声明路由和文件候选都不是已部署 URL${endpoints.entryPartial ? "；证据不完整" : ""}${limitations.length ? "；" + limitations.join("；") : ""}。`
          : "";
      }
      $("#endpointCount").textContent = `${fmtNum(data.total)} 个 Java 解析入口 · 统一证据 ${fmtNum(entries.length)} · 控制器 ${data.coverage.controllers_found} · 无控制 ${fmtNum(counts.unprotected || 0)}`;
      if (!data.items.length) {
        const hint = entries.length
          ? `未解析到 Java 注解级路由；统一证据中已有 ${fmtNum(entries.length)} 条入口线索（见下方）。Java 注解清单不覆盖 PHP/.NET 等语言，不能据此判断没有 HTTP 入口。`
          : "调整检索条件。注解级清单只覆盖 Java；不能据此判断非 Java 项目没有 HTTP 入口。";
        rows.innerHTML = `<tr><td colspan="6">${emptyState("i-route", "没有匹配的 Java 注解级入口", hint)}</td></tr>`;
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

  const endpointSourceLabels = {
    java_audit: "Java 注解",
    codescan: "代码路由",
    application_entry: "入口文件",
  };
  const endpointKindLabels = {
    annotation_route: "注解入口",
    route_declaration: "声明路由",
    application_entry: "文件候选",
    request_script: "请求脚本候选",
  };
  const endpointLimitationLabels = {
    code_audit_not_run: "代码路由分析尚未运行",
    authz_not_run: "权限尚未评估",
    java_audit_not_run: "Java 注解分析未运行",
    entrypoint_not_run: "入口文件扫描未运行",
    entry_candidate_not_deployed_route: "入口文件不是已部署 URL",
    route_declaration_not_deployment: "声明路由不等于已部署路由",
    entry_duplicate_suppressed: "重复路由证据已折叠",
    entrypoint_inventory_truncated: "入口候选数量已截断",
    php_request_script_candidate_not_route: "请求脚本不是已部署路由",
    php_request_script_not_deployed: "请求脚本未验证部署",
    php_request_script_content_bounded_1mib: "请求脚本仅扫描前 1 MiB",
    lexical_annotation_inventory_not_ast: "Java 注解清单是词法级，不是完整 AST",
  };

  function endpointLimitationLabel(value) {
    if (endpointLimitationLabels[value]) return endpointLimitationLabels[value];
    for (const key of Object.keys(endpointLimitationLabels)) {
      if (value.startsWith(key + ":")) return endpointLimitationLabels[key];
    }
    return "";
  }

  function endpointUnifiedRow(entry) {
    const language = (typeof codeLanguageLabels !== "undefined" && codeLanguageLabels[entry.language]) || entry.language || "unknown";
    const source = endpointSourceLabels[entry.source] || entry.source || "unknown";
    const kind = endpointKindLabels[entry.kind] || entry.kind || "证据";
    const methods = (entry.http_methods || []).map((method) => `<span class="chip mono">${esc(method)}</span>`).join(" ") || '<span class="status muted">—</span>';
    const location = entry.path_status === "dynamic_unresolved" ? "动态路由 · 路径未解析" : (entry.path || entry.file || "");
    const file = entry.file || entry.path || "";
    const line = entry.start_line || 1;
    const authz = entry.authz ? decisionPill(entry.authz.decision) : '<span class="status muted">未评估</span>';
    const confidence = entry.confidence ? `<span class="status muted">${esc(entry.confidence)}</span>` : '<span class="status muted">—</span>';
    const detail = [entry.path_status, entry.reason].filter(Boolean).join(" · ");
    return `<tr class="clickable" tabindex="0" data-file="${esc(file)}" data-line="${esc(line)}" title="${esc(detail)}">
      <td><span class="chip">${esc(language)}</span> <span class="status muted">${esc(source)}</span></td>
      <td>${methods}</td>
      <td class="file"><span class="mono">${esc(location)}</span><div class="status muted mono">${esc(file)}:${line}</div></td>
      <td>${esc(kind)}</td>
      <td>${authz}</td>
      <td>${confidence}</td>
    </tr>`;
  }

  // ── dependencies ───────────────────────────────────────────────────────

  async function viewDependencies() {
    const data = await api("/api/dependencies");
    const report = data.report;
    const coverage = report.coverage;
    const project = report.project;
    const ecosystems = project.ecosystems && project.ecosystems.length ? project.ecosystems.join(" + ") : (project.build_system || "unknown");
    const advisories = report.advisories || [];
    const matches = report.advisory_matches || [];
    const candidates = matches.filter((item) => item.finding_status === "candidate");
    const manifests = report.manifests || [];
    $("#view").innerHTML = `
      ${coverage.advisories_loaded === 0 ? `<div class="banner warn"><svg class="icon"><use href="#i-alert"/></svg><span>未加载公告目录。依赖声明仍会被解析，但不会产生候选漏洞匹配。到「设置 → 分析配置」填写公告目录 / 文件并保存即可立即生效，无需重启；也可在启动时用 <code>trident web --advisories &lt;file&gt;</code> 指定本地固定公告。</span></div>` : ""}
      <div class="tiles">
        ${tile("package", "violet", fmtNum(coverage.dependencies_declared), "直接依赖声明", `${fmtNum(project.module_count)} 个模块 · ${fmtNum(coverage.manifest_files_scanned)} 个清单`)}
        ${tile("layer", "blue", fmtNum(project.pom_count), "构建文件", `${esc(ecosystems)}`)}
        ${tile("flag", "amber", fmtNum(candidates.length), "公告候选", `${fmtNum(advisories.length)} 条公告`)}
        ${tile("alert", "teal", fmtNum(coverage.dependencies_unresolved), "未解析版本", `拒绝 POM ${fmtNum(coverage.poms_rejected)} · 清单 ${fmtNum(coverage.manifest_files_rejected)}`)}
      </div>
      <div class="grid-2">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>模块 / 清单</h3><span class="card-sub">${fmtNum((report.modules || []).length)} modules · ${fmtNum(manifests.length)} manifests</span></div>
          <div class="card-body">
            ${(report.modules || []).length ? `<div class="module-grid">${report.modules.map((module) => `<div class="module"><div class="module-top"><strong>${esc(module.artifact_id || module.directory)}</strong><span class="chip mono">${esc(module.packaging || "jar")}</span></div><div class="module-meta">${esc(module.group_id)} · ${esc(module.version || "未解析")}<br>${esc(module.pom)}${module.aggregator ? " · aggregator" : ""}</div></div>`).join("")}</div>` : emptyState("i-package", "未发现 Maven 模块", "Maven 模块仅来自 pom.xml；其他生态见下方清单。")}
            ${manifests.length ? `<div class="table-wrap section-gap"><table><thead><tr><th>清单</th><th>生态</th><th>类型</th><th>依赖</th><th>状态</th></tr></thead><tbody>${manifests.map((item) => `<tr><td class="mono">${esc(item.path)}</td><td><span class="chip">${esc(item.ecosystem)}</span></td><td>${esc(item.kind || "—")}</td><td>${fmtNum(item.dependencies || 0)}</td><td><span class="status ${item.status === "declared" || item.status === "version_source" ? "ok" : "warn"}">${esc(item.status)}</span></td></tr>`).join("")}</tbody></table></div>` : ""}
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-alert"/></svg>公告匹配</h3><span class="card-sub">精确版本 · 非可达性</span></div>
          <div class="card-body">
            ${matches.length ? matches.map((match) => `<div class="advisory ${match.finding_status === "candidate" ? "candidate" : ""}">
              <span class="status ${match.finding_status === "candidate" ? "warn" : "muted"}">${esc(match.finding_status)}</span>
              <span class="advisory-main"><strong>${esc(match.advisory_id)} · ${esc(match.dependency)} ${esc(match.declared_version || "—")}</strong><span>${esc(match.module)} · version ${esc(match.version_status)} · runtime ${esc(match.runtime_status)}</span></span>
            </div>`).join("") : emptyState("i-check", "没有公告匹配", "未加载公告目录、没有精确版本命中，或快照中没有可匹配的依赖。")}
          </div>
        </section>
      </div>
      <section class="card section-gap">
        <div class="card-head">
          <h3><svg class="icon"><use href="#i-package"/></svg>依赖声明</h3>
          <div class="card-head-actions">
            <span class="card-sub">声明级 · 多生态 · CycloneDX 1.5</span>
            <button class="btn sm ghost" id="exportSarifBtn" type="button" title="与 trident audit sarif 相同的 SARIF 2.1.0"><svg class="icon"><use href="#i-download"/></svg>SARIF</button>
            <button class="btn sm ghost" id="exportSbomBtn" type="button"><svg class="icon"><use href="#i-download"/></svg>导出 SBOM</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>模块</th><th>生态</th><th>依赖</th><th>版本</th><th>Scope</th><th>版本状态</th><th>声明文件</th></tr></thead>
            <tbody>
              ${report.dependencies.length ? report.dependencies.map((dependency) => `<tr>
                <td class="mono">${esc(dependency.module)}</td>
                <td><span class="chip">${esc(dependency.ecosystem || "maven")}</span></td>
                <td class="strong mono">${esc(dependency.name || `${dependency.group_id}:${dependency.artifact_id}`)}</td>
                <td class="mono">${esc(dependency.version || "—")}</td>
                <td>${esc(dependency.scope || "—")}</td>
                <td><span class="status ${dependency.version_status === "resolved" ? "ok" : "warn"}">${esc(dependency.version_status)}</span></td>
                <td class="file">${esc(dependency.manifest || dependency.declaration_pom)}</td>
              </tr>`).join("") : `<tr><td colspan="7">${emptyState("i-package", "没有依赖声明", "快照中没有解析到 Maven、npm、Composer、NuGet、pip 或 Go 依赖。")}</td></tr>`}
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
      throw error;
    }
    const cov = report.coverage || {};
    const rows = (report.dependencies || []).map((item) => `
      <tr><td class="strong">${esc(item.module)}</td><td><span class="chip">${esc(item.ecosystem || "maven")}</span></td><td class="mono">${esc(item.dependency)}${item.version ? "@" + esc(item.version) : ""}</td>
      <td><span class="status ${item.reachability === "reachable" ? "ok" : item.reachability === "unreachable" ? "muted" : "warn"}">${esc(item.reachability)}</span></td>
      <td class="wrap">${esc(item.language || "")} ${esc(item.reason || "")}${(item.paths || []).length ? ` · ${item.paths.length} 条路径` : ""}</td></tr>`).join("");
    $("#view").innerHTML = `
      <div class="hero"><div class="hero-copy"><span class="eyebrow">BOUNDED IMPORT / CALL GRAPH</span>
        <h2>依赖到入口有界可达性</h2>
        <p>Java 入口 ${fmtNum(cov.entrypoints || 0)} · 类 ${fmtNum(cov.classes_indexed || 0)} · 语言文件 ${fmtNum(cov.language_files_scanned || 0)} · reachable ${fmtNum(cov.reachable || 0)} / unreachable ${fmtNum(cov.unreachable || 0)} / unknown ${fmtNum(cov.unknown || 0)}。非 Java 匹配为文件级导入证据，三态都不证明类加载或运行时利用。</p></div></div>
      <div class="card section-gap"><div class="card-body tight"><div class="table-wrap"><table>
        <thead><tr><th>模块</th><th>生态</th><th>依赖</th><th>可达性</th><th>依据</th></tr></thead><tbody>${rows}</tbody>
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

  function profileOverrideKey(hash) {
    return `trident.profile.${hash || "none"}`;
  }

  function chatProfileOverride(hash) {
    try { return localStorage.getItem(profileOverrideKey(hash)) || ""; } catch (_) { return ""; }
  }

  function setChatProfileOverride(hash, id) {
    try {
      if (id) localStorage.setItem(profileOverrideKey(hash), id);
      else localStorage.removeItem(profileOverrideKey(hash));
    } catch (_) {}
  }

  async function viewAgent(params) {
    const showAll = Boolean(state.agent && state.agent.showAll);
    const scope = showAll ? "?hash=all" : "";
    const requestedConversation = Number(params?.get("conversation") || 0);
    const explicitRun = Number(params?.get("run") || 0);
    const requestedRun = explicitRun || (requestedConversation ? 0 : (state.agent && state.agent.openId) || 0);
    const [chat, conversationsPayload] = await Promise.all([
      api("/api/agent/chat/state").catch((error) => ({ enabled: false, reason: error.message })),
      api("/api/agent/conversations" + scope).catch((error) => ({ conversations: [], active_run: 0, active_task: 0, error: error.message, status: error.status })),
    ]);
    const conversations = conversationsPayload.conversations || [];
    let conversationId = requestedConversation;
    if (!conversationId && state.agent && state.agent.conversationId && conversations.some((item) => item.id === state.agent.conversationId)) {
      conversationId = state.agent.conversationId;
    }
    if (!conversationId && !requestedRun && conversations.length) conversationId = conversations[0].id;
    const query = (state.agent && state.agent.query) || "";
    state.agent = {
      chat, conversations, conversationId, conversation: null, runs: [], tasks: [],
      openId: requestedRun, steps: [], run: null, busy: Boolean(conversationsPayload.active_run),
      timer: null, lastSeq: 0, query, showAll, showHistory: false,
      threadError: conversationsPayload.error || "", threadErrorStatus: conversationsPayload.status || 0,
    };

    $("#view").innerHTML = `
      <div class="chat-shell" id="chatShell">
        <button type="button" class="chat-rail-backdrop" data-rail-close aria-label="关闭会话列表"></button>
        <aside class="chat-rail" id="chatRail">
          <div class="chat-rail-head">
            <div class="chat-rail-title"><span class="chat-rail-kicker">WORKSPACE</span><h3>会话</h3></div>
            <div class="row-actions">
              <button class="btn sm" type="button" id="allThreads">${showAll ? "仅当前项目" : "全部项目"}</button>
              <button class="btn sm primary" type="button" id="newThread"><svg class="icon"><use href="#i-plus"/></svg>新建</button>
              <button class="chat-rail-close" type="button" data-rail-close aria-label="关闭会话列表"><svg class="icon"><use href="#i-x"/></svg></button>
            </div>
          </div>
          <div class="chat-rail-filter">
            <svg class="icon"><use href="#i-search"/></svg>
            <input id="chatSearch" class="input" placeholder="筛选会话…" autocomplete="off" value="${esc(state.agent.query)}">
          </div>
          <div class="chat-threads" id="chatThreads"></div>
          <div class="chat-rail-foot">
            <span class="chip mono">${esc(shortHash(chat.project_hash || state.config?.project?.hash || ""))}</span>
            <span class="form-hint">${showAll ? "显示全部项目的会话" : "会话按项目快照隔离；编排的 planner/worker Run 不再单独占一条会话"}</span>
          </div>
        </aside>
        <section class="chat-main">
          <div class="chat-head" id="chatHead"></div>
          <div id="chatContext"></div>
          <div class="chat-stream" id="chatStream"></div>
          <form class="composer" id="composer">
            ${chat.enabled ? `<div class="goal-presets">${[
              ["未授权访问", "检查全部 HTTP 入口的访问控制：列出无控制与无法解析的入口，逐条给出文件、行号与依据；不要浏览无关目录。"],
              ["SQL 注入", "追踪 HTTP 参数到 SQL 执行的数据流，列出可达的拼接点并引用实际读到的行号；无法验证的标注 UNVERIFIED INFERENCE。"],
              ["路径遍历", "检查文件读取类入口的路径拼接与规范化，列出可被外部输入影响的调用点并给出行号证据。"],
              ["依赖风险", "结合依赖声明与公告目录，检查是否存在命中已知漏洞的依赖，给出声明 POM 与公告编号。"],
            ].map(([label, text]) => `<button type="button" class="chip chip-btn" data-preset="${esc(text)}">${esc(label)}</button>`).join("")}</div>` : ""}
            <textarea id="chatGoal" rows="2" placeholder="${chat.enabled ? "描述这次分析目标，例如：审计 SQL 注入与未授权访问风险" : esc(chat.reason || "对话未启用")}" ${chat.enabled ? "" : "disabled"}></textarea>
            <div class="composer-bar">
              <div class="composer-controls">
                <label class="profile-pick">运行方式
                  <select id="chatMode" ${chat.enabled ? "" : "disabled"}>
                    <option value="chat" selected>单次对话</option>
                    <option value="orchestrate">编排任务（小预算）</option>
                  </select>
                </label>
                <label class="profile-pick">模型
                  <select id="chatProfile" ${chat.enabled ? "" : "disabled"}>
                    <option value=""${chatProfileOverride(state.config?.project?.hash) ? "" : " selected"}>跟随默认${chat.resolved && chat.resolved.main ? `（${esc(chat.resolved.main.entry_name)} · ${esc(chat.resolved.main.model)}）` : ""}</option>
                    ${(chat.profiles || []).map((profile) => `<option value="${esc(profile.id)}"${chatProfileOverride(state.config?.project?.hash) === profile.id ? " selected" : ""}>${esc(profile.label || profile.model)}${profile.key_present ? "" : "（缺密钥）"}</option>`).join("")}
                  </select>
                </label>
                <label class="check"><input type="checkbox" id="chatEgress" ${chat.enabled ? "" : "disabled"}>批准外发快照与目标</label>
                <label class="check" title="仅在本次 Run 暴露 Case 写工具；不会修改 pinned snapshot 或 Case 原目录"><input type="checkbox" id="chatRepair" ${chat.enabled && chat.repair_available ? "" : "disabled"} ${chat.repair_available ? "" : "title=\"当前控制台没有可写 workspace\""}>批准写入 Case 工作副本并隔离验证</label>
                <span class="form-hint">修复工具由服务端按本次批准暴露；未批准时模型看不到写工具。</span>
              </div>
              <div class="composer-submit">
                <span class="composer-status" id="composerStatus"></span>
                <button class="btn primary" type="submit" id="chatSend" ${chat.enabled ? "" : "disabled"}>发送<svg class="icon"><use href="#i-chev-right"/></svg></button>
              </div>
            </div>
          </form>
        </section>
      </div>`;

    renderConversationList();
    const chatShell = $("#chatShell");
    const closeRail = () => chatShell && chatShell.classList.remove("rail-open");
    if (chatShell) {
      chatShell.addEventListener("click", (event) => {
        if (event.target.closest("[data-rail-toggle]")) {
          chatShell.classList.toggle("rail-open");
          return;
        }
        if (event.target.closest("[data-rail-close]")) closeRail();
      });
    }
    const profileSelect = $("#chatProfile");
    if (profileSelect) {
      profileSelect.addEventListener("change", () => {
        const hash = state.config?.project?.hash || "";
        setChatProfileOverride(hash, profileSelect.value);
        if (!profileSelect.value) {
          toast("已回到默认主模型", "ok");
          return;
        }
        const picked = (chat.profiles || []).find((profile) => profile.id === profileSelect.value);
        toast(`本次会话覆盖为 ${picked ? picked.label || picked.model : profileSelect.value}；不写回模型库`, "ok");
      });
    }
    const modeSelect = $("#chatMode");
    if (modeSelect) {
      modeSelect.addEventListener("change", () => {
        const button = $("#chatSend");
        if (button) button.textContent = modeSelect.value === "orchestrate" ? "启动任务" : "发送";
        const status = $("#composerStatus");
        if (status && chat.enabled && chat.key_present) {
          status.textContent = modeSelect.value === "orchestrate" ? "将创建编排任务：3 轮 / 4 意图 / 1 执行者" : "";
          status.className = "composer-status";
        }
      });
    }
    $("#allThreads").addEventListener("click", () => {
      state.agent.showAll = !state.agent.showAll;
      viewAgent();
    });
    $("#newThread").addEventListener("click", () => {
      closeRail();
      state.agent.conversationId = 0;
      state.agent.conversation = null;
      state.agent.runs = [];
      state.agent.tasks = [];
      state.agent.openId = 0;
      state.agent.steps = [];
      state.agent.run = null;
      renderConversationList();
      renderChatContext();
      renderThread();
      $("#chatGoal").focus();
    });
    $("#chatThreads").addEventListener("click", (event) => {
      const row = event.target.closest("[data-conversation]");
      if (!row) return;
      closeRail();
      openConversation(Number(row.dataset.conversation));
    });
    $("#chatSearch").addEventListener("input", (event) => {
      state.agent.query = event.target.value;
      renderConversationList();
    });
    if (state.pendingAgentGoal) {
      const goal = $("#chatGoal");
      if (goal) {
        goal.value = state.pendingAgentGoal;
        goal.focus();
      }
      state.pendingAgentGoal = "";
    }
    if (state.pendingRepair) {
      const repair = $("#chatRepair");
      if (repair && !repair.disabled) {
        repair.checked = true;
        toast("已预选修复批准；仍需勾选外发并发送本次 Run", "ok");
      } else {
        toast("当前控制台没有可写 workspace，修复写工具不可用", "bad");
      }
      state.pendingRepair = false;
    }
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
      $("#composerStatus").textContent = "主模型未配置密钥：到「设置 → 模型」填写 API Key，或设置环境变量后重启";
      $("#composerStatus").className = "composer-status warn-text";
    }
    if (requestedRun) await openThread(requestedRun, true);
    else if (conversationId) await openConversation(conversationId);
    else { renderChatContext(); renderThread(); }
  }

  async function openConversation(conversationId) {
    if (!conversationId || !state.agent) return;
    stopPolling();
    state.agent.conversationId = conversationId;
    state.agent.showHistory = false;
    renderConversationList();
    $("#chatStream").innerHTML = `<div class="chat-loading">${skeletonView()}</div>`;
    try {
      const payload = await api(`/api/agent/conversations/detail?id=${conversationId}`);
      state.agent.conversation = payload.conversation || null;
      state.agent.runs = payload.runs || [];
      state.agent.tasks = payload.tasks || [];
      state.agent.openId = state.agent.runs.length ? state.agent.runs[state.agent.runs.length - 1].id : 0;
      renderConversationList();
      renderChatContext();
      if (state.agent.openId) await openThread(state.agent.openId);
      else { state.agent.run = null; renderThread(); }
    } catch (error) {
      $("#chatStream").innerHTML = emptyState("i-alert", "无法加载会话", error.message);
    }
  }

  function renderConversationList() {
    const host = $("#chatThreads");
    if (!host || !state.agent) return;
    const all = state.agent.conversations || [];
    const query = String(state.agent.query || "").trim().toLowerCase();
    const items = query
      ? all.filter((conversation) => String(conversation.title || "").toLowerCase().includes(query))
      : all;
    if (!all.length) {
      const error = state.agent.threadError || "";
      if (state.agent.threadErrorStatus === 412) {
        host.innerHTML = `<div class="chat-empty"><strong>无法读取会话库</strong><br>${esc(error)}<br><br>到「设置 → Agent 与编排」填写会话库连接串并保存即可立即接入，<strong>无需重启</strong>。</div>`;
      } else if (error) {
        host.innerHTML = `<div class="chat-empty">会话加载失败：${esc(error)}</div>`;
      } else {
        host.innerHTML = `<div class="chat-empty">当前项目还没有会话。输入目标开始第一轮，或切换为编排任务。</div>`;
      }
      return;
    }
    if (!items.length) {
      host.innerHTML = `<div class="chat-empty">没有匹配的会话。</div>`;
      return;
    }
    host.innerHTML = items.map((conversation) => {
      const title = conversation.title || "(无标题)";
      const last = conversation.last_run_state || conversation.last_task_state || "";
      return `<button class="chat-thread${conversation.id === state.agent.conversationId ? " active" : ""}" type="button" data-conversation="${conversation.id}" title="${esc(title)}">
        <span class="chat-thread-title">${esc(title.length > 60 ? `${title.slice(0, 60)}…` : title)}</span>
        <span class="chat-thread-meta">
          <span class="chip">${conversation.task_count && conversation.run_count ? "对话 + 任务" : conversation.mode === "orchestrate" ? "编排" : "对话"}</span>
          ${last ? runStatePill(last) : `<span class="chip">未开始</span>`}
          <span class="mono">#${conversation.id}</span>
          <span>${conversation.run_count || 0} 轮 / ${conversation.task_count || 0} 任务</span>
          <span class="chat-thread-time">${esc((conversation.updated_at || "").slice(5, 16).replace("T", " "))}</span>
        </span>
      </button>`;
    }).join("");
  }

  function taskStatePill(taskState) {
    const labels = { created: "已创建", running: "运行中", completed: "已完成", cancelled: "已停止", failed: "失败" };
    const cls = taskState === "running" ? "ok" : taskState === "failed" ? "bad" : taskState === "cancelled" ? "warn" : "muted";
    return `<span class="status ${cls}"><span class="dot ${cls === "ok" ? "ok" : cls === "bad" ? "bad" : cls === "warn" ? "warn" : ""}"></span>${esc(labels[taskState] || taskState || "未知")}</span>`;
  }

  function renderChatContext() {
    const host = $("#chatContext");
    if (!host || !state.agent) return;
    const conversation = state.agent.conversation;
    if (!conversation) {
      host.innerHTML = state.agent.openId ? `<div class="chat-context chat-context-standalone"><span class="chip">独立 Run #${state.agent.openId}</span><span class="form-hint">该 Run 不在当前会话内；可从任务或仪表盘深链打开。</span></div>` : "";
      return;
    }
    const runs = state.agent.runs || [];
    const tasks = state.agent.tasks || [];
    const expanded = Boolean(state.agent.showHistory);
    const total = runs.length + tasks.length;
    host.innerHTML = `<div class="chat-context">
      <div class="chat-context-head">
        <div><span class="chip">会话 #${conversation.id}</span><strong>${esc(conversation.title || "(无标题)")}</strong><span class="chip">${tasks.length && runs.length ? "对话 + 任务" : conversation.mode === "orchestrate" ? "编排" : "对话"}</span></div>
        <div class="chat-context-actions">
          <span class="form-hint">${runs.length} 轮对话 / ${tasks.length} 个任务</span>
          ${total > 1 ? `<button class="btn sm ghost" type="button" id="chatHistoryToggle">${expanded ? "收起历史" : "历史"}</button>` : ""}
        </div>
      </div>
      <div class="chat-turns"${expanded || total <= 1 ? "" : " hidden"}>
        ${runs.map((run, index) => `<button type="button" class="chat-turn${run.id === state.agent.openId ? " active" : ""}" data-conv-run="${run.id}" title="${esc(run.goal || "")}">
          <span class="mono">#${run.id}</span><span>${esc((run.goal || "无目标").slice(0, 48))}</span>${runStatePill(run.state)}
        </button>`).join("")}
        ${tasks.map((task) => `<a class="chat-task-card" href="#/tasks?task=${task.id}" title="${esc(task.goal || "")}">
          <span class="chip">编排任务</span><strong>${esc(task.title || `任务 #${task.id}`)}</strong>
          <span>${task.planner_rounds || 0}/${task.max_planner_rounds || 0} 轮 · ${task.intents_spawned || 0}/${task.max_intents || 0} 意图</span>
          ${taskStatePill(task.state)}
        </a>`).join("")}
      </div>
    </div>`;
    host.querySelectorAll("[data-conv-run]").forEach((button) => {
      button.addEventListener("click", () => openThread(Number(button.dataset.convRun)));
    });
    const toggle = host.querySelector("#chatHistoryToggle");
    if (toggle) toggle.addEventListener("click", () => {
      state.agent.showHistory = !expanded;
      renderChatContext();
    });
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
      renderConversationList();
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

  async function openThread(runID, standalone = false) {
    stopPolling();
    state.agent.openId = runID;
    renderConversationList();
    renderChatContext();
    $("#chatStream").innerHTML = `<div class="chat-loading">${skeletonView()}</div>`;
    try {
      const payload = await api("/api/agent/steps?run_id=" + runID + "&limit=1000");
      state.agent.steps = payload.steps || [];
      state.agent.run = payload.run || null;
      state.agent.usage = payload.usage || null;
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
          state.agent.usage = payload.usage || state.agent.usage;
          state.agent.lastSeq = steps.length ? steps[steps.length - 1].seq : 0;
          renderThread();
          renderConversationList();
        } else if (payload.run) {
          state.agent.run = payload.run;
        }
        if (state.agent.run && terminalStates.includes(state.agent.run.state)) {
          stopPolling();
          renderThread();
          await refreshConversations();
          await refreshConversationDetail();
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
    const mode = ($("#chatMode") && $("#chatMode").value) || "chat";
    const repairApproved = mode === "chat" && Boolean($("#chatRepair") && $("#chatRepair").checked);
    if (mode === "orchestrate" && $("#chatRepair") && $("#chatRepair").checked) {
      toast("编排任务暂不暴露 Case 修复写工具；请用「单次对话」并保持修复批准勾选", "bad");
      return;
    }
    const button = $("#chatSend");
    button.disabled = true;
    button.textContent = "启动中…";
    try {
      if (mode === "orchestrate") {
        const result = await api("/api/agent/orchestration", {
          method: "POST",
          body: {
            title: (goal.split(/\r?\n/)[0] || "编排任务").slice(0, 120),
            goal,
            approve_egress: true,
            profile_id: ($("#chatProfile") && $("#chatProfile").value) || "",
            conversation_id: state.agent.conversationId || 0,
            // Chat-created tasks use a tight budget; the full task page remains
            // available for larger runs.
            max_planner_rounds: 3,
            max_intents: 4,
            max_workers: 1,
            deadline_minutes: 20,
            max_model_calls: 8,
            max_tool_calls: 12,
            max_tokens: 150000,
          },
        });
        $("#chatGoal").value = "";
        state.agent.conversationId = result.conversation_id;
        await refreshConversations();
        await openConversation(result.conversation_id);
        toast(`编排任务 #${result.task_id} 已启动，已挂到当前会话`, "ok");
        return;
      }
      const result = await api("/api/agent/chat", {
        method: "POST",
        body: {
          goal,
          approve_egress: true,
          approve_repair: repairApproved,
          profile_id: ($("#chatProfile") && $("#chatProfile").value) || "",
          conversation_id: state.agent.conversationId || 0,
        },
      });
      $("#chatGoal").value = "";
      state.agent.busy = true;
      if (result.conversation_id) {
        state.agent.conversationId = result.conversation_id;
        await refreshConversations();
        await openConversation(result.conversation_id);
      } else {
        await refreshConversations();
        await openThread(result.run_id);
      }
      toast(`Run #${result.run_id} 已启动`, "ok");
    } catch (error) {
      toast(error.message, "bad");
    } finally {
      button.textContent = (($("#chatMode") && $("#chatMode").value) || "chat") === "orchestrate" ? "启动任务" : "发送";
      button.disabled = false;
      updateComposerState();
    }
  }

  async function refreshConversations() {
    try {
      const scope = state.agent.showAll ? "?hash=all" : "";
      const payload = await api("/api/agent/conversations" + scope);
      state.agent.conversations = payload.conversations || [];
      renderConversationList();
    } catch (error) {
      /* the conversation rail is not critical for sending */
    }
  }

  async function refreshConversationDetail() {
    if (!state.agent.conversationId) return;
    try {
      const payload = await api(`/api/agent/conversations/detail?id=${state.agent.conversationId}`);
      state.agent.conversation = payload.conversation || state.agent.conversation;
      state.agent.runs = payload.runs || state.agent.runs;
      state.agent.tasks = payload.tasks || state.agent.tasks;
      renderChatContext();
    } catch (error) {
      /* keep the current turn visible if the detail refresh fails */
    }
  }

  function chatUsageChip() {
    const usage = state.agent && state.agent.usage;
    if (!usage) return "";
    if (usage.estimated_cost_usd != null) {
      const amount = Number(usage.estimated_cost_usd);
      const text = amount >= 0.01 ? amount.toFixed(3) : amount.toFixed(6);
      return `<span class="chip mono" title="${esc(usage.note || "按当前条目单价估算")}">≈ $${text}</span>`;
    }
    if (usage.usage_known) {
      return `<span class="chip mono" title="${esc(usage.note || "")}">输入 ${fmtNum(usage.input_tokens)} / 输出 ${fmtNum(usage.output_tokens)}</span>`;
    }
    return `<span class="chip" title="${esc(usage.note || "provider 未报告用量")}">成本未定</span>`;
  }

  function renderThread() {
    const run = state.agent.run;
    const head = $("#chatHead");
    const stream = $("#chatStream");
    if (!head || !stream) return;
    renderChatContext();
    if (!run) {
      head.innerHTML = `<div class="chat-head-main">
        <span class="chat-kicker">AGENT WORKSPACE</span>
        <h2>新的分析会话</h2>
        <p class="chat-subline">写入目标并批准外发后，Agent 会用只读工具读取当前项目快照。</p>
      </div>
      <div class="chat-actions">
        <button class="btn sm ghost rail-toggle" type="button" data-rail-toggle><svg class="icon"><use href="#i-menu"/></svg>会话</button>
      </div>`;
      stream.innerHTML = `<div class="chat-intro">${emptyState("i-server", "还没有开始", "描述一个分析目标即可。Agent 只能读取快照，不会执行项目代码。")}</div>`;
      return;
    }
    const alias = threadAlias(run);
    head.innerHTML = `
      <div class="chat-head-main">
        <span class="chat-kicker">AGENT SESSION <span class="mono">· Run #${run.id}</span></span>
        <h2 title="${esc(run.goal)}">${esc(alias || (run.goal || "").slice(0, 120))}</h2>
        <div class="chat-head-line">
          ${runStatePill(run.state)}
          <span class="chat-stat">${run.model_calls} 模型调用</span>
          <span class="chat-stat">${run.tool_calls} 工具调用</span>
          <span class="chat-stat">${fmtNum(run.tokens_used)} tokens</span>
          ${chatUsageChip()}
          ${alias ? `<p class="chat-goal-raw">原始目标：${esc(run.goal)}</p>` : ""}
        </div>
      </div>
      <div class="chat-actions">
        <button class="btn sm ghost rail-toggle" type="button" data-rail-toggle><svg class="icon"><use href="#i-menu"/></svg>会话</button>
        <button class="btn sm ghost" type="button" data-chat-action="rename" title="别名只保存在本机浏览器">重命名</button>
        <button class="btn sm ghost" type="button" data-copy="${esc(run.goal || "")}" title="复制原始目标"><svg class="icon"><use href="#i-copy"/></svg>复制目标</button>
        <button class="btn sm ghost" type="button" data-chat-action="rerun" title="用同一目标开一轮新会话"><svg class="icon"><use href="#i-plus"/></svg>以此目标新建</button>
      </div>`;
    $$("[data-chat-action]", head).forEach((button) => {
      button.addEventListener("click", () => {
        if (button.dataset.chatAction === "rename") startThreadRename(run);
        if (button.dataset.chatAction === "rerun") {
          const shell = $("#chatShell");
          if (shell) shell.classList.remove("rail-open");
          state.agent.conversationId = 0;
          state.agent.conversation = null;
          state.agent.runs = [];
          state.agent.tasks = [];
          state.agent.openId = 0;
          state.agent.steps = [];
          state.agent.run = null;
          renderConversationList();
          renderChatContext();
          renderThread();
          const goal = $("#chatGoal");
          if (goal) {
            goal.value = run.goal || "";
            goal.focus();
          }
        }
      });
    });
    const blocks = buildBlocks(state.agent.steps, run.goal);
    stream.innerHTML = blocks.map(renderBlock).join("") || emptyState("i-clock", "等待第一个事件", "Run 刚创建，step 正在写入。");
    stream.scrollTop = stream.scrollHeight;
  }

  // buildBlocks turns the append-only step log into readable messages: the
  // user goal, one assistant message per model turn, tool calls folded into
  // a process summary, and a final/state block.
  function buildBlocks(steps, goal) {
    const blocks = [];
    let tools = null;
    let pending = new Map();
    if (goal) blocks.push({ type: "user", text: goal });
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
        case "run.cancelled":
        case "run.unknown": {
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
    if (block.type === "user") {
      return `<div class="msg msg-user"><div class="msg-body"><span class="msg-label">你</span>${renderText(block.text)}</div></div>`;
    }
    if (block.type === "assistant") {
      // Models sometimes emit a JSON fragment as "content"; folding it keeps
      // the readable answer separate from raw structured output.
      if (looksStructured(block.text)) {
        const raw = String(block.text).trim();
        return `<details class="tool-block json-block"><summary><svg class="icon"><use href="#i-code"/></svg>模型结构化输出 · ${fmtNum(raw.length)} 字节</summary><pre class="json-pre">${esc(raw.slice(0, 4000))}${raw.length > 4000 ? "\n…" : ""}</pre></details>`;
      }
      return `<div class="msg msg-assistant"><div class="msg-body"><span class="msg-label">AGENT</span>${renderText(block.text)}</div></div>`;
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
      const legacyCheckpoint = /checkpoint limit/i.test(block.reason || "");
      const note = legacyCheckpoint
        ? "这是旧版检查点限制产生的历史停止记录；该限制已删除，可重新发起。"
        : block.kind === "run.unknown"
          ? "控制台在工具执行期间停止；该 Run 的结果无法确认，可重新发起一轮。"
          : "";
      const labels = {
        "run.failed": "运行失败",
        "run.paused": "已暂停",
        "run.budget_exhausted": "预算耗尽",
        "run.cancelled": "已取消",
        "run.unknown": "状态不明",
      };
      return `<div class="state-card"><b>${esc(labels[block.kind] || block.kind)}</b><p>${esc(block.reason)}</p>${note ? `<p class="state-hint">${esc(note)}</p>` : ""}</div>`;
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

  // ── model settings (v2: channel catalog, capabilities, role slots) ─────

  const ModelAPIs = [
    ["openai-completions", "OpenAI Chat Completions（当前运行时唯一支持）"],
  ];
  const ModelRoleMeta = {
    main: { label: "主模型", short: "会话默认", owner: "手动 Run", hint: "控制台对话的默认端点；编排未单配时也回退到它" },
    planner: { label: "规划者", short: "编排规划", owner: "规划轮", hint: "编排引擎的规划轮：只出意图与目标判定，调用少、上下文长" },
    worker: { label: "执行者", short: "编排执行", owner: "执行轮", hint: "编排引擎的执行会话：并发领意图读码，工具多、输出短" },
  };
  const ModelProbeLabels = {
    key_missing: "缺密钥", auth: "认证失败", not_found: "路径错误", upstream: "上游不可用",
    network: "连接失败", protocol: "协议不匹配", empty: "无模型",
  };

  function modelCaps(profile) {
    const caps = profile.capabilities || {};
    const labels = [];
    if (caps.context_window) labels.push(`${Math.round(caps.context_window / 1000)}k 上下文`);
    if (caps.max_output) labels.push(`输出 ${Math.round(caps.max_output / 1000)}k`);
    if (caps.reasoning) labels.push("思考");
    if (caps.vision) labels.push("图片");
    return labels;
  }

  function modelPrice(profile) {
    const cost = profile.cost;
    if (!cost) return "";
    const trim = (value) => Number(value || 0).toFixed(4).replace(/\.?0+$/, "");
    return `输入 $${trim(cost.input)} · 输出 $${trim(cost.output)} / 百万 token`;
  }

  function modelRoleChips(profile) {
    const roles = profile.roles || [];
    if (!roles.length) return '<span class="status muted">未使用</span>';
    return roles.map((role) => {
      const meta = ModelRoleMeta[role] || { label: role };
      return `<span class="chip${role === "main" ? " role-main" : ""}">${esc(meta.label)}</span>`;
    }).join("");
  }

  function modelProbe(profileID) {
    return state.modelSettings.probes[profileID];
  }

  function modelProbePill(profileID) {
    const probe = modelProbe(profileID);
    if (probe === "testing") return '<span class="status warn">测试中…</span>';
    if (probe === undefined) return '<span class="status muted">未测试</span>';
    if (probe === null) return '<span class="status bad">无响应</span>';
    if (probe.ok) return `<span class="status ok" title="${esc((probe.models || []).slice(0, 12).join(", "))}">${fmtNum(probe.latency_ms || 0)}ms</span>`;
    const label = ModelProbeLabels[probe.status] || "失败";
    return `<span class="status bad" title="${esc(probe.error || "")}">${esc(label)}</span>`;
  }

  function profileLabel(id) {
    const profiles = (state.modelSettings && state.modelSettings.library.profiles) || [];
    const found = profiles.find((item) => item.id === id);
    return found ? (found.label || found.model) : (id || "—");
  }

  async function viewSettingsModel() {
    const [library, chat] = await Promise.all([
      api("/api/agent/models").catch((error) => ({ profiles: [], default: "", error: error.message })),
      api("/api/agent/chat/state").catch((error) => ({ enabled: false, reason: error.message })),
    ]);
    const previous = state.modelSettings || {};
    const tab = previous.tab === "roles" ? "roles" : "library";
    state.modelSettings = {
      library, chat,
      probes: previous.probes || {},
      tab,
      query: "",
      editing: null,
      rolePicker: null,
    };
    $("#view").innerHTML = `
      <section class="card">
        <div class="card-head model-head">
          <div class="model-head-main">
            <span class="model-icon"><svg class="icon"><use href="#i-server"/></svg></span>
            <div>
              <h3>模型</h3>
              <p class="form-hint">渠道目录 → 模型条目 → 角色槽位。密钥可以写在启动环境变量，也可以直接在条目里填写本机密钥（立即生效）；两者都不会回显。</p>
            </div>
          </div>
          <span class="model-summary" id="modelSummary"></span>
        </div>
        <div class="tabs" id="modelTabs">
          <button type="button" data-tab="library">模型库 <em>${(library.profiles || []).length}</em></button>
          <button type="button" data-tab="roles">角色分配</button>
        </div>
        <div class="card-body" id="modelTabBody"></div>
      </section>
      <div id="modelDrawer"></div>`;
    $("#modelTabs").addEventListener("click", (event) => {
      const button = event.target.closest("[data-tab]");
      if (!button) return;
      state.modelSettings.tab = button.dataset.tab;
      renderModelTab();
    });
    renderModelTab();
  }

  function renderModelTab() {
    const settings = state.modelSettings;
    const library = settings.library || {};
    const profiles = library.profiles || [];
    const body = $("#modelTabBody");
    if (!body) return;
    $$("#modelTabs button").forEach((button) => button.classList.toggle("active", button.dataset.tab === settings.tab));
    const summary = $("#modelSummary");
    if (summary) {
      const unused = profiles.filter((profile) => !(profile.roles || []).length).length;
      const resolved = Object.keys(library.resolved || {}).length;
      summary.innerHTML = `${fmtNum(profiles.length)} 个模型 · ${fmtNum(unused)} 个未使用 · ${resolved}/3 角色已解析`;
    }
    if (settings.tab === "roles") {
      body.innerHTML = modelRolesPanel(library);
      wireModelRoles();
      return;
    }
    body.innerHTML = modelLibraryPanel(library);
    wireModelLibrary();
  }

  function filteredProfiles() {
    const profiles = (state.modelSettings.library.profiles || []);
    const query = String(state.modelSettings.query || "").trim().toLowerCase();
    if (!query) return profiles;
    return profiles.filter((profile) => [profile.id, profile.label, profile.model, profile.endpoint]
      .some((field) => String(field || "").toLowerCase().includes(query)));
  }

  function modelRowsMarkup() {
    const rows = filteredProfiles().map((profile) => {
      const caps = modelCaps(profile);
      return `<tr data-row="${esc(profile.id)}">
        <td>
          <div class="id-cell"><strong>${esc(profile.label || profile.id)}</strong><span class="mono">${esc(profile.model)}</span></div>
          <span class="model-sub mono" title="${esc(profile.endpoint)}">${esc(profile.endpoint.replace(/^https?:\/\//, ""))} · ${esc(profile.api || "openai-completions")}</span>
          ${profile.cost ? `<span class="model-price">${esc(modelPrice(profile))}</span>` : '<span class="model-price">价格未声明</span>'}
        </td>
        <td>${modelProbePill(profile.id)}<div class="mt-6">${profile.key_present
          ? `<span class="chip">${profile.key_source === "stored" ? "密钥本机" : "密钥环境"}</span>`
          : '<span class="status bad">缺密钥</span>'}</div></td>
        <td><div class="model-caps">${caps.length ? caps.map((cap) => `<span class="chip">${esc(cap)}</span>`).join("") : '<span class="status muted">未声明</span>'}</div></td>
        <td><div class="model-caps">${modelRoleChips(profile)}</div></td>
        <td class="right"><div class="row-actions">
          <button class="btn sm" type="button" data-probe="${esc(profile.id)}">测试</button>
          <button class="btn sm ghost" type="button" data-copy="${esc(profile.id)}">复制</button>
          <button class="btn sm ghost" type="button" data-edit="${esc(profile.id)}">编辑</button>
          <button class="btn sm ghost" type="button" data-remove="${esc(profile.id)}">删除</button>
        </div></td>
      </tr>`;
    }).join("");
    if (rows) return rows;
    return `<tr><td colspan="5">${emptyState("i-server", "没有匹配的模型", "换个关键词，或点右上角「新建模型」。")}</td></tr>`;
  }

  function modelLibraryPanel(library) {
    const profiles = library.profiles || [];
    const chat = state.modelSettings.chat || {};
    return `
      <div class="model-summary">
        <span>密钥来源：本机保存（优先）或环境变量；都不回显</span>
        <span class="foot-sep"></span>
        <span>${chat.enabled ? '<span class="status ok"><span class="dot ok"></span>对话可用</span>' : `<span class="status bad"><span class="dot bad"></span>${esc(chat.reason || "对话未启用")}</span>`}</span>
      </div>
      <div class="toolbar mt-14">
        <input class="input" id="modelSearch" placeholder="搜索名称、模型 ID、端点" value="${esc(state.modelSettings.query || "")}" spellcheck="false" autocomplete="off">
        <button class="btn sm" type="button" id="testAllModels" ${profiles.length ? "" : "disabled"}>全部测试</button>
        <span class="spacer"></span>
        <button class="btn primary" type="button" id="newProfile"><svg class="icon"><use href="#i-plus"/></svg>新建模型</button>
      </div>
      <div class="table-wrap mt-14">
        <table class="grid-fixed cols-models-v2">
          <thead><tr><th>模型</th><th>状态</th><th>能力</th><th>角色</th><th class="right">操作</th></tr></thead>
          <tbody id="modelRows">${modelRowsMarkup()}</tbody>
        </table>
      </div>`;
  }

  function refreshModelRows() {
    const tbody = $("#modelRows");
    if (!tbody) return;
    tbody.innerHTML = modelRowsMarkup();
    wireModelRows();
  }

  function wireModelLibrary() {
    const newButton = $("#newProfile");
    if (newButton) newButton.addEventListener("click", () => openModelDrawer(null));
    const search = $("#modelSearch");
    if (search) {
      search.addEventListener("input", () => {
        state.modelSettings.query = search.value;
        refreshModelRows();
      });
    }
    const testAll = $("#testAllModels");
    if (testAll) {
      testAll.addEventListener("click", async () => {
        testAll.disabled = true;
        const ids = (state.modelSettings.library.profiles || []).map((profile) => profile.id);
        for (const id of ids) await probeModel(id);
        testAll.disabled = false;
        toast(ids.length ? `已完成 ${ids.length} 个条目的连接测试` : "模型库是空的", "ok");
      });
    }
    wireModelRows();
  }

  function wireModelRows() {
    $$("#modelRows [data-probe]").forEach((button) => {
      button.addEventListener("click", () => probeModel(button.dataset.probe));
    });
    $$("#modelRows [data-edit]").forEach((button) => {
      const profile = (state.modelSettings.library.profiles || []).find((item) => item.id === button.dataset.edit);
      if (profile) button.addEventListener("click", () => openModelDrawer(profile));
    });
    $$("#modelRows [data-copy]").forEach((button) => {
      const profile = (state.modelSettings.library.profiles || []).find((item) => item.id === button.dataset.copy);
      if (profile) button.addEventListener("click", () => openModelDrawer(profile, true));
    });
    $$("#modelRows [data-remove]").forEach((button) => {
      button.addEventListener("click", () => removeModel(button.dataset.remove));
    });
  }

  async function probeModel(id) {
    state.modelSettings.probes[id] = "testing";
    refreshModelRows();
    try {
      const result = await api("/api/agent/models/probe", { method: "POST", body: { id } });
      state.modelSettings.probes[id] = result;
      if (result.ok) toast(`可用：返回 ${(result.models || []).length} 个模型（${result.latency_ms}ms）`, "ok");
      else toast(result.error || "连接失败", "bad");
    } catch (error) {
      state.modelSettings.probes[id] = { ok: false, status: "network", error: error.message };
      toast(error.message, "bad");
    }
    refreshModelRows();
  }

  async function removeModel(id) {
    if (!window.confirm(`删除模型条目「${profileLabel(id)}」？被角色引用的条目会被拒绝，已保存的本机密钥会一并删除，环境变量不受影响。`)) return;
    try {
      await api("/api/agent/models/remove", { method: "POST", body: { id } });
      toast("已删除", "ok");
      await viewSettingsModel();
    } catch (error) {
      toast(error.message, "bad");
    }
  }

  function modelRolesPanel(library) {
    const resolved = library.resolved || {};
    const profiles = library.profiles || [];
    const rows = ["main", "planner", "worker"].map((role) => {
      const meta = ModelRoleMeta[role];
      const entry = resolved[role];
      const profile = entry ? profiles.find((item) => item.id === entry.entry_id) : null;
      const caps = profile ? modelCaps(profile) : [];
      return `<div class="role-row">
        <div>
          <h4>${esc(meta.label)}</h4>
          <div class="role-owner">${esc(meta.short)} · ${esc(meta.owner)}</div>
        </div>
        <div>
          ${entry ? `<div class="role-model"><strong>${esc(entry.entry_name || entry.entry_id)}</strong> <span class="mono">· ${esc(entry.model)}</span>${entry.followed_main ? ' <span class="chip">跟随主模型</span>' : ""}</div>
            <span class="model-sub mono">${esc(String(entry.endpoint || "").replace(/^https?:\/\//, ""))} · ${esc(entry.api || "")}</span>
            <div class="model-caps mt-6">${caps.length ? caps.map((cap) => `<span class="chip">${esc(cap)}</span>`).join("") : '<span class="status muted">能力未声明</span>'}</div>`
          : `<div class="role-empty">未绑定：主模型未配置时，依赖它的角色也无法解析</div>`}
        </div>
        <div class="role-actions">
          <button class="btn sm" type="button" data-role="${role}">更换</button>
          ${entry ? `<button class="btn sm ghost" type="button" data-role-probe="${esc(entry.entry_id)}">测试</button>` : ""}
        </div>
      </div>`;
    }).join("");
    return `
      <div class="model-summary"><span>为每个真实存在的消费方选择模型；规划者/执行者可以「跟随主模型」，主模型不能跟随自己</span></div>
      <div class="mt-14">${rows}</div>
      <p class="model-hint">TRIDENT 只有三类模型消费方：对话主 Agent、编排规划轮、编排执行会话。没有 AI 守门、LLM 复核或监督会话，因此不设这些角色。</p>`;
  }

  function wireModelRoles() {
    $$("#modelTabBody [data-role]").forEach((button) => {
      button.addEventListener("click", () => openRolePicker(button.dataset.role));
    });
    $$("#modelTabBody [data-role-probe]").forEach((button) => {
      button.addEventListener("click", async () => {
        button.disabled = true;
        button.textContent = "测试中…";
        try {
          const result = await api("/api/agent/models/probe", { method: "POST", body: { id: button.dataset.roleProbe } });
          toast(result.ok ? `可用：${(result.models || []).length} 个模型（${result.latency_ms}ms）` : (result.error || "连接失败"), result.ok ? "ok" : "bad");
        } catch (error) {
          toast(error.message, "bad");
        }
        button.disabled = false;
        button.textContent = "测试";
      });
    });
  }

  function openRolePicker(role) {
    state.modelSettings.rolePicker = role;
    renderRolePicker();
  }

  function renderRolePicker() {
    const role = state.modelSettings.rolePicker;
    const host = $("#modelDrawer");
    if (!host || !role) return;
    const meta = ModelRoleMeta[role];
    const library = state.modelSettings.library || {};
    const profiles = library.profiles || [];
    const current = (library.roles || {})[role] || "";
    const resolved = (library.resolved || {})[role] || null;
    const options = [];
    if (role !== "main") {
      options.push(`<label class="role-picker-option ${current === "follow-main" ? "is-on" : ""}">
        <input type="radio" name="roleTarget" value="follow-main" ${current === "follow-main" ? "checked" : ""}>
        <span class="role-picker-option-body">
          <span class="role-picker-title">跟随主模型</span>
          <span class="model-sub">${resolved ? `解析为 ${esc(resolved.entry_name)} · ${esc(resolved.model)}` : "主模型尚未配置"}</span>
        </span>
      </label>`);
    }
    profiles.forEach((profile) => {
      options.push(`<label class="role-picker-option ${current === profile.id ? "is-on" : ""}">
        <input type="radio" name="roleTarget" value="${esc(profile.id)}" ${current === profile.id ? "checked" : ""}>
        <span class="role-picker-option-body">
          <span class="role-picker-title">${esc(profile.label || profile.id)} · <span class="mono">${esc(profile.model)}</span></span>
          <span class="model-sub mono">${esc(profile.endpoint.replace(/^https?:\/\//, ""))}</span>
          <span class="model-caps mt-6">
            ${modelCaps(profile).map((cap) => `<span class="chip">${esc(cap)}</span>`).join("")}
            ${modelRoleChips(profile)}
            ${modelProbePill(profile.id)}
          </span>
        </span>
      </label>`);
    });
    host.innerHTML = `<div class="drawer-layer" role="dialog" aria-modal="true" aria-label="更换${esc(meta.label)}">
      <div class="drawer-backdrop" data-close-role></div>
      <aside class="drawer narrow">
        <div class="drawer-head">
          <div class="drawer-head-main">
            <span class="eyebrow">ROLE ASSIGNMENT</span>
            <h2>更换${esc(meta.label)}</h2>
            <p class="model-hint">${esc(meta.hint)} · 同一模型可被多个角色复用</p>
            <div class="drawer-badges"><span class="chip">当前：${resolved ? `${esc(resolved.entry_name)} · ${esc(resolved.model)}` : "未绑定"}</span></div>
          </div>
          <button class="icon-btn" type="button" data-close-role><svg class="icon"><use href="#i-x"/></svg></button>
        </div>
        <div class="drawer-body">
          ${options.join("")}
          <p class="role-picker-note">更多模型在「模型库」中添加；这里只改分配，不改条目本身。</p>
        </div>
        <div class="drawer-foot">
          <button class="btn primary" type="button" id="applyRole">应用</button>
          <button class="btn" type="button" data-close-role>取消</button>
        </div>
      </aside>
    </div>`;
    $$("[data-close-role]").forEach((element) => element.addEventListener("click", closeModelDrawer));
    $$("#modelDrawer input[name=roleTarget]").forEach((input) => {
      input.addEventListener("change", () => {
        $$("#modelDrawer .role-picker-option").forEach((option) => option.classList.toggle("is-on", Boolean(option.querySelector("input:checked"))));
      });
    });
    $("#applyRole").addEventListener("click", async () => {
      const picked = $("#modelDrawer input[name=roleTarget]:checked");
      if (!picked) { toast("先选择一个目标", "bad"); return; }
      const button = $("#applyRole");
      button.disabled = true;
      button.textContent = "应用中…";
      try {
        await api("/api/agent/models/roles", { method: "POST", body: { role, target: picked.value } });
        closeModelDrawer();
        toast("角色分配已更新", "ok");
        await viewSettingsModel();
      } catch (error) {
        toast(error.message, "bad");
        button.disabled = false;
        button.textContent = "应用";
      }
    });
  }

  function closeModelDrawer() {
    const host = $("#modelDrawer");
    if (host) host.innerHTML = "";
    state.modelSettings.editing = null;
    state.modelSettings.rolePicker = null;
  }

  function openModelDrawer(profile, duplicate = false) {
    const editing = Boolean(profile) && !duplicate;
    const base = profile || {
      id: "", label: "", endpoint: "", model: "", key_env: "TRIDENT_MODEL_API_KEY",
      api: "openai-completions", capabilities: {}, cost: null,
      defaults: { model_calls: 12, tool_calls: 24, tokens: 131072 },
    };
    const draft = JSON.parse(JSON.stringify(base));
    if (duplicate) {
      draft.id = `${base.id}-copy`;
      draft.label = `${base.label || base.id} 副本`;
    }
    state.modelSettings.editing = editing ? draft.id : "";
    state.modelSettings.draft = draft;
    renderModelDrawer(editing);
  }

  function renderModelDrawer(editing) {
    const draft = state.modelSettings.draft;
    const host = $("#modelDrawer");
    if (!host || !draft) return;
    const caps = draft.capabilities || {};
    const cost = draft.cost || {};
    const defaults = draft.defaults || { model_calls: 12, tool_calls: 24, tokens: 131072 };
    host.innerHTML = `<div class="drawer-layer" role="dialog" aria-modal="true" aria-label="模型条目">
      <div class="drawer-backdrop" data-close-form></div>
      <aside class="drawer">
        <div class="drawer-head">
          <div class="drawer-head-main">
            <span class="eyebrow">${editing ? "EDIT MODEL" : "NEW MODEL"}</span>
            <h2>${editing ? esc(draft.label || draft.id) : "新建模型条目"}</h2>
            <div class="drawer-badges">
              <span class="chip mono" id="mfApiBadge">${esc(draft.api || "openai-completions")}</span>
              ${draft.model ? `<span class="chip mono">${esc(draft.model)}</span>` : ""}
              <span class="status muted">未保存</span>
            </div>
          </div>
          <button class="icon-btn" type="button" data-close-form><svg class="icon"><use href="#i-x"/></svg></button>
        </div>
        <div class="drawer-body">
          <section class="model-form-section">
            <h4><svg class="icon"><use href="#i-route"/></svg>连接配置</h4>
            <div class="form-grid">
              <label class="field"><span>渠道</span><select class="input" id="mfChannel"><option value="">自定义渠道（自己填 Base URL 与协议）</option></select></label>
              <label class="field"><span>显示名称</span><input class="input" id="mfLabel" value="${esc(draft.label || "")}" placeholder="默认使用模型 ID"></label>
            </div>
            <p class="model-hint">渠道决定端点与协议；目录之外的中转选「自定义渠道」。密钥只作用于这个端点。</p>
            <div class="form-grid">
              <label class="field"><span>基础 URL</span><input class="input" id="mfEndpoint" value="${esc(draft.endpoint || "")}" placeholder="https://api.deepseek.com"></label>
              <label class="field"><span>协议</span><select class="input" id="mfAPI">${ModelAPIs.map(([value, label]) => `<option value="${value}" ${value === (draft.api || "openai-completions") ? "selected" : ""}>${label}</option>`).join("")}</select></label>
            </div>
            <p class="model-hint">控制台只实现 OpenAI Chat Completions 适配器；Anthropic/Google 等端点请先经兼容网关转换。</p>
            <div class="form-grid">
              <label class="field"><span>模型 ID</span><input class="input" id="mfModel" value="${esc(draft.model || "")}" placeholder="deepseek-chat / glm-4.6 / qwen3-coder-plus"></label>
              <label class="field"><span>目录预设</span><select class="input" id="mfPreset"><option value="">先选渠道，再选预设</option></select></label>
            </div>
            <div class="row-actions left">
              <button class="btn sm" type="button" id="mfLookup">按模型 ID 查目录</button>
              <span class="form-hint">匹配时只补能力与价格，不改端点。</span>
            </div>
            <div class="form-grid">
              <label class="field"><span>密钥环境变量（填变量名，不是密钥本身）</span><input class="input" id="mfKeyEnv" value="${esc(draft.key_env || "TRIDENT_MODEL_API_KEY")}" placeholder="例如 TRIDENT_MODEL_API_KEY"></label>
            </div>
            <p class="model-hint">环境变量名大小写须与系统一致（Windows 不区分，Linux/macOS 区分）；设置后需重启控制台进程才会生效。下面的 API Key 直填会立即生效，无需重启。</p>
            <div class="form-grid">
              <label class="field"><span>API Key（只存本机，不回显）</span><input class="input" id="mfKey" type="password" autocomplete="new-password" placeholder="粘贴 Key；保存后立即生效"></label>
            </div>
            <div class="row-actions left">
              <button class="btn sm" type="button" id="mfKeySave" ${editing ? "" : "disabled"}>保存密钥</button>
              <button class="btn sm ghost" type="button" id="mfKeyClear" ${editing && draft.key_source === "stored" ? "" : "disabled"}>清除本机密钥</button>
              <span class="model-hint" id="mfKeyStatus">${editing ? "" : "创建时会一并保存这里填写的密钥"}</span>
            </div>
          </section>

          <section class="model-form-section">
            <h4><svg class="icon"><use href="#i-sliders"/></svg>模型能力<span class="form-hint">声明式，不做探测</span></h4>
            <div class="form-grid">
              <label class="field"><span>上下文窗口（tokens）</span><input class="input" id="mfContext" type="number" min="0" max="10000000" step="1000" value="${caps.context_window || 0}"></label>
              <label class="field"><span>最大输出（tokens）</span><input class="input" id="mfMaxOut" type="number" min="0" max="1000000" step="1000" value="${caps.max_output || 0}"></label>
            </div>
            <label class="check line"><input type="checkbox" id="mfReasoning" ${caps.reasoning ? "checked" : ""}>支持思考 / 推理</label>
            <label class="check line"><input type="checkbox" id="mfVision" ${caps.vision ? "checked" : ""}>支持图片输入</label>
            <p class="model-hint">0 表示未声明；未声明的能力不会在表格里显示标签。</p>
          </section>

          <section class="model-form-section">
            <h4><svg class="icon"><use href="#i-grid"/></svg>价格与缓存<span class="form-hint">美元 / 百万 token</span></h4>
            <div class="form-grid">
              <label class="field"><span>输入</span><input class="input" id="mfCostIn" type="number" min="0" step="0.0001" value="${cost.input ?? ""}" placeholder="0"></label>
              <label class="field"><span>输出</span><input class="input" id="mfCostOut" type="number" min="0" step="0.0001" value="${cost.output ?? ""}" placeholder="0"></label>
            </div>
            <div class="form-grid">
              <label class="field"><span>缓存读</span><input class="input" id="mfCacheRead" type="number" min="0" step="0.0001" value="${cost.cache_read ?? ""}" placeholder="0"></label>
              <label class="field"><span>缓存写</span><input class="input" id="mfCacheWrite" type="number" min="0" step="0.0001" value="${cost.cache_write ?? ""}" placeholder="0"></label>
            </div>
            <p class="model-hint">四项留空表示未声明；只用于成本估算，不影响请求。缓存分项未参与 Run 成本计算。</p>
          </section>

          <div class="model-inline-status" id="mfStatus"></div>
        </div>
        <div class="drawer-foot">
          ${editing ? '<button class="btn sm ghost" type="button" id="mfDelete">删除</button>' : ""}
          <button class="btn sm" type="button" id="mfTest" ${editing ? "" : "disabled"}>测试连接</button>
          <span class="spacer"></span>
          <button class="btn" type="button" data-close-form>取消</button>
          <button class="btn primary" type="button" id="mfSave">${editing ? "保存" : "创建"}</button>
        </div>
      </aside>
    </div>`;

    $$("[data-close-form]").forEach((element) => element.addEventListener("click", closeModelDrawer));
    const channelSelect = $("#mfChannel");
    api("/api/agent/model-channels").then((payload) => {
      const options = (payload.channels || []).map((channel) => `<option value="${esc(channel.provider)}">${esc(channel.name)} · ${esc(channel.base_url.replace(/^https?:\/\//, ""))} · ${channel.model_count} 个模型</option>`).join("");
      channelSelect.insertAdjacentHTML("beforeend", options);
      const current = (payload.channels || []).find((channel) => draft.endpoint && draft.endpoint.replace(/\/$/, "") === channel.base_url.replace(/\/$/, ""));
      if (current) channelSelect.value = current.provider;
      if (current) loadChannelModels(current.provider);
    }).catch(() => {});

    channelSelect.addEventListener("change", async () => {
      const provider = channelSelect.value;
      if (!provider) return;
      await loadChannelModels(provider, true);
    });

    $("#mfPreset").addEventListener("change", () => {
      const selected = state.modelSettings.presets || [];
      const preset = selected.find((item) => item.model_id === $("#mfPreset").value);
      if (!preset) return;
      $("#mfModel").value = preset.model_id;
      $("#mfAPI").value = preset.api;
      $("#mfContext").value = preset.capabilities.context_window || 0;
      $("#mfMaxOut").value = preset.capabilities.max_output || 0;
      $("#mfReasoning").checked = Boolean(preset.capabilities.reasoning);
      $("#mfVision").checked = Boolean(preset.capabilities.vision);
      if (preset.cost) {
        $("#mfCostIn").value = preset.cost.input ?? "";
        $("#mfCostOut").value = preset.cost.output ?? "";
        $("#mfCacheRead").value = preset.cost.cache_read ?? "";
        $("#mfCacheWrite").value = preset.cost.cache_write ?? "";
      }
      if (!$("#mfLabel").value.trim()) $("#mfLabel").value = preset.name || preset.model_id;
    });

    $("#mfAPI").addEventListener("change", () => { $("#mfApiBadge").textContent = $("#mfAPI").value; });

    $("#mfLookup").addEventListener("click", async () => {
      const modelID = $("#mfModel").value.trim();
      if (!modelID) { toast("先填写模型 ID，再查内置目录", "bad"); return; }
      try {
        const payload = await api(`/api/agent/model-catalog/lookup?model_id=${encodeURIComponent(modelID)}&base_url=${encodeURIComponent($("#mfEndpoint").value.trim())}`);
        const match = (payload.matches || [])[0];
        if (!match) { toast("内置目录里没有该模型：能力与价格需要手动填写", "bad"); return; }
        $("#mfAPI").value = match.api;
        $("#mfApiBadge").textContent = match.api;
        $("#mfContext").value = match.capabilities.context_window || 0;
        $("#mfMaxOut").value = match.capabilities.max_output || 0;
        $("#mfReasoning").checked = Boolean(match.capabilities.reasoning);
        $("#mfVision").checked = Boolean(match.capabilities.vision);
        if (match.cost) {
          $("#mfCostIn").value = match.cost.input ?? "";
          $("#mfCostOut").value = match.cost.output ?? "";
          $("#mfCacheRead").value = match.cost.cache_read ?? "";
          $("#mfCacheWrite").value = match.cost.cache_write ?? "";
        }
        toast(`已按「${match.provider_name}」目录填充能力与价格`, "ok");
      } catch (error) {
        toast(error.message, "bad");
      }
    });

    $("#mfTest").addEventListener("click", async () => {
      if (!editing) return;
      const status = $("#mfStatus");
      status.innerHTML = '<span class="status warn">测试中…</span>';
      try {
        const result = await api("/api/agent/models/probe", { method: "POST", body: { id: draft.id } });
        state.modelSettings.probes[draft.id] = result;
        status.innerHTML = result.ok
          ? `<span class="status ok">可用</span><span>${fmtNum(result.latency_ms)}ms · 返回 ${(result.models || []).length} 个模型</span>`
          : `<span class="status bad">${esc(ModelProbeLabels[result.status] || "失败")}</span><span>${esc(result.error || "")}</span>`;
      } catch (error) {
        status.innerHTML = `<span class="status bad">失败</span><span>${esc(error.message)}</span>`;
      }
    });

    if (editing) {
      $("#mfDelete").addEventListener("click", async () => {
        await removeModel(draft.id);
      });
    }

    $("#mfSave").addEventListener("click", async () => {
      const numberOrZero = (selector) => Number($(selector).value || 0);
      const costFields = ["#mfCostIn", "#mfCostOut", "#mfCacheRead", "#mfCacheWrite"];
      const hasCost = costFields.some((selector) => String($(selector).value).trim() !== "");
      const payload = {
        id: draft.id || "",
        label: $("#mfLabel").value.trim(),
        endpoint: $("#mfEndpoint").value.trim(),
        model: $("#mfModel").value.trim(),
        key_env: $("#mfKeyEnv").value.trim(),
        api: $("#mfAPI").value,
        capabilities: {
          context_window: numberOrZero("#mfContext"),
          max_output: numberOrZero("#mfMaxOut"),
          reasoning: $("#mfReasoning").checked,
          vision: $("#mfVision").checked,
        },
        cost: hasCost ? {
          input: numberOrZero("#mfCostIn"), output: numberOrZero("#mfCostOut"),
          cache_read: numberOrZero("#mfCacheRead"), cache_write: numberOrZero("#mfCacheWrite"),
        } : null,
        defaults: {
          model_calls: Number($("#mfModels").value || 12),
          tool_calls: Number($("#mfTools").value || 24),
          tokens: Number($("#mfTokens").value || 131072),
        },
      };
      const button = $("#mfSave");
      button.disabled = true;
      button.textContent = "保存中…";
      const pendingKey = ($("#mfKey") && $("#mfKey").value.trim()) || "";
      try {
        const saved = await api("/api/agent/models", { method: "POST", body: payload });
        if (pendingKey) {
          const targetID = (saved && saved.profile && saved.profile.id) || payload.id;
          await api("/api/agent/models/key", { method: "POST", body: { id: targetID, key: pendingKey } });
          toast(editing ? "已保存，密钥已更新" : "已创建并保存密钥", "ok");
        } else {
          toast(editing ? "已保存" : "已创建", "ok");
        }
        closeModelDrawer();
        await viewSettingsModel();
      } catch (error) {
        toast(error.message, "bad");
        button.disabled = false;
        button.textContent = editing ? "保存" : "创建";
      }
    });

    const keyStatus = () => {
      if (!editing) return "创建时会一并保存这里填写的密钥";
      if (draft.key_present && draft.key_source === "stored") return "来源：本机保存（优先于环境变量）";
      if (draft.key_present) return `来源：环境变量 ${draft.key_env}`;
      return `未配置：填写后会立即生效，或设置环境变量 ${draft.key_env}`;
    };
    const syncKeyChip = () => {
      const record = (state.modelSettings.library.profiles || []).find((item) => item.id === draft.id);
      if (!record) return;
      record.key_present = draft.key_present;
      record.key_source = draft.key_source;
      refreshModelRows();
    };
    const statusHost = $("#mfKeyStatus");
    if (statusHost) statusHost.textContent = keyStatus();

    $("#mfKeySave").addEventListener("click", async () => {
      if (!editing) return;
      const input = $("#mfKey");
      const key = (input.value || "").trim();
      if (!key) { toast("先粘贴 API Key；要清除已保存的密钥请用「清除本机密钥」", "bad"); return; }
      const button = $("#mfKeySave");
      button.disabled = true;
      try {
        const result = await api("/api/agent/models/key", { method: "POST", body: { id: draft.id, key } });
        draft.key_present = result.key_present;
        draft.key_source = result.key_source;
        input.value = "";
        if (statusHost) statusHost.textContent = keyStatus();
        $("#mfKeyClear").disabled = draft.key_source !== "stored";
        syncKeyChip();
        toast("密钥已保存到本机，立即生效", "ok");
      } catch (error) {
        toast(error.message, "bad");
      }
      button.disabled = false;
    });

    $("#mfKeyClear").addEventListener("click", async () => {
      if (!editing) return;
      try {
        const result = await api("/api/agent/models/key", { method: "POST", body: { id: draft.id, key: "" } });
        draft.key_present = result.key_present;
        draft.key_source = result.key_source;
        if (statusHost) statusHost.textContent = keyStatus();
        $("#mfKeyClear").disabled = true;
        syncKeyChip();
        toast(result.key_source === "env" ? "已清除本机密钥，回退到环境变量" : "已清除本机密钥", "ok");
      } catch (error) {
        toast(error.message, "bad");
      }
    });

    async function loadChannelModels(provider, fillEndpoint = false) {
      const preset = $("#mfPreset");
      preset.innerHTML = '<option value="">加载中…</option>';
      try {
        const payload = await api(`/api/agent/model-channels/${encodeURIComponent(provider)}/models`);
        state.modelSettings.presets = payload.models || [];
        if (fillEndpoint) {
          $("#mfEndpoint").value = payload.base_url || "";
          $("#mfAPI").value = payload.api || "openai-completions";
          $("#mfApiBadge").textContent = payload.api || "openai-completions";
        }
        preset.innerHTML = '<option value="">选择模型预设</option>' + state.modelSettings.presets
          .map((model) => `<option value="${esc(model.model_id)}">${esc(model.name)} · ${esc(model.model_id)}${model.capabilities.context_window ? ` · ${Math.round(model.capabilities.context_window / 1000)}k` : ""}</option>`)
          .join("");
      } catch (error) {
        preset.innerHTML = '<option value="">目录加载失败</option>';
      }
    }
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
              <li><svg class="icon"><use href="#i-check"/></svg><span>Agent 聊天与编排需显式启用；每轮模型外发都要单独批准，密钥只在本机保存。</span></li>
              <li><svg class="icon"><use href="#i-check"/></svg><span>静态 finding 与 runtime_status 分离：所有结论保持 not_run。</span></li>
              <li><svg class="icon"><use href="#i-check"/></svg><span>缺少证据只表示 inconclusive；absence_is_not_safety。</span></li>
              <li><svg class="icon"><use href="#i-check"/></svg><span>仅监听 loopback；访问令牌 + SameSite=Strict Cookie + CSP + nosniff。</span></li>
            </ul>
          </div>
        </section>
      </div>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-server"/></svg>控制台 API</h3><span class="card-sub">浏览器实际调用；最后三行为运维/探活端点</span></div>
        <div class="card-body">
          ${apiRow("POST", "/api/session", "用访问令牌换取会话 Cookie")}
          ${apiRow("GET", "/api/health", "进程与快照状态")}
          ${apiRow("GET", "/api/overview", "快照、覆盖与类别统计")}
          ${apiRow("GET", "/api/findings", "筛选与分页的发现摘要")}
          ${apiRow("GET", "/api/finding?id=", "单一发现完整证据")}
          ${apiRow("GET", "/api/cases", "Case 目录与五段状态链（无需项目）")}
          ${apiRow("POST", "/api/cases", "从 Finding 创建 Case，或读取已有 Case")}
          ${apiRow("GET", "/api/case?id=", "Case 详情：Finding、证据、补丁、验证、上游")}
          ${apiRow("POST", "/api/case/propose", "读取已落盘补丁产物；不重新生成")}
          ${apiRow("POST", "/api/case/verify", "读取已落盘验证记录；不把未执行写成已验证")}
          ${apiRow("GET", "/api/case/export?id=", "导出 Case、补丁与上游文件 JSON")}
          ${apiRow("GET", "/api/endpoints", "Spring MVC 注解入口")}
          ${apiRow("GET", "/api/dependencies", "Maven 声明与公告匹配")}
          ${apiRow("GET", "/api/files", "快照文件清单")}
          ${apiRow("GET", "/api/file?path=", "逐行源码读取")}
          ${apiRow("GET", "/api/search", "快照内字面量检索")}
          ${apiRow("GET", "/api/report", "下载统一证据 JSON")}
          ${apiRow("GET", "/api/sbom", "下载 CycloneDX 1.5 JSON")}
          ${apiRow("GET", "/api/tree", "声明级依赖树")}
          ${apiRow("GET", "/api/reachability", "有界可达性（设置页配置 Package map 后启用）")}
          ${apiRow("GET", "/api/sarif", "下载 SARIF 2.1.0")}
          ${apiRow("GET", "/api/runtime-report", "运行时关联报告（设置页配置报告路径后启用）")}
          ${apiRow("GET", "/api/authz", "权限与越权控制清单")}
          ${apiRow("GET", "/api/code-audit", "多语言代码审计视图")}
          ${apiRow("GET", "/api/symbols", "符号浏览：语言/类型/关键词/分页")}
          ${apiRow("GET", "/api/model", "Java 语义模型类型索引")}
          ${apiRow("GET", "/api/model/type?fqn=", "单类型调用边")}
          ${apiRow("GET", "/api/agent/threads", "概览页最近 Agent Run")}
          ${apiRow("GET", "/api/agent/conversations", "项目会话列表")}
          ${apiRow("GET", "/api/agent/conversations/detail?id=", "单个会话与 Run 历史")}
          ${apiRow("GET", "/api/agent/chat/state", "聊天能力、模型与预算状态")}
          ${apiRow("GET/POST", "/api/agent/models", "模型库读取与档案写入")}
          ${apiRow("POST", "/api/agent/models/remove", "删除模型档案")}
          ${apiRow("POST", "/api/agent/models/probe", "探测模型端点")}
          ${apiRow("POST", "/api/agent/models/roles", "分配 main/planner/worker 角色")}
          ${apiRow("POST", "/api/agent/models/key", "保存或清除本机模型密钥")}
          ${apiRow("GET", "/api/agent/model-channels", "模型通道目录")}
          ${apiRow("GET", "/api/agent/model-channels/{provider}/models", "通道模型列表")}
          ${apiRow("GET", "/api/agent/model-catalog/lookup?model_id=", "模型能力与价格查询")}
          ${apiRow("GET/POST", "/api/agent/runtime", "Agent 运行时与数据库配置")}
          ${apiRow("GET/POST", "/api/agent/runtime/quick", "一键启用本机运行时")}
          ${apiRow("POST", "/api/agent/chat", "创建并执行一个 Agent Run；可选 approve_repair 暴露 Case 写工具")}
          ${apiRow("GET", "/api/agent/steps?run_id=", "Run step 时间线")}
          ${apiRow("GET/POST", "/api/agent/orchestration", "编排任务列表与创建")}
          ${apiRow("GET", "/api/agent/orchestration/detail?id=", "编排任务详情")}
          ${apiRow("POST", "/api/agent/orchestration/steer", "向编排任务追加指令")}
          ${apiRow("POST", "/api/agent/orchestration/stop?id=", "停止编排任务")}
          ${apiRow("GET/POST", "/api/config", "运行时配置读取与更新")}
          ${apiRow("GET/POST", "/api/projects", "项目列表与导入")}
          ${apiRow("POST", "/api/projects/select", "切换已导入项目")}
          ${apiRow("POST", "/api/projects/forget", "从列表移除项目")}
          ${apiRow("GET", "/api/fs", "目录选择器")}
          ${apiRow("POST", "/api/analysis/rerun", "清空缓存并重新分析")}
          ${apiRow("GET", "/export/report", "下载确定性 HTML 审阅报告")}
          ${apiRow("GET", "/api/metrics", "运维：只读指标 JSON（非界面调用）")}
          ${apiRow("GET", "/metrics", "运维：Prometheus 文本抓取（非界面调用）")}
          ${apiRow("GET", "/healthz", "运维：未认证探活（非界面调用）")}
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
      // Refresh the topbar switcher now: this path bypasses boot(), and
      // without it the label keeps its initial "未选择项目" placeholder until
      // the menu is opened once.
      await refreshProjectSwitcher();
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

  // ── multi-language code audit ──────────────────────────────────────────
  const codeLanguageOptions = [
    ["all", "全部语言"], ["php", "PHP"], ["csharp", ".NET / C#"], ["python", "Python"],
    ["javascript", "JavaScript"], ["typescript", "TypeScript"], ["java", "Java"], ["go", "Go"],
  ];
  const codeCategoryOptions = [
    ["all", "全部类别"], ["sql", "SQL 注入"], ["command", "命令注入"], ["code_exec", "代码执行"],
    ["deserialization", "反序列化"], ["path", "路径穿越"], ["ssrf", "SSRF"], ["xss", "XSS"],
    ["xxe", "XXE"], ["template", "模板注入"], ["upload", "文件上传"], ["ldap", "LDAP 注入"],
  ];
  const codeLanguageLabels = Object.fromEntries(codeLanguageOptions);
  const codeCategoryLabels = Object.fromEntries(codeCategoryOptions);

  function codeSeverityPill(value) {
    const meta = { high: ["高", "bad"], medium: ["中", "warn"], low: ["低", "muted"] }[value] || [value || "未知", "warn"];
    return `<span class="status ${meta[1]}"><span class="dot ${meta[1]}"></span>${esc(meta[0])}</span>`;
  }

  function codeRow(item) {
    const source = item.source ? esc(item.source.symbol) : "—";
    const sink = item.sink ? esc(item.sink.symbol) : "—";
    const line = item.sink ? item.sink.line : item.start_line;
    const flow = (item.flow || []).map((step) => `<li><span class="mono">L${step.line}</span> ${esc(step.kind)} · ${esc(step.detail)}</li>`).join("");
    return `<tr>
      <td><div class="id-cell"><strong>${esc(item.title || item.rule_id)}</strong><span class="mono">${esc(item.rule_id)} · ${esc(item.cwe)}</span></div></td>
      <td><span class="chip">${esc(codeLanguageLabels[item.language] || item.language)}</span></td>
      <td>${codeSeverityPill(item.severity)}</td>
      <td><button class="btn btn-sm" type="button" data-code-src="${esc(item.file)}" data-code-line="${line}" title="在源码浏览中打开">${esc(item.file)}:L${line}</button></td>
      <td><details class="flow-details"><summary>${source} → ${sink}</summary><ul class="flow-list">${flow || "<li>无传播步骤</li>"}</ul></details></td>
    </tr>`;
  }

  const codeSymbolKindLabels = {
    function: "函数", method: "方法", class: "类", interface: "接口", struct: "结构",
    enum: "枚举", record: "记录", trait: "Trait", type: "类型",
  };

  const codeRejectReasonLabels = {
    file_too_large: "超过 2 MiB 上限",
    lex_rejected: "token / 词法上限",
    statement_limit: "statement 上限",
    file_limit: "文件数量上限",
  };

  const codeScopeLabels = {
    project: "项目源码",
    vendor: "第三方依赖",
    generated: "生成/压缩产物",
  };

  const codeSymbolKindOptions = [
    ["all", "全部类型"], ["function", "函数"], ["method", "方法"], ["class", "类"],
    ["interface", "接口"], ["struct", "结构"], ["enum", "枚举"], ["record", "记录"],
    ["trait", "Trait"], ["type", "类型"],
  ];

  function symbolLink(symbol, label) {
    return `<button type="button" class="chip mono symbol-link" data-symbol-file="${esc(symbol.file)}" data-symbol-line="${symbol.line}" title="打开 ${esc(symbol.file)}:L${symbol.line}">${esc(label)}</button>`;
  }

  function renderSymbolEvidence(host, data) {
    if (!host) return;
    const coverage = data.coverage || {};
    const symbols = data.symbols || [];
    const calls = data.calls || [];
    const unresolved = data.unresolved || [];
    const languages = (data.symbol_languages || data.languages || []).filter((item) =>
      item.status === "scanned" || item.symbols || item.calls || item.unresolved);
    const totalSymbols = typeof coverage.symbols_found === "number"
      ? coverage.symbols_found : languages.reduce((sum, item) => sum + (item.symbols || 0), 0);
    const totalCalls = typeof coverage.calls_found === "number"
      ? coverage.calls_found : languages.reduce((sum, item) => sum + (item.calls || 0), 0);
    const totalUnresolved = typeof coverage.unresolved_found === "number"
      ? coverage.unresolved_found : languages.reduce((sum, item) => sum + (item.unresolved || 0), 0);
    const pending = data.symbol_reason || "";
    if (!host.dataset.symbolBound) {
      host.dataset.symbolBound = "1";
      host.addEventListener("click", (event) => {
        const target = event.target.closest("[data-symbol-file]");
        if (!target) return;
        go("source", { path: target.dataset.symbolFile, line: Number(target.dataset.symbolLine) || 1 });
      });
    }
    if (!languages.length && !symbols.length && !calls.length) {
      host.innerHTML = emptyState("i-layer", pending ? "符号索引未运行" : "暂无符号证据",
        pending || "当前快照没有可索引的声明；这不等于没有入口或没有风险。") +
        (pending ? `<div class="card-actions"><button class="btn btn-sm" type="button" data-run-code>打开代码审计页</button></div>` : "");
      return;
    }
    const partialChip = data.symbol_partial ? `<span class="chip warn">符号索引截断</span>` : "";
    const summary = `<div class="symbol-note"><span class="chip"><svg class="icon icon-xs"><use href="#i-layer"/></svg>符号 ${fmtNum(totalSymbols)}</span><span class="chip">调用 ${fmtNum(totalCalls)}</span><span class="chip">未解析 ${fmtNum(totalUnresolved)}</span>${partialChip}<span class="muted">列表最多 ${fmtNum(200)} 条，统计为全量；same_file 仅表示同文件同名声明</span></div>`;
    const groups = languages.map((item) => {
      const languageSymbols = symbols.filter((symbol) => symbol.language === item.language);
      const languageCalls = calls.filter((call) => call.language === item.language);
      const languageUnresolved = unresolved.filter((call) => call.language === item.language);
      const kinds = languageSymbols.reduce((acc, symbol) => {
        const label = codeSymbolKindLabels[symbol.kind] || symbol.kind || "其他";
        acc[label] = (acc[label] || 0) + 1;
        return acc;
      }, {});
      const samples = languageSymbols.slice(0, 8).map((symbol) =>
        symbolLink(symbol, `${codeSymbolKindLabels[symbol.kind] || symbol.kind} · ${symbol.qualified_name || symbol.name}`)).join("");
      const sampleCount = Math.min(languageSymbols.length, 8);
      const unresolvedSamples = languageUnresolved.slice(0, 2).map((call) =>
        `<span class="mono">${esc(call.expr)} <span class="muted">L${call.line}</span></span>`).join(" · ");
      return `<div class="symbol-group">
        <div class="kv"><span>${esc(codeLanguageLabels[item.language] || item.language)}</span><b>符号 ${fmtNum(item.symbols || 0)} · 调用 ${fmtNum(item.calls || 0)} · 未解析 ${fmtNum(item.unresolved || 0)}</b></div>
        ${Object.keys(kinds).length ? `<div class="chip-row">${Object.entries(kinds).map(([label, count]) => `<span class="chip">${esc(label)} ${fmtNum(count)}</span>`).join("")}</div>` : ""}
        ${samples ? `<div class="symbol-chips">${samples}${(item.symbols || 0) > sampleCount ? `<span class="muted">… 样本已截断</span>` : ""}</div>` : ""}
        ${unresolvedSamples ? `<div class="symbol-unresolved">未解析示例：${unresolvedSamples}</div>` : ""}
      </div>`;
    }).join("");
    host.innerHTML = `${summary}${groups}`;
  }

  function symbolRow(item) {
    const kind = codeSymbolKindLabels[item.kind] || item.kind || "其他";
    const params = (item.parameters || []).map((parameter) => parameter.name).filter(Boolean).join(", ") || "—";
    return `<tr>
      <td><span class="chip">${esc(kind)}</span></td>
      <td><div class="id-cell"><strong class="mono">${esc(item.name)}</strong><span>${esc(item.qualified_name || item.container || "")}</span></div></td>
      <td><button class="btn btn-sm" type="button" data-symbol-file="${esc(item.file)}" data-symbol-line="${item.line}" title="打开 ${esc(item.file)}:L${item.line}">${esc(item.file)}:L${item.line}</button></td>
      <td class="file">${esc(params)}</td>
    </tr>`;
  }

  async function loadSymbols() {
    const browser = state.symbols;
    const seq = ++browser.seq;
    const rows = $("#symbolRows");
    if (!rows) return;
    rows.innerHTML = `<tr><td colspan="4" class="muted">正在加载符号索引…</td></tr>`;
    const params = new URLSearchParams({ limit: String(browser.limit), offset: String(browser.offset) });
    if (browser.language !== "all") params.set("language", browser.language);
    if (browser.kind !== "all") params.set("kind", browser.kind);
    if (browser.q) params.set("q", browser.q);
    let data;
    try {
      data = await api("/api/symbols?" + params.toString());
    } catch (error) {
      if (seq === browser.seq) rows.innerHTML = `<tr><td colspan="4">${esc(error.message)}</td></tr>`;
      return;
    }
    if (seq !== browser.seq || state.route !== "code") return;
    browser.total = data.total || 0;
    browser.items = data.items || [];
    if (!data.available) {
      rows.innerHTML = `<tr><td colspan="4">${emptyState("i-layer", "符号索引未运行", data.reason || "当前快照没有可用的代码审计结果。")}</td></tr>`;
      $("#symbolCount").textContent = "未运行";
      $("#symbolRange").textContent = "—";
      $("#symbolPrev").disabled = true;
      $("#symbolNext").disabled = true;
      return;
    }
    rows.innerHTML = browser.items.length ? browser.items.map(symbolRow).join("") :
      `<tr><td colspan="4" class="muted">当前筛选下没有符号；无符号不等于没有入口或没有风险</td></tr>`;
    const kinds = (data.kinds || []).map((item) => `${codeSymbolKindLabels[item.key] || item.key} ${fmtNum(item.value)}`).join(" · ");
    $("#symbolCount").textContent = `符号 ${fmtNum(data.total)} · 返回 ${fmtNum(browser.items.length)}${data.symbol_partial ? " · 符号层截断" : ""}`;
    $("#symbolRange").textContent = data.total ? `${fmtNum(data.offset + 1)}–${fmtNum(Math.min(data.offset + browser.limit, data.total))} / ${fmtNum(data.total)}` : "0 / 0";
    if (kinds) $("#symbolCount").title = kinds;
    $("#symbolPrev").disabled = data.offset === 0;
    $("#symbolNext").disabled = data.offset + browser.limit >= data.total;
  }

  function renderModelOverview(host, data) {
    if (!host) return;
    const languages = (data.symbol_languages || []).filter((item) =>
      item.status === "scanned" || item.files_scanned || item.symbols || item.calls || item.unresolved);
    const pending = data.symbol_reason || "";
    if (!languages.length) {
      host.innerHTML = emptyState("i-layer", pending ? "代码审计未运行" : "暂无语言模型",
        pending || "当前快照没有可用的多语言代码审计结果。") +
        (pending ? `<div class="card-actions"><button class="btn btn-sm" type="button" data-run-code>运行代码审计</button></div>` : "");
      return;
    }
    const rows = languages.map((item) => {
      const rejected = item.files_rejected ? ` · 拒绝 ${fmtNum(item.files_rejected)}` : "";
      return `<div class="kv"><span>${esc(codeLanguageLabels[item.language] || item.language)}</span><b>文件 ${fmtNum(item.files_scanned)}${rejected} · 符号 ${fmtNum(item.symbols || 0)} · 调用 ${fmtNum(item.calls || 0)} · 未解析 ${fmtNum(item.unresolved || 0)}</b></div>`;
    }).join("");
    const partial = data.symbol_partial ? `<span class="chip warn">符号索引截断</span>` : "";
    host.innerHTML = `<div class="symbol-note"><span class="chip">已缓存代码审计</span>${partial}<span class="muted">Java AST 只覆盖 Java；其他语言以下面的符号索引为准</span></div>${rows}<div class="card-actions"><button class="btn btn-sm" type="button" data-open-symbols>打开符号浏览</button></div>`;
  }

  async function viewCode() {
    const code = state.code;
    $("#view").innerHTML = `
      <section class="card">
        <div class="card-head"><h3><svg class="icon"><use href="#i-code"/></svg>多语言代码审计</h3><span class="card-sub" id="codeRuleset">首次分析大项目可能需要数十秒…</span></div>
        <div class="card-body" id="codeKpis"></div>
      </section>
      <section class="card section-gap">
        <div class="toolbar">
          <select class="input" id="codeLang">${codeLanguageOptions.map(([value, label]) => `<option value="${value}"${code.language === value ? " selected" : ""}>${label}</option>`).join("")}</select>
          <select class="input" id="codeCat">${codeCategoryOptions.map(([value, label]) => `<option value="${value}"${code.category === value ? " selected" : ""}>${label}</option>`).join("")}</select>
          <div class="seg" id="codeSeverity">${[["all", "全部"], ["high", "高"], ["medium", "中"], ["low", "低"]].map(([value, label]) => `<button type="button" data-severity="${value}" class="${code.severity === value ? "active" : ""}">${label}</button>`).join("")}</div>
          <input class="input wide" id="codeSearch" data-search placeholder="搜索规则、文件、CWE 或符号…" value="${esc(code.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="codeCount">—</span>
        </div>
        <div class="table-wrap">
          <table class="grid-fixed cols-code">
            <thead><tr><th>规则 / 类别</th><th>语言</th><th>严重度</th><th>位置</th><th>证据路径</th></tr></thead>
            <tbody id="codeRows"></tbody>
          </table>
        </div>
        <div class="pager">
          <span id="codeRange">—</span>
          <div class="pager-actions">
            <button class="btn" type="button" id="codePrev"><svg class="icon"><use href="#i-chev-left"/></svg>上一页</button>
            <button class="btn" type="button" id="codeNext">下一页<svg class="icon"><use href="#i-chev-right"/></svg></button>
          </div>
        </div>
      </section>
      <div class="grid-2 section-gap">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-code"/></svg>语言覆盖</h3><span class="card-sub">声明级覆盖，不等于安全</span></div>
          <div class="card-body" id="codeLanguages"></div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-route"/></svg>声明入口</h3><span class="card-sub">源码中观察到的路由声明</span></div>
          <div class="card-body" id="codeRoutes"></div>
        </section>
      </div>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-alert"/></svg>文件拒绝</h3><span class="card-sub">文件级缺口；不代表这些文件没有风险</span></div>
        <div class="card-body" id="codeRejected"></div>
      </section>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>符号索引</h3><span class="card-sub">同文件简单名匹配；其余为未解析，不伪造调用图</span></div>
        <div class="card-body" id="codeSymbols"></div>
      </section>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-search"/></svg>符号浏览</h3><span class="card-sub">按语言/类型检索；点击文件行进入源码</span></div>
        <div class="toolbar">
          <select class="input" id="symbolLang">${codeLanguageOptions.map(([value, label]) => `<option value="${value}"${state.symbols.language === value ? " selected" : ""}>${label}</option>`).join("")}</select>
          <select class="input" id="symbolKind">${codeSymbolKindOptions.map(([value, label]) => `<option value="${value}"${state.symbols.kind === value ? " selected" : ""}>${label}</option>`).join("")}</select>
          <input class="input wide" id="symbolSearch" data-search placeholder="搜索符号名、文件名或容器…" value="${esc(state.symbols.q)}" />
          <span class="spacer"></span>
          <span class="toolbar-count" id="symbolCount">—</span>
        </div>
        <div class="table-wrap">
          <table class="grid-fixed cols-symbol">
            <thead><tr><th>类型</th><th>符号</th><th>文件</th><th>参数</th></tr></thead>
            <tbody id="symbolRows"></tbody>
          </table>
        </div>
        <div class="pager">
          <span id="symbolRange">—</span>
          <div class="pager-actions">
            <button class="btn" type="button" id="symbolPrev"><svg class="icon"><use href="#i-chev-left"/></svg>上一页</button>
            <button class="btn" type="button" id="symbolNext">下一页<svg class="icon"><use href="#i-chev-right"/></svg></button>
          </div>
        </div>
      </section>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>限制与边界</h3><span class="card-sub">runtime_status 恒为 not_run</span></div>
        <div class="card-body" id="codeLimits"></div>
      </section>
    `;
    $("#codeLang").addEventListener("change", (event) => { code.language = event.target.value; code.offset = 0; loadCode(); });
    $("#codeCat").addEventListener("change", (event) => { code.category = event.target.value; code.offset = 0; loadCode(); });
    $("#codeSeverity").addEventListener("click", (event) => {
      const button = event.target.closest("[data-severity]");
      if (!button) return;
      code.severity = button.dataset.severity;
      code.offset = 0;
      $$("#codeSeverity button").forEach((item) => item.classList.toggle("active", item === button));
      loadCode();
    });
    $("#codeSearch").addEventListener("input", (event) => {
      clearTimeout(code.searchTimer);
      const value = event.target.value;
      code.searchTimer = setTimeout(() => { code.q = value.trim(); code.offset = 0; loadCode(); }, 220);
    });
    $("#codePrev").addEventListener("click", () => { code.offset = Math.max(0, code.offset - code.limit); loadCode(); });
    $("#codeNext").addEventListener("click", () => { if (code.offset + code.limit < code.total) { code.offset += code.limit; loadCode(); } });
    $("#codeRows").addEventListener("click", (event) => {
      const button = event.target.closest("[data-code-src]");
      if (button) go("source", { path: button.dataset.codeSrc, line: Number(button.dataset.codeLine) || 1 });
    });
    $("#symbolLang").addEventListener("change", (event) => {
      state.symbols.language = event.target.value;
      state.symbols.offset = 0;
      loadSymbols();
    });
    $("#symbolKind").addEventListener("change", (event) => {
      state.symbols.kind = event.target.value;
      state.symbols.offset = 0;
      loadSymbols();
    });
    let symbolTimer = null;
    $("#symbolSearch").addEventListener("input", (event) => {
      clearTimeout(symbolTimer);
      const value = event.target.value;
      symbolTimer = setTimeout(() => {
        state.symbols.q = value.trim();
        state.symbols.offset = 0;
        loadSymbols();
      }, 240);
    });
    $("#symbolPrev").addEventListener("click", () => {
      state.symbols.offset = Math.max(0, state.symbols.offset - state.symbols.limit);
      loadSymbols();
    });
    $("#symbolNext").addEventListener("click", () => {
      if (state.symbols.offset + state.symbols.limit < state.symbols.total) {
        state.symbols.offset += state.symbols.limit;
        loadSymbols();
      }
    });
    $("#symbolRows").addEventListener("click", (event) => {
      const button = event.target.closest("[data-symbol-file]");
      if (button) go("source", { path: button.dataset.symbolFile, line: Number(button.dataset.symbolLine) || 1 });
    });
    await loadCode();
    await loadSymbols();
  }

  async function loadCode() {
    const code = state.code;
    const seq = ++code.seq;
    const params = new URLSearchParams({ limit: String(code.limit), offset: String(code.offset) });
    if (code.language !== "all") params.set("language", code.language);
    if (code.category !== "all") params.set("category", code.category);
    if (code.severity !== "all") params.set("severity", code.severity);
    if (code.q) params.set("q", code.q);
    const rows = $("#codeRows");
    if (!rows) return;
    rows.innerHTML = `<tr><td colspan="5" class="muted">正在运行多语言规则分析；大型项目首次可能需要数十秒，结果会被缓存…</td></tr>`;
    let data;
    try {
      data = await api("/api/code-audit?" + params.toString());
    } catch (error) {
      rows.innerHTML = `<tr><td colspan="5">${esc(error.message)}</td></tr>`;
      return;
    }
    if (seq !== code.seq || state.route !== "code") return;
    code.total = data.total || 0;
    code.limitations = data.limitations || [];
    code.items = data.items || [];
    rows.innerHTML = code.items.length ? code.items.map(codeRow).join("") :
      `<tr><td colspan="5" class="muted">当前筛选下没有发现；无发现不等于安全</td></tr>`;
    const coverage = data.coverage || {};
    const partialAxes = [
      data.file_partial ? "文件" : "",
      data.symbol_partial ? "符号" : "",
      data.finding_partial ? "发现" : "",
    ].filter(Boolean);
    $("#codeCount").textContent = `发现 ${fmtNum(code.total)} · 规则 ${fmtNum(coverage.rules_active)} · 文件 ${fmtNum(coverage.files_scanned)}`;
    $("#codeRuleset").textContent = data.available ? `规则集 ${data.ruleset_version}` : `未运行：${data.reason || "未知原因"}`;
    $("#codeKpis").innerHTML = `
      <span class="chip"><svg class="icon icon-xs"><use href="#i-bug"/></svg>发现 ${fmtNum(code.total)}</span>
      <span class="chip"><svg class="icon icon-xs"><use href="#i-code"/></svg>语言 ${fmtNum((data.languages || []).filter((item) => item.status === "scanned").length)}</span>
      <span class="chip"><svg class="icon icon-xs"><use href="#i-shield"/></svg>规则 ${fmtNum(coverage.rules_active)}</span>
      <span class="chip"><svg class="icon icon-xs"><use href="#i-route"/></svg>入口 ${fmtNum(coverage.routes_found)}</span>
      <span class="chip"><svg class="icon icon-xs"><use href="#i-layer"/></svg>符号 ${fmtNum(coverage.symbols_found)} · 调用 ${fmtNum(coverage.calls_found)} · 已解析 ${fmtNum(coverage.calls_resolved)} · 未解析 ${fmtNum(coverage.unresolved_found)}</span>
      <span class="chip"><svg class="icon icon-xs"><use href="#i-code"/></svg>变量 ${fmtNum(coverage.variables_found)} · 字符串常量 ${fmtNum(coverage.string_constants_found)}</span>
      <span class="chip"><svg class="icon icon-xs"><use href="#i-flag"/></svg>状态 ${data.partial ? "部分覆盖" : "完整清单"}${partialAxes.length ? " · " + partialAxes.join("/") : ""}</span>
      <span class="chip"><svg class="icon icon-xs"><use href="#i-clock"/></svg>运行时 ${esc(data.runtime_status || "not_run")}</span>
    `;
    $("#codeLanguages").innerHTML = (data.languages || []).map((item) => `<div class="kv"><span>${esc(codeLanguageLabels[item.language] || item.language)}</span><b>${esc(item.status)} · 文件 ${fmtNum(item.files_scanned)} · 发现 ${fmtNum(item.findings)} · 入口 ${fmtNum(item.routes)} · 调用已解析 ${fmtNum(item.calls_resolved || 0)} · 变量 ${fmtNum(item.variables || 0)} · 字符串 ${fmtNum(item.string_constants || 0)}</b></div>`).join("") || emptyState("i-code", "无语言覆盖", "快照中没有受支持语言的源码文件");
    $("#codeRoutes").innerHTML = (data.routes || []).slice(0, 24).map((route) => {
      const dynamic = route.path_status === "dynamic_unresolved";
      const convention = route.path_status === "convention_candidate";
      const label = dynamic ? `<span class="chip warn">动态未解析</span> ` : convention ? `<span class="chip warn">框架约定候选</span> ` : "";
      const source = route.source ? `<span class="chip">${esc(route.source)}</span>` : "";
      return `<div class="kv"><span class="mono">${label}${esc((route.http_methods || []).join("/") || "ANY")} ${esc(dynamic ? "路径由变量/数据库决定" : route.path)}${route.target ? ` → ${esc(route.target)}` : ""}</span><b>${source}${esc(codeLanguageLabels[route.language] || route.language)} · ${esc(route.file)}:L${route.line}</b></div>`;
    }).join("") || emptyState("i-route", "无声明入口", "未观察到路由声明；这不等于没有 HTTP 入口");
    const rejected = data.rejected_files || [];
    const rejectedScopes = (data.rejected_scopes || []).map((item) => `<span class="chip">${esc(codeScopeLabels[item.key] || item.key)} ${fmtNum(item.value)}</span>`).join("");
    $("#codeRejected").innerHTML = !data.available
      ? emptyState("i-alert", "代码审计未运行", data.reason || "当前快照没有可用的代码审计结果。")
      : (rejectedScopes ? `<div class="symbol-note">${rejectedScopes}<span class="muted">分类只用于判断缺口来源；不改变 file_partial</span></div>` : "") + (rejected.length ? rejected.map((item) =>
        `<div class="kv"><span class="mono">${esc(item.file)}</span><b>${esc(codeScopeLabels[item.scope] || item.scope || "项目源码")} · ${esc(codeLanguageLabels[item.language] || item.language)} · ${esc(codeRejectReasonLabels[item.reason] || item.reason || "未知原因")}</b></div>`).join("") :
        emptyState("i-alert", "没有文件级拒绝", "当前报告没有 file_too_large、lex_rejected 或 statement_limit；这不代表快照覆盖完整。"));
    renderSymbolEvidence($("#codeSymbols"), data);
    $("#codeLimits").innerHTML = limitationList(data.limitations);
    $("#codeRange").textContent = code.total ? `${fmtNum(code.offset + 1)}–${fmtNum(Math.min(code.offset + code.limit, code.total))} / ${fmtNum(code.total)}` : "0 / 0";
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
        <div class="card-head"><h3><svg class="icon"><use href="#i-shield"/></svg>多语言控制适配</h3><span class="card-sub">入口级决策；未附着的文件级证据单列（应用入口不附着脚本鉴权）</span></div>
        <div class="card-body" id="authzLanguageAdapters"></div>
      </section>
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
      const languageEntries = (data.language_counts || []).filter((row) => row.language !== "java").reduce((sum, row) => sum + (row.total || 0), 0);
      $("#authzCount").textContent = `无控制 ${fmtNum(data.counts.unprotected)} · 未知 ${fmtNum(data.counts.unknown)} · 受保护 ${fmtNum(data.counts.protected)} · 公开 ${fmtNum(data.counts.public)} · 非 Java 入口 ${fmtNum(languageEntries)} · 文件级证据 ${fmtNum(data.file_evidence_total || 0)}`;
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
      renderAuthzLanguageAdapters(data.language_adapters || [], data.file_evidence || [], data.language_counts || []);
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

  function authzEntryKindLabel(kind) {
    return { application_entry: "应用入口", request_script: "请求脚本", route_declaration: "路由声明" }[kind] || "文件级";
  }

  function renderAuthzLanguageAdapters(adapters, fileEvidence, counts) {
    const host = $("#authzLanguageAdapters");
    if (!host) return;
    const rows = Array.isArray(counts) ? counts : [];
    const summary = rows.map((row) => `<div class="kv-row"><span class="kv-key">${esc(row.language)}</span><span class="kv-val">受保护 ${fmtNum(row.protected)} · 无控制 ${fmtNum(row.unprotected)} · 未知 ${fmtNum(row.unknown)} · 公开 ${fmtNum(row.public)} · 入口 ${fmtNum(row.total)}${row.file_evidence ? ` · 文件级 ${fmtNum(row.file_evidence)}` : ""}</span></div>`).join("");
    const attachedList = adapters.length
      ? `<ul class="limits section-gap">${adapters.slice(0, 60).map((item) => `<li class="limit-row"><svg class="icon"><use href="#i-${item.decision === "protected" ? "lock" : "alert"}"/></svg><span><b>${esc(item.language)} · ${esc(authzEntryKindLabel(item.entry_kind))}</b> <span class="limit-text">${esc(item.decision)} · ${esc(item.control || "none")} · ${esc(item.file)}:${item.line}${item.control_line ? ` · 控制:${item.control_line}` : ""}</span></span></li>`).join("")}</ul>`
      : emptyState("i-shield", "没有入口级控制证据", "请求脚本、路由声明与应用入口均未发现可识别的鉴权标记；这不等于这些入口没有访问控制。");
    const evidenceList = fileEvidence.length
      ? `<div class="card-sub section-gap">文件级证据（未附着到入口） ${fmtNum(fileEvidence.length)} 条</div><ul class="limits">${fileEvidence.slice(0, 40).map((item) => `<li class="limit-row"><svg class="icon"><use href="#i-alert"/></svg><span><b>${esc(item.language)}</b> <span class="limit-text">${esc(item.decision)} · ${esc(item.control || "none")} · ${esc(item.file)}:${item.line}（未附着到入口，不计入入口统计）</span></span></li>`).join("")}</ul>`
      : "";
    host.innerHTML = `${summary ? `<div class="kv">${summary}</div>` : ""}${attachedList}${evidenceList}`;
  }

  // ── java semantic model ────────────────────────────────────────────────

  async function viewModel() {
    const model = state.model;
    $("#view").innerHTML = `
      <section class="card">
        <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>代码模型概览</h3><span class="card-sub">按语言看文件与符号覆盖；Java AST 只是 Java 视图</span></div>
        <div class="card-body" id="modelOverview"></div>
      </section>
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-code"/></svg>Java AST 类型索引</h3><span class="card-sub">受限子集解析，不等于完整语义模型</span></div>
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
      <section class="card section-gap">
        <div class="card-head"><h3><svg class="icon"><use href="#i-layer"/></svg>多语言符号索引</h3><span class="card-sub">来自 codescan；同文件简单名匹配，其余未解析</span></div>
        <div class="card-body" id="modelSymbols"></div>
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
    $("#modelSymbols").addEventListener("click", (event) => {
      if (event.target.closest("[data-run-code]")) go("code");
    });
    $("#modelOverview").addEventListener("click", (event) => {
      if (event.target.closest("[data-run-code]")) go("code");
      if (event.target.closest("[data-open-symbols]")) go("code");
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
      renderModelOverview($("#modelOverview"), data);
      renderSymbolEvidence($("#modelSymbols"), data);
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
    const [config, runtime, quick] = await Promise.all([
      api("/api/config"),
      api("/api/agent/runtime").catch(() => null),
      api("/api/agent/runtime/quick").catch(() => null),
    ]);
    state.config = config;
    state.agentRuntime = runtime;
    const paths = config.paths;
    const features = config.features;
    const rt = runtime || { enabled: false, ready: false, reason: "", dsn_stored: false, token_stored: false, dsn_target: "", model_ready: false, active_run: 0, active_task: 0 };
    const q = quick || { enabled: false, ready: false, can_enable: false, dsn_found: false, dsn_ok: false, principal_found: false, principal_role: "", model_ready: false, dsn_target: "", reason: "快速启用状态不可用" };
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
          </div>` : `<p class="form-hint warn-text">当前为固定快照模式，项目与路径配置只读。改用 <code>trident web --workspace &lt;dir&gt;</code> 启动一次后，即可在「设置」页随时切换项目、修改分析路径与 Agent 运行时配置，之后无需再重启。</p>`}
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
        <div class="card-head"><h3><svg class="icon"><use href="#i-server"/></svg>Agent 与编排</h3><span class="card-sub">保存后立即生效，无需重启</span></div>
        <div class="card-body">
          <div class="rt-quick">
            <p class="rt-lead">${q.enabled ? "Agent 已启用，可以直接发起对话或编排任务。" : "自动识别本机已保存的会话库与主体令牌，点一次即可启用；不用手填连接串和 64 位令牌。"}</p>
            <div class="rt-checks">
              <span class="status ${q.dsn_ok ? "ok" : "warn"}">会话库${q.dsn_ok ? "已连接" : "不可用"}</span>
              <span class="status ${q.principal_found ? "ok" : "warn"}">主体令牌${q.principal_found ? "可用 · " + esc(q.principal_role) : "未找到"}</span>
              <span class="status ${q.model_ready ? "ok" : "warn"}">主模型密钥${q.model_ready ? "可用" : "缺失"}</span>
            </div>
            ${!q.model_ready ? `<p class="form-hint">启用后还需配置主模型与 API Key：<a href="#/settings/model">前往「设置 → 模型」</a></p>` : ""}
            ${!q.enabled && !q.can_enable && q.reason ? `<p class="form-hint warn-text">${esc(q.reason)}</p>` : ""}
            <div class="row-actions left">
              ${q.enabled
                ? `<button class="btn" type="button" id="quickDisable" ${features.workspace_editable && rt.active_run === 0 && rt.active_task === 0 ? "" : "disabled"}>停用 Agent 与编排</button>`
                : `<button class="btn primary" type="button" id="quickEnable" ${features.workspace_editable && q.can_enable ? "" : "disabled"}>一键启用</button>`}
              ${!q.enabled && !q.can_enable ? `<span class="form-hint">可展开下方「高级设置」手动填写</span>` : ""}
            </div>
            ${rt.enabled && !rt.ready ? `<p class="form-hint warn-text">${esc(rt.reason || "已启用但未就绪")}</p>` : ""}
          </div>
          <details class="rt-advanced">
            <summary>高级设置 · 手动填写连接串与令牌</summary>
            <div class="kv mt-14">
              ${kvRow("状态", rt.ready ? "已就绪" : rt.enabled ? "已启用但未就绪" : "未启用", rt.ready ? "good" : "warn")}
              ${kvRow("会话库", q.dsn_target || (rt.dsn_stored ? rt.dsn_target : "未配置"), q.dsn_ok || rt.dsn_stored ? "good" : "warn")}
              ${kvRow("主体令牌", rt.token_stored ? "已保存" : "未配置", rt.token_stored ? "good" : "warn")}
              ${kvRow("主模型密钥", rt.model_ready ? "可用" : "缺失", rt.model_ready ? "good" : "warn")}
              ${kvRow("运行中", `Run ${rt.active_run} · 编排 ${rt.active_task}`)}
            </div>
            ${rt.reason ? `<p class="form-hint warn-text">${esc(rt.reason)}</p>` : ""}
            <label class="check line"><input type="checkbox" id="rtEnabled" ${rt.enabled ? "checked" : ""} ${features.workspace_editable ? "" : "disabled"}>启用 Agent 对话与编排</label>
            <div class="form-grid">
              <label class="field"><span>Agent 会话库连接串</span><input class="input mono" id="rtDSN" placeholder="${rt.dsn_stored ? "已保存；输入新连接串可替换" : "postgres://用户:密码@127.0.0.1:55432/trident_test?sslmode=disable"}" autocomplete="off" spellcheck="false"></label>
              <label class="field"><span>主体令牌（具备创建 Run 权限）</span><input class="input" id="rtToken" type="password" autocomplete="new-password" placeholder="${rt.token_stored ? "已保存；留空不改" : "粘贴主体令牌"}"></label>
            </div>
            <p class="model-hint">连接串与令牌只保存在本机工作区（0600），前端只看到「已保存」，永不回显；保存前会真实连接并校验令牌。有 Run 或编排任务运行时拒绝修改。</p>
            <div class="row-actions left">
              <button class="btn primary" type="button" id="saveAgentRuntime" ${features.workspace_editable ? "" : "disabled"}>保存运行时配置</button>
              <button class="btn sm ghost" type="button" id="clearAgentToken" ${rt.token_stored ? "" : "disabled"}>清除令牌</button>
              <button class="btn sm ghost" type="button" id="clearAgentDSN" ${rt.dsn_stored ? "" : "disabled"}>清除连接</button>
            </div>
          </details>
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
        <div class="card-head"><h3><svg class="icon"><use href="#i-info"/></svg>能力状态</h3><span class="card-sub">随运行时配置变化</span></div>
        <div class="card-body">
          <div class="kv">
            ${kvRow("项目导入", features.project_import ? "可用" : "不可用", features.project_import ? "good" : "warn")}
            ${kvRow("路径配置", features.workspace_editable ? "可用" : "不可用", features.workspace_editable ? "good" : "warn")}
            ${kvRow("代码模型", features.java_model ? "已生成" : "未生成", features.java_model ? "good" : "warn")}
            ${kvRow("Agent 观测", features.agent_store ? "已连接只读库" : "未配置会话库", features.agent_store ? "good" : "warn")}
            ${kvRow("Agent 编排", features.agent_chat_ready ? "已就绪" : features.agent_chat_enabled ? "已启用未就绪" : "未启用", features.agent_chat_ready ? "good" : "warn")}
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
    const saveAgentRuntime = async (body, okText) => {
      try {
        await api("/api/agent/runtime", { method: "POST", body });
        toast(okText, "ok");
        await viewSettings();
      } catch (error) {
        toast(error.message, "bad");
        // Keep the persisted switch state visible; the typed credentials stay so
        // the user can correct them without re-entering everything.
        if (state.agentRuntime) $("#rtEnabled").checked = state.agentRuntime.enabled;
      }
    };
    const quickEnableBtn = $("#quickEnable");
    if (quickEnableBtn) {
      quickEnableBtn.addEventListener("click", async () => {
        quickEnableBtn.disabled = true;
        quickEnableBtn.textContent = "启用中…";
        try {
          await api("/api/agent/runtime/quick", { method: "POST" });
          toast("Agent 与编排已启用，立即生效", "ok");
          await viewSettings();
        } catch (error) {
          toast(error.message, "bad");
          quickEnableBtn.disabled = false;
          quickEnableBtn.textContent = "一键启用";
        }
      });
    }
    const quickDisableBtn = $("#quickDisable");
    if (quickDisableBtn) {
      quickDisableBtn.addEventListener("click", () => {
        if (!window.confirm("停用 Agent 对话与编排？已保存的会话库与令牌保留，可随时重新启用。")) return;
        void saveAgentRuntime({ enabled: false }, "已停用 Agent 与编排");
      });
    }
    const saveRuntimeBtn = $("#saveAgentRuntime");
    if (saveRuntimeBtn) {
      saveRuntimeBtn.addEventListener("click", () => saveAgentRuntime({
        enabled: $("#rtEnabled").checked,
        dsn: $("#rtDSN").value.trim(),
        token: $("#rtToken").value.trim(),
      }, "运行时配置已保存，立即生效"));
    }
    const clearTokenBtn = $("#clearAgentToken");
    if (clearTokenBtn) {
      clearTokenBtn.addEventListener("click", () => {
        if (!window.confirm("清除已保存的主体令牌？对话与编排会同时停用，可随时重新填写。")) return;
        void saveAgentRuntime({ clear_token: true }, "令牌已清除，对话与编排已停用");
      });
    }
    const clearDSNBtn = $("#clearAgentDSN");
    if (clearDSNBtn) {
      clearDSNBtn.addEventListener("click", () => {
        if (!window.confirm("清除已保存的会话库连接？只影响本机保存，数据库本身不变。")) return;
        void saveAgentRuntime({ clear_dsn: true }, "已清除保存的会话库连接");
      });
    }
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
          </div>` : `<p class="form-hint warn-text">当前为固定快照模式，无法导入项目。改用 <code>trident web --workspace .trident</code> 启动一次后即可在界面选择项目，并在「设置」页随时修改配置（无需再重启）。</p>`}
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
    const restore = () => {
      button.disabled = false;
      button.innerHTML = `<svg class="icon"><use href="#i-download"/></svg>导入并分析`;
    };
    button.disabled = true;
    button.textContent = "导入中…";
    try {
      const result = await api("/api/projects", { method: "POST", body: { source } });
      state.browse.pick = source;
      // Report success immediately. The first overview analysis used to be
      // awaited here, which left the button spinning for the whole (possibly
      // 30+ second) analysis of a large project even though import succeeded.
      restore();
      toast(`已导入 ${result.project.files} 个文件 · ${shortHash(result.project.hash)}；分析在打开页面时进行`, "ok");
      resetAnalysisState();
      await ensureConfig(true);
      await refreshProjectSwitcher();
      go("overview");
    } catch (error) {
      toast(error.message, "bad");
      restore();
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
        const route = parseHash().name;
        if (route !== "projects" && route !== "cases" && route !== "case") {
          location.hash = "#/projects";
        }
        await renderRoute();
        return;
      }
      await refreshProjectSwitcher();
      if (!location.hash) {
        location.hash = "#/overview";
      }
      // Render the requested route first. On a non-overview route, warm the
      // overview in the background so topbar metadata does not block the page
      // the user asked for.
      await renderRoute();
      if (parseHash().name !== "overview") {
        ensureOverview().catch(() => {});
      }
    } catch (error) {
      if (error.status === 401) showLogin("");
      else showLogin("控制台服务不可用：" + error.message);
    }
  }

  boot();

// ---------------------------------------------------------------------------
// #/tasks — multi-agent orchestration (planner/worker exploration graph)
// ---------------------------------------------------------------------------

  async function viewOrchTasks(routeParams) {
    const deepTask = Number(routeParams?.get("task") || 0);
    state.orch = { detailId: deepTask || (state.orch && state.orch.detailId) || 0, showForm: Boolean(state.orch && state.orch.showForm), timer: null };
    const orchState = {
      created: ["已创建", "muted"], running: ["运行中", "ok"], completed: ["已完成", "ok"],
      cancelled: ["已停止", "warn"], failed: ["失败", "bad"],
    };
    const statePill = (value) => {
      const [label, cls] = orchState[value] || [value || "未知", "muted"];
      const dot = cls === "ok" ? "ok" : cls === "bad" ? "bad" : cls === "warn" ? "warn" : "";
      return `<span class="status ${cls}">${dot ? `<span class="dot ${dot}"></span>` : ""}${esc(label)}</span>`;
    };
    const nodeStateLabel = { open: "待处理", running: "执行中", done: "完成", met: "已达成", exhausted: "预算耗尽", blocked: "受阻", cancelled: "已取消", invalid: "无效" };
    $("#view").innerHTML = `
      <section class="hero">
        <div class="hero-copy">
          <span class="eyebrow">MULTI-AGENT STATIC EXPLORATION</span>
          <h2>编排任务</h2>
          <p>规划者事件驱动派发审计意图，执行者并发只读读码，结论写回可回溯的探索图。Agent 产出恒为候选发现，不是确认漏洞；runtime_status 始终保持 not_run。</p>
          <div class="hero-meta" id="orchMeta"><span class="chip">加载中…</span></div>
        </div>
        <div class="hero-side">
          <div class="hero-badge" id="orchBadge"><strong>0</strong><span>TASKS</span></div>
          <button class="btn primary" type="button" id="orchNew"><svg class="icon"><use href="#i-plus"/></svg>新建任务</button>
        </div>
      </section>
      <div class="grid-2">
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-flag"/></svg>任务</h3><span class="card-sub">最近 50 个 · 每 5 秒刷新</span></div>
          <div class="card-body tight" id="orchList"><div class="sk sk-row"></div></div>
        </section>
        <section class="card">
          <div class="card-head"><h3><svg class="icon"><use href="#i-shield"/></svg>运行方式</h3></div>
          <div class="card-body">
            <div class="kv">
              ${kvRow("规划者", "事件驱动派意图，唯一生成者")}
              ${kvRow("执行者", "并发领意图，只读工具读码")}
              ${kvRow("图写回", "引擎校验引用后才落图")}
              ${kvRow("候选发现", "不是确认漏洞，需人+三态确认", "warn")}
              ${kvRow("预算收尾", "最后一次调用前强制写回", "good")}
              ${kvRow("与手动 Run", "互斥，同一时刻只跑一个", "warn")}
            </div>
          </div>
        </section>
      </div>
      <section class="card section-gap" id="orchFormCard" hidden>
        <div class="card-head"><h3><svg class="icon"><use href="#i-plus"/></svg>新建编排任务</h3><span class="card-sub">外发需显式批准</span></div>
        <div class="card-body">
          <form id="orchForm">
            <div class="grid-2">
              <label class="field"><span>任务标题</span><input class="input" id="orchTitle" maxlength="200" placeholder="例如：market 后台模块专项审计" required></label>
              <label class="field"><span>模型配置</span><select class="input" id="orchProfile"></select></label>
            </div>
            <label class="field"><span>审计目标（规划者的最终目标，可含量化验收条件）</span><textarea class="input" id="orchGoal" rows="4" maxlength="8000" placeholder="例如：梳理全部 HTTP 入口并核查鉴权缺失；每条意图给出文件与行号证据。" required></textarea></label>
            <div class="grid-3">
              <label class="field"><span>规划轮数上限</span><input class="input" id="orchRounds" type="number" min="1" max="12" value="6"></label>
              <label class="field"><span>意图总数上限</span><input class="input" id="orchIntents" type="number" min="1" max="24" value="12"></label>
              <label class="field"><span>并发执行者</span><input class="input" id="orchWorkers" type="number" min="1" max="4" value="2"></label>
            </div>
            <div class="grid-3">
              <label class="field"><span>截止（分钟）</span><input class="input" id="orchDeadline" type="number" min="5" max="240" value="30"></label>
              <label class="field"><span>单会话模型调用上限</span><input class="input" id="orchModelCalls" type="number" min="1" max="64" value="12"></label>
              <label class="field"><span>单会话工具调用上限</span><input class="input" id="orchToolCalls" type="number" min="1" max="256" value="24"></label>
            </div>
            <label class="check egress"><input type="checkbox" id="orchEgress" required>我批准外发：快照与目标将随每个规划/执行会话发送到所选模型端点</label>
            <div class="row-actions"><button class="btn primary" type="submit">启动任务</button><button class="btn" type="button" id="orchFormCancel">取消</button></div>
          </form>
        </div>
      </section>
      <div id="orchDetail" class="section-gap"></div>`;

    if (deepTask) {
      const detail = $("#orchDetail");
      const hero = $("#view .hero");
      if (detail && hero) hero.after(detail);
    }

    const setMeta = (tasks) => {
      const meta = $("#orchMeta");
      const badge = $("#orchBadge");
      if (!meta || !badge) return;
      badge.querySelector("strong").textContent = String(tasks.length);
      const running = tasks.filter((task) => task.state === "running").length;
      const finished = tasks.filter((task) => task.state === "completed").length;
      const stopped = tasks.filter((task) => task.state === "cancelled" || task.state === "failed").length;
      meta.innerHTML = `
        <span class="chip"><span class="dot ${running ? "ok" : ""}"></span>运行中 ${running}</span>
        <span class="chip">已完成 ${finished}</span>
        <span class="chip">停止/失败 ${stopped}</span>
        <span class="chip mono">并发上限 4 · 意图上限 24</span>`;
    };

    async function refreshList() {
      const list = $("#orchList");
      if (!list) return;
      let payload;
      try {
        payload = await api("/api/agent/orchestration");
      } catch (error) {
        setMeta([]);
        list.innerHTML = emptyState("i-server", "编排未启用", error.message || "需要写库会话与主体令牌");
        if (state.orch && state.orch.timer) {
          clearInterval(state.orch.timer);
          state.orch.timer = null;
        }
        return;
      }
      const tasks = payload.tasks || [];
      setMeta(tasks);
      if (!tasks.length) {
        list.innerHTML = emptyState("i-flag", "还没有编排任务", "新建一个任务后，规划者会自动开始派发审计意图；候选发现会按血缘写回探索图。");
        return;
      }
      list.innerHTML = `<table class="orch-tasks"><thead><tr><th>ID</th><th>标题</th><th>状态</th><th>轮次</th><th>意图</th><th>截止</th><th></th></tr></thead><tbody>
        ${tasks.map((task) => `<tr>
          <td class="mono">#${task.id}</td>
          <td><strong>${esc(task.title)}</strong>${task.reason ? `<div class="card-sub">${esc(task.reason)}</div>` : ""}</td>
          <td>${statePill(task.state)}</td>
          <td class="mono">${task.planner_rounds}/${task.max_planner_rounds}</td>
          <td class="mono">${task.intents_spawned}/${task.max_intents}</td>
          <td class="mono">${esc((task.deadline || "").slice(5, 16).replace("T", " "))}</td>
          <td><span class="row-actions">
            <button class="btn sm" type="button" data-detail="${task.id}">查看图</button>
            ${task.state === "running" && payload.active_task === task.id ? `<button class="btn sm danger" type="button" data-stop="${task.id}">停止</button>` : ""}
          </span></td>
        </tr>`).join("")}
      </tbody></table>`;
      list.querySelectorAll("[data-detail]").forEach((button) => button.addEventListener("click", async () => {
        state.orch.detailId = Number(button.dataset.detail);
        await viewOrchTasks();
        const detail = $("#orchDetail");
        if (detail) detail.scrollIntoView({ behavior: "smooth", block: "start" });
      }));
      list.querySelectorAll("[data-stop]").forEach((button) => button.addEventListener("click", async () => {
        try { await api(`/api/agent/orchestration/stop?id=${button.dataset.stop}`, { method: "POST" }); toast("已请求停止；在跑会话会保留已提交步骤", "ok"); viewOrchTasks(); }
        catch (error) { toast(error.message, "bad"); }
      }));
    }

    async function refreshProfiles() {
      const select = $("#orchProfile");
      if (!select) return;
      const payload = await api("/api/agent/chat/state").catch(() => ({ profiles: [], resolved: {} }));
      const profiles = payload.profiles || [];
      const resolved = payload.resolved || {};
      const follow = resolved.planner && resolved.worker
        ? `跟随角色配置（规划者 ${resolved.planner.entry_name} · 执行者 ${resolved.worker.entry_name}）`
        : "跟随角色配置（规划者 / 执行者）";
      select.innerHTML = `<option value="" selected>${esc(follow)}</option>` + profiles.map((profile) => `<option value="${esc(profile.id)}">${esc(profile.label)}（${esc(profile.model)}）</option>`).join("");
      if (!profiles.length) select.disabled = true;
    }

    async function refreshDetail() {
      const target = $("#orchDetail");
      if (!target) return;
      if (!state.orch.detailId) { target.innerHTML = ""; return; }
      let payload;
      try { payload = await api(`/api/agent/orchestration/detail?id=${state.orch.detailId}`); }
      catch (error) { target.innerHTML = `<div class="card"><div class="empty">${esc(error.message)}</div></div>`; return; }
      const task = payload.task || {};
      const nodes = payload.nodes || [];
      const kindRows = (kind, hint, icon) => {
        const rows = nodes.filter((node) => node.kind === kind);
        if (!rows.length) return "";
        return `<section class="card section-gap">
          <div class="card-head"><h3><svg class="icon"><use href="#${icon}"/></svg>${hint}</h3><span class="card-sub">${rows.length} 条</span></div>
          <div class="card-body tight"><table class="orch-nodes"><thead><tr><th>ID</th><th>状态</th><th>内容</th><th>会话</th></tr></thead><tbody>
            ${rows.map((node) => {
              let run = 0;
              try { const parsed = JSON.parse(node.payload || "{}"); run = parsed.run || parsed.planner_run || 0; } catch (_) {}
              return `<tr>
                <td class="mono">#${node.id}</td>
                <td><span class="chip">${esc(nodeStateLabel[node.state] || node.state)}</span>${node.confidence ? `<span class="chip mono">${esc(node.confidence)}</span>` : ""}</td>
                <td>${esc(node.summary)}</td>
                <td>${run ? `<a class="chip mono" href="#/agent?run=${run}" title="在 Agent 对话页查看该 Run">Run ${run}</a>` : "—"}</td>
              </tr>`;
            }).join("")}
          </tbody></table></div>
        </section>`;
      };
      const constraints = (payload.constraints || []).map((item) => `<span class="chip ${item.kind === "deny" ? "bad" : ""}">${item.kind === "deny" ? "禁止" : "允许"}：${esc(item.text)}</span>`).join(" ");
      const conversationHref = task.conversation_id ? `#/agent?conversation=${task.conversation_id}` : "#/agent";
      target.innerHTML = `
        <section class="card">
          <div class="card-head">
            <h3><svg class="icon"><use href="#i-flag"/></svg>任务 #${task.id} · ${esc(task.title)}</h3>
            <span class="card-head-actions">${statePill(task.state)}<a class="card-link" href="${conversationHref}">${task.conversation_id ? `会话 #${task.conversation_id}` : "会话记录"}<svg class="icon"><use href="#i-chev-right"/></svg></a></span>
          </div>
          <div class="card-body">
            <p class="task-goal">${esc(task.goal)}</p>
            <div class="kv">
              ${kvRow("轮次", `${task.planner_rounds} / ${task.max_planner_rounds}`)}
              ${kvRow("意图", `${task.intents_spawned} / ${task.max_intents}`)}
              ${kvRow("并发执行者", String(task.max_workers))}
              ${kvRow("截止", esc((task.deadline || "").slice(0, 19).replace("T", " ")))}
              ${task.reason ? kvRow("结论", esc(task.reason), "warn") : ""}
            </div>
            ${constraints ? `<div class="hero-meta mt-10">${constraints}</div>` : ""}
          </div>
        </section>
        ${kindRows("goal", "目标", "i-flag")}
        ${kindRows("intent", "意图", "i-route")}
        ${kindRows("fact", "事实（Agent 观察）", "i-info")}
        ${kindRows("finding_candidate", "候选发现（不是确认漏洞）", "i-bug")}
        <section class="card section-gap">
          <div class="card-head"><h3><svg class="icon"><use href="#i-sliders"/></svg>操舵</h3><span class="card-sub">写回图，下一轮派发生效</span></div>
          <div class="card-body">
            <div class="grid-3">
              <label class="field"><span>补充意图</span><input class="input" id="steerIntent" placeholder="直接注入一条要审的方向"></label>
              <label class="field"><span>战略提示</span><input class="input" id="steerHint" placeholder="给规划者的调整建议"></label>
              <label class="field"><span>新增目标</span><input class="input" id="steerGoal" placeholder="新增一个要达成的目标"></label>
            </div>
            <label class="field"><span>操作约束（以「禁止」开头登记为 deny，否则 allow）</span><input class="input" id="steerConstraint" placeholder="例如：只审 src/main 下的自有代码"></label>
            <div class="row-actions">
              <button class="btn sm" type="button" id="steerIntentBtn">注入意图</button>
              <button class="btn sm" type="button" id="steerHintBtn">提交提示</button>
              <button class="btn sm" type="button" id="steerGoalBtn">登记目标</button>
              <button class="btn sm" type="button" id="steerConstraintBtn">登记约束</button>
            </div>
            <p class="card-sub mt-8">每条操舵只写回图，运行中的会话不被打断；候选发现是 Agent 推断，不是确认漏洞。</p>
          </div>
        </section>`;
      const steer = async (kind, inputId) => {
        const input = $(`#${inputId}`);
        const text = (input.value || "").trim();
        if (!text) { toast("内容不能为空", "bad"); return; }
        try {
          await api("/api/agent/orchestration/steer", { method: "POST", body: { task_id: task.id, kind, text } });
          toast(kind === "constraint" ? "约束已登记" : "已写回探索图，下一轮派发生效", "ok");
          input.value = "";
          viewOrchTasks();
        } catch (error) { toast(error.message, "bad"); }
      };
      $("#steerIntentBtn").addEventListener("click", () => steer("intent", "steerIntent"));
      $("#steerHintBtn").addEventListener("click", () => steer("hint", "steerHint"));
      $("#steerGoalBtn").addEventListener("click", () => steer("goal", "steerGoal"));
      $("#steerConstraintBtn").addEventListener("click", () => steer("constraint", "steerConstraint"));
    }

    $("#orchNew").addEventListener("click", () => { state.orch.showForm = true; $("#orchFormCard").hidden = false; refreshProfiles(); });
    $("#orchFormCancel").addEventListener("click", () => { $("#orchFormCard").hidden = true; });
    $("#orchForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const body = {
        title: $("#orchTitle").value.trim(), goal: $("#orchGoal").value.trim(),
        approve_egress: $("#orchEgress").checked,
        profile_id: $("#orchProfile").value,
        max_planner_rounds: Number($("#orchRounds").value) || undefined,
        max_intents: Number($("#orchIntents").value) || undefined,
        max_workers: Number($("#orchWorkers").value) || undefined,
        deadline_minutes: Number($("#orchDeadline").value) || undefined,
        max_model_calls: Number($("#orchModelCalls").value) || undefined,
        max_tool_calls: Number($("#orchToolCalls").value) || undefined,
      };
      try {
        const payload = await api("/api/agent/orchestration", { method: "POST", body });
        toast(`任务 ${payload.task_id} 已启动；规划者正在生成第一批意图`, "ok");
        state.orch.detailId = payload.task_id;
        await viewOrchTasks();
        const detail = $("#orchDetail");
        if (detail) detail.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (error) { toast(error.message, "bad"); }
    });
    await Promise.all([refreshList(), refreshDetail()]);
    if (deepTask) {
      const detail = $("#orchDetail");
      if (detail) detail.scrollIntoView({ block: "start" });
    }
    clearInterval(state.orch.timer);
    state.orch.timer = setInterval(() => {
      if (state.route !== "tasks" || !state.orch.timer) { clearInterval(state.orch.timer); return; }
      refreshList().catch(() => {});
      if (state.orch.detailId) refreshDetail().catch(() => {});
    }, 5000);
  }

})();
