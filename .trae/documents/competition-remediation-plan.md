# TRIDENT 比赛化改造路线：证据闭环 v1

## 0. 决策

- **产品主线改为一个可复核的 Case，而不是继续扩能力面。**
- 对外定位：**TRIDENT 是面向开源教育系统的、证据驱动的供应链安全与修复 Agent。**
- 首个真实靶场：**GibbonEdu/core v30.0.00**，修复对照 **v30.0.01**。
- 首个 Case：**Reports 归档路径 LFI → RCE（CVE-2026-8208）**；第二 Finding：**Tracking 认证后 SQLi（CVE-2026-8207）**。
- 不改写 `codescan`、不统一 AST、不新增第 8 种语言；只补“从 Finding 到可验证补丁”的主路径。
- 上游动作：先生成 PR-ready bundle；**未经明确确认，不向外部仓库提交 Issue/PR**。

## 1. 定位（写进 README 的第一段）

> TRIDENT 把一条安全发现变成可复现的 Case：源码证据、运行时证明、最小补丁、回归验证、上游补丁包，全部可追溯。

不再使用的定位：
- “统一安全 Agent 平台”
- “7 语言完整语义审计”
- “多租户安全治理平台”

## 2. 目标与非目标

### 目标

1. 在一个真实开源教育系统上，独立产出可复现的 Finding/Case。
2. 证明漏洞成立，而不是只给静态候选。
3. 生成最小补丁，并在隔离副本中验证漏洞消失、正常功能不回归。
4. 生成可提交上游的 `patch.diff`、advisory、复现脚本和 PR 描述。
5. 把这条链接入 Web 控制台和 Agent 工具，而不是只留在 CLI。

### 非目标

- 不做完整 PHP AST、类型系统、跨过程污点。
- 不把 Gibbon 的官方补丁当作 TRIDENT 的“发现结果”；官方 diff 只作为 ground truth 对照。
- 不把“扫到很多文件/路由/依赖”当成功指标。
- 不做真实 GitHub 提交，除非用户明确确认。

## 3. 靶场与事实基线

| 项 | 值 |
|---|---|
| 仓库 | `https://github.com/GibbonEdu/core` |
| 漏洞版本 | `v30.0.00`，commit `c431e25fdc874adece5d2dc7e408e9aa2d1abadb` |
| 修复版本 | `v30.0.01`，commit `b3b0219f49f2328508b989afd7e9b0843450cb9f` |
| 许可证 | GPL-3.0 |
| 官方安全 diff | `https://github.com/GibbonEdu/core/compare/v30.0.00...v30.0.01.diff` |
| 关键文件 | `modules/Reports/archive_manage_addProcess.php`、`editProcess.php`、`uploadProcess.php`、`modules/Tracking/graphing.php`、`src/Data/Validator.php` |
| 运行依赖 | PHP 8.x、MySQL 8、Apache；Docker 可用 |

### 当前环境事实

- Docker 28.4.0 可用；本地有 `mysql:8.0`、`wordpress:php8.3-apache`。
- 本机没有 PHP 8 CLI、Composer、MySQL CLI；优先 Docker。
- Git 在 `D:\DevTools\Git\cmd\git.exe`，不在 PATH。
- GitHub 直连会 403/限流；代理 `http://127.0.0.1:7897` 可用。

## 4. 阶段、验收与验证命令

### P0-1 可复现实验环境

**行为**
- 在 `cases/gibbon-v30.0.00/` 建立独立 Case 工作区。
- Docker Compose 启动 MySQL 8 + PHP 8.3 Apache；加载 `gibbon.sql` 与 `gibbon_demo.sql`；生成 `config.php`。
- 暴露 `127.0.0.1:8081`，保留登录、Tracking、Reports 页面。

**文件**
- `cases/gibbon-v30.0.00/docker-compose.yml`
- `cases/gibbon-v30.0.00/Dockerfile`
- `cases/gibbon-v30.0.00/config.php`
- `cases/gibbon-v30.0.00/seed.ps1` 或等价初始化脚本
- `cases/gibbon-v30.0.00/README.md`

**验收**
- `docker compose up -d` 后 `/login.php` 返回 200。
- 使用 demo 管理员登录成功。
- `/index.php?q=/modules/Tracking/graphing.php` 可访问。

**验证**
```
docker compose -f cases/gibbon-v30.0.00/docker-compose.yml up -d
python cases/gibbon-v30.0.00/check_env.py
```

---

### P0-2 独立检测与 Finding

**行为**
- 对 v30.0.00 做 TRIDENT 快照与 `audit code`。
- 先确认现有 `php.path.file_access` 是否命中 `archive_manage_addProcess.php` 的 `$_POST['path']`。
- 若未命中，新增**有界、可解释**的 PHP 规则：用户可控 `$_POST['path']` 进入归档路径/文件操作 sink；不添加“看到文件名就报”的规则。
- 产出 Finding：文件、行号、source、sink、证据、限制、CWE、置信状态。
- 官方 diff 只用于事后对照，不参与规则生成。

**文件**
- `internal/codescan/rules.go` 或现有规则文件
- `internal/codescan/*_test.go`
- `cases/gibbon-v30.0.00/finding.json`
- `cases/gibbon-v30.0.00/evidence.md`

**验收**
- `trident audit code` 在 v30.0.00 输出至少 1 条可定位 Finding。
- Finding 的 source 行、sink 行、文件 SHA-256 与快照一致。
- 对 v30.0.01 运行同一规则，Finding 应消失或降级（证明规则不是纯文件名匹配）。
- 不把 UEditor 等第三方目录计入该 Case。

**验证**
```
go test ./internal/codescan -count=1
python cases/gibbon-v30.0.00/check_detection.py
```

---

### P0-3 运行时证明（PoC）

**行为**
- 优先做 LFI→RCE：教师/管理员创建归档路径到 `uploads` 下，上传 ZIP polyglot，通过 `index.php?q=` 包含临时 ZIP。
- 同时保留 SQLi 作为第二 Finding：`gibbonDepartmentIDs[]` 注入，响应出现 SQL 错误或时间差。
- PoC 只访问本机 8081，不碰外部目标；凭据从 demo 数据读取，不写入日志。

**文件**
- `cases/gibbon-v30.0.00/poc_lfi.py`
- `cases/gibbon-v30.0.00/poc_sqli.py`
- `cases/gibbon-v30.0.00/poc_common.py`

**验收**
- v30.0.00：LFI PoC 输出唯一 marker（如 `TRIDENT_POC_<random>`），证明代码执行。
- SQLi PoC 输出数据库错误/时间差证据，且不破坏数据。
- 记录 HTTP 请求、响应片段、会话角色、时间戳、容器版本。

**验证**
```
python cases/gibbon-v30.0.00/poc_lfi.py --base http://127.0.0.1:8081
python cases/gibbon-v30.0.00/poc_sqli.py --base http://127.0.0.1:8081
```

---

### P0-4 补丁生成与隔离验证

**行为**
- 用 `trident patch propose --finding ...` 生成补丁；模型优先 `deepseek-flash`，记录模型、tokens、费用。
- 若模型补丁不可用，保留“确定性最小补丁”作为 fallback，并明确标记 `human_fallback`，不能冒充 AI 生成。
- 补丁只改必要文件；与官方 diff 对比，不额外重构。
- 在独立副本 `cases/gibbon-v30.0.00/patched/` 应用补丁，不修改原始快照。
- 验证：`php -l`、LFI PoC blocked、SQLi PoC blocked、登录/页面 smoke 通过。

**文件**
- `cases/gibbon-v30.0.00/patch.diff`
- `cases/gibbon-v30.0.00/patch_meta.json`
- `cases/gibbon-v30.0.00/verify_patch.py`
- `cases/gibbon-v30.0.00/verify.log`

**验收**
- 补丁前后 PoC 状态分别为 `vulnerable` / `blocked`。
- 正常登录、Tracking、Reports 页面不回归。
- 补丁不删除测试、不放宽权限、不修改无关文件。
- 验证失败时保留失败状态，不写“修复成功”。

**验证**
```
python cases/gibbon-v30.0.00/verify_patch.py --vuln http://127.0.0.1:8081 --patched http://127.0.0.1:8082
```

---

### P0-5 上游 PR-ready bundle

**行为**
- 生成维护者可直接消费的材料：`patch.diff`、`security-advisory.md`、`repro.md`、`test-plan.md`、`pr-body.md`。
- 明确标注这是对已公开 CVE 的独立复现与修复验证，不声称“首次发现”。
- 不自动提交 GitHub；等待用户确认目标仓库和提交身份。

**文件**
- `cases/gibbon-v30.0.00/upstream/README.md`
- `cases/gibbon-v30.0.00/upstream/security-advisory.md`
- `cases/gibbon-v30.0.00/upstream/pr-body.md`
- `cases/gibbon-v30.0.00/upstream/repro.md`

**验收**
- 上游 bundle 中的 commit、版本、文件、行号、PoC、补丁全部可复核。
- `pr-body.md` 说明影响、根因、修复、验证、兼容性、测试命令。

---

### P1-1 Case API 与 Web 工作台

**行为**
- 新增 Case 领域对象，把 Finding、PoC、Patch、Validation、Upstream 串成一条状态链。
- API：
  - `POST /api/cases`（从 finding 创建）
  - `GET /api/cases`
  - `GET /api/case?id=...`
  - `POST /api/case/propose`
  - `POST /api/case/verify`
  - `GET /api/case/export`
- UI：`#/cases` 列表，`#/case?id=...` 详情；Finding 详情增加“创建 Case / 生成补丁 / 验证 / 导出”。
- 不增加与 Case 无关的新页面。

**验收**
- 从 Finding 创建 Case，页面显示 `finding → poc → patch → validation → upstream` 五段状态。
- 生成补丁、验证、导出都可在 UI 触发；失败显示原因，不伪装成功。
- 前后端 API 一一对应，旧接口不残留。

**P1-1 实际落地结果（2026-11-17）**
- 后端：新增 `internal/casework`（目录发现、状态链、工作区 Case 保存、路径受限读取）与 `internal/webui/cases.go`；`--cases <dir>` 已接入 `trident web`。
- 真实 Gibbon Case 经 API 验证：`GET /api/cases` 返回 1 个 Case；`GET /api/case?id=gibbon-v30.0.00` 返回 `finding=verified, poc=verified, patch=ready, validation=verified, upstream=draft`，整体 `verified`。
- `propose` 只读 `patch.diff`（10,765 bytes，SHA-256 `BE5812B01E31…`）；`verify` 只读 `verify.log`（`FULL_CASE_VERIFIED`）；`export` 返回补丁正文与 6 个 upstream 文件。
- 前端：新增 `#/cases`、`#/case?id=`、导航与 Finding 抽屉“创建 Case”；阶段链、补丁/验证/导出按钮、空态与失败原因已接通。
- 无项目也可进入 Case 工作台；`--workspace` 存在时从 Finding 创建 Case，保存到 `<workspace>/cases/<id>.json`，不覆盖已有 Case。
- 验证证据：`go test ./...` 通过；`internal/casework` 与 `internal/webui` 新增 Case 测试；`go vet ./...`、`node --check`、`scripts/test-web.py` 通过；真实 UI 已验证列表、详情、`生成补丁`/`验证补丁`/`导出 JSON` 反馈、从 Finding 创建 Case 与缺补丁失败提示。
- 启动行为：`boot()` 先渲染目标路由，概览数据在后台加载；避免 `#/cases` 在 `/api/overview` 完成前短暂显示概览。目标页的顶栏快照/版本会在概览返回后补全。
- 边界：`propose` / `verify` 是读取已落盘产物，不在 Web 请求内重新生成/执行；真正的 Agent 写工具与显式批准在 P1-2。上游仍为 DRAFT，不自动提交。

---

### P1-2 Agent 修复工具

**行为**
- 在现有 Agent 工具注册表之外新增受控写工具：
  - `propose_patch`
  - `verify_patch`
  - `export_case`
- 写工具必须显式批准、限制在 Case 工作副本、记录审计事件。
- Agent 会话注入前序 Run 的结论摘要，支持“先分析、再补丁、再验证”的连续对话。
- 先在一轮 deepseek-flash Run 上验证，不追求复杂自主规划。

**验收**
- Agent Run 能从 Finding ID 生成补丁，调用验证，返回 Case 导出路径。
- 未批准时工具拒绝执行。
- 失败/超时/模型不可用时不产生“已修复”状态。

---

### P2-1 评估与叙事

**行为**
- 以 Gibbon Case 为真实正例；增加 10 个负例/边界样本，记录 Precision/Recall、误报、补丁成功率、token/时间。
- 与至少一个成熟工具做同靶对照（Semgrep 或 Trivy；若环境不允许，明确标注未完成）。
- 重写 README 首屏为一页：问题、目标、真实 Case、验证结果、上游包、复现命令。
- 保留 limitations，但不再用“不是 MVP”作为开头。

**验收**
- `docs/competition-eval.md` 有样本量、分母、失败项、复现命令。
- README 10 分钟内能看懂“做了什么、证明了什么、怎么复现”。

---

## 5. 执行顺序

1. P0-1 环境与登录。
2. P0-2 检测与 Finding。
3. P0-3 SQLi PoC（先易后难）。
4. P0-3 LFI→RCE PoC。
5. P0-4 补丁与双实例验证。
6. P0-5 上游 bundle。
7. P1-1 Web Case 工作台。
8. P1-2 Agent 修复工具与多轮上下文。
9. P2-1 评估与 README 重写。

## 6. 验证门禁

每个阶段结束必须重跑：

```
go build ./...
go vet ./...
go test ./... -count=1 -p 1
node --check internal/webui/assets/app.js
python scripts/test-web.py
python scripts/test-code-audit.py
python cases/gibbon-v30.0.00/check_env.py
python cases/gibbon-v30.0.00/verify_patch.py
```

补充规则：任何“已修复/已验证”结论必须有当前轮命令输出；不拿历史结果代替。

## 7. 风险与停止条件

| 风险 | 处理 |
|---|---|
| Docker 拉取/构建失败 | 用本地 `wordpress:php8.3-apache` + `mysql:8.0`；必要时改 portable PHP 8.3 |
| Gibbon 安装依赖缺失 | 在 Dockerfile 中安装 `pdo_mysql`、`gettext`、`intl`；失败则记录具体扩展并停在环境阶段 |
| 登录/会话依赖 HTTPS | 本机 HTTP 允许；若会话失败，检查 `absoluteURL` 与 cookie 配置 |
| PoC 需要教师/管理员权限 | 明确标注“认证后”影响，不夸大为未授权 RCE |
| AI 补丁不可用 | 保留 deterministic fallback，标注来源；不冒充 AI |
| 上游提交风险 | 只生成 bundle，不自动提交；等待用户确认 |

## 8. 成本控制

- 默认 `deepseek-flash`；单次 Agent/补丁 Run 记录 tokens 与调用数。
- 每个 Run 只做一件事：检测、补丁、验证分开记录。
- 超过预算或模型不可用，保留失败证据，不重复烧钱。

## 9. 完成定义

P0 完成必须同时满足：

1. v30.0.00 可启动、可登录、可访问两个漏洞页面。
2. TRIDENT 产出至少 1 条有源码证据的 Finding，且 v30.0.01 对照消失/降级。
3. 至少 1 个 PoC 在 v30.0.00 成功、在补丁副本失败。
4. 补丁通过语法检查与正常功能 smoke。
5. 上游 bundle 可被人独立复现。

P1 完成必须同时满足：

1. Web 能从 Finding 创建 Case，并展示完整状态链。
2. Agent 能在批准后生成补丁、验证、导出 Case。
3. 前后端接口一一对应，失败状态可见。

## 10. P0 实际收口结果（2026-11-17）

P0 已在真实 Gibbon v30.0.00 上跑通，结果如下：

| 阶段 | 状态 | 实际证据 |
|---|---|---|
| P0-1 环境 | 完成 | `check_env.py` 返回 `ENV_OK`；8081 登录、Tracking、Reports 均 200 |
| P0-2 Finding | 完成 | `findings/` 两份 JSON；含 file/line/source/sink/SHA-256 |
| P0-3 PoC | 完成 | `poc_lfi.py` 输出 `TRIDENT_LFI_OK`；`poc_sqli.py` 基线 4.93s、注入 23.48s，差 18.54s |
| P0-4 补丁/双实例 | 完成 | `patched/`、8082；五个改动文件 `php -l` 通过；`smoke_patch.py` 返回 `PATCH_VERIFIED` |
| P0-5 上游 bundle | 完成 | `upstream/` + `patch.diff`；`git apply --check` 通过；未提交 GitHub |

关键修正：此前 SQLi 的 `HY093 Invalid parameter number` 不是漏洞不存在，而是
测试客户端把数组编码成了字符串（`['0004']`），导致占位符名变成
`:department_MB['0004']`。`case_client.py` 改为 `doseq=True` 并用
`gibbonDepartmentIDs[]` 字段后，合法请求返回一行 fixture 数据；使用
`0005` + `0005 OR SLEEP(10)` 时 SQL 中注入的 `SLEEP(10)` 被执行，PoC 成立。

闭环结论：v30.0.00 上 LFI 与 SQLi 均可复现；同一套 PoC 在 8082 补丁实例上分别
被阻断/降级，同时正常归档创建与 Tracking 查询仍可用。`verify_patch.py` 输出
`FULL_CASE_VERIFIED`。

剩余边界：P1-1 Case 工作台已完成（见 P1-1 实际落地结果）；P1-2 Agent 修复工具与多轮上下文、P2-1 评估与 README 尚未开始；
上游 bundle 仍等待用户确认后才可提交。

