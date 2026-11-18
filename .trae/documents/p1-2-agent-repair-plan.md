# P1-2 Agent 修复工具与多轮上下文

## 目标

在不改变 P1-1 只读 Case 工作台语义的前提下，让 Agent 在一次显式批准的 Run 中完成：

`Case/Finding -> propose_patch -> verify_patch -> export_case`

并且满足：

- 未批准写工具时拒绝执行，不靠模型自觉。
- 写产物只落在 `<workspace>/repairs/<case>/...`，不修改 Case 原目录、不修改 pinned snapshot。
- 补丁生成失败、验证失败、超时、模型不可用、未批准都不产生“已修复 / verified”状态。
- 写入与验证动作有独立审计事件。
- 新 Run 注入同一 Conversation 前序 Run 的结论摘要，支持“先分析、再修复、再验证”的连续对话。

## 架构

### 1. Agent 工具接口

把 `agent.Execute` 的 registry 参数从具体 `*tools.Registry` 扩展为窄接口：

```go
type ToolRegistry interface {
    SnapshotHash() string
    Definitions() []model.Tool
    Execute(context.Context, string, json.RawMessage) (json.RawMessage, error)
}
```

现有 `tools.Registry` 继续满足该接口，不改变只读工具行为；新增 `internal/caseagent` 实现该接口，内部委托只读 registry，并追加三个受控写工具。

### 2. 写工具契约

- `propose_patch`：`{"case_id":"...","goal":"可选"}`。从 Case 的 Finding 源码证据取 `path + lines` 窗口（最多 4 个，每个窗口由证据行向两侧扩展 40 行，受 200 行上限约束），调用 `r3.Propose`；补丁写入工作副本。没有源文件、模型失败、上下文不足都返回结构化失败，不写伪补丁。
- `propose_patch` 的模型请求显式关闭 provider thinking（`reasoning_effort=none`）。`deepseek-flash` / `deepseek-v4-pro` 默认开启 thinking，会把输出预算全部耗在 `reasoning_content`，最终 `content` 为空、`stop=length`；关闭 thinking 后同一个真实 Case 已生成 1,790 bytes 补丁。
- `r3` diff 解析从 hunk body 推导 old/new 行数；header 计数不再作为硬错误，精确 context/removal 匹配仍是安全边界。
- `verify_patch`：`{"case_id":"...","patch_path":"可选"}`。只接受 Case 工作副本内的补丁；调用 `r3.Verify`，在独立 workspace 副本中执行固定 profile；返回 `validation_passed` / `validation_failed` / `timeout` / `setup_failed`，不把“语法通过”写成“漏洞已修复”。
- `export_case`：`{"case_id":"..."}`。读取 Case、工作副本补丁与 upstream 文件，导出 JSON；写新文件，不覆盖已有 Case。

三个工具都要求服务端 `ApproveRepair=true`；模型参数中没有 `approve` 字段，模型不能自行授权。

### 3. 工作副本与审计

- 工作根：`<workspace>/repairs`；`workspace` 为空时禁用修复工具。
- 每个 Case：`<workspace>/repairs/<case_id>/`。
- 补丁：`proposals/<nonce>/patch.diff`，新文件 `O_EXCL`。
- 验证：`verify/<nonce>/`，由 `r3.Verify` 创建；`php-lint` 依赖宿主 `php` 在 PATH 中。隔离 8793 实例以 phpstudy PHP 7.3 运行 `php -l`，报告中的 `validation_passed` 只代表固定语法检查通过，不代表 PHP 8 运行时或漏洞已修复。
- `POST /api/agent/chat` 为修复工具单独创建 180 秒超时的模型客户端，避免 chat 的 60 秒短超时截断补丁生成；主 Agent 工具循环仍使用 60 秒客户端。
- 导出：`exports/case-<nonce>.json`。
- 审计：`<workspace>/repairs/audit.jsonl`，记录时间、tool、case、approval、状态、相对产物路径、patch sha256；不含密钥、快照内容或完整源码。

### 4. 显式批准

- `POST /api/agent/chat` 新增 `approve_repair` 布尔字段，默认 false。
- 前端 Agent 输入区新增“批准写入 Case 工作副本并执行隔离验证”复选框。
- 只有 `approve_repair=true` 且 workspace 可用、模型配置可用时，才向 Agent 暴露三个写工具；否则 Agent 只拿到原只读工具。
- 直接调用 `caseagent.Registry` 且未批准时，三个工具返回 `approval_required`，不产生文件。

### 5. 多轮上下文

- `agent.Config` 新增可选 `prior_context`（≤8 KiB，单行/纯文本），由 Web 从同一 Conversation 的前序 Run 提取最终 `summary` + hypotheses 标题 + state，截断后写入。
- 初始 checkpoint 消息为：system、goal、可选 prior-context user 消息；恢复时沿用 checkpoint，不重复注入。
- system prompt 根据 `repair_enabled` 选择只读版或修复版；旧 Run 的 `repair_enabled=false` 仍匹配旧 prompt，不破坏已有 checkpoint。

### 6. 前端 Case 联动

- Case 详情增加“让 Agent 修复”按钮：把 `case_id`、标题、五段状态与要求写入待发送目标，跳到 Agent 页；Agent 页仍需勾选外发与修复批准。
- Agent 页面显示写工具批准说明；未勾选时后端不暴露写工具。

## 文件清单

新增：
- `internal/caseagent/caseagent.go`
- `internal/caseagent/source_windows.go`
- `internal/caseagent/caseagent_test.go`
- `internal/caseagent/source_windows_test.go`
- `internal/agent/context.go`
- `internal/agent/context_test.go`

修改：
- `internal/agent/loop.go`：`ToolRegistry` 接口、system prompt 选择、prior context、初始消息。
- `internal/agent/config.go`：`PriorContext`、`RepairEnabled` 校验。
- `internal/model/model.go`：`Request.ReasoningEffort`。
- `internal/model/openai/client.go`：把 `reasoning_effort` 传给 provider，拒绝未知值。
- `internal/r3/propose.go`：`ProposeWindow`、`Windows`、证据行窗口、`reasoning_effort=none`、结构化 stop/bytes 错误。
- `internal/r3/diff.go`：从 hunk body 归一化 old/new 计数。
- `internal/tools/evidence.go`：写工具结果不进入源码证据账本。
- `internal/webui/agent_chat.go`：`approve_repair`、构建 prior context、注入 caseagent registry、180 秒修复客户端。
- `internal/webui/assets/app.js`：批准复选框、Case 页入口、API 文档。
- `internal/webui/webui.go`：若需要暴露 workspace 路径，增加只读方法。
- `internal/casework/casework.go`：`SourceDir` 只读定位（如需要）。

## 验收 ID

| ID | 行为 | 验证 |
|---|---|---|
| A1 | 未批准时三个写工具拒绝 | `caseagent_test.go`：approval=false 返回 `approval_required`，无文件 |
| A2 | 批准后可生成并落盘补丁 | 假模型 + 临时 snapshot；`propose_patch` 返回 `patch_proposed`，patch 存在且 hash 匹配 |
| A3 | 验证只落在隔离副本 | `verify_patch` 返回 `validation_passed/failed`，原 snapshot 哈希不变，原 Case 目录不变 |
| A4 | 导出可读且不覆盖 | `export_case` 输出 JSON 含 case/patch/upstream，二次导出不覆盖；返回的 `export_sha256`/`export_bytes` 必须与磁盘文件实际 SHA-256/长度一致 |
| A5 | 审计事件 | `audit.jsonl` 含 tool/case/approval/status，无密钥 |
| A6 | 多轮上下文 | 新 Run checkpoint 含 prior context；旧 checkpoint 不失效 |
| A7 | Agent 注册表兼容 | `go test ./internal/agent ./internal/tools ./internal/caseagent ./internal/webui` |
| A8 | 真实 deepseek-flash Run | 隔离控制台 + 真实模型 + Case；Run 产生工具调用/结构化失败，不伪造 verified |
| A9 | 真实 propose/verify/export 产物 | 真实 Gibbon Case 产生 `proposals/*/patch.diff`、`verify/*/report.json`、`exports/*.json`；README 与审计一致 |
| A10 | thinking 关闭与证据窗口回归 | `go test ./internal/r3 ./internal/caseagent` 覆盖 `ReasoningEffort=none`、bounded window、hunk count 归一化 |

## 验证命令

```powershell
D:\DevTools\Go\bin\gofmt.exe -w internal\caseagent internal\agent internal\tools internal\webui
D:\DevTools\Go\bin\go.exe test ./internal/caseagent ./internal/agent ./internal/tools ./internal/webui -count=1
D:\DevTools\Go\bin\go.exe vet ./...
node --check internal\webui\assets\app.js
python scripts\test-web.py
```

## 真实 Run 证据（2026-11-17）

隔离实例 `127.0.0.1:8793`，workspace `C:\Users\zx\AppData\Local\Temp\trident-p2-ws`，snapshot `828687aa2626f5b56efff428634b4430c5af6d4c0d4d8f05add9b822075502d3`（Gibbon v30.0.00 的 5 文件 LFI 证据子集）。

- Run 134（`deepseek-flash`，`approve_repair=true`）：`propose_patch` -> `patch_proposed`。
  - patch：`repairs\gibbon-v30.0.00\proposals\20261117T145645.119193700Z-7c22aea470b64e0e\patch.diff`
  - 1,790 bytes；`src/View/Page.php`；+23/-7；SHA-256 `34792ae5...60e733`。
  - Run 最终 envelope 失败，但工具产物已落盘；不把 Run 状态当作补丁成功。
- Run 135：`verify_patch` -> `validation_error`（当时 PATH 中无 `php`，报告 `php executable not found`）；`export_case` -> `case_exported`。
  - export：`repairs\gibbon-v30.0.00\exports\case-20261117T145750.739118100Z-da81f85d4b2e14e0.json`，21,672 bytes，patch_source=`case_work_copy`。
- Run 136（给 8793 的 PATH 加入 `D:\DevTools\phpstudy_pro\Extensions\php\php7.3.4nts`）：`verify_patch` -> `validation_passed`。
  - report：`repairs\gibbon-v30.0.00\verify\20261117T150249.538504500Z-ec4b0ade8e966cee\report.json`
  - 5 个 PHP 文件 `php -l` 全部 exit 0；`original_snapshot_intact=true`；`runtime_status=isolated_validation_only`；quality `B/80`。
  - 限制：PHP 7.3 仅做语法 lint；不是 PHP 8 运行时、不是漏洞修复证明；`php.ini` 自身在 stderr 报告 line 1953 语法错误，但 `php -l` 退出码为 0。
- Run 130/131/132/133 的失败链用于定位：`stop=length, bytes=0` -> provider thinking 消耗输出预算；关闭 thinking 后 Run 134 首次真实产出补丁。`stop=length` 在关闭 thinking 前于 4096/8192/16384 均可复现；`deepseek-v4-pro` 同样复现。

## 真实导出哈希复核（2026-11-18）

- Run 141（8793，`export_case`）：返回 `export_sha256=3a109ecc357539ae6b1b19b8c849134b4a778144bbf213e13bb4d84ad7ac86b8`、`export_bytes=21671`、`patch_sha256=34792ae5...`。
  - 磁盘文件 `exports/case-20261118T024433.458855900Z-ba270a7266d4791a.json` 实际为 21,672 bytes，SHA-256 `0d770377b13cf8cc5614dfbf4cd76b0d70de40feef2f1f9e965fd8ab219e0c7a`，与返回不一致。
  - 根因：写文件时追加 `'\n'`，但 `export_sha256`/`export_bytes` 按未追加的 `encoded` 计算。
- 修复：`caseagent.go` 先构造实际写入的 `fileBytes = encoded + '\n'`，上限、写入、`export_sha256`、`export_bytes` 全部使用同一字节切片；`caseagent_test.go` 增加磁盘文件 SHA/长度断言。
- Run 142（新二进制，`export_case`）：返回 `export_bytes=21672`、`export_sha256=14fe5ea6d50dd4e07b0a127faa6e9768603603211114d660fd6be5a586ecfebc`、`patch_sha256=34792ae5...`.
  - 磁盘文件 `exports/case-20261118T025208.365715000Z-b86cb88b96c0c52a.json` 实际 21,672 bytes，SHA-256 同 `14fe5ea6...`；返回与磁盘一致。
- `audit.jsonl` 末条为 Run 142 的 `export_case`，`patch_sha256` 仍为真实补丁 `34792ae5...`，与 `export_sha256` 语义分离。

## 边界

- 不在 Web 请求内执行不受控 shell；`verify_patch` 只经 R3 的隔离副本与固定 profile。
- 不在本阶段自动提交上游 PR；`export_case` 只产出本地 bundle。
- 不把 `validation_passed` 当作漏洞修复证明；报告保留 limitations 与 runtime_status。
- 真实 Run 若模型不可用/超时，记录失败原因并停止，不降级为“本地假装成功”。

