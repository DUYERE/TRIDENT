# PHP 语言级入口证据

## 目标

把 PHP 入口证据从 ThinkPHP 专用文件名/路由扩展为语言级、框架无关的 Web 脚本候选：

`PHP 文件 -> 请求超全局访问（$_GET/$_POST/$_REQUEST/$_FILES/$_SERVER/php://input） -> request_script 入口候选`

该候选仍是证据，不是已部署 URL，也不是漏洞结论。ThinkPHP 动态路由解析保持不变。

## 范围

新增/修改：
- `internal/entrypoint/entrypoint.go`：在既有文件名候选之外，增加有界 PHP 请求脚本候选。
- `internal/entrypoint/entrypoint_test.go`：普通 PHP 脚本、排除目录、去重、无请求访问、上限测试。
- `internal/entry/entry_test.go`：Provider 保留 `request_script` 类型与置信度。
- `internal/entry/providers.go`：按 Entry.Kind 设置 confidence/reason。
- `docs/multi-language-parity-gap.md` 或 `docs/web-console-contract.md`：记录 PHP 语言级入口边界。
- `README.md`：一句话说明 PHP 不依赖 ThinkPHP 的入口候选。

不做：
- 不实现 PHP AST、完整控制流、框架路由部署语义、PHP authz。
- 不把 `request_script` 当 URL、路由或漏洞。
- 不读取 `vendor/tests/examples/src/app/lib/config/routes/resources` 等框架内部目录。
- 不改变既有 ThinkPHP 动态路由与 convention candidate。

## 判定规则

1. 只处理 `.php/.phtml/.php5`。
2. 路径必须通过既有 excludedSegments，并额外排除框架内部目录：
   `src/app/lib/libs/config/routes/resources/storage/bootstrap/database/migrations/extend`。
3. 文件大小 ≤ `MaxCandidateBytes`（1 MiB）。
4. 内容出现请求超全局或 `php://input` 时生成一条候选；记录第一次出现的行。
5. 已通过文件名规则识别的路径不再生成第二条。
6. 总候选数受 `MaxEntries` 限制并置 `partial=true`、`entrypoint_inventory_truncated`。
7. 候选字段：
   - `Language=php`
   - `Framework=PHP`（由现有 `inferFramework` 推断，可为 Laravel/Symfony/CodeIgniter）
   - `Kind=request_script`
   - `Reason=php_request_superglobal_observed`
   - `Line=首次请求访问行`
   - `SHA256=manifest sha`
8. 限制追加：
   - `php_request_script_candidate_not_route`
   - `php_request_script_not_deployed`
   - `php_request_script_content_bounded_1mib`

## 验收 ID

| ID | 行为 | 验证 |
|---|---|---|
| P1 | 普通 PHP 脚本出现 `$_GET` 生成 request_script | `entrypoint_test.go` 新 fixture |
| P2 | `modules/Reports/a.php` 的 `$_POST` 生成候选 | 同上，框架为 PHP |
| P3 | `vendor/tests/src/app` 下请求脚本被排除 | 同上，断言不存在 |
| P4 | 已识别的 `public/index.php` 不重复 | 同上，按路径计数 |
| P5 | 没有请求访问的 PHP 文件不生成候选 | 同上 |
| P6 | 超过 `MaxEntries` 置 partial | 构造小上限 fixture 或直接调用辅助函数 |
| P7 | `entry` Provider 保留 `request_script` 与 `request_script_heuristic` | `internal/entry/entry_test.go` |
| P8 | 全量 build/test/vet | 仓库原生命令 |

## 验证命令

```powershell
D:\DevTools\Go\bin\gofmt.exe -w internal\entrypoint internal\entry
D:\DevTools\Go\bin\go.exe test ./internal/entrypoint ./internal/entry -count=1
D:\DevTools\Go\bin\go.exe test ./... -count=1
D:\DevTools\Go\bin\go.exe vet ./...
node --check internal\webui\assets\app.js
```

## 真实目标

- 优先用 Gibbon `cases/gibbon-v30.0.00/target` 导入临时快照，跑 `audit endpoints`，确认根目录与 `modules/` 下的普通 PHP 请求脚本出现在 `application_entries`，不再只依赖 ThinkPHP 文件名。
- ThinkPHP `www.test.com` 现有快照回归：既有 `public/index.php`、`public/router.php` 与 `urlconfig` 动态路由结果不减少。

## 验收结果（2026-11-18）

- 全量 `go test ./... -count=1`：通过。
- 全量 `go vet ./...`：exit 0。
- `node --check internal/webui/assets/app.js`：exit 0。
- 真实 Gibbon 五文件快照 `/api/endpoints`：
  - `entry_total=3`，`entry_partial=false`。
  - `modules/Reports/archive_manage_addProcess.php:28` 与
    `modules/Reports/archive_manage_uploadPreview.php:42` 为 `request_script`。
  - `entry_coverage` 为 `mixed_entry_heuristics`，reason `known_entry_filename_and_request_superglobal`。
- ThinkPHP `www.test.com` 快照回归：
  - `entry_total=3`，保留 `public/index.php`、`public/router.php`。
  - 新增 `public/ipapi.php:263` 为 `request_script`。
  - `thinkphp/library/think/*` 与 `public/static/.../ueditor` 未被误报。
- Web UI 已显示“请求脚本候选”；硬刷新后服务端 `app.js` 与页面同步。
- `export_case` 已修复返回哈希/字节数与磁盘文件不一致：Run 142 返回 `export_sha256=14fe5ea6...`、`export_bytes=21672`，与导出文件实际 SHA-256/长度一致；`patch_sha256=34792ae5...` 仍与真实补丁一致。
- 最新二进制 `C:\Users\zx\AppData\Local\Temp\trident-p2b.exe` 已启动 8791/8793；8794/8795 临时实例已停止。

