# PHP 请求脚本端点级鉴权证据计划

## 目标

在不引入完整 PHP AST、跨文件数据流或运行时探测的前提下，为已有 `request_script` 入口增加一个有界、可复核的鉴权结论：

- 只分析 PHP 文件内、首次请求访问行之前出现的识别控制。
- 结论必须带文件、请求访问行、控制证据行和 reason。
- 结论写回统一入口证据的 `authz` 字段，前端“HTTP 入口”与“权限清单”可见。
- 不把“未识别控制”伪装成“可未授权访问”；继续保留 `unprotected` 不等于漏洞结论的限制。

## 验收

| ID | Required behavior | Exact API, default, or boundary | Necessary files and consumers | Observable assertion | Repository-native validation |
|---|---|---|---|---|---|
| A1 | PHP `request_script` 生成脚本级鉴权候选 | 仅 `.php`，复用 entrypoint 的请求超全局行检测；单文件 ≤2 MiB，扫描文件 ≤4000 | `internal/authz/language.go`、`internal/entrypoint/entrypoint.go` | `Report.LanguageAdapters` 含 `scope=request_script`、`line=请求访问行` | `go test ./internal/authz -count=1` |
| A2 | 控制必须早于请求访问行才算保护 | 行号严格小于请求访问行；同文件后置检查不得算 protected | `internal/authz/language.go` | `late-check.php` 返回 `unknown`，reason=`php_script_guard_after_request_access` | `go test ./internal/authz -count=1` |
| A3 | 支持常见 PHP 入口控制与显式公开标记 | session 登录检查、`checkLogin/isLoggedIn/Auth::check`、auth 文件 require/include、middleware、角色/权限函数；显式 `allowAnonymous/noAuth` | `internal/authz/language.go` | protected/public/unprotected/unknown 四类 fixture 断言 | `go test ./internal/authz -count=1` |
| A4 | 统一入口证据携带 PHP 鉴权 | 仅对 `kind=request_script` 附加；按 `file` 与 `line` 匹配；`application_entry` 必须保持 nil | `internal/entry/providers.go`、`internal/entry/entry_test.go`、`internal/webui/application_entries_test.go` | request_script entry `authz.decision` 与 adapter 一致；application_entry 的 `authz=nil` | `go test ./internal/entry ./internal/webui -count=1` |
| A5 | Web API/UI 可见 | `/api/endpoints` 统一条目返回 `authz`；权限清单语言适配卡显示 `scope=request_script` | `internal/webui/application_entries_test.go`、`internal/webui/assets/app.js` | API 断言 + 页面文本含“请求脚本”与结论 | `go test ./internal/webui -count=1`、`node --check internal/webui/assets/app.js` |
| A6 | 不破坏既有 Java / ThinkPHP 证据 | Java endpoints、ThinkPHP filename/request_script 条目数量不变 | 全仓库 | 既有测试通过；真实 8791/8793 复核 | `go test ./... -count=1`、`go vet ./...` |
| A7 | 边界可审计 | 报告 limitations 明确词法、文件本地、非运行时、unprotected 不证明可达 | `internal/authz/authz.go` | JSON 含 `php_script_authz_file_local` 等限制 | `go test ./internal/authz -count=1` |

## 实现边界

- 不执行 PHP，不加载框架，不做跨文件包含解析。
- 控制识别是行级词法；注释/字符串可能误命中，报告必须注明。
- `protected` 只表示在请求访问行之前识别到控制，不表示控制覆盖所有分支。
- `unprotected` 只表示未识别到请求访问行之前的控制，不表示未授权可达。
- 不将 PHP 脚本结论加入 Java `Endpoints` 计数；它们进入 `LanguageAdapters` 与统一入口 `authz`。

## 验证命令

```powershell
D:\DevTools\Go\bin\gofmt.exe -w internal\authz internal\entry internal\entrypoint internal\webui
D:\DevTools\Go\bin\go.exe test ./internal/authz ./internal/entry ./internal/webui -count=1
D:\DevTools\Go\bin\go.exe test ./... -count=1
D:\DevTools\Go\bin\go.exe vet ./...
node --check internal\webui\assets\app.js
```

真实复核：8793 `/api/endpoints` 的 Gibbon 两个 `request_script` 应带 `authz`；8791 的 `public/ipapi.php:263` 应带 `authz`，页面显示结论。

## 验收结果（2026-11-18）

| ID | 状态 | 证据 |
|---|---|---|
| A1 | passed | `TestPHPScriptAuthzDecisions` 断言 9 个脚本 adapter 的 `scope=request_script`、请求行与控制行 |
| A2 | passed | `public/late.php` → `unknown`、`php_script_guard_after_request_access` |
| A3 | passed | `protected.php`/`public.php`/`open.php`/`require-auth.php`/`role.php`/`permission.php`/`conflict.php`/`same-line.php` 全覆盖 |
| A4 | passed | `internal/webui/application_entries_test.go` 断言 `application_entry.authz=nil`；真实 `public/router.php` 不再显示“无控制” |
| A5 | passed | `/api/endpoints.entries[].authz` 与 `/api/authz.language_adapters` 真实返回；8791 `#/endpoints` 显示“请求脚本候选/无控制”，`#/authz` 显示脚本适配器 |
| A6 | passed | `go test ./... -count=1`、`go vet ./...`、`node --check internal/webui/assets/app.js` 全部 exit 0；8791/8793 p2f 已重启 |
| A7 | passed | `internal/authz` 断言 `php_script_authz_file_local` 与 `php_script_unprotected_inconclusive` |

补充结果：

- 真实 Gibbon：`archive_manage_uploadPreview.php:42` → `protected` / `permission_check@33`；`archive_manage_addProcess.php:28` → `unknown` / `php_script_guard_after_request_access` / `permission_check@32`；`index.php` 为 `application_entry`，`authz=nil`。
- 真实 ThinkPHP：`public/ipapi.php:263` → `unprotected`；`public/index.php:23`、`public/router.php:16` 为 `application_entry`，`authz=nil`。
- 最终二进制：`C:\Users\zx\AppData\Local\Temp\trident-p2f.exe`，39,970,304 bytes，2026-11-18 11:49:59；8791 PID `23692`、8793 PID `28924`，`/healthz` 200。

