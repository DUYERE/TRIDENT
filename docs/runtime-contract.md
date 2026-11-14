# 运行时 HTTP 验证契约

## 1. 定位与信任边界

`trident runtime http` 执行调用者提供的 HTTP 请求计划，用实际响应记录运行时证据。它不读取快照、数据库或模型，不自动从静态 finding 生成请求，也不把运行时结果回写为 `static_confirmed`。

- 目标由计划的 `base_url` 与显式 `--approve-target` 共同限定；两者 origin 必须完全一致。
- loopback 目标额外要求 `--allow-loopback`。
- 默认不跟随重定向、不并发、不使用代理、使用默认 TLS 校验。
- 请求计划中的 `form`、`json` 与 header 值不会写入报告；报告不输出 Cookie 或 Authorization 值，
  也不输出解析后的凭据或 CSRF token。
- 这是“调用者声明的断言执行器”，不是通用扫描器、PoC 生成器或授权绕过证明。

## 2. 计划格式

```json
{
  "schema_version": 1,
  "name": "access-control-check",
  "base_url": "http://127.0.0.1:18080",
  "roles": [
    {
      "id": "admin",
      "session": "role-admin",
      "csrf": {"selector": "meta[name=_csrf]", "field": "_csrf"},
      "login": [
        {"id": "page", "method": "GET", "path": "/login", "expect": {"status": 200}},
        {"id": "submit", "method": "POST", "path": "/dologin",
         "form": {"user": "admin", "pass": "${ENV:TRIDENT_RUNTIME_PASS}"},
         "expect": {"status": 302, "location_prefix": "/main"}}
      ]
    }
  ],
  "requests": [
    {
      "id": "admin-page",
      "method": "GET",
      "path": "/admin",
      "expect": {"status": 302}
    }
  ],
  "matrix": [
    {"role": "admin", "request": "admin-page",
     "expect": {"status": 200, "body_contains": "管理员"}}
  ]
}
```

- `schema_version` 固定为 `1`；未知字段、重复 `id`、非 `GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS` 方法、绝对路径、非相对 `path` 与缺失 `expect.status` 均拒绝。
- `session` 相同的请求共享一个内存 cookie 集合；不同 session 隔离；不同角色必须使用不同 `session`。
- `expect` 支持 `status`、`location_prefix`、`body_contains`、`body_not_contains`、`header_contains`。
- `roles` 可选。每个角色声明 `id`、可选 `session`（缺省等于 `id`）、`login` 步骤与可选 `csrf`。
  `login` 最多 16 步；凭据值可使用 `${ENV:NAME}` 占位符，计划文件不保存明文。
- `csrf` 声明有界 token 来源：`selector` 仅接受 `meta[name=...]` 或 `input[name=...]`，
  `field`/`header` 至少声明一个；token 提取后注入这些位置。
- `matrix` 可选。每个单元引用已声明的角色与请求，同一 `(role, request)` 不得重复；期望沿用 `expect` 语义。
- 单计划最多 64 次实际请求（顶层 `requests` + 所有 `login` 步骤 + `matrix` 单元）、1 MiB；单响应最多读取 64 KiB。


## 3. 执行语义

1. 顶层请求按计划顺序执行；每个请求使用独立超时，默认 10 秒、最大 60 秒。
2. 随后按 `roles` 声明顺序执行每个角色的 `login` 步骤：先解析 `${ENV:NAME}` 占位符（未设置则
   该步骤 `error=credential_placeholder_unresolved` 并停止该角色），再按需注入 CSRF token。
3. CSRF token 只从最近一次成功登录响应体中的显式 `meta`/`input` 选择器提取，长度不超过 512 字节；
   非 `GET/HEAD/OPTIONS` 请求注入到声明的表单字段或请求头。未能提取时该步骤
   `inconclusive`、`error=csrf_token_not_found`，该角色标记为登录未完成，不猜测 token。
4. `matrix` 单元按声明顺序执行：使用所属角色会话与单元期望；角色登录未完成时单元
   `inconclusive`、`error=role_login_incomplete`。
5. 3xx 响应不会被跟随，`observed_status` 与 `location` 记录第一跳响应；`location` 只保留路径，丢弃查询串。
6. 响应体超过 64 KiB 时截断并标记 `body_truncated`；依赖被截断内容的“不包含”断言为 `inconclusive`，而不是失败或通过。
7. 每个断言记录 `name/expected/observed/passed`；请求状态为 `passed`、`failed`、`inconclusive` 或 `error`。
8. 报告状态：任一 `failed/error` → `failed`；否则任一 `inconclusive` → `inconclusive`；否则 `passed`。

## 4. 输出契约

- 身份：`schema_version=1`、`tool_version=0.2.0-p1.1+r1-http-runtime-v2`、`analysis_kind=http_runtime_assertions_v1`、`plan_name`、`origin`。
- `status`、`runtime_status=observed`（至少执行过一个请求）、`results[]`、`coverage`、`limitations[]`。
- `results[]`：`id/method/path/session/status/observed_status/location/content_type/body_sha256/body_bytes/body_truncated/assertions/role/matrix/csrf/error`。
  角色登录步骤 `id=role:<role>:<step>`，矩阵单元 `id=matrix:<role>:<request>`；
  `csrf` 取值 `token_injected`、`token_observed`、`token_available`、`token_missing`。
- `coverage`：总请求数、passed/failed/inconclusive；声明角色时附带 `roles{<id>:{requests,passed,failed,inconclusive,login_status}}`，
  `login_status` 为 `complete|incomplete|not_declared`。
- 固定限制：`runtime_observed_not_exploit_proof`、`redirects_not_followed`、`body_bounded_to_64KiB`、
  `credentials_caller_supplied_and_not_echoed`、`roles_caller_defined`、`csrf_token_extraction_bounded`、
  `no_proxy_or_concurrency`、`target_allowlist_exact_origin`。
- 失败或未批准目标返回非零；已执行请求的报告仍输出到 stdout。

## 5. 验收

- `go test ./internal/httpverify`：计划校验（含 roles/matrix 结构、CSRF 选择器、角色会话隔离）、cookie session、
  302 不跟随、失败断言、截断体 inconclusive、origin/loopback 授权、角色矩阵与 CSRF 注入、缺失 token inconclusive。
- `python scripts/test-runtime.py`：本地 loopback HTTP 服务，4 条基础请求全部通过，验证 session 复用、重定向不跟随、
  凭据不落报告、错误断言失败、未批准 origin 与未授权 loopback 拒绝；角色矩阵 2 个角色 × 2 登录 + 2 请求 + 4 单元
  共 10 次执行全部 `passed`、每角色 `4/4`、`login_status=complete`、`csrf=token_injected`、凭据与 token 不出现在 stdout；
  缺失 token → `inconclusive` + `csrf_token_not_found`/`role_login_incomplete`；未设置的 `${ENV:NAME}` →
  `credential_placeholder_unresolved`；共享 session 的角色计划被拒绝。
- 真实环境：此前 Tomcat 9.0.106 + MySQL 8.0.46（`D:\Code\Java\market` 补丁部署）15 条请求计划为
  15/15 `passed`、`runtime_status=observed`；该计划未纳入本仓库，本次变更未重跑。该结果只证明这些请求的响应，
  不证明其他漏洞或生产安全。
