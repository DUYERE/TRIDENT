# 运行时 HTTP 验证契约

## 1. 定位与信任边界

`trident runtime http` 执行调用者提供的 HTTP 请求计划，用实际响应记录运行时证据。它不读取快照、数据库或模型，不自动从静态 finding 生成请求，也不把运行时结果回写为 `static_confirmed`。

- 目标由计划的 `base_url` 与显式 `--approve-target` 共同限定；两者 origin 必须完全一致。
- loopback 目标额外要求 `--allow-loopback`。
- 默认不跟随重定向、不并发、不使用代理、使用默认 TLS 校验。
- 请求计划中的 `form`、`json` 与 header 值不会写入报告；报告不输出 Cookie 或 Authorization 值。
- 这是“调用者声明的断言执行器”，不是通用扫描器、PoC 生成器或授权绕过证明。

## 2. 计划格式

```json
{
  "schema_version": 1,
  "name": "access-control-check",
  "base_url": "http://127.0.0.1:18080",
  "requests": [
    {
      "id": "login-page",
      "method": "GET",
      "path": "/manager/login",
      "expect": {"status": 200}
    },
    {
      "id": "manager-login",
      "method": "POST",
      "path": "/manager/dologin",
      "session": "manager",
      "form": {"managerid": "1001", "pwd": "***"},
      "expect": {"status": 302, "location_prefix": "/manager/flatform/main"}
    },
    {
      "id": "manager-auth",
      "method": "GET",
      "path": "/manager/getbyid?managerid=1001",
      "session": "manager",
      "expect": {"status": 200, "body_contains": "管理员"}
    }
  ]
}
```

- `schema_version` 固定为 `1`；未知字段、重复 `id`、非 `GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS` 方法、绝对路径、非相对 `path` 与缺失 `expect.status` 均拒绝。
- `session` 相同的请求共享一个内存 cookie 集合；不同 session 隔离。
- `expect` 支持 `status`、`location_prefix`、`body_contains`、`body_not_contains`、`header_contains`。
- 单计划最多 64 个请求、1 MiB；单响应最多读取 64 KiB。

## 3. 执行语义

1. 请求按计划顺序执行；每个请求使用独立超时，默认 10 秒、最大 60 秒。
2. 3xx 响应不会被跟随，`observed_status` 与 `location` 记录第一跳响应；`location` 只保留路径，丢弃查询串。
3. 响应体超过 64 KiB 时截断并标记 `body_truncated`；依赖被截断内容的“不包含”断言为 `inconclusive`，而不是失败或通过。
4. 每个断言记录 `name/expected/observed/passed`；请求状态为 `passed`、`failed`、`inconclusive` 或 `error`。
5. 报告状态：任一 `failed/error` → `failed`；否则任一 `inconclusive` → `inconclusive`；否则 `passed`。

## 4. 输出契约

- 身份：`schema_version=1`、`tool_version`、`analysis_kind=http_runtime_assertions_v1`、`plan_name`、`origin`。
- `status`、`runtime_status=observed`（至少执行过一个请求）、`results[]`、`coverage`、`limitations[]`。
- `results[]`：`id/method/path/session/status/observed_status/location/content_type/body_sha256/body_bytes/body_truncated/assertions/error`。
- `coverage`：请求数、passed/failed/inconclusive；`runtime_status=observed`。
- 固定限制：`runtime_observed_not_exploit_proof`、`redirects_not_followed`、`body_bounded_to_64KiB`、`credentials_caller_supplied_and_not_echoed`、`no_proxy_or_concurrency`、`target_allowlist_exact_origin`。
- 失败或未批准目标返回非零；已执行请求的报告仍输出到 stdout。

## 5. 验收

- `go test ./internal/httpverify`：计划校验、cookie session、302 不跟随、失败断言、截断体 inconclusive、origin/loopback 授权。
- `python scripts/test-runtime.py`：本地 loopback HTTP 服务，4 条请求全部通过，验证 session 复用、重定向不跟随、凭据不落报告、错误断言失败、未批准 origin 与未授权 loopback 拒绝。
- 真实环境：Tomcat 9.0.106 + MySQL 8.0.46（`D:\Code\Java\market` 补丁部署）执行 15 条请求，覆盖登录页、未登录 302、管理员/员工登录后 200、跨会话 302 与错误密码不建立会话，结果 15/15 `passed`、`runtime_status=observed`。该结果只证明这些请求的响应，不证明其他漏洞或生产安全。
