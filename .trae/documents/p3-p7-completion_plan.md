# P2 剩余项 + P3–P7 一次性落地计划

## 目标

把当前报告中仍未落地的能力一次性补成“有界但可验证”的实现，保持只读快照、无网络、无代码执行、失败关闭。

## 边界

- 不重写 `codescan` 的词法 IR，不引入编译器级类型系统。
- 所有跨文件、跨语言能力均显式输出 `same_file`、`same_project`、`cross_file_unresolved`、`external_or_unresolved` 等状态，不把猜测当作已解析。
- 数据库动态路由只有在快照内存在可解析的 SQLite/SQL/JSON 数据时才展开；否则保留 `dynamic_unresolved`。
- 所有新增解析器有文件数、字节数、条目数上限。

## 路线

| ID | 需求 | 精确边界 | 文件/消费者 | 可观察断言 | 验证 |
|---|---|---|---|---|---|
| C1 | 变量/字符串常量索引 + 跨文件调用解析 | `Symbol` 增加 `variable`/`constant`；`Call` 增加 `resolved_file`/`resolved_symbol`；跨文件按唯一简单名或限定名解析；歧义保持 unresolved | `internal/codescan/model.go`、`symbols.go`、`analyze.go` | 符号 kind 含 variable/constant；唯一跨文件调用为 `same_project`；同名冲突为 `ambiguous_symbol` | `go test ./internal/codescan` |
| C2 | ThinkPHP 动态路由展开 + 默认路由候选 | 解析快照内 `urlconfig` 的 SQLite/JSON/SQL 数据；仅展开明确 aliases→url 行；无数据时保留 dynamic；默认路由生成 `convention_candidate` | `internal/codescan`、`internal/entry/providers.go` | 有 fixture 时 `path_status=declared` 且来源为 database；无数据时仍 dynamic_unresolved；默认控制器候选可见 | `go test ./internal/codescan ./internal/entry` |
| C3 | P3 鉴权适配器 | PHP ThinkPHP/Laravel、.NET ASP.NET Core、Python Django/Flask/FastAPI、JS Express/Koa/Nest、Go Gin/Echo/net/http；输出 protected/unprotected/unknown，未知不默认 public | `internal/authz`、`internal/webui` | 每语言三态 fixture；未识别控制为 unknown | `go test ./internal/authz ./internal/webui` |
| C4 | P4 多生态 SCA/SBOM | Composer、NuGet、pip、npm、Go 声明与锁文件；Dependency 增加 language/ecosystem/package/purl；SBOM 输出 ecosystem purl | `internal/sca`、`internal/sbom`、`internal/webui` | 每生态离线 fixture 有组件；无锁文件 `version_unresolved`；SBOM 有 purl | `go test ./internal/sca ./internal/sbom` |
| C5 | P5 多语言可达性 | 从快照提取 import/require/use，按依赖包前缀匹配；输出 reachable/unreachable/unknown 三态；反射/动态调用 unknown | `internal/reach`、`internal/webui` | 每语言 fixture 至少一个 reachable 和一个 unknown | `go test ./internal/reach ./internal/webui` |
| C6 | P6 补丁验证 profile | PHP `php -l`、Python `compileall/pytest`、Node `node --check/npm test`、Go `go test ./...`、.NET `dotnet build`；先探测工具链，缺失为 `toolchain_unavailable` | `internal/r3`、`cmd/trident/patch.go` | 缺失工具链不伪造通过；Go/Python fixture 通过 | `go test ./internal/r3` |
| C7 | P7 运行时/Agent/UI 收口 | `/api/dependencies`、`/api/authz`、`/api/reachability` 消费新字段；Agent 新增符号查询并更新描述；入口/依赖/权限/可达性页面显示语言与限制 | `internal/webui`、`internal/tools`、`assets/app.js` | 页面可见生态/语言/三态；Agent 工具描述不再 Java-only | `node --check`、浏览器 |
| V1 | 全量验证 | `go test -p 1 -count=1 -timeout 10m ./...`、`go vet ./...`、`node --check`、`test-web.py`、`test-code-audit.py`、真实项目 API | 全仓 | 全部退出 0；p3 启动 `/healthz` 200；真实项目多语言能力可见 | 完整输出 |

## 完成口径

- 每个 ID 有测试或真实 API 证据；不以“代码已写”代替验证。
- 所有新增限制写入 `limitations`，UI 不把 unknown 显示成无风险。
- 最后重新构建二进制并重启控制台，浏览器验收。
