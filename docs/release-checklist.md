# TRIDENT 发布与验收检查表（R6 草稿）

本文件是发布前检查入口，不是生产就绪声明。运行时状态与验证事实以
[`development-progress.md`](development-progress.md) 为准。

## 1. 固定版本与工具链

| 组件 | 固定版本 | 说明 |
|---|---|---|
| Go | `go 1.26.3`（本机验证 `go1.27.1`） | `go build ./...`、`go test ./...`、`go vet ./...` |
| PostgreSQL | `postgres:18@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42` | `compose.yaml`，仅绑定 `127.0.0.1:55432` |
| Java | Temurin 17.0.16 | 仅 R3 验证；分析命令不执行 Java |
| Maven | 3.9.9 | R3 `maven` profile，离线 `-o` |
| JUnit | 4.12 | 调用者提供 classpath；不依赖 Surefire |
| Docker 验证镜像 | `maven:3.9.9-eclipse-temurin-17@sha256:f58d59b6273e785ac0a4477f6e9b5ba1d7731c75b906c0f7b34076f1851318cc` | `patch verify/propose` 的 docker/gvisor 沙箱 |
| gVisor | `runsc`（可选） | 未注册时 `--sandbox gvisor` 失败关闭 |
| CycloneDX Schema | 1.5，固定副本 `tests/schemas/bom-1.5.schema.json` | Python `jsonschema` Draft 7 验收 |
| SARIF | 2.1.0 | `audit sarif`，不写时间戳，输出确定 |

所有快照、fixture、策略与公告目录均为本地显式路径；运行时不访问网络（模型和 R3 执行除外，且需显式批准）。

## 2. 构建、启动与备份

```bash
# [01] 只读分析：不需要数据库或模型密钥。
go build -o bin/trident ./cmd/trident
bin/trident version

# [02] Agent/Run：需要 PostgreSQL 与显式迁移。
export TRIDENT_DATABASE_URL='postgres://.../trident_test'
export TRIDENT_MIGRATION_ACTOR='release-operator'
bin/trident migrate
bin/trident check

# [03] 测试库启动（专用测试环境）。
# compose.yaml 要求 .env 中设置 TRIDENT_POSTGRES_PASSWORD。
docker compose -f compose.yaml up -d

# [04] 备份：由数据库管理员执行；本工具不会自动备份或删除数据。
pg_dump --format=custom --file=trident.dump "$TRIDENT_DATABASE_URL"
```

Agent 表是 append-only；`agent export` 只读导出，不做物理删除。数据库清理、凭据轮换、服务账号分权仍属部署方职责。

## 3. 可复现基准

```bash
python scripts/benchmark.py 3
```

本机 2026-11-13、Go 1.27.1、2 次迭代的实际结果（合成样本）：

| 样本 | 命令 | 中位耗时 |
|---|---|---|
| `java-maven` | `sca inspect` | 约 122 ms |
| `java-maven` | `sca resolve`（离线 Maven，单次） | 约 2—4 s |
| `java-maven` | `audit dataflow` | 约 229 ms |
| `java-maven` | `audit findings` | 约 151 ms |
| `java-advanced-sinks` | `audit dataflow` | 约 106 ms |
| `java-flow-gaps` | `audit findings` | 约 100 ms |
| `gradle-basic` | `sca inspect` | 约 109 ms |

基准只测 wall-clock 与输出字节，不包含数据库、模型、网络、Maven/Java；样本很小，不能外推大型项目成本。

## 4. 可复现验收

| 门槛 | 命令 | 当前状态 |
|---|---|---|
| 快照与只读工具 | `python scripts/test-project.py` | 通过 |
| SCA/Gradle/区间/树 | `python scripts/test-sca.py`、`python scripts/test-intel.py` | 通过 |
| 入口清单 | `python scripts/test-audit.py` | 通过 |
| 数据流/元素精度/框架 sink | `python scripts/test-dataflow.py` | 通过 |
| 统一证据与 SARIF | `python scripts/test-findings.py`、`python scripts/test-intel.py` | 通过 |
| SBOM 官方 Schema | `python scripts/test-sbom.py` | 通过 |
| 只读 Web 控制台 | `python scripts/test-web.py` | 通过 |
| 真实 PostgreSQL/Agent | `python scripts/test-local.py`、`python scripts/test-agent.py` | 通过 |
| R3 真实 Java/Maven/JUnit | `python scripts/test-patch.py` | 通过 |
| R3 AI 补丁 + Docker | `python scripts/test-patch-ai.py` | 通过（loopback 模型） |
| Linux race | `python scripts/test-linux.py` | 通过（固定 `golang:1.26.3-bookworm`） |
| 真实模型只读 | Run 43/46/48 记录 | 已获准并通过，其他模型/快照需重新授权 |
| 真实模型 AI 补丁（合成目标） | `patch repair` + `patch verify`（2026-11-14） | 通过：`deepseek-v4-pro` 补丁，Maven 与 JUnit 各一轮 `validation_passed`，快照完整；仅合成 fixture |
| 真实项目 AI 补丁 | `patch repair` + `patch verify`（`D:\Code\Java\market`，2026-11-14） | 通过（编译级）：`deepseek-v4-pro` 访问控制补丁，`maven-compile` 通过，quality 80/B；无测试、无运行时验证 |
| 真实项目集中式访问控制补丁 | `patch verify --profile maven-test`（2026-11-14） | 通过：LoginInterceptor 全量拦截 manager/staff 路由，4 个 JUnit 测试通过，offline `mvn test` 退出 0，quality 75/B，快照完整 |
| 补丁回滚、模块与 Gradle 验证 profile | `go test ./internal/r3` + `python scripts/test-patch.py` | 通过：失败/通过报告含 `rollback` 原始哈希与 `rubric_version`；`--module .` 逐模块结果；越界模块拒绝；`gradle-test` 以 PATH 桩工具链验证命令、退出码与 JUnit XML（真实 Gradle 未验证） |
| 派生索引缓存与性能门槛 | `go test ./internal/cache` + `python scripts/test-cache.py` + `python scripts/benchmark.py --baseline` | 通过：冷 `miss`/热 `hit`/损坏 `partial`、单文件变更局部重建；缓存仅 JSON 且无源码；缓存与快照重叠拒绝；相对中位数倍数门槛通过 |
| 真实 Tomcat/MySQL HTTP 权限 | Tomcat 9.0.106 + MySQL 8.0.46 容器（2026-11-14） | 通过：未登录 manager/staff 业务端点均 302 到各自登录页，登录后放行；跨会话拒绝；错误密码不建立会话 |
| 硬件 VM/系统调用隔离 | — | 未实现；gVisor 是用户态内核 |
| Maven 有效依赖树（离线） | `python scripts/test-resolve.py` | 通过（3 模块/31 依赖/25 传递） |
| Gradle 有效依赖树（离线） | `python scripts/test-gradle-resolve.py` | 通过（Gradle 8.14.3：3 模块/5 依赖/2 传递；需 `TRIDENT_GRADLE` 或 PATH，离线缓存 POM 缺失时 skip） |
| 依赖升级验证 | `python scripts/test-upgrade.py` | 通过：commons-text 1.9→1.10.0，基线测试与升级后测试均通过，快照完整；Gradle 升级可生成补丁并用 `gradle-test` 验证，真实 Gradle 工具链未验证 |
| 权限/越权控制清单 | `python scripts/test-authz.py` | 通过：旧 fixture 5 控制/11 入口，6 protected、2 public、2 unprotected、1 unknown，2 条 CWE-306 `inconclusive` finding；`java-authz-chain` 2 条有序链、5 protected/3 public/1 unknown、`ROLE_ADMIN` 归一化、context-path 外部路径 |
| 运行时 HTTP 验证自动化 | `python scripts/test-runtime.py` + 真实 Tomcat/MySQL | 通过（本机）：基础 loopback 4/4；角色矩阵 2 角色 × (2 登录 + 2 单元) 共 10/10、每角色 4/4、`login_status=complete`、`csrf=token_injected`；缺失 token/未设置占位符/共享 session 失败关闭；凭据与 token 不落报告。真实环境 15/15 为既有结果，本次未重跑 |
| 静态—运行时关联报告 | `go test ./internal/correlate` + `python scripts/test-runtime.py` | 通过：`runtime correlate` 三态（唯一匹配/多匹配歧义/无匹配）、无 endpoint finding、未命中运行时结果；原 findings 字节不变、输出确定性、覆盖输入/缺失输入/未观测运行时失败关闭 |
| 本地制品哈希与来源核对 | `python scripts/test-artifact-hash.py` | 通过：fixture 本地仓库 jar/pom SHA-256 与字节命中；调用者清单 exact/mismatch/catalog-only 三态；空仓库 `unavailable`；非法清单/不存在仓库失败关闭；SBOM 同一组 observed 哈希；快照与仓库字节不变 |
| 依赖到入口有界可达性 | `python scripts/test-reachability.py` | 通过：`java-reachability` 三模块 3 入口，`reachable` 路径 2 步且带 SHA-256/行号，仅声明未引用 `unreachable`，`Class.forName` 为 `unknown/reflection_not_resolved`；findings 假设 `supported/unsupported/unverified`；无 package map 全部 unknown |
| 受限 Java 语义模型 | `python scripts/test-java-ast.py` | 通过：`java-ast-model` 5 文件（1 个语法错误单独拒绝）；嵌套类、泛型擦除重载、唯一实现接口分派、双实现歧义分派、注解常量/数组/枚举折叠、确定性、fixture 字节不变 |
| Web 控制台多用户与审计 | `go test ./internal/webui ./cmd/trident` + `python scripts/test-web.py`（第二阶段） | 通过：`--tokens` JSON `[{id,role,token_hash}]` 仅存 SHA-256 并 mtime 热重载（轮换/撤销下一请求生效）；`--access-log` JSONL 记录 time/token_id/method/path/status 且不含令牌明文；`/export/report` 两次跨用户字节一致、无外部 URL/时间戳；TLS 反代说明未经真实域名/证书联调 |
| 控制台可观测性（本地部分） | `go test ./internal/webui` + `python scripts/test-web.py` | 通过：`/healthz` 未认证探活（仅 status/product/version）；`/api/metrics` 令牌门禁只读计数器（requests/unauthorized/forbidden、analysis 冷热/失败/终态）单调；Prometheus 告警规则模板与响应手册见 `docs/deployment.md` §2.2（未接真实监控系统） |
| SARIF GitHub 规则映射 | `go test ./internal/sarif` + Actions `upload-sarif` 步骤 | 通过：规则级 `security-severity`（confirmed 7.5/inconclusive 3.0/refuted 0.0）、`precision`、`tags`（security + CWE-n）、结果级确定性 `primaryLocationLineHash`；run 43585400725 已将该 SARIF 成功上传 GitHub code scanning（告警呈现需在仓库 Security 页人工复核） |
| 离线全量门禁 | `powershell -File scripts/verify-offline.ps1` | 通过（Go 测试/vet + 14 个离线 CLI 验收脚本） |
| CI 门禁真实 runner 落地 | GitHub Actions 页面 run 记录 | 通过：`offline`（Go 测试 + 10 个 CLI 验收 + SARIF 生成并上传 code scanning）与 `db-governance`（一次性 PostgreSQL 18 容器演练）在 run 43585245302、43585400725 全绿；故意红灯探针 `e1119d3` 使 `Go tests and vet` 失败（run 43585523523），revert `97a04e7` 后恢复；`release-artifacts` 仅 `v*` tag 触发（tag 构建未演练，见下） |
| 部署/备份/升级文档 | `docs/deployment.md` | 已提供构建、迁移、备份恢复、凭据分权与版本矩阵；生产恢复演练仍待完成 |
| 最小权限角色与迁移/运行分权 | `python scripts/test-db-governance.py` | 通过：一次性 PostgreSQL 18 容器；`migrate` 幂等、runtime/readonly 可 `check`、runtime 建表/建角色与 readonly 写入被拒绝、新表默认权限生效、`bootstrap` 与 `demo-offline` 在 runtime 账号下完成写入；未在独立生产库执行 |
| 备份恢复演练 | `python scripts/test-db-governance.py` | 通过：`pg_dump --format=custom` → 新库 `pg_restore` → `trident check` → `principals`/`tasks`/`tool_calls`/`approvals`/`schema_migrations` 行数一致；不含生产数据量、备份窗口与恢复时限 |
| 基准报告 | `python scripts/benchmark.py 3` + `docs/benchmark-report.md` | 通过：4 个合成 fixture、7 条只读命令；仅 wall-clock，不含 DB/模型/Java/Maven |

## 5. 版本兼容与已知边界

- Windows 11 与 Linux（`openat2`/`statx` Mount ID 5.8+）快照路径语义不同；不支持网络/FUSE/无法安全判断的文件系统。
- `agent` 检查点 v2；v1 不自动恢复。模型适配只承诺 Chat Completions 子集，不支持所有供应商扩展。
- 公告区间是调用者声明判据，不是 Maven 版本语义的完整实现；`reachable` 是本快照类级有界图的静态证据，`unreachable` 不排除反射、动态代理、框架装配或运行时生成代码。
- 制品哈希只覆盖调用者显式本地仓库/缓存中已存在的字节；不验证 GPG/签名，不证明来源或未被篡改。
- Gradle 有效树优先 `runtimeClasspath`、其次 `compileClasspath`，含 `*RuntimeClasspath`/`*CompileClasspath` 后缀回退；不解释 Android variant、version catalog、BOM/platform 或插件脚本副作用。
- 静态 finding 的 `runtime_status` 恒为 `not_run`；R3 的 `runtime_status=isolated_validation_only`。
- `runtime http` 的 `runtime_status=observed` 只覆盖调用者声明的请求与断言，不是漏洞利用或生产安全证明，也不自动回写 finding。
- `runtime correlate` 仅按注解级 route/method 字面量匹配；不解析 context path、部署前缀、路径变量或归一化，`correlated` 不证明参数可控、控制缺失或可利用。
- `rollback` 只提供原始文件哈希与人工回退说明，不执行回滚命令；`gradle-test` profile 的桩工具链验收只证明命令构造与报告解析，不证明真实 Gradle 构建。
- `audit endpoints --cache-dir` 只缓存端点派生索引，不存源码；缓存不改变分析结论，也不代表大型仓库的实际加速比。
- gVisor 需要 Docker 注册 `runsc`；Docker 不是硬件 VM。

## 6. 发布门槛

1. 所有第 4 节可在本机离线复现的门槛通过，且工作区有对应 Git commit。
2. 真实模型、真实项目快照外发、真实项目 AI 补丁分别取得逐次书面授权，并记录端点、模型、快照 hash、调用上限与费用上限。
3. 若声明“生产可用”，还需独立完成生产部署、生产级备份恢复演练（真实数据量/时限/异地）、凭据分权审计、监控、SARIF/CI 集成和硬件 VM 或等效隔离评审。
4. 不得把合成样本、loopback 模型、静态分析或隔离副本结果表述为生产漏洞利用或修复上线证明。
