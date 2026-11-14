# 部署、升级与备份指南

本文是本地/受控环境的部署说明，不是“生产就绪”声明。生产声明仍需完成硬件 VM 或等效隔离、独立安全评审、真实业务数据库演练和发布审批。

## 1. 构建

```bash
go build -trimpath -o trident ./cmd/trident
./trident version
```

- Go 模块要求 `go 1.26.3`；当前实测环境为 Go 1.27.1（Windows amd64）。
- 二进制不依赖数据库即可运行 `version`、`project`、`sca`、`audit`、`web`、`runtime`；`migrate`/`check`/`bootstrap`/`agent` 需要 PostgreSQL。
- Python 3.12+ 仅用于验收脚本；`test-sbom.py` 需要 `jsonschema`。

## 2. 配置与凭据

| 变量/参数 | 用途 | 备注 |
|---|---|---|
| `TRIDENT_DATABASE_URL` | 运行时数据库 DSN | 不写入仓库；生产应使用 `trident_runtime` 账号 |
| `TRIDENT_MIGRATION_ACTOR` | 迁移操作者标识 | 仅 `migrate` 需要；生产应使用 `trident_migrator` 账号 |
| `TRIDENT_POSTGRES_PASSWORD` | 本地 compose 初始化密码 | 只写入本机 `.env`，不要提交 |
| `TRIDENT_MODEL_API_KEY` | 真实模型命令的密钥 | 仅在显式 `--approve-egress` 时读取；不落 Run/日志 |
| `web --token` | 单用户控制台访问令牌 | 省略时随机生成并只打印一次；不要通过 URL 传递 |
| `web --tokens` | 多用户令牌文件（P2-2） | JSON `[{id, role, token_hash}]`，`token_hash=sha256(token)` 十六进制；文件永不存令牌明文；mtime 变化热重载，轮换/撤销下一个请求生效 |
| `web --access-log` | JSONL 审计访问日志 | 记录 time/token_id/method/path/status；永不记录令牌明文；轮转交给外部日志工具 |
| `runtime http --approve-target` | 运行时目标 origin | 必须与计划 `base_url` 完全一致；loopback 另需 `--allow-loopback` |

原则：迁移账号与运行账号分离；模型密钥与数据库密钥不共用；控制台只绑定 loopback，远程团队访问必须经同机 TLS 反向代理（见 §2.1）。

### 2.1 Web 控制台 TLS 反向代理部署（P2-2）

```nginx
server {
  listen 443 ssl;
  server_name console.example;
  # 证书与 HSTS 由部署方提供；ssl_certificate ... 省略
  add_header Strict-Transport-Security "max-age=31536000" always;

  # 不记录令牌/Cookie 头：保持 nginx 默认，禁止在自定义 log_format 中加入
  # $http_x_trident_token 或 $http_cookie
  location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
  }
}
server {
  listen 80;
  server_name console.example;
  return 301 https://$host$request_uri;
}
```

- 反向代理必须与控制台同机，只转发到数值 loopback 地址；不要把控制台端口暴露到非 loopback 网卡。
- 不得剥离或覆盖应用安全响应头（CSP/`nosniff`/`DENY`/`no-referrer`/`CORP`/`no-store`）；只能追加。
- 令牌文件按密钥管理：`token_hash` 生成方式见 [Web 控制台契约](web-console-contract.md) §2.1；轮换=同 id 换新哈希，撤销=删除条目，均无需重启。
- 代理层访问日志可记录来源 IP，与应用层 JSONL 审计日志（无 IP、无令牌）互补。
- 多用户令牌与审计日志不改变只读边界：控制台仍无写路由、无执行/修复入口。

### 2.2 监控与告警规则（P2-3）

控制台提供三类可采集信号，**已用真实 Prometheus v2.53.0 + Alertmanager v0.27.0 容器端到端联调**
（`python scripts/test-monitoring.py`，四项 PASS；实测记录见 [容量与成本模型](capacity-cost.md) §5）：

1. **抓取端点**：`GET /metrics`（Prometheus 文本格式 0.0.4；令牌门禁，`authorization.credentials_file` 注入 Bearer 令牌）；`GET /healthz`（未认证探活）。配置与规则在 [`ops/monitoring/`](../ops/monitoring/)（`prometheus.yml`、`alerts.yml`、`docker-compose.yml`），指标名与告警规则对齐。
2. **JSON 指标**：`GET /api/metrics`（令牌 + console 头），字段见 [Web 控制台契约](web-console-contract.md) §6.1；采集方以只读令牌轮询（15–60s）。
3. **结构化日志**：`--access-log` JSONL（每行 time/token_id/method/path/status）+ stderr 告警行；JSONL 适合 filebeat/loki 逐行采集。

告警规则（`ops/monitoring/alerts.yml`，已在真实 Alertmanager 验证加载与送达）：`TridentConsoleDown`、`TridentConsoleUnauthorizedSpike`（10m 内 >50 次令牌拒绝）、`TridentConsoleForbiddenSpike`、`TridentAnalysisFailure`、`TridentAnalysisStale`（30 分钟无缓存分析）、`TridentAlertDeliveryProbe`（**管道探针，仅演练用，生产删除**）。阈值按环境调整。

- 告警响应手册要点：`ConsoleDown` → 检查进程与 loopback 端口；`UnauthorizedSpike` → 对照审计日志 `token_id` 分布与令牌文件轮换记录；`AnalysisFailure` → 复现 `trident audit findings --snapshot ...` CLI 侧失败原因（同一分析引擎）。
- 指标不含令牌值、Cookie、路径查询串；`last_error` 采集中按敏感信息策略脱敏后再入告警注释。
- 拓扑约束：控制台只绑定 loopback；Windows/macOS Docker Desktop 经 `host.docker.internal` 抓宿主 loopback，Linux 需 socat sidecar 或宿主网络，不得放宽控制台绑定。镜像当前为 tag pin，生产必须 digest pin。Prometheus→Alertmanager 首次通知可能因 gossip settle 重试延迟数分钟，告警验收窗口按分钟计。

## 3. 数据库迁移

```bash
export TRIDENT_DATABASE_URL='postgres://trident_migrator@db.example/trident'
export TRIDENT_MIGRATION_ACTOR='release-operator'
./trident check
./trident migrate
```

- `check` 只读校验 Schema 与迁移校验和，不建库、不改表。
- `migrate` 显式前向应用 `db/migrations/`，要求操作者标识；普通启动不会自动迁移。
- 生产建议先在备份/克隆库演练，再对主库执行；迁移账号只授予 `USAGE, CREATE`，运行账号只授予 DML。
- 最小权限模板见 [`db/roles.example.sql`](../db/roles.example.sql)。模板中的密码占位符必须由密钥管理系统替换，且需要在真实表 owner 与数据库名下复核。
- 本地一次性容器演练：`python scripts/test-db-governance.py`（PostgreSQL 18 固定镜像）。已实测通过：`trident_migrator` 可重复执行 `migrate`；`trident_runtime`/`trident_readonly` 可通过 `check`；runtime 建表、建角色被拒绝；readonly 写入被拒绝；新建表继承默认权限（runtime DML、readonly 只读）；`bootstrap` 与 `demo-offline` 在 runtime 账号下完成真实写入。演练库与随机密码随容器销毁，不接触既有测试库。
- 该演练不等同于生产环境执行：生产仍需在真实表 owner、数据库名和密钥系统下复核，并完成审计与回滚审批。

## 4. 备份与恢复

```bash
# 备份（custom 格式，包含 Schema 与数据）
pg_dump --format=custom --file=trident-$(date +%Y%m%d).dump "$TRIDENT_DATABASE_URL"

# 恢复到新库后检查 Schema
pg_restore --clean --if-exists --dbname="$TRIDENT_RESTORE_URL" trident-YYYYMMDD.dump
TRIDENT_DATABASE_URL="$TRIDENT_RESTORE_URL" ./trident check
```

- Agent Run/Step 表为 append-only 审计记录，备份应包含它们；当前没有自动物理清理。
- 恢复后先用 `check` 验证迁移校验和，再启动 Web/Agent。
- 备份文件包含授权与证据元数据，按敏感数据管理；不要放入仓库或公开对象存储。
- 恢复演练：`python scripts/test-db-governance.py` 已在一次性 PostgreSQL 18 容器内完成 `pg_dump --format=custom` → 新库 `pg_restore` → `trident check` → 行数比对（`principals`、`tasks`、`tool_calls`、`approvals`、`schema_migrations`），结果一致。
- **数据量级演练与 RTO/RPO（2026-11-14）**：`python scripts/test-backup-scale.py` 在 624 MB / 约 170 万行的真实迁移 Schema 上实测——dump 3.6s（归档 37 MB）、restore 6.7s、check+行数核对 3.1s，**RTO（restore+verify）9.8s**；并演示 RPO 语义（备份后写入的 5000 行不在恢复点内）。估算公式（restore 吞吐 ≈105 MB/s、归档压缩比 ≈16:1、RPO 由备份策略决定）见 [容量与成本模型](capacity-cost.md)；生产 RTO/RPO 承诺必须按该模型在生产硬件上重测。

## 5. CI 与 SARIF

- 工作流：[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)，三个 job（2026-11-14 起在真实 GitHub runner 验证）：
  - `offline`：Go 测试/vet + 10 个离线 CLI 验收脚本 + 构建 CLI + 生成 SARIF；SARIF 上传为 code scanning（`github/codeql-action/upload-sarif@v3`，需 `security-events: write`）并保留 artifact。
  - `db-governance`：`scripts/test-db-governance.py` 在一次性 digest 固定的 PostgreSQL 18 容器中演练最小权限与迁移/运行分离（runner 自带 docker，脚本自管容器生命周期）。
  - `release-artifacts`：仅 `v*` tag push 触发；构建 linux/windows amd64 二进制（`-trimpath`）、从固定 fixture 生成 SBOM 与 SARIF、SHA256 校验和，上传 artifact（不创建 GitHub Release，保持 `contents: read`）。
- 本地等价检查：`powershell -File scripts/verify-offline.ps1`（需要 Python 3.12+ 与 `jsonschema`；本地比 CI 多 4 个脚本）。
- CI 不调用模型、不执行 Java/Maven/Gradle 构建；db-governance 只触碰自身启动的一次性容器。
- 失败路径已在真实 runner 复现：故意失败探针提交（`e1119d3`）使 `Go tests and vet` 红灯（run 43585523523），随后 revert 恢复；门禁可证失败关闭。
- SARIF 只包含静态 finding，`runtime_status` 仍为 `not_run`；不要用它声明运行时验证通过。

## 6. 版本矩阵（已测试）

| 组件 | 版本 |
|---|---|
| Go | 1.27.1（模块下限 1.26.3） |
| PostgreSQL | 18（`postgres:18@sha256:e3d24f...` 测试容器） |
| Maven | 3.9.9 |
| JDK | 17.0.16、8u202 |
| Gradle | 8.14.3 |
| Tomcat | 9.0.106 |
| MySQL | 8.0.46 |
| JUnit | 4.12 |

## 7. 未完成的生产门槛

- 硬件 VM 或等效隔离；当前 Docker/gVisor 不是硬件边界。
- 本地容器分权与恢复演练已通过，但未在独立生产环境执行和审计。
- 完整 Java AST/调用图/跨方法污点、制品哈希与依赖到入口调用可达性。
- CI 中的 Java/Maven/Gradle、模型与运行时 job 需要专用 runner、授权和密钥管理（DB 治理 job 已落地；SARIF 已接 code scanning）。
- 监控告警、生产级备份恢复（数据量/时限/异地）与容量/成本报告。
- TLS 反向代理示例未经真实域名/证书联调（命令结构与安全要求已在契约固化）；OIDC 仅预留 `role` 接口。
