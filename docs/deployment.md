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
| `web --token` | 控制台访问令牌 | 省略时随机生成并只打印一次；不要通过 URL 传递 |
| `runtime http --approve-target` | 运行时目标 origin | 必须与计划 `base_url` 完全一致；loopback 另需 `--allow-loopback` |

原则：迁移账号与运行账号分离；模型密钥与数据库密钥不共用；控制台只绑定 loopback，若需远程访问必须另加 TLS、反向代理和强认证，当前实现不提供这些生产能力。

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
- 最小权限模板见 [`db/roles.example.sql`](../db/roles.example.sql)。模板中的密码占位符必须由密钥管理系统替换，且需要在真实表 owner 与数据库名下复核；本项目尚未在独立生产环境执行该模板。

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

## 5. CI 与 SARIF

- 工作流模板：[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)。它在 Ubuntu 上运行 Go 测试、离线 CLI 验收，并上传 `trident.sarif` 构建产物。
- 本地等价检查：`powershell -File scripts/verify-offline.ps1`（需要 Python 3.12+ 与 `jsonschema`）。
- CI 不调用模型、不访问数据库、不执行 Java/Maven/Gradle 构建；这些需要独立授权与专用 runner。
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
- 生产数据库迁移/运行账号分权已在模板中给出，但未在独立生产环境执行和审计。
- 完整 Java AST/调用图/跨方法污点、制品哈希与依赖到入口调用可达性。
- CI 中的 Java/Maven/Gradle、模型与运行时 job 需要专用 runner、授权和密钥管理。
- TLS/多用户控制台、监控告警、备份恢复演练与容量/成本报告。
