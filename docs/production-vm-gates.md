# 生产与 VM 隔离门槛

本文把“生产可用”和“硬件 VM/等效隔离”从散落在
[`deployment.md`](deployment.md)、[`release-checklist.md`](release-checklist.md)、
[`capacity-cost.md`](capacity-cost.md) 的说明收成可勾选的门槛清单。

**当前结论：两条门槛都未通过。** Docker 与可选 gVisor 只提供进程/用户态隔离，
不是硬件 VM；生产部署、真实数据量恢复、独立安全评审与发布审批均未完成。
合成样本、loopback 模型和隔离副本的结果不得当作生产漏洞利用或修复上线证明。

## 1. 发布前置门槛（离线）

- [ ] `go test ./...`、`go vet ./...`、`go build ./cmd/trident` 在目标提交上全绿。
- [ ] `scripts/verify-offline.ps1` 的 Go 测试 + 离线 CLI 验收全绿，并保留日志。
- [ ] 工作区干净，改动有对应 commit；交付二进制与 SBOM/SARIF 可从该 commit 重建。
- [ ] 版本、Schema、迁移文件、规则库与公告目录均已固定，无浮动 `latest`。
- [ ] 已知边界（`release-checklist.md` §5）随发布说明一起交付，不删减。

## 2. VM 隔离门槛

目标：不可信项目代码与补丁验证不得在开发机、控制台主机或共享内核上直接执行。

- [ ] 使用硬件虚拟化（KVM/Hyper-V/ESXi 等）或等效的独立物理机，**不以 Docker、
      gVisor、nsjail 单独替代**；gVisor 只能作为额外一层。
- [ ] 每次验证从固定 digest 的镜像/快照启动，验证结束后销毁；不复用带状态的 VM。
- [ ] VM 内无生产凭据、无外网默认路由；仅按需挂载只读源码/补丁副本。
- [ ] CPU、内存、磁盘、进程数与运行时长均有硬上限；超限失败关闭。
- [ ] 逃逸与横向移动评审：容器逃逸、宿主挂载、元数据服务、内核漏洞面均有测试记录。
- [ ] 验证产物（日志、补丁、报告）经只读通道导出，VM 不回写源快照。
- [ ] 失败/超时/取消路径均能终止 VM 并清理临时卷，留存审计记录。

当前证据：`internal/r3` 有 Docker/gVisor 沙箱与回滚报告，真实 Java/Maven/JUnit
验证通过；`release-checklist.md` 明确“硬件 VM/系统调用隔离 — 未实现”。

## 3. 生产部署门槛

- [ ] 控制台只绑定 loopback；远程访问经同机 TLS 反向代理，代理不记录令牌/Cookie。
- [ ] 安全响应头不被剥离；CSP、`nosniff`、`DENY`、`no-referrer`、`CORP`、`no-store` 保留。
- [ ] 运行账号、迁移账号、只读账号分离；无超级用户日常运行。
- [ ] `--tokens` 文件权限 0600，`token_hash` 管理、轮换、撤销有演练记录。
- [ ] 数据库迁移先在副本演练，`trident check` 通过后才切生产；迁移可回退。
- [ ] 备份使用 `pg_dump` + WAL 归档/流复制，RPO/RTO 有书面声明并在生产硬件演练。
- [ ] `/healthz`、`/metrics`、`/api/metrics`、JSONL 访问日志接入监控与日志平台。
- [ ] `TridentConsoleDown`、`UnauthorizedSpike`、`ForbiddenSpike`、`AnalysisFailure`、
      `AnalysisStale` 告警在真实 Alertmanager 送达；生产删除演练探针。
- [ ] 容器/二进制镜像按 digest 固定；构建产物有校验和与来源记录。
- [ ] 模型端点、外发范围、费用上限逐次批准；密钥不落 Run、日志或仓库。
- [ ] 真实项目快照、真实模型、真实项目补丁分别取得书面授权并记录 hash/预算。
- [ ] 独立安全评审与发布审批完成；残余风险、未实现项和回滚方案签字。

当前证据：TLS 反代只有文档、未做真实域名/证书联调；备份恢复为 624 MB 合成数据、
本机实测；监控用真实 Prometheus/Alertmanager 容器联调；生产硬件、生产数据量、
异地恢复与独立评审均未完成。

## 4. 验收记录格式

每次生产/VM 验收至少记录：

| 字段 | 内容 |
|---|---|
| 提交 | Git commit / 二进制 SHA-256 |
| 环境 | VM 类型、镜像 digest、CPU/内存/磁盘上限、网络策略 |
| 数据 | 真实项目/快照 hash、文件数、字节数、是否 partial |
| 授权 | 批准人、外发范围、模型端点、调用/费用上限、有效期 |
| 结果 | 命令、退出码、关键计数、报告路径、失败关闭证据 |
| 残余风险 | 未覆盖项、已知边界、回滚与清理结果 |

没有上述记录，只能记为“本地/合成环境通过”，不得写成“生产可用”。
