# TRIDENT P0.1 首批验收记录（历史）

> 本文保留当时的验收结果与未完成项，不代表 P0.2 或当前产品能力。后续路线以 [TRIDENT 统一安全 Agent 执行方案 v2.0](TRIDENT_统一安全Agent执行方案_v2.0.md) 为准；旧 P0—P6 阶段不再作为开发顺序。

日期：2026-11-12。范围：首批离线数据/授权/事务闭环，**不代表完整 P0 验收**。

## 环境

- Windows 本机 Go 1.27.1；模块声明 Go 1.26.3。
- 独立 Docker PostgreSQL 18.6，仅绑定 127.0.0.1:55432，Compose 项目 trident-p0。
- Linux 竞态验收：Go 1.26.3-bookworm 固定镜像摘要，源码只读挂载。
- 未修改上游项目，未向任何测试目标执行 HTTP、扫描或漏洞验证。

## 最终结果

| 检查 | 结果 |
|---|---|
| go vet ./... | 通过 |
| 单元测试：迁移清单/历史校验、Scope、状态机、Outbox 参数 | 通过 |
| 显式迁移、重复执行及只读 Schema checksum 检查 | 通过 |
| Offline Lifecycle 与消费/事实/结算幂等 | 通过 |
| 100 Worker 并发 Claim 单赢家 | 通过 |
| 20 并发 Mission 预留，共10步预算，单份3步，恰好3份成功 | 通过 |
| 多容量池互不误杀、旧 Worker Fencing、保留不确定预算 | 通过 |
| 授权撤销后拒绝执行、可信服务结算 | 通过 |
| Scope 不可变、非法状态、跨 Task 边、孤立 Node、删除保留 | 通过 |
| Outbox 插入失败时业务事务回滚 | 通过 |
| 已 settled Mission 不得直接重试 | 通过 |
| Claim 等池锁跨过 deadline 后拒绝 | 通过 |
| Outbox 队首/死信阻塞、重放、旧代数 ACK 拒绝 | 通过 |
| Outbox ACK 等锁跨过租约有效期后拒绝 | 通过 |
| 伪造身份、角色提升、范围外和待审核资产、过期授权拒绝 | 通过 |
| Linux go test -race -tags=integration ./... | 通过 |
| CLI demo-offline | done，network_execution=false |

最终 Windows 真实数据库集成结果：`ok trident/tests/integration 9.265s`。
最终 Linux race 真实数据库集成结果：`ok trident/tests/integration 5.363s`。

## 遇到并处理的问题

1. Windows 原生 `-race` 受本机 C 工具链影响：`runtime/cgo ... cgo.exe: exit status 2`。未将其算作通过，改在 Linux 容器实跑并通过。
2. 最终复测曾因测试使用100ms真实TTL，负载下有效租约先行过期导致断言失败。改为一分钟合法租约先验证并发，再在专属测试库显式注入过期；重新执行本机与Linux-race均通过。
3. 复核发现已结算预留可被旧 Mission 重试、池锁等待跨过截止时间和续租/缩容竞争，已补预算双闸、统一资源锁和锁后独立时间重验，并加入对应回归。

## 未覆盖与后续门禁

生产数据库角色分权和任务级身份授权、完整审计/证据/Finding 模型、审批请求绑定、Scope 更新、完整CAS接口、旧结果隔离、崩溃/断连/commit不确定故障矩阵、事件消费者幂等与备份恢复仍未完成。完整清单见 README。

这些工作完成前不能声称 P0 全部通过；P1 的真实出口、进程终止和只读沙箱也未由本次测试证明。

复测命令见 README 与 `docs/p0-contracts.md`。测试会新增合成记录，不自动删除数据卷或重置数据库。
