# P0.1 / P0.2 事务与信任契约（历史实现记录）

> 2026-11-12：产品路线已切换为统一 TRIDENT Agent，当前执行基线为 [统一安全 Agent 执行方案 v2.0](TRIDENT_统一安全Agent执行方案_v2.0.md)。本文仅记录已有 P0.1/P0.2 代码的事务语义，不是现行产品架构或后续开发顺序；下文旧阶段编号按历史含义理解。

## 范围和信任根

这是旧 v1.2.1 路线下形成的可运行事务基础，不表示原 P0 已全部验收。现有代码仅支持本地可信 CLI 与 Store 调用，不开放目标测试工具、网络执行或模型调用；可按新方案需要适配，不再保留旧三角色架构要求。

- 数据库是权威状态，未实现第二套文件状态。测试管理员、服务凭据由显式操作创建，随机 256-bit Token 仅保存摘要。
- Session 只能经 Authenticate 获得；每个事务重新核验主体状态。P0.2 要求非 admin 的 scheduler / worker / reconciler 同时具有当前 Task 的 active 对应角色成员资格。人工 admin 是部署级信任根，不是生产多租户角色。
- `CreateTask` 暂限 human admin，避免尚无合同级委托时由全局 scheduler 自建任务自授权。成员授予须角色匹配全局角色；撤销会阻断该 Worker 的活动 Mission、撤销租约和未消费审批，保留预算。重新授予不复活旧租约。
- 任务成员校验在持久幂等结果返回之前，已撤销成员不能通过旧 key 读取回执。仍有任务权限的历史 Finish 回执不要求租约继续 active，不产生新增副作用。
- 人工证明核验意味着持授权批准权限的本地管理员确认材料，系统不会据一个 Hash 自动认定法律授权成立。当前 CLI 演示只使用 synthetic 数据。
- `single_operator_mode` 默认关闭；创建者与授权主体不能在默认模式下以同一身份自批准。
- DB 账号目前可信，Worker/LLM 尚不存在，不能将同进程 Store 隔离宣称为已实现 OS/数据库最小权限隔离。P1 前须完成数据库服务账号拆分。

## 幂等与事务

- 幂等键作用域为 actor + operation + key。持久请求摘要与首次结果和业务变更同事务提交。
- 同键同摘要返回首次结果，同键不同摘要拒绝。历史结果返回不是新的执行许可，不续租、不重扣预算。
- Activity、Aggregate Version、Outbox 与业务同事务。事件写失败整体回滚，不使用 best-effort 保存点。
- 提交响应不确定时只能携带同键查询首次结果，不能自行换键重放有副作用操作。
- 迁移由明确命令执行，每个 SQL 文件及 checksum 登记同事务；固定连接持迁移锁。已应用 SQL 不得编辑，修改必须新增迁移。
- 目前失败迁移通过错误返回留痕，独立持久失败审计尚未实现。

## 锁顺序与时钟

常用业务路径：认证主体共享锁 → 幂等锁 → Authorization → Task/Version → Intent/Mission → Resource Pool → Lease；账本按 kind 排序。只修改预算的事务不反向申请资源池；Claim 不同时占有 Ledger 锁。Outbox 事务不进入业务锁链。

为减少首批复杂性，同一任务/授权下业务事务有串行化锁；并非高吞吐多租户方案。100 Worker 验收会建立独立并发数据库调用，但数据库最终通过行锁选单赢家。

所有可执行状态校验使用数据库 `clock_timestamp()`；等锁后用独立 SQL 重读有效期，不依赖事务开始时刻。期限最晚取 Task/Mission 约束；授权实时失效时拒绝新副作用。

## 预算

`allocated = available + reserved + consumed`，全部整数非负。当前单位：steps=步、tokens=token、http_requests=请求、storage=字节、wall_clock=毫秒；P0.1 演示仅消费 steps。

- 创建 Mission 与所有预算维度预留同事务。
- Consume 将对应预留转入 consumed，不能超过当前 Reservation。
- Finish 结算剩余预留并释放 Lease，重复结算不二次扣费。
- 过期或撤销不等于消费为零，未确认副作用时保留预留，状态 blocked 等待人工/可信服务对账。
- 已 settled 的 Mission 不允许使用旧预留重试。重新投入需另建 Mission 并重新预留；完整重开 API 待下一批。

## Lease 与 Fencing

有效性绑定：`task + mission + lease_id + holder + runtime_id + fencing_token + status + lease_until`。

- 资源池计数器只分配单调 Token，**不要求每个有效租约的 Token 都等于池最新计数器**。
- 多容量池中一个新 Worker 不会使其他合法租约失效。
- Claim 锁资源池，状态化过期 Lease，检查容量并分配 Token。续租与缩容共享资源池锁。
- TTL 只接受 1ms～5min 的整毫秒，拒绝截断为零的亚毫秒输入。
- 服务端每个新增 Worker 写事务验证 Token；旧 Worker 不能续租、消费或权威写回。
- 到期恢复只能先 blocked，人工确认旧执行终止/重试安全后才转 retry_pending。
- 真实进程终止、出口封锁、短期凭据撤销和隔离晚到结果尚未完成，不能把数据库侧 Fencing 测试等同 P1 执行边界验收。

## 图和保留

首批只含 intent / mission / fact 强类型节点；关系矩阵为 intent→mission(spawns)、mission→fact(yields)、fact→intent(derived_from)。插边前锁 Task，再做递归路径防环。领域扩展表以复合外键绑定 Node kind，提交时拒绝孤立 Node。

Scope 文档、证明与授权事件禁止原地改写。审计链 Hash 受应用/数据库权限保护，不抵抗拥有数据库管理员权限者重写全库；尚无外部签名锚定。外键采用 RESTRICT，不提供删除 Task 的业务入口，完整保留周期与受控销毁留待下一批。

## Outbox

- 至少一次通知；不是外部副作用恰好一次执行。
- 聚合版本定义顺序。SKIP LOCKED 只能跳过不同聚合，不能越过同聚合未发布队首；队首重试/死信均阻塞后续。
- 领取带 dispatcher + claim generation + expiry；ACK/Fail 先取锁再独立时钟检查。旧代次、旧 owner、过期或重复确认拒绝。
- Replay 仅管理员可用，修改原通知投递状态并记录 Activity；不创建新 Mission，不重新执行工具。
- 消费者业务幂等与可靠 Publisher 进程仍待实现，当前只提供存储协议并用 PG 验证。

## P0.2 Scope 与审批

- 新版 Scope 为不可变 draft，提案绑定合同、版本、base_version、Scope Hash 和证明摘要。提案不影响现有执行；只有人工批准精确基线和摘要后才生效。
- 切换在合同锁下同步更新所有关联 Task：旧 active 先 superseded，新版 active，旧活动 Mission stopped，Lease revoked，未消费 ToolCall/Approval revoked，资产重新 pending_review。预算留待对账，旧 Mission 快照不覆盖，旧 blocked Mission 不能按新 Scope 重试。
- 仅支持 `offline.observe` / 工具版本 `1` / 策略 `p0.2-offline-v1` / 动作 `observe`。URL 规范化与 Scope 静态预检不解析 DNS，也不产生请求。
- 请求摘要绑定 Task/Mission/Lease/Token/runtime/requester、工具及版本、目标/协议/端口、动作/参数、策略、Authorization/Scope 版本和 Hash。
- 参数为 <=16KiB、<=16层的 JSON 对象，递归拒绝重复键，保留数字词法和大整数。规范请求字节以 TEXT 存储（附 JSON 合法性约束），避免 JSONB 改写指数/小数词法而破坏摘要；单独的 JSONB arguments 用于检索，不作为摘要权威来源。
- 批准需要 human admin、不同于请求服务身份；过期或摘要不符拒绝。消费按 Mission->Pool->Lease->ToolCall->Approval->Ledger 锁，全部锁后独立重验时钟/租约，`approved -> consumed`、一次 admission、steps=1、Activity/Outbox/幂等结果同事务。
- `tool_admissions` 仅是离线持久化回执，不能交给未来 Executor 直接执行。同key历史返回不新建准入，不扣第二次预算；不同key也受唯一请求/审批约束。Outbox 重放不执行工具。
- Outbox 在 LIMIT 前按任务成员过滤，按 Authorization/Task 稳定排序加锁后才领取事件。回执除 dispatcher/generation 外绑定 claimed_by_principal_id，另一个同名派发服务也不能确认。
- 003 迁移不修改 001/002，不批量补成员，对旧 active Lease 失败关闭并阻断执行，保留账本/快照和升级审计。升级前停止旧业务进程；Store.Open 只读 Schema Check 是新二进制门禁，不能替代部署停止旧二进制。

## 验证命令

```bash
go -C 'E:/pentest agent/TRIDENT' test ./...
go -C 'E:/pentest agent/TRIDENT' vet ./...
python 'E:/pentest agent/TRIDENT/scripts/test-local.py'

# [01] Windows runtime/cgo 不兼容时，在独立 Linux 容器实跑竞态验收。
python 'E:/pentest agent/TRIDENT/scripts/test-linux.py'
```

`test-local.py --race` 在本机 Windows 工具链曾遇 `runtime/cgo ... cgo.exe: exit status 2`，不是测试通过。Linux 脚本采用固定 Go 1.26.3 镜像及摘要，源码只读挂载，凭据以环境变量名称转发，模块/构建缓存使用项目独立数据卷。测试缺数据库配置直接失败，不整体 Skip。

**执行网络边界：** 开发时下载依赖/镜像属于工程环境准备；离线演示和验收本身不向任何测试目标发请求，只操作独立数据库。
