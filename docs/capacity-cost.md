# 容量与成本估算模型（P2-3）

估算方法与实测样本，**不构成 SLA**。所有实测数据来自本机一次性容器与合成数据；生产容量承诺必须用真实项目、生产硬件与真实负载重新测量。每节给出「实测样本 → 估算公式 → 复核要求」。

## 1. 备份与恢复（RTO/RPO）

实测样本（`scripts/test-backup-scale.py`，2026-11-14，Windows amd64 / postgres:18 容器）：

| 阶段 | 数据 | 实测 |
|---|---|---|
| 灌入合成数据 | 50 万 principals + 100 万 activities + 20 万 outbox_events + 2000 tasks | 19.1s，库体积 624 MB |
| pg_dump（custom，compress=6） | 同上 | 3.6s，归档 37 MB（压缩比约 16:1） |
| pg_restore 到新库 | 同上 | 6.7s |
| `trident check` + 全表行数核对 | 5 张表 | 3.1s |
| **RTO（restore + verify）** | 624 MB | **9.8s** |
| RPO 窗口 | 仅定期 pg_dump 策略 | dump 后写入 5000 行全部不在恢复点内 |

估算公式：

- `RTO ≈ (数据库体积 / restore 吞吐) + 校验时间`；本机 restore 吞吐约 **105 MB/s**（624 MB / 5.9s），校验约 3–5s 基数 + 行数核对耗时。
- `备份窗口 ≈ 数据库体积 / dump 吞吐`（本机约 175 MB/s 逻辑数据）；归档体积 ≈ 体积 × 0.06（JSONB 重复内容压缩比更高）。
- **RPO 由备份策略决定，不由工具决定**：仅每日 pg_dump → 最大丢失窗口 24h；`pg_dump` + WAL 归档/流复制 → 秒级。生产必须声明所用策略并演练。

复核要求：真实数据分布（JSONB 体积、TOAST、索引数量都会改变吞吐）、生产磁盘/网络、真实恢复流程（含角色重建与 `trident check`）、以及按上述公式重测。

## 2. 静态分析容量

实测样本（`scripts/benchmark.py 3`，小合成 fixture，中位耗时 57–84 ms/命令）：

- 冷分析成本按快照规模近似线性增长；引擎内建上限显式有界：`reach` 最多 2000 个 Java 文件/2MB 单文件/8 跳路径深度/2 万边；dataflow 为有界污点传播。
- 控制台语义：**每个快照一次冷分析**（失败也缓存为终态），后续全部缓存命中；`/api/metrics` 的 `analysis.runs_total` 与 `cache_hits_total` 可直接观测冷热比。

估算公式：`冷分析耗时 ≈ 基准 × (文件数 / 3 fixture 文件) × 复杂度因子`。fixture 太小（3–5 文件），外推大项目必须重新基准化：对目标仓库跑 `trident audit findings` 一次并记录 wall-clock，即为该快照的真实冷分析成本。

复核要求：真实项目规模基准、并发控制台会话数（缓存互斥，冷分析串行）、依赖公告目录规模。

## 3. 数据库增长

实测样本：100 万 activities（detail JSONB ≈ 200B）+ 20 万 outbox_events（payload ≈ 300B）≈ 350 MB 表数据。

估算公式：`存储 ≈ 每行字节 × 行数 × (1 + 索引/TOAST 开销约 0.3–1.0)`；审计类表（`activities`、`outbox_events`、`authorization_events`）是增长主体，`outbox_events` 带 `published_at` 语义可归档清理（归档属于运维策略，工具不自动删除——迁移与不可变审计边界见 findings/governance 契约）。

复核要求：真实写入速率（每任务 activities/outbox 行数）、保留策略、磁盘预算。

## 4. 模型成本（OpenAI Chat Completions）

**未实测**：live-model 验收仍处于 pending（需要逐次授权、真实 API key 与费用上限），以下仅为公式。

- `成本 = Σ(每次调用 输入 tokens × 输入单价 + 输出 tokens × 输出单价)`
- 输入 tokens ≈ 系统/工具描述（固定）+ 每步注入的只读结果摘要（随快照规模增长）；输出 tokens ≈ 计划与结论文本（每次调用几十至数百行）。
- Agent 每步一个调用，步数受预算账本（`budget_ledgers.kind='tokens'`）硬约束；预算上限是主要成本控制手段。
- 接入后复核要求：按真实快照记录每步 token 数（`agent export` 输出）、单快照总成本、失败重试率。

## 5. 监控联调实测（P2-3）

`scripts/test-monitoring.py`（2026-11-14，Docker Desktop）验证了生产监控链路：

1. Prometheus v2.53.0 以 Bearer 令牌抓取控制台 `GET /metrics`（target up）；
2. `trident_console_*` 指标可查询（build_info/uptime/requests/analysis 计数器）；
3. `alerts.yml` 规则评估后经 Alertmanager v0.27.0 webhook 端到端送达（探针告警）；
4. 每次抓取都落在 JSONL 审计日志（`token_id` 归因，状态 200）。

部署注意：控制台只绑定 loopback（安全边界）；Windows/macOS Docker Desktop 用 `host.docker.internal` 抓宿主 loopback，Linux 需 socat sidecar 或宿主网络，**不要放宽控制台绑定**。镜像当前为 tag pin，生产必须 digest pin。Prometheus→Alertmanager 首次通知可能因 gossip settle 重试延迟数分钟，告警验收窗口按分钟计。
