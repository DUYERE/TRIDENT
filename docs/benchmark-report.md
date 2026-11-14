# 基准报告（2026-11-14）

命令：`python scripts/benchmark.py 3`

环境：Windows amd64，Go 1.27.1。构建耗时 2448 ms；每个样本/命令执行 3 次，取中位数。

## 结果摘要

| fixture | 命令 | 中位耗时 (ms) | 输出字节 |
|---|---|---:|---:|
| java-maven | sca inspect | 70.4 | 4,991 |
| java-maven | sca tree | 61.4 | 2,455 |
| java-maven | audit endpoints | 62.4 | 4,332 |
| java-maven | audit dataflow | 69.3 | 10,736 |
| java-maven | audit findings | 70.7 | 24,337 |
| java-maven | audit sarif | 83.6 | 9,855 |
| java-maven | audit reachability | 63.5 | 2,179 |
| java-advanced-sinks | audit dataflow | 60.5 | 22,048 |
| java-advanced-sinks | audit findings | 62.7 | 70,220 |
| java-advanced-sinks | audit sarif | 64.2 | 27,580 |
| java-flow-gaps | audit dataflow | 57.5 | 31,745 |
| java-flow-gaps | audit findings | 60.7 | 102,098 |
| java-flow-gaps | audit sarif | 67.8 | 39,057 |
| gradle-basic | audit findings | 59.4 | 4,379 |

完整逐项结果（含 min/max）由命令直接输出，未在本文件复制全部 28 项。

## 解释与限制

- 仅测 wall-clock 与 JSON 输出字节；不包含数据库、模型、网络、Maven/Java/Gradle 执行。
- 样本均为小型合成 fixture，不能外推大型项目的分析成本。
- `audit findings` 现在包含 authz finding，输出字节较旧基准增加；这是功能变化，不是性能回退。
- 基准不构成 SLA；生产容量评估需要真实项目、并发、数据库与模型调用数据。
