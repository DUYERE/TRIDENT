# 派生索引缓存契约

## 1. 定位

`trident audit endpoints --cache-dir <dir>` 可选复用每文件端点清单的派生索引。缓存只加速同一快照/文件 SHA-256 的重复分析，不改变分析语义，也不产生新的漏洞结论。

- 缓存目录必须位于快照之外；缓存目录与快照目录任一方向重叠都拒绝。
- 默认不启用缓存；未提供 `--cache-dir` 时 `coverage.cache=not_used`。
- 不访问网络、模型、数据库、Maven 或 Java；不执行项目代码。

## 2. 缓存键与内容

- 键：`SHA-256(tool_version, "endpoint-inventory-v1", file_sha256)`；参数与工具版本变化会使旧条目失效。
- 内容：单文件解析出的控制器/端点元数据（路径、HTTP 方法、注解、参数、文件相对路径、文件 SHA-256、行号）。
- **不存源码、源码片段、凭据、Cookie、环境变量或密钥**；`scripts/test-cache.py` 以源码标记扫描缓存文件。
- 条目为 JSON，`schema_version=1` 且带 `kind`/`key`/`tool_version` 校验；单个条目上限 8 MiB。

## 3. 读取与写入

1. 读取时缺失条目为 miss；损坏、schema/版本/键不匹配或无法解码的条目视为 `ErrCorrupt`，不信任其内容，重新解析后覆盖写入。
2. 写入使用同目录临时文件 + 原子重命名，文件权限 `0600`、目录 `0700`；不写入快照。
3. 只缓存成功解析的文件；解析失败文件不缓存，并在每次运行时重新报告 `rejected_java`。

## 4. 输出契约

`audit endpoints` 的 `coverage` 新增：

- `cache`：`not_used|miss|hit|partial`。启用缓存且全部文件命中为 `hit`；全部未命中为 `miss`；其余为 `partial`。
- `cache_files_hit`/`cache_files_miss`：命中和重新解析的文件数（0 时省略）。
- `cache_corrupt`：损坏条目数（0 时省略）。

启用缓存时追加限制：

- `cache_derived_index_only`：缓存只含端点元数据，不含源码。
- `cache_key_file_sha_tool_version`：仅当文件 SHA-256、工具版本与提取参数一致时才复用。
- 出现损坏条目时追加 `cache_entry_corrupt_rebuilt`。

缓存命中/未命中不影响 `endpoints[]`、`controllers[]`、`coverage` 中的非缓存计数或 limitations 的语义内容；同一输入的冷/热运行结果应一致。

## 5. 并发与失效

- 不提供跨进程锁；并发写同一键时后写入者原子覆盖，读取者要么看到完整旧条目，要么看到完整新条目。
- 快照文件内容变化 → 新文件 SHA-256 → 新键；未变化文件继续命中，形成局部重建。
- 工具版本或提取参数变化 → 全部旧条目不再命中（键不同）。
- 不做分布式缓存、不做跨机器共享、不自动清理旧条目。

## 6. 验收

- `go test ./internal/cache`：往返、缺失、工具版本不匹配、损坏条目、非法 kind/key、缓存不含源码。
- `python scripts/test-cache.py`：冷启动 `miss` → 热运行 `hit` 且端点结果与冷运行一致、输出字节一致；缓存文件全为 JSON 且不含源码标记；损坏一个条目后 `partial` + `cache_corrupt` + `cache_entry_corrupt_rebuilt`，结果不变；修改一个文件后同一缓存 `partial`（其余文件结果不变）；缓存与快照重叠、缓存路径为文件均失败关闭且快照字节不变。
- `python scripts/benchmark.py 3 --baseline <baseline.json> --max-ratio <n>`：按相对中位数比较，超过倍数阈值返回非零；不使用绝对时间阈值。
