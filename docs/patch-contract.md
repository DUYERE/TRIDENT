# R3 补丁生成、隔离验证与沙箱契约

- 日期：2026-11-13（首片 verify；同日增加 `patch propose` 与 Docker sandbox）
- 状态：已实现并完成本地真实 CLI + 真实 Java/Maven/JUnit + Docker 验收；**AI 补丁仍需人工复核，容器隔离不是 VM**。

## 1. 定位与边界

`trident patch verify` 把已 pin 的快照复制到**新的可写工作区**，应用统一 diff，在固定验证 profile 下编译并运行，最后重新校验原快照未被修改。

`trident patch propose` 在显式外发许可下调用模型生成一个统一 diff；它先在仅包含被修改文件的临时副本上做精确上下文验证，验证通过后才写出补丁。它不执行补丁、不修改原快照，也不自动把补丁应用到原仓库。

验证不执行目标网络请求。**目录隔离不是 OS 级沙箱**；`--sandbox docker` 增加容器与 `--network none` 隔离，但仍不是 VM、内核或完整系统调用边界。

## 2. 命令

```bash
trident patch propose \
  --snapshot <dir> --snapshot-hash <sha256> \
  (--finding <finding-id> | --path <snapshot-relative> [--path ...]) \
  --goal <text> --out <new-patch-file> \
  --endpoint <https-base-url> --model <model> --approve-egress \
  [--api-key-env TRIDENT_MODEL_API_KEY] [--output-parameter max_tokens|max_completion_tokens] \
  [--max-output-tokens 4096] [--timeout-seconds 120] [--allow-loopback-http]

trident patch verify \
  --snapshot <dir> --snapshot-hash <sha256> \
  --workspace <new-dir> --patch <unified.diff> \
  --profile <maven|javac|junit> \
  [--main-class <dotted.Class>] \
  [--test-class <dotted.TestClass> --test-classpath <jars-or-dirs>] \
  [--sandbox process|docker --sandbox-image <image@sha256:...> \
   --sandbox-network none|default --sandbox-memory 1g --sandbox-cpus 1 \
   --sandbox-pids 256 --sandbox-maven-repo <host-.m2>] \
  [--timeout-seconds 180] --approve-execution
```

`propose` 约束：`--out` 必须是快照之外尚不存在的文件；`--finding` 使用 `audit findings` 的 ID，或显式指定 1–4 个源码路径；最多 48 KiB 源码窗口会外发，模型只返回一个 JSON 对象 `{"patch":"...","rationale":"..."}`。补丁必须通过 `parsePatch` 与精确上下文应用验证；任何路径穿越、创建/删除/重命名、二进制、Markdown 围栏或无效 JSON 都拒绝。模型响应非 `stop`、空补丁或无法应用时不写文件。`--approve-egress` 为每次调用的显式授权，密钥只从指定环境变量读取。

1. `--workspace` 必须不存在，且不能等于或位于快照目录内；父目录必须已存在。工具仅创建该新目录。
2. `--patch` 必须是存在的普通 UTF-8 文本文件，1 B–1 MiB。
3. `--profile maven`：执行 `mvn -o -B -q -DskipTests compile`，再执行 `java -cp target/classes <main-class>`。离线模式要求本机 Maven 插件与依赖已缓存，不尝试联网。
4. `--profile javac`：编译 `src/main/java`（最多 100 个源文件、单文件 2 MiB、总量 32 MiB），再执行 `java -cp build/classes <main-class>`。
5. `--profile junit`：用 `javac` 编译 `src/main/java` 与 `src/test/java`，再执行 `java -cp build/classes:build/test-classes:<test-classpath> org.junit.runner.JUnitCore <test-class>`。JUnit/Hamcrest 等 jar 由调用者通过 `--test-classpath` 提供，不联网、不依赖 Maven Surefire；不使用 `--main-class`。
6. `--approve-execution` 是编译和运行不可信补丁代码的显式授权；缺失即拒绝，且不会创建 workspace。默认总超时 180 秒，最大 600 秒。
7. CLI 在生成报告后：`validation_passed` 退出 0；其他已生成报告的状态退出非零；参数/审批/输入错误不输出成功报告。

## 3. 工作区与补丁安全

- 复制仅通过 `Snapshot.ReadFile` 逐文件读取并校验大小与 SHA-256；不复制 `.trident-manifest.json`。复制失败清理本次新建目录。
- 仅支持已存在文本文件的统一 diff：`---/+++` 路径必须一致，拒绝 `/dev/null`、重命名、创建、删除、二进制补丁、绝对路径、`..`、反斜杠、盘符、NUL 和引号。
- 上下文必须逐行精确匹配；没有 fuzz、偏移搜索或自动三方合并。重叠/越界 hunk、行数不匹配、重复文件路径均失败。
- 补丁写入采用同目录临时文件 + rename，文件权限 0600；工作区保留供调用者检查，不自动删除已成功或失败的工作区。
- 原快照在验证后再次 `project.Open` 校验；失败则状态为 `snapshot_integrity_failed`。

## 4. 执行隔离与输出

- 不使用 Unix shell；Windows 仅使用固定的 `cmd.exe /d /s /c` 启动 `mvn`，参数不拼接模型或补丁内容。
- 验证进程使用环境白名单，仅传递 PATH、HOME、JAVA_HOME、Maven 与必要 Windows 变量；不传递 `TRIDENT_*`、数据库 URL、模型密钥或其它宿主秘密。
- stdout/stderr 各限制 64 KiB，超出标记 `output_truncated`；超时终止进程。
- `java` 的 main class 必须是点分 Java 标识符；不接受任意命令行参数。

### 4.1 Docker sandbox

- `--sandbox docker` 要求 `--sandbox-image` 以 `@sha256:` 固定 digest；拒绝 tag、未固定 digest 或任意网络名。
- 每个验证步骤运行一次性容器：`--network none`（默认）、`--memory`、`--cpus`、`--pids-limit`、`--cap-drop ALL`、`--security-opt no-new-privileges`；工作区只绑定到 `/workspace`，不传宿主环境变量。
- `--sandbox-maven-repo` 可选，将宿主 `.m2` 只读挂载到 `/root/.m2` 供离线 Maven 使用；不挂载其他宿主目录。
- 容器名唯一；非成功状态（失败/超时/启动错误）执行 `docker rm -f` 清理，避免 `--rm` 之外遗留容器。
- `maven` 与 `javac` profile 支持 docker；`junit` profile 仍只在 process 沙箱提供，因为调用者 classpath 是宿主路径。
- 这是容器级隔离，不是 VM/内核边界；镜像由调用者选择并信任。

## 5. 报告

```json
{
  "schema_version": 1,
  "status": "validation_passed|validation_failed|validation_timeout|validation_error|patch_failed|snapshot_integrity_failed|setup_failed",
  "snapshot_hash": "...",
  "workspace": {"path": "...", "files": 5, "bytes": 1644},
  "patch": {"sha256": "...", "files_changed": [{"path": "...", "additions": 1, "deletions": 1, "sha256_before": "...", "sha256_after": "..."}]},
  "validation": {"profile": "maven", "main_class": "demo.Main", "sandbox": "process|docker", "status": "...", "commands": [{"command": "...", "exit_code": 0, "status": "ok", "stdout": "...", "stderr": "...", "duration_ms": 123}]},
  "original_snapshot_intact": true,
  "runtime_status": "isolated_validation_only",
  "limitations": ["..."]
}
```

`runtime_status=isolated_validation_only` 只表示隔离副本上的编译/运行结果，不表示生产漏洞可利用或修复已上线。

## 6. 非目标

- 不自动选择或应用补丁到原仓库；AI 生成的补丁必须由人工复核。补丁质量评分是启发式，不是安全或正确性证明。
- JUnit profile 支持多个测试类、Surefire 风格 XML 报告与可选 JaCoCo agent/XML 覆盖率；不做测试发现、不保证漏洞路径被覆盖。Maven Surefire 不参与。
- Docker/gVisor sandbox 不是硬件 VM；gVisor `runsc` 是用户态内核，仍需宿主机与镜像供应链可信。
- 不证明原仓库可构建、依赖可解析、生产环境可利用性或修复有效；这些仍需独立授权和运行时验证。

## 7. 验收（2026-11-13）

- `go test ./internal/r3 -count=1`：通过（工作区复制、补丁应用、路径穿越/上下文不匹配/新建文件拒绝、审批与 profile 校验）。
- `python scripts/test-patch.py`：通过。真实 Java 17 + Maven 3.9.9：
  - 基线补丁 + Maven：`validation_failed`，Java 退出 1，输出 `injection guard missing`。
  - 安全补丁 + Maven：`validation_passed`，Java 输出 `safe`，原快照未修改。
  - 安全补丁 + javac：`validation_passed`。
  - 基线补丁 + JUnit 4.12：`validation_failed`（`Tests run: 1, Failures: 1`）。
  - 安全补丁 + JUnit 4.12：`validation_passed`（`OK (1 test)`）。
  - 未审批、错误哈希、路径穿越、上下文不匹配、已存在 workspace、workspace 位于快照内均拒绝。
  - 宿主环境注入的 `TRIDENT_MODEL_API_KEY` / `TRIDENT_DATABASE_URL` 未传入验证进程；快照与 fixture 前后字节级一致。
- 未运行：VM 级隔离、完整网络命名空间/系统调用过滤、目标网络执行、生产部署验证。

### 7.1 AI 补丁生成与 Docker sandbox 验收（2026-11-13）

- `go test ./internal/r3 -count=1`：通过（新增 `Propose` 正/负例、finding 上下文、sandbox 参数校验与 docker 命令隔离参数）。
- `python scripts/test-patch-ai.py`：通过。真实 CLI + loopback 脚本化模型（非真实 LLM）：
  - `patch propose` 严格解析 JSON，生成 `safe.patch` 等价补丁；输出文件位于快照外，快照不变。
  - process Maven：`validation_passed`；Docker sandbox（`--network none`、`--cap-drop ALL`、固定 digest `maven:3.9.9-eclipse-temurin-17@sha256:f58d…`）：`validation_passed`。
- 真实模型补丁生成：DeepSeek `deepseek-flash` 对 `tests/fixtures/java-patch` 生成参数化 SQL 补丁（`patch propose`，快照 `fd07c8…`），随后 process Maven 与 Docker sandbox 均为 `validation_passed`，原快照未修改。
- 未验证：真实项目的 AI 补丁、多文件/复杂修复、补丁质量评分、VM 级隔离、docker junit profile。

## 8. 2026-11-13 扩展（R3 修复闭环强化）

- `patch verify` JUnit 支持 `--test-class` 逗号分隔多类、`--junit-report-dir`（有界解析 `<testsuite>` 聚合）、`--jacoco-agent` + `--jacoco-report`（可选覆盖率，报告路径固定在工作区内）。覆盖率只表示观测，不证明漏洞路径或修复被覆盖。
- Docker/gVisor JUnit：classpath 条目逐个只读挂载到 `/trident-cp/<n>`，容器内完成 main/test 编译与 JUnitCore 运行；JaCoCo agent 挂载为 `/trident-jacoco.jar`。
- `--sandbox gvisor` 使用 `--runtime=runsc`，启动前通过 `docker info` 检查 runsc 是否注册；未注册时失败关闭，不回退到普通容器。
- `patch propose` 支持 `--policy` remediation policy（schema_version=1、最大文件/变更行数、禁止新增正则、首选策略）；默认策略限制 4 文件/200 行并禁止新增 `Runtime.exec`、`ObjectInputStream`、`XMLDecoder`。策略是调用者配置，不是安全证明。
- `patch repair` 在 1—5 轮内重复 propose→verify，每轮使用新的 workspace；模型失败立即停止、不重试，重复 patch SHA 停止；最终 JSON 包含每轮 proposal/validation/quality。
- `quality` 为启发式 0—100 分（validation、tests、patch size、files、regression clean），不参与通过/失败判定。
- 验收：`go test ./internal/r3` 覆盖 JUnit 摘要/XML/JaCoCo、policy、repair failure/bounds、quality、gVisor 参数；`python scripts/test-patch.py` 与 `test-patch-ai.py` 通过；真实项目 AI 补丁与硬件 VM 未验证。
