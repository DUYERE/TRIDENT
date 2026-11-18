#!/usr/bin/env python
"""[java-mainline] Java 主线检测力真实 CLI 验收。

覆盖：MyBatis #{} / ${} 建模、框架生成片段不误报、默认低噪声语义、
--emit-unobserved 兼容、脱离 HTTP 入口的 sink 锚定、确定性与只读边界。
不编译/执行 Java，不访问网络，不调用模型。
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-mybatis-sinks"
MAPPER = "src/main/resources/mapper/UserMapper.xml"


def tree_hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-java-mainline-")
    try:
        yield work
    finally:
        for attempt in range(40):
            try:
                shutil.rmtree(work)
                break
            except FileNotFoundError:
                break
            except OSError:
                if attempt == 39:
                    print(f"WARNING: temporary verification directory retained: {work}", file=sys.stderr)
                else:
                    time.sleep(0.25)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def by_id(report, finding_id):
    for item in report["findings"]:
        if item["id"] == finding_id:
            return item
    return None


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before, "缺少 Java 主线 fixture")
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                       cwd=ROOT, env=env, check=True, timeout=180)

        def invoke(*args, failure=False):
            result = subprocess.run([str(binary), *args], cwd=ROOT, env=env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=180)
            if failure:
                require(result.returncode != 0 and not result.stdout.strip(),
                        f"应失败关闭但成功或输出 JSON: {args!r}")
                return None
            require(result.returncode == 0, result.stderr.strip() or f"CLI failed: {args!r}")
            return result.stdout

        snapshot = parent / "snapshot"
        imported = json.loads(invoke("project", "import", "--source", str(FIXTURE),
                                     "--snapshot", str(snapshot)))
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        default_raw = invoke("audit", "dataflow", *common)
        compat_raw = invoke("audit", "dataflow", *common, "--emit-unobserved")
        anchors_raw = invoke("audit", "dataflow", *common, "--include-sink-anchors")
        sinks_raw = invoke("audit", "sinks", *common)
        current, legacy, merged, sinks = (json.loads(x) for x in
                                          (default_raw, compat_raw, anchors_raw, sinks_raw))

        require(current["analysis_kind"] == "source_sink_multi_category_v2" and
                legacy["analysis_kind"] == "source_sink_multi_category_v1",
                "默认/兼容模式未用不同 analysis_kind 标识语义")
        require(current["tool_version"].endswith("source-sink-flow-v14"), "工具版本未升级")
        require(current["coverage"]["unobserved_paths"] > 0 and
                legacy["coverage"]["unobserved_paths"] == 0,
                "无观察路径未按默认语义计入 coverage")
        require(all(item["evidence_strength"] != "unobserved" for item in current["findings"]),
                "默认报告仍包含无观察 finding")
        print("[01] 默认低噪声输出与 v1 兼容开关: PASS")

        orm = current["orm"]
        require(orm["mappers"] and any(m["namespace"] == "demo.UserMapper" for m in orm["mappers"]),
                "Mapper 命名空间未解析")
        statements = {item["id"]: item for item in orm["statements"]}
        assessments = {item["assessment"] for item in orm["statements"]}
        require(len(orm["statements"]) >= 6, f"ORM 语句过少: {len(orm['statements'])}")
        require({"parameterized", "substitution", "framework_fragment"} <= assessments,
                f"ORM 判定分级缺失: {assessments}")
        require(any(item["kind"] == "annotation" for item in orm["statements"]),
                "注解 SQL 未被解析")
        require(current["coverage"]["mybatis_refuted"] == 1 and
                current["coverage"]["mybatis_confirmed"] == 1,
                "MyBatis 证据计数不正确")
        print(f"[02] MyBatis XML/注解解析与 {len(orm['statements'])} 条语句分级: PASS")

        unsafe = by_id(current, "CWE-89:/users/order:column")
        require(unsafe is not None and unsafe["status"] == "static_confirmed" and
                unsafe["evidence_strength"] == "sink" and
                unsafe["orm"]["assessment"] == "substitution" and
                unsafe["sink"]["file"] == MAPPER and unsafe["sink"]["line"] > 0,
                "${} 字符串替换未被确认为 SQL 拼接证据")
        require(by_id(current, "CWE-89:/users/find:name") is None,
                "#{} 参数绑定不应作为漏洞 finding 输出")
        safe = by_id(legacy, "CWE-89:/users/find:name")
        require(safe is not None and safe["status"] == "refuted" and
                safe["orm"]["assessment"] == "parameterized" and
                safe["protection"]["file"] == MAPPER,
                "兼容模式未保留 #{} refuted 证据")
        require(not any(item["status"] == "static_confirmed" and item["cwe"] == "CWE-89"
                        and "WhereClause" in json.dumps(item, ensure_ascii=False)
                        for item in current["findings"]),
                "框架生成片段 ${} 被误报为注入")
        print("[03] #{} 反驳 / ${} 确认 / 框架片段不误报: PASS")

        anchor_ids = {item["api"] + ":" + item["symbol"] for item in sinks["anchors"]}
        require(sinks["analysis_kind"] == "sink_anchored_v1" and len(sinks["anchors"]) >= 2,
                "非入口 sink 锚点缺失")
        require(any(item["symbol"] == "OfflineJobs.main" and "readObject" in item["api"]
                    for item in sinks["anchors"]), "无 controller 的反序列化 sink 未定位")
        require(any(item["symbol"] == "OfflineJobs.scheduled" and item["api"] == "exec" and
                    item["parameter_reachable"] for item in sinks["anchors"]),
                "非入口命令 sink 与参数可达性未定位")
        require(all(item["status"] == "inconclusive" and item["runtime_status"] == "not_run"
                    and item["evidence_strength"] in ("sink_observed", "parameter_reachable")
                    for item in sinks["anchors"]),
                "sink 锚点被提升为可利用结论")
        require(all(item["file"] and len(item["sha256"]) == 64 and item["line"] > 0
                    for item in sinks["anchors"]), "sink 锚点缺少快照证据")
        require(len(merged.get("sink_anchors", [])) >= 1 and
                merged["coverage"]["sink_anchors"] >= 1,
                "--include-sink-anchors 未合并锚点")
        require(len(anchor_ids) == len(sinks["anchors"]), "sink 锚点未去重")
        print(f"[04] 脱离 HTTP 入口的 {len(sinks['anchors'])} 条 sink 锚点: PASS")

        for args, expected in ((("audit", "dataflow", *common), default_raw),
                               (("audit", "sinks", *common), sinks_raw)):
            require(invoke(*args) == expected, f"输出不确定: {args[:2]}")
        print("[05] 两类报告字节级确定性: PASS")

        invoke("audit", "dataflow", "--snapshot", str(snapshot),
               "--snapshot-hash", "0" * 64, failure=True)
        invoke("audit", "sinks", "--snapshot", str(snapshot),
               "--snapshot-hash", "0" * 64, failure=True)
        print("[06] 错误快照哈希失败关闭: PASS")

        require(tree_hashes(FIXTURE) == fixture_before, "fixture 字节被修改")
        require(tree_hashes(snapshot) == snapshot_before, "快照字节被修改")
        print("[07] 样本与快照字节不变（无 Java/Maven 执行、无网络、无模型）: PASS")
        print("TRIDENT Java mainline acceptance passed.")


if __name__ == "__main__":
    main()
