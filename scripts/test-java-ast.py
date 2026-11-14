#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证受限 Java 语义模型：语法错误隔离、嵌套类、泛型重载、接口分派与注解常量折叠。"""
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
AST_FIXTURE = ROOT / "tests" / "fixtures" / "java-ast-model"


def tree_hashes(root):
    return {str(path.relative_to(root)).replace(os.sep, "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-java-ast-")
    try:
        yield Path(work)
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


def main():
    fixture_before = tree_hashes(AST_FIXTURE)
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as parent:
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                       cwd=ROOT, env=env, check=True, timeout=180)

        def invoke(*args, failure=False, retries=0):
            for attempt in range(retries + 1):
                result = subprocess.run([str(binary), *args], cwd=ROOT, env=env,
                                        capture_output=True, text=True, encoding="utf-8", timeout=180)
                if not failure and result.returncode != 0 and attempt < retries \
                        and "share access flags are incompatible" in result.stderr:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                break
            if failure:
                require(result.returncode != 0 and not result.stdout.strip(),
                        "Expected failure without success JSON: " + repr(args))
                return None
            require(result.returncode == 0, result.stderr.strip() or "CLI failed")
            return json.loads(result.stdout)

        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(AST_FIXTURE),
                          "--snapshot", str(snapshot), retries=3)
        snapshot_hash = imported["snapshot_hash"]
        manifest = json.loads((snapshot / ".trident-manifest.json").read_text(encoding="utf-8"))
        digests = {entry["path"]: entry["sha256"] for entry in manifest["entries"]}
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]
        report = invoke("audit", "java-model", *common, retries=3)

        require(report["analysis_kind"] == "java_semantic_model_v1"
                and report["coverage"]["runtime_status"] == "not_run"
                and report["schema_version"] == 1,
                "Semantic model header mismatch")

        # [02] Malformed file is rejected alone; the snapshot stays analyzable.
        require(report["partial"] is True
                and report["coverage"]["files_scanned"] == 5
                and report["coverage"]["files_rejected"] == 1,
                "Rejected file coverage mismatch")
        broken = next(item for item in report["files"]
                      if item["path"].endswith("Broken.java"))
        require(broken["parse_error"] and broken["boundaries"] == ["rejected_java_file"]
                and broken["sha256"] == digests[broken["path"]],
                "Malformed file evidence mismatch")
        require(report["coverage"]["types_indexed"] >= 14
                and report["coverage"]["methods_indexed"] >= 17,
                "Declaration coverage mismatch")

        types = {item["fqn"]: item for item in report["types"]}

        # [03] Nested classes are indexed with outer/inner symbols.
        inner = types["com.example.model.Outer.Inner"]
        require(inner["kind"] == "class"
                and types["com.example.model.Outer"]["nested"] == ["com.example.model.Outer.Inner"]
                and inner["methods"][0]["symbol"] == "com.example.model.Outer.Inner#describe()",
                "Nested class model mismatch")
        label = next(call for call in report["calls"] if call["api"] == "label")
        require(label["status"] == "resolved"
                and label["target"] == "com.example.model.Outer#label()"
                and label["target_sha256"] == digests[label["target_file"]],
                "Enclosing-class call resolution mismatch")

        # [04] Generic overloads resolve after erasure by argument type.
        picks = [call for call in report["calls"] if call["api"] == "pick"]
        require(len(picks) == 2, "Overload call coverage mismatch")
        targets = {call["arg_types"][0]: call["target"] for call in picks}
        require(targets["java.lang.String"] == "com.example.model.Overloads#pick(java.lang.String)"
                and targets["java.util.List"] == "com.example.model.Overloads#pick(java.util.List)",
                "Generic erasure overload resolution mismatch")

        # [05] Interface dispatch resolves a single implementation and keeps
        # two implementations explicitly ambiguous.
        save = next(call for call in report["calls"] if call["api"] == "save")
        require(save["status"] == "resolved"
                and save["reason"] == "interface_dispatch"
                and save["target"] == "com.example.model.JdbcStore#save(java.lang.String)",
                "Interface dispatch mismatch")
        handle = next(call for call in report["calls"] if call["api"] == "handle")
        require(handle["status"] == "ambiguous" and handle["reason"] == "ambiguous_dispatch",
                "Ambiguous dispatch mismatch")
        require(report["coverage"]["calls_resolved"] == 4
                and report["coverage"]["calls_ambiguous"] == 1
                and report["coverage"]["calls_unresolved"] == 0
                and report["coverage"]["interface_dispatches"] == 1,
                "Call coverage mismatch")

        # [06] Annotation arguments fold constants, arrays and enum constants.
        annotated = types["com.example.model.Annotated"]
        route = next(method for method in annotated["methods"] if method["name"] == "list")
        args = {item["name"]: item["value"] for item in route["annotations"][0]["args"]}
        require(route["annotations"][0]["name"] == "Route"
                and args["value"] == {"kind": "string", "text": "api/items"}
                and args["tags"]["kind"] == "array"
                and [element["text"] for element in args["tags"]["elements"]] == ["api", "read"],
                "Annotation constant folding mismatch")
        admin = next(method for method in annotated["methods"] if method["name"] == "admin")
        access = admin["annotations"][0]
        require(access["name"] == "Access"
                and access["args"][0]["value"] == {"kind": "name", "text": "com.example.model.Role.ADMIN"},
                "Enum annotation constant mismatch")
        require(report["coverage"]["annotations_indexed"] == 2
                and report["coverage"]["constants_folded"] == 1,
                "Folding coverage mismatch")

        # [07] Determinism and failure-closed CLI behavior.
        repeated = invoke("audit", "java-model", *common, retries=3)
        require(json.dumps(repeated, sort_keys=True) == json.dumps(report, sort_keys=True),
                "Semantic model output is not deterministic")
        invoke("audit", "java-model", "--snapshot", str(snapshot), failure=True)
        invoke("audit", "java-model", "--snapshot", str(snapshot),
               "--snapshot-hash", "0" * 64, failure=True)

    require(tree_hashes(AST_FIXTURE) == fixture_before, "Fixture bytes changed during verification")
    print("java-ast: PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 - CLI verification reports a single failure line
        print(f"java-ast: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
