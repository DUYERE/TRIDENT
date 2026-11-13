#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证 Spring MVC 入口清单；不编译/执行 Java。"""
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
FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    """[02] Windows may briefly retain the launched executable; retry only our new directory."""
    work = tempfile.mkdtemp(prefix="trident-audit-")
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


def endpoint(report, path):
    for entry in report["endpoints"]:
        if entry["path"] == path:
            return entry
    raise RuntimeError(f"missing endpoint {path}")


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before, "Missing synthetic Java fixture")
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                       cwd=ROOT, env=env, check=True, timeout=180)

        def invoke(*args, failure=False, retries=0):
            # [03] Windows may briefly deny the strict snapshot sharing mode while
            # a freshly written file is scanned. Retry only that exact transient.
            for attempt in range(retries + 1):
                result = subprocess.run([str(binary), *args], cwd=ROOT, env=env,
                                        capture_output=True, text=True, encoding="utf-8", timeout=120)
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

        # [03] Import the local synthetic fixture directly; the snapshot importer
        # accepts only explicitly supported local filesystems.
        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(FIXTURE), "--snapshot", str(snapshot), retries=3)
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        report = invoke("audit", "endpoints", *common, retries=3)
        require(report["schema_version"] == 1
                and report["analysis_kind"] == "http_annotation_inventory"
                and report["snapshot_hash"] == snapshot_hash,
                "Unexpected endpoint report identity")
        require(report["partial"] is False
                and report["coverage"]["controllers_found"] == 1
                and report["coverage"]["endpoints_found"] == 3
                and report["coverage"]["java_files_scanned"] >= 6,
                "Endpoint coverage mismatch")
        require(len(report["controllers"]) == 1, "Unexpected controller count")
        controller = report["controllers"][0]
        require(controller["class"] == "CustomerController"
                and controller["symbol"] == "example.synthetic.CustomerController"
                and controller["base_paths"] == ["/synthetic/customers"]
                and controller["base_path_status"] == "resolved",
                "Controller/base path mismatch")
        unsafe = endpoint(report, "/synthetic/customers/unsafe")
        require(unsafe["http_methods"] == ["GET"]
                and unsafe["method"] == "unsafe"
                and unsafe["symbol"] == "example.synthetic.CustomerController.unsafe"
                and unsafe["path_status"] == "resolved"
                and unsafe["anchor"] == "fixture:unsafe-http-source",
                "Unsafe endpoint mismatch")
        require(len(unsafe["parameters"]) == 1
                and unsafe["parameters"][0]["name"] == "name"
                and unsafe["parameters"][0]["type"] == "String"
                and unsafe["parameters"][0]["bindings"] == ["RequestParam"]
                and unsafe["parameters"][0]["binding_name"] == "name",
                "Parameter binding mismatch")
        require(endpoint(report, "/synthetic/customers/parameterized")["anchor"] == "fixture:safe-http-source",
                "Parameterized anchor mismatch")
        require(endpoint(report, "/synthetic/customers/dynamic")["anchor"] == "fixture:dynamic-http-source",
                "Dynamic anchor mismatch")
        require(all(entry["class"] == "CustomerController" for entry in report["endpoints"]),
                "Endpoint was attributed to a non-controller")
        require(report["coverage"]["java_ast"] == "not_available"
                and report["coverage"]["taint_analysis"] == "not_run"
                and report["coverage"]["runtime_status"] == "not_run",
                "Audit coverage overclaimed analysis")

        # [04] Trust anchors and snapshot integrity fail closed.
        invoke("audit", "endpoints", "--snapshot", str(snapshot), failure=True)
        invoke("audit", "endpoints", *common[:-1], "0" * 64, failure=True)
        require(tree_hashes(snapshot) == snapshot_before, "Audit changed its read-only snapshot")
        tampered = snapshot / "jdbc-app" / "src" / "main" / "java" / "example" / "synthetic" / "CustomerController.java"
        tampered.write_bytes(tampered.read_bytes() + b"\n// tampered\n")
        invoke("audit", "endpoints", *common, failure=True)
        require(tree_hashes(FIXTURE) == fixture_before, "Original synthetic fixture was changed")

        print(json.dumps({"result": "passed", "snapshot_hash": snapshot_hash,
                          "java_files": report["coverage"]["java_files_scanned"],
                          "controllers": report["coverage"]["controllers_found"],
                          "endpoints": report["coverage"]["endpoints_found"],
                          "checks": ["real_cli", "no_database", "no_java_execution",
                                     "controller_base_path", "get_routes", "request_param_binding",
                                     "fixture_anchors", "non_controller_ignored",
                                     "trusted_hash_required", "source_unchanged",
                                     "snapshot_unchanged", "content_tampering_rejected"],
                          "java_executed": False, "model_called": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT endpoint inventory verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
