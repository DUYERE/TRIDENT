#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证统一 Finding/Hypothesis 证据模型；不执行 Java/模型。"""
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
ADVISORY = FIXTURE / "advisories" / "CVE-2022-42889.json"


def tree_hashes(root):
    return {str(path.relative_to(root)).replace(os.sep, "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-findings-")
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


def finding(report, kind, path=None):
    for entry in report["findings"]:
        if entry["kind"] != kind:
            continue
        if path is None or (entry.get("endpoint") or {}).get("path") == path:
            return entry
    raise RuntimeError(f"missing finding {kind} {path}")


def hypothesis(entry, suffix):
    for item in entry["hypotheses"]:
        if item["id"].endswith(suffix):
            return item
    raise RuntimeError(f"missing hypothesis {suffix} in {entry['id']}")


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before, "Missing synthetic Java fixture")
    require(ADVISORY.is_file(), "Missing synthetic advisory fixture")
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
            # [02] Windows may briefly deny the strict snapshot sharing mode while
            # a freshly written file is scanned; retry only that transient.
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

        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(FIXTURE), "--snapshot", str(snapshot), retries=3)
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        report = invoke("audit", "findings", *common, "--advisories", str(ADVISORY), retries=3)
        require(report["schema_version"] == 1
                and report["analysis_kind"] == "unified_finding_evidence_v1"
                and report["snapshot_hash"] == snapshot_hash,
                "Unexpected findings report identity")
        require(report["partial"] is False and len(report["findings"]) == 4,
                "Finding count mismatch")
        coverage = report["coverage"]
        require(coverage["findings_static_confirmed"] == 1
                and coverage["findings_refuted"] == 1
                and coverage["findings_inconclusive"] == 2,
                "Finding status coverage mismatch")
        require(coverage["hypotheses_supported"] == 3
                and coverage["hypotheses_unsupported"] == 1
                and coverage["hypotheses_unverified"] == 6,
                "Hypothesis coverage mismatch")
        require(coverage["sca_advisory_candidates"] == 1
                and coverage["sca_advisory_not_affected"] == 1
                and coverage["endpoints_inventoried"] == 3
                and coverage["dataflow_findings"] == 3,
                "Linked analysis coverage mismatch")
        require(coverage["java_ast"] == "not_available"
                and coverage["sca_resolution"] == "declaration_only"
                and coverage["taint_analysis"] == "bounded_lexical_multi_category"
                and coverage["runtime_status"] == "not_run"
                and coverage["dependency_reachability"] == "unverified",
                "Findings coverage overclaimed analysis")

        for entry in report["findings"]:
            require(entry["runtime_status"] == "not_run", "Runtime status upgraded")
            evidence_ids = [item["id"] for item in entry["evidence"]]
            require(len(evidence_ids) == len(set(evidence_ids)), "Duplicate evidence IDs in finding")
            runtime = hypothesis(entry, ":runtime_exploitation")
            require(runtime["status"] == "unverified" and runtime["required_evidence"],
                    "Runtime hypothesis missing or claimed")

        unsafe = finding(report, "sql_injection", "/synthetic/customers/unsafe")
        require(unsafe["status"] == "static_confirmed" and unsafe["severity"] == "high"
                and unsafe["cwe"] == "CWE-89",
                "Unsafe finding status mismatch")
        require(hypothesis(unsafe, ":source_to_sink")["status"] == "supported",
                "Unsafe flow hypothesis not supported")
        anchors = {item.get("anchor") for item in unsafe["evidence"]}
        require({"fixture:unsafe-http-source", "fixture:sql-concatenation"} <= anchors,
                "Unsafe evidence anchors missing")
        safely_pinned(unsafe, snapshot, "Unsafe")
        require(any(item["kind"] == "sink" and item["detail"] == "statement.executeQuery"
                    and item["start_line"] == 28
                    for item in unsafe["evidence"]),
                "Unsafe sink evidence missing")

        parameterized = finding(report, "sql_injection", "/synthetic/customers/parameterized")
        require(parameterized["status"] == "refuted"
                and hypothesis(parameterized, ":source_to_sink")["status"] == "unsupported"
                and hypothesis(parameterized, ":value_binding")["status"] == "supported",
                "Parameterized negative control mismatch")

        dynamic = finding(report, "sql_injection", "/synthetic/customers/dynamic")
        require(dynamic["status"] == "inconclusive"
                and "dynamic_invocation" in hypothesis(dynamic, ":source_to_sink")["reason"],
                "Dynamic finding mismatch")

        dependency = finding(report, "vulnerable_dependency")
        require(dependency["status"] == "inconclusive" and dependency["severity"] == "unknown"
                and dependency["cwe"] == "CWE-1395",
                "Advisory finding status mismatch")
        require(dependency["component"]["declared_version"] == "1.9"
                and dependency["component"]["advisory_id"] == "CVE-2022-42889"
                and dependency["component"]["declaration_pom"],
                "Advisory component mismatch")
        require(hypothesis(dependency, ":declared_version_matches_advisory")["status"] == "supported",
                "Version hypothesis not supported")
        reachability = hypothesis(dependency, ":dependency_reachable_from_http_entrypoint")
        require(reachability["status"] == "unverified" and not reachability["evidence_ids"],
                "Reachability hypothesis overclaimed")
        pom_evidence = [item for item in dependency["evidence"] if item["kind"] == "pom"]
        require(pom_evidence, "Missing POM evidence")
        for item in pom_evidence:
            actual = (snapshot / item["file"]).read_bytes()
            require(hashlib.sha256(actual).hexdigest() == item["sha256"],
                    f"POM evidence digest mismatch: {item['file']}")

        require(any(value.startswith("static_runtime_separation:") for value in report["limitations"])
                and any(value.startswith("correlation_not_exploitation:") for value in report["limitations"]),
                "Separation limitations missing")

        without = invoke("audit", "findings", *common, retries=3)
        require(len(without["findings"]) == 3
                and without["coverage"]["sca_advisory_candidates"] == 0
                and any(value.startswith("advisory_catalog_not_provided") for value in without["limitations"]),
                "Missing optional-advisory behavior")

        repeat = invoke("audit", "findings", *common, "--advisories", str(ADVISORY), retries=3)
        require(repeat == report, "Findings output is not deterministic")

        invoke("audit", "findings", "--snapshot", str(snapshot), failure=True)
        invoke("audit", "findings", *common[:-1], "0" * 64, failure=True)
        invoke("audit", "findings", *common, "--advisories", str(parent / "missing.json"), failure=True)
        require(tree_hashes(snapshot) == snapshot_before, "Findings changed its read-only snapshot")
        tampered = snapshot / "jdbc-app" / "src" / "main" / "java" / "example" / "synthetic" / "CustomerRepository.java"
        tampered.write_bytes(tampered.read_bytes() + b"\n// tampered\n")
        invoke("audit", "findings", *common, "--advisories", str(ADVISORY), failure=True)
        require(tree_hashes(FIXTURE) == fixture_before, "Original synthetic fixture was changed")

        print(json.dumps({"result": "passed", "snapshot_hash": snapshot_hash,
                          "findings": len(report["findings"]),
                          "confirmed": coverage["findings_static_confirmed"],
                          "refuted": coverage["findings_refuted"],
                          "inconclusive": coverage["findings_inconclusive"],
                          "sca_candidates": coverage["sca_advisory_candidates"],
                          "checks": ["real_cli", "no_database", "no_java_execution",
                                     "sca_endpoint_dataflow_linked", "stable_evidence_ids",
                                     "static_runtime_separated", "runtime_hypotheses_unverified",
                                     "evidence_digests_match_snapshot",
                                     "optional_advisory_catalog", "trusted_hash_required",
                                     "snapshot_unchanged", "content_tampering_rejected"],
                          "java_executed": False, "model_called": False}, ensure_ascii=False))


def safely_pinned(entry, snapshot, label):
    for item in entry["evidence"]:
        if not item.get("file") or not item.get("sha256"):
            continue
        path = snapshot / item["file"]
        require(path.is_file(), f"{label} evidence file missing: {item['file']}")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"],
                f"{label} evidence digest mismatch: {item['file']}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT findings verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
