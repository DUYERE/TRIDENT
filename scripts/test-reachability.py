#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证有界入口调用图三态（reachable/unreachable/unknown）与路径证据。"""
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
REACH_FIXTURE = ROOT / "tests" / "fixtures" / "java-reachability"
MAVEN_FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"
ADVISORY = MAVEN_FIXTURE / "advisories" / "CVE-2022-42889.json"


def tree_hashes(root):
    return {str(path.relative_to(root)).replace(os.sep, "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-reachability-")
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
    reach_before = tree_hashes(REACH_FIXTURE)
    maven_before = tree_hashes(MAVEN_FIXTURE)
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

        package_map = parent / "package-map.json"
        package_map.write_text(json.dumps({"schema_version": 1, "dependencies": {
            "org.example:lib": ["org.example.lib"]}}), encoding="utf-8")

        # [02] Three-state fixture: reachable through a service, unused, reflective.
        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(REACH_FIXTURE),
                          "--snapshot", str(snapshot), retries=3)
        snapshot_hash = imported["snapshot_hash"]
        manifest = json.loads((snapshot / ".trident-manifest.json").read_text(encoding="utf-8"))
        digests = {entry["path"]: entry["sha256"] for entry in manifest["entries"]}
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]
        report = invoke("audit", "reachability", *common, "--package-map", str(package_map), retries=3)
        require(report["analysis_kind"] == "bounded_entry_call_graph_v1"
                and report["runtime_status"] == "not_run"
                and report["coverage"]["reachable"] == 1
                and report["coverage"]["unreachable"] == 1
                and report["coverage"]["unknown"] == 1
                and report["coverage"]["entrypoints"] == 3
                and report["coverage"]["classes_indexed"] == 4,
                "Reachability coverage mismatch")
        states = {item["module"]: item for item in report["dependencies"]
                  if item["dependency"] == "org.example:lib"}
        require(set(states) == {"reachable-app", "unused-app", "reflect-app"}, "Missing module states")
        reachable = states["reachable-app"]
        require(reachable["reachability"] == "reachable" and reachable["paths"], "Reachable case failed")
        path = reachable["paths"][0]
        require(len(path["steps"]) == 2
                and path["steps"][0]["relation"] == "entry"
                and path["steps"][0]["class"] == "ReachController"
                and path["steps"][1]["class"] == "ReachService"
                and path["import"]["import"] == "org.example.lib.LibApi"
                and path["import"]["line"] >= 1,
                "Reachability path evidence mismatch")
        for step in path["steps"]:
            require(step["sha256"] == digests[step["file"]] and step["line"] >= 1,
                    "Reachability step digest mismatch")
        require(states["unused-app"]["reachability"] == "unreachable"
                and states["unused-app"]["reason"] == "no_path_from_module_entrypoints",
                "Unused case failed")
        require(states["reflect-app"]["reachability"] == "unknown"
                and states["reflect-app"]["reason"] == "reflection_not_resolved",
                "Reflective case failed")
        require("import_reachable" not in report["dependencies"][0], "Legacy classification leaked")
        require("reachability_bounded_call_graph" in " ".join(report["limitations"]),
                "Bounded call graph limitation missing")
        repeated = invoke("audit", "reachability", *common, "--package-map", str(package_map), retries=3)
        require(repeated == report, "Reachability report is not deterministic")
        unmapped = invoke("audit", "reachability", *common, retries=3)
        require(unmapped["coverage"]["unknown"] == unmapped["coverage"]["dependencies"]
                and unmapped["coverage"]["reachable"] == 0, "Unmapped dependencies must stay unknown")

        # [03] Findings: an unreachable dependency hypothesis is unsupported, not a vulnerability.
        maven_snapshot = parent / "maven-snapshot"
        maven_imported = invoke("project", "import", "--source", str(MAVEN_FIXTURE),
                                "--snapshot", str(maven_snapshot), retries=3)
        maven_map = parent / "maven-map.json"
        maven_map.write_text(json.dumps({"schema_version": 1, "dependencies": {
            "org.apache.commons:commons-text": ["org.apache.commons.text"]}}), encoding="utf-8")
        findings = invoke("audit", "findings", "--snapshot", str(maven_snapshot),
                          "--snapshot-hash", maven_imported["snapshot_hash"],
                          "--advisories", str(ADVISORY), "--package-map", str(maven_map), retries=3)
        require(findings["coverage"]["dependency_reachability"] == "bounded_entry_call_graph",
                "Findings did not run bounded reachability")
        candidates = [item for item in findings["findings"] if item["kind"] == "vulnerable_dependency"]
        require(len(candidates) == 1, "Expected exactly one dependency candidate")
        candidate = candidates[0]
        hypothesis = next(item for item in candidate["hypotheses"]
                          if item["id"].endswith(":dependency_reachable_from_http_entrypoint"))
        # FixtureText imports commons-text but no controller reaches it.
        require(hypothesis["status"] == "unsupported"
                and hypothesis["reason"] == "no_path_from_entrypoint_in_bounded_call_graph"
                and hypothesis["evidence_ids"], "Unreachable hypothesis status mismatch")
        require(candidate["runtime_status"] == "not_run" and candidate["status"] == "inconclusive",
                "Static status was upgraded")
        require(all(item["kind"] != "reachability_step" for item in candidate["evidence"]),
                "Unreachable finding must not fabricate path evidence")
        no_map = invoke("audit", "findings", "--snapshot", str(maven_snapshot),
                        "--snapshot-hash", maven_imported["snapshot_hash"],
                        "--advisories", str(ADVISORY), retries=3)
        no_map_hypothesis = next(item for item in
                                 [entry for entry in no_map["findings"]
                                  if entry["kind"] == "vulnerable_dependency"][0]["hypotheses"]
                                 if item["id"].endswith(":dependency_reachable_from_http_entrypoint"))
        require(no_map["coverage"]["dependency_reachability"] == "unverified"
                and no_map_hypothesis["status"] == "unverified"
                and not no_map_hypothesis["evidence_ids"],
                "Without a package map reachability must stay unverified")

        # [04] Malformed package maps fail closed.
        bad_map = parent / "bad-map.json"
        bad_map.write_text(json.dumps({"schema_version": 1, "dependencies": {
            "org.example:lib": ["../escape"]}}), encoding="utf-8")
        invoke("audit", "reachability", *common, "--package-map", str(bad_map), failure=True)

        require(tree_hashes(REACH_FIXTURE) == reach_before, "Reachability fixture changed")
        require(tree_hashes(MAVEN_FIXTURE) == maven_before, "Maven fixture changed")
        print(json.dumps({"result": "passed", "snapshot_hash": snapshot_hash,
                          "checks": ["real_cli", "three_states", "entry_to_import_path",
                                     "file_sha256_and_line", "reflection_unknown",
                                     "deterministic", "unmapped_unknown", "findings_unsupported",
                                     "findings_unverified_without_map", "static_status_kept",
                                     "malformed_package_map_rejected", "fixtures_unchanged"],
                          "maven_executed": False, "java_executed": False,
                          "model_called": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT reachability verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
