#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证离线 Maven 声明分析与固定公告匹配；不运行 Maven/Java。"""
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
SOURCE = ROOT / "tests" / "fixtures" / "java-maven"
ADVISORY = SOURCE / "advisories" / "CVE-2022-42889.json"


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    """[02] Windows may briefly retain the launched executable; retry only our new directory."""
    work = tempfile.mkdtemp(prefix="trident-sca-")
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


def dependency(report, module, artifact):
    for entry in report["dependencies"]:
        if entry["module"] == module and entry["artifact_id"] == artifact:
            return entry
    raise RuntimeError(f"missing dependency {module}:{artifact}")


def main():
    before = tree_hashes(SOURCE)
    require(before and ADVISORY.is_file(), "Missing synthetic Java/advisory fixture")
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

        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(SOURCE), "--snapshot", str(snapshot), retries=3)
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        report = invoke("sca", "inspect", *common, "--advisories", str(ADVISORY), retries=3)
        require(report["schema_version"] == 1 and report["analysis_kind"] == "maven_declaration_inventory",
                "Unexpected SCA report identity")
        require(report["partial"] is False and report["snapshot_hash"] == snapshot_hash,
                "Snapshot binding or partial coverage mismatch")
        require(report["project"]["build_system"] == "Maven"
                and report["project"]["pom_count"] == 3
                and report["project"]["module_count"] == 2
                and report["project"]["root_poms"] == ["pom.xml"],
                "Project/module identification mismatch")
        require(report["coverage"]["dependencies_declared"] == 6
                and report["coverage"]["dependencies_resolved"] == 6
                and report["coverage"]["dependencies_unresolved"] == 0,
                "Dependency coverage mismatch")
        candidate = dependency(report, "jdbc-app", "commons-text")
        require(candidate["version"] == "1.9" and candidate["scope"] == "compile"
                and candidate["management_pom"] == "pom.xml"
                and candidate["property"] == "commons-text.version"
                and candidate["property_pom"] == "pom.xml"
                and candidate["version_status"] == "resolved",
                "Parent property/dependencyManagement resolution mismatch")
        control = dependency(report, "advisory-control", "commons-text")
        require(control["version"] == "1.10.0"
                and control["management_pom"] == "pom.xml"
                and control["property_pom"] == "advisory-control/pom.xml",
                "Child property override did not apply to managed version")
        require(not any(entry["module"] == "." for entry in report["dependencies"]),
                "dependencyManagement was misreported as an imported dependency")
        require(len(report["advisory_matches"]) == 2, "Unexpected advisory match count")
        matches = {match["module"]: match for match in report["advisory_matches"]}
        require(matches["jdbc-app"]["version_status"] == "version_matched"
                and matches["jdbc-app"]["finding_status"] == "candidate"
                and matches["jdbc-app"]["declared_version"] == "1.9"
                and matches["jdbc-app"]["input_reachability"] == "unknown",
                "Candidate advisory match mismatch")
        require(matches["advisory-control"]["version_status"] == "not_affected"
                and matches["advisory-control"]["finding_status"] == "none"
                and "CVE-2022-42889" in matches["advisory-control"]["assessment_scope"],
                "Control advisory match mismatch")
        require(report["coverage"]["maven_executed"] is False
                and report["coverage"]["transitive_tree"] == "not_available"
                and report["coverage"]["artifact_hashes"] == "not_available"
                and report["coverage"]["runtime_status"] == "not_run",
                "SCA coverage overclaimed execution")
        require(report["advisories"][0]["all_cves_checked"] is False,
                "Advisory fixture overclaimed all-CVE coverage")

        # [03] Without an explicit catalog no matching is invented.
        bare = invoke("sca", "inspect", *common, retries=3)
        require(bare["coverage"]["advisories_loaded"] == 0
                and bare["advisory_matches"] == []
                and any("advisory_matching_disabled" in item for item in bare["limitations"]),
                "Advisory matching ran without an explicit catalog")

        # [04] Malformed catalog and missing trust anchors fail closed.
        bad_advisory = parent / "bad.json"
        bad_advisory.write_text(json.dumps({"advisory_id": "CVE-X", "ecosystem": "npm"}),
                                encoding="utf-8")
        invoke("sca", "inspect", *common, "--advisories", str(bad_advisory), failure=True)
        invoke("sca", "inspect", "--snapshot", str(snapshot), failure=True)
        invoke("sca", "inspect", *common, "--snapshot-hash", "0" * 64, failure=True)

        require(tree_hashes(SOURCE) == before, "Original synthetic source was changed")
        require(tree_hashes(snapshot) == snapshot_before, "SCA changed its read-only snapshot")

        # [05] Content tampering must abort, not produce partial.success output.
        tampered = snapshot / "jdbc-app" / "pom.xml"
        tampered.write_bytes(tampered.read_bytes() + b"\n<!-- tampered -->\n")
        invoke("sca", "inspect", *common, "--advisories", str(ADVISORY), failure=True)

        print(json.dumps({"result": "passed", "snapshot_hash": snapshot_hash,
                          "poms": report["project"]["pom_count"],
                          "modules": report["project"]["module_count"],
                          "dependencies": report["coverage"]["dependencies_declared"],
                          "advisory_matches": len(report["advisory_matches"]),
                          "checks": ["real_cli", "no_database", "declaration_only",
                                     "parent_property_inheritance", "child_property_override",
                                     "dependency_management_not_import", "exact_version_candidate",
                                     "exact_version_control", "no_catalog_no_matching",
                                     "malformed_catalog_rejected", "trusted_hash_required",
                                     "source_unchanged", "snapshot_unchanged",
                                     "content_tampering_rejected"],
                          "maven_executed": False, "java_executed": False,
                          "model_called": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT SCA verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
