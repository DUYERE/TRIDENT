"""Supply-chain, reachability and SARIF acceptance on real CLI output.

No database, model, network, Maven or Java execution is used. All snapshots are
pinned imports of synthetic fixtures.
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
MAVEN_FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"
GRADLE_FIXTURE = ROOT / "tests" / "fixtures" / "gradle-basic"
ADVISORY = MAVEN_FIXTURE / "advisories" / "CVE-2022-42889.json"


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-intel-")
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


def main():
    maven_before = tree_hashes(MAVEN_FIXTURE)
    gradle_before = tree_hashes(GRADLE_FIXTURE)
    require(maven_before and gradle_before, "Missing fixtures")
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
                                    capture_output=True, text=True, encoding="utf-8", timeout=120)
            if failure:
                require(result.returncode != 0 and not result.stdout.strip(),
                        "Expected failure without success JSON: " + repr(args))
                return None
            require(result.returncode == 0, result.stderr.strip() or "CLI failed")
            return json.loads(result.stdout)

        # [01] Java snapshot: SARIF, import reachability and module tree.
        snapshot = parent / "java-snapshot"
        imported = invoke("project", "import", "--source", str(MAVEN_FIXTURE), "--snapshot", str(snapshot))
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        sarif = invoke("audit", "sarif", *common)
        require(sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json"),
                "SARIF identity mismatch")
        require(len(sarif["runs"]) == 1 and len(sarif["runs"][0]["results"]) > 0
                and len(sarif["runs"][0]["tool"]["driver"]["rules"]) > 0,
                "SARIF results or rules missing")
        for result in sarif["runs"][0]["results"]:
            require(result["properties"]["runtime_status"] == "not_run",
                    "SARIF upgraded runtime_status")
            require(result["locations"] and result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1,
                    "SARIF location missing")

        package_map = parent / "package-map.json"
        package_map.write_text(json.dumps({
            "schema_version": 1,
            "dependencies": {"org.apache.commons:commons-text": ["org.apache.commons.text"]},
        }), encoding="utf-8")
        reach = invoke("audit", "reachability", *common, "--package-map", str(package_map))
        require(reach["coverage"]["imports_parsed"] > 0 and reach["coverage"]["entrypoints"] > 0
                and reach["coverage"]["unreachable"] >= 1 and reach["coverage"]["unknown"] >= 1
                and reach["coverage"]["reachable"] == 0,
                "Bounded reachability coverage mismatch")
        states = {entry["module"]: entry["reachability"] for entry in reach["dependencies"]
                  if entry["dependency"] == "org.apache.commons:commons-text"}
        require(states.get("jdbc-app") == "unreachable" and states.get("advisory-control") == "unknown"
                and all(entry["runtime_status"] == "not_run" for entry in reach["dependencies"]),
                "Bounded reachability state mismatch")
        unmapped = invoke("audit", "reachability", *common)
        require(unmapped["coverage"]["unknown"] == unmapped["coverage"]["dependencies"],
                "Dependencies without a package map must stay unknown")

        tree = invoke("sca", "tree", *common, "--advisories", str(ADVISORY))
        require(len(tree["roots"]) == 1 and tree["roots"][0]["pom"] == "pom.xml"
                and tree["coverage"]["modules"] == 2 and tree["coverage"]["external_leaves"] > 0,
                "Maven module tree mismatch")
        require(tree["runtime_status"] == "not_run", "Module tree upgraded runtime_status")

        # [02] Range/alias advisory matching on the same snapshot.
        range_advisory = parent / "range-advisory.json"
        range_advisory.write_text(json.dumps({
            "schema_version": "1.0.0", "fixture_id": "range", "kind": "curated_advisory_fixture",
            "advisory_id": "CVE-RANGE", "aliases": ["GHSA-range"], "aliases_complete": True,
            "published_date": "2026-01-01", "retrieved_date": "2026-01-01", "ecosystem": "Maven",
            "package": {"group_id": "org.apache.commons", "artifact_id": "commons-text"},
            "sources": [], "matching_scope": {"source_id": "", "policy": "range",
            "fixed_default_configuration_release": ""},
            "version_cases": [{"version_range": ">=1.9,<1.10", "version_matched": True,
                               "supply_chain_status": "version_matched", "finding_status": "candidate",
                               "assessment_scope": "declared range", "runtime_status": "not_run"}],
            "exploitability_prerequisites": [], "forbidden_inferences": [],
            "coverage": {"advisories": [], "all_cves_checked": False, "artifact_hashes_available": False,
                         "effective_dependency_tree_available": False, "runtime_exploit_test_available": False},
        }), encoding="utf-8")
        ranged = invoke("sca", "inspect", *common, "--advisories", str(range_advisory))
        matches = {entry["module"]: entry for entry in ranged["advisory_matches"]}
        require(matches["jdbc-app"]["version_status"] == "version_matched"
                and matches["jdbc-app"]["matched_by"] == "range"
                and "GHSA-range" in matches["jdbc-app"]["aliases"],
                "Range candidate mismatch")
        require(matches["advisory-control"]["version_status"] == "not_affected"
                and matches["advisory-control"]["matched_by"] == "range_excluded",
                "Outside-range negative mismatch")

        # [03] Gradle declarations and project tree.
        gradle_snapshot = parent / "gradle-snapshot"
        gradle_imported = invoke("project", "import", "--source", str(GRADLE_FIXTURE),
                                 "--snapshot", str(gradle_snapshot))
        gradle_hash = gradle_imported["snapshot_hash"]
        gradle_snapshot_before = tree_hashes(gradle_snapshot)
        gradle_common = ["--snapshot", str(gradle_snapshot), "--snapshot-hash", gradle_hash]
        gradle = invoke("sca", "inspect", *gradle_common)
        require(gradle["project"]["build_system"] == "Gradle"
                and gradle["project"]["gradle_file_count"] == 2
                and gradle["coverage"]["gradle_files_scanned"] == 2,
                "Gradle project coverage mismatch")
        require(gradle["coverage"]["dependencies_declared"] == 5
                and gradle["coverage"]["dependencies_resolved"] == 4
                and gradle["coverage"]["dependencies_unresolved"] == 1,
                "Gradle dependency coverage mismatch")
        require(gradle["project"]["module_count"] == 2
                and gradle["project"]["root_gradle_files"] == ["build.gradle"],
                "Gradle module coverage mismatch")
        gradle_tree = invoke("sca", "tree", *gradle_common)
        require(len(gradle_tree["roots"]) == 1 and gradle_tree["roots"][0]["pom"] == "build.gradle",
                "Gradle tree root mismatch")
        require(any(child["pom"] == "app/build.gradle.kts" for child in gradle_tree["roots"][0]["children"]),
                "Gradle project dependency edge missing")
        require(gradle_tree["coverage"]["external_leaves"] > 0, "Gradle external leaves missing")

        # [04] Negative controls and immutability.
        invoke("audit", "reachability", "--snapshot", str(snapshot), failure=True)
        invoke("sca", "tree", *common[:-1], "0" * 64, failure=True)
        bad_map = parent / "bad-map.json"
        bad_map.write_text('{"schema_version":1,"dependencies":{"g:a":["../escape"]}}', encoding="utf-8")
        invoke("audit", "reachability", *common, "--package-map", str(bad_map), failure=True)
        require(tree_hashes(snapshot) == snapshot_before, "Java snapshot changed")
        require(tree_hashes(gradle_snapshot) == gradle_snapshot_before, "Gradle snapshot changed")
        require(tree_hashes(MAVEN_FIXTURE) == maven_before, "Maven fixture changed")
        require(tree_hashes(GRADLE_FIXTURE) == gradle_before, "Gradle fixture changed")

        print(json.dumps({
            "result": "passed", "snapshot_hash": snapshot_hash, "gradle_hash": gradle_hash,
            "sarif_results": len(sarif["runs"][0]["results"]),
            "reachability_matches": reach["coverage"]["reachable"] + reach["coverage"]["unreachable"],
            "tree_modules": tree["coverage"]["modules"], "gradle_dependencies": gradle["coverage"]["dependencies_declared"],
            "checks": ["real_cli", "no_database", "no_model", "no_java_execution", "sarif_2_1_0",
                       "sarif_runtime_not_run", "bounded_reachability", "unmapped_unknown",
                       "module_tree", "advisory_range", "advisory_alias", "range_excluded",
                       "gradle_declarations", "gradle_tree", "wrong_hash_rejected", "unsafe_map_rejected",
                       "snapshot_unchanged", "fixtures_unchanged"],
            "java_executed": False, "model_called": False,
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT intel verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
