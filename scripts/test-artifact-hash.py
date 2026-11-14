#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证本地制品 SHA-256、调用者哈希清单与 SBOM 哈希；不运行 Maven/Java。"""
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
FIXTURE = ROOT / "tests" / "fixtures" / "java-artifact-hash"
PROJECT = FIXTURE / "project"
REPO = FIXTURE / "repo"
ARTIFACT = REPO / "org" / "apache" / "commons" / "commons-text" / "1.9"
JAR = ARTIFACT / "commons-text-1.9.jar"
POM = ARTIFACT / "commons-text-1.9.pom"


def tree_hashes(root):
    return {str(path.relative_to(root)).replace(os.sep, "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-artifact-hash-")
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


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(report, kind):
    for entry in report["artifacts"]:
        if entry["kind"] == kind:
            return entry
    raise RuntimeError(f"missing {kind} artifact")


def write_catalog(path, entries):
    path.write_text(json.dumps({"schema_version": 1, "artifacts": entries}), encoding="utf-8")


def main():
    before = tree_hashes(FIXTURE)
    project_before = tree_hashes(PROJECT)
    repo_before = tree_hashes(REPO)
    require(before and JAR.is_file() and POM.is_file(), "Missing artifact-hash fixture")
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
        imported = invoke("project", "import", "--source", str(PROJECT), "--snapshot", str(snapshot), retries=3)
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        # [02] Local Maven layout: both jar and pom are hashed locally.
        report = invoke("sca", "inspect", *common, "--maven-repo", str(REPO), retries=3)
        require(report["coverage"]["artifact_hashes"] == "observed"
                and report["coverage"]["runtime_status"] == "not_run"
                and report["partial"] is False,
                "Local artifact coverage mismatch")
        jar, pom = artifact(report, "jar"), artifact(report, "pom")
        require(jar["status"] == "observed" and jar["source"] == "local_repository"
                and jar["repository"] == "maven_local"
                and jar["path"] == "org/apache/commons/commons-text/1.9/commons-text-1.9.jar"
                and jar["sha256"] == digest(JAR) and jar["bytes"] == JAR.stat().st_size,
                "Jar artifact hash mismatch")
        require(pom["sha256"] == digest(POM) and pom["bytes"] == POM.stat().st_size,
                "Pom artifact hash mismatch")
        require("artifact_hash_local_only" in report["limitations"]
                and "artifact_signature_not_verified" in report["limitations"]
                and "artifact_hashes_unavailable" not in report["limitations"],
                "Artifact hash limitations mismatch")
        require(invoke("sca", "inspect", *common, "--maven-repo", str(REPO), retries=3) == report,
                "Artifact report is not deterministic")

        # [03] SBOM carries only locally observed hashes.
        sbom = invoke("sca", "sbom", *common, "--maven-repo", str(REPO), retries=3)
        component = next((item for item in sbom["components"]
                          if item["bom-ref"] == "pkg:maven/org.apache.commons/commons-text@1.9"), None)
        require(component is not None and len(component["hashes"]) == 2
                and {entry["content"] for entry in component["hashes"]} == {digest(JAR), digest(POM)}
                and all(entry["alg"] == "SHA-256" for entry in component["hashes"]),
                "SBOM artifact hashes mismatch")
        properties = {item["name"]: item["value"] for item in sbom["metadata"]["properties"]}
        require(properties.get("trident:artifact_hashes") == "observed",
                "SBOM artifact hash coverage mismatch")

        # [04] Caller catalog: exact match, mismatch, and catalog-only evidence.
        catalog = parent / "catalog.json"
        entries = [
            {"group_id": "org.apache.commons", "artifact_id": "commons-text", "version": "1.9",
             "kind": "jar", "sha256": digest(JAR)},
            {"group_id": "org.apache.commons", "artifact_id": "commons-text", "version": "1.9",
             "kind": "pom", "sha256": digest(POM)},
        ]
        write_catalog(catalog, entries)
        matched = invoke("sca", "inspect", *common, "--maven-repo", str(REPO),
                         "--hash-catalog", str(catalog), retries=3)
        require(matched["coverage"]["artifact_hashes"] == "observed"
                and artifact(matched, "jar")["catalog_match"] == "matched"
                and matched["partial"] is False,
                "Matching catalog should stay observed")

        write_catalog(catalog, [dict(entries[0], sha256="0" * 64), entries[1]])
        mismatch = invoke("sca", "inspect", *common, "--maven-repo", str(REPO),
                          "--hash-catalog", str(catalog), retries=3)
        require(mismatch["coverage"]["artifact_hashes"] == "partial" and mismatch["partial"] is True
                and artifact(mismatch, "jar")["status"] == "mismatch"
                and artifact(mismatch, "jar")["catalog_match"] == "mismatch"
                and any(value.startswith("artifact_hash_mismatch:") for value in mismatch["limitations"]),
                "Catalog mismatch was not reported")

        write_catalog(catalog, entries)
        catalog_only = invoke("sca", "inspect", *common, "--hash-catalog", str(catalog), retries=3)
        require(catalog_only["coverage"]["artifact_hashes"] == "partial"
                and artifact(catalog_only, "jar")["status"] == "catalog_only"
                and artifact(catalog_only, "jar")["source"] == "caller_catalog"
                and artifact(catalog_only, "jar")["sha256"] == digest(JAR),
                "Catalog-only evidence mismatch")

        # [05] Missing and malformed inputs fail closed or stay unavailable.
        empty = parent / "empty-repo"
        empty.mkdir()
        missing = invoke("sca", "inspect", *common, "--maven-repo", str(empty), retries=3)
        require(missing["coverage"]["artifact_hashes"] == "unavailable"
                and all(entry["status"] == "missing" and entry["source"] == "unavailable"
                        for entry in missing["artifacts"])
                and "artifact_hashes_unavailable" in missing["limitations"],
                "Empty repository should be unavailable")
        bad_catalog = parent / "bad-catalog.json"
        bad_catalog.write_text(json.dumps({"schema_version": 1, "artifacts": [], "extra": True}),
                               encoding="utf-8")
        invoke("sca", "inspect", *common, "--maven-repo", str(REPO),
               "--hash-catalog", str(bad_catalog), failure=True)
        bad_catalog.write_text(json.dumps({"schema_version": 1, "artifacts": [
            dict(entries[0], sha256="not-hex")]}), encoding="utf-8")
        invoke("sca", "inspect", *common, "--maven-repo", str(REPO),
               "--hash-catalog", str(bad_catalog), failure=True)
        invoke("sca", "inspect", *common, "--maven-repo", str(parent / "absent"), failure=True)

        require(tree_hashes(PROJECT) == project_before, "Original fixture project was changed")
        require(tree_hashes(REPO) == repo_before, "Local repository bytes changed")
        require(tree_hashes(snapshot) == snapshot_before, "Artifact lookup changed its read-only snapshot")

        print(json.dumps({"result": "passed", "snapshot_hash": snapshot_hash,
                          "artifacts": len(report["artifacts"]),
                          "checks": ["real_cli", "no_java_execution", "no_maven_execution",
                                     "local_maven_layout", "jar_pom_sha256", "bytes_match",
                                     "deterministic", "sbom_hashes", "catalog_match",
                                     "catalog_mismatch", "catalog_only", "missing_unavailable",
                                     "malformed_catalog_rejected", "repository_bytes_unchanged",
                                     "snapshot_unchanged"],
                          "maven_executed": False, "java_executed": False,
                          "model_called": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT artifact hash verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
