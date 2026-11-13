#!/usr/bin/env python
"""[01] 构建真实 CLI 并用官方 CycloneDX 1.5 Schema 验证声明级 SBOM。"""
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

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"
ADVISORY = FIXTURE / "advisories" / "CVE-2022-42889.json"
SCHEMA = ROOT / "tests" / "schemas" / "bom-1.5.schema.json"


def tree_hashes(root):
    return {str(path.relative_to(root)).replace(os.sep, "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-sbom-")
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


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before, "Missing synthetic Java fixture")
    require(ADVISORY.is_file(), "Missing synthetic advisory fixture")
    require(SCHEMA.is_file(), "Missing vendored CycloneDX 1.5 schema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)

    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                       cwd=ROOT, env=env, check=True, timeout=180)
        snapshot = parent / "snapshot"
        imported = subprocess.run(
            [str(binary), "project", "import", "--source", str(FIXTURE), "--snapshot", str(snapshot)],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        require(imported.returncode == 0, imported.stderr.strip() or "import failed")
        snapshot_hash = json.loads(imported.stdout)["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        def run(*args):
            result = subprocess.run([str(binary), *args], cwd=ROOT, env=env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=120)
            require(result.returncode == 0, result.stderr.strip() or "CLI failed")
            return result.stdout

        first = run("sca", "sbom", *common, "--advisories", str(ADVISORY))
        second = run("sca", "sbom", *common, "--advisories", str(ADVISORY))
        require(first == second, "SBOM output is not deterministic")
        document = json.loads(first)
        validator.validate(document)

        require(document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5", "SBOM identity mismatch")
        require(document["version"] == 1 and document["serialNumber"].startswith("urn:uuid:"), "SBOM serial mismatch")
        require(len(document["components"]) == 5, "component count mismatch")
        refs = {component["bom-ref"] for component in document["components"]}
        require("pkg:maven/org.apache.commons/commons-text@1.9" in refs, "declared dependency missing")
        require(len(document["vulnerabilities"]) == 1, "candidate vulnerability count mismatch")
        vulnerability = document["vulnerabilities"][0]
        require(vulnerability["id"] == "CVE-2022-42889"
                and vulnerability["analysis"]["state"] == "in_triage"
                and any(item["ref"] == "pkg:maven/org.apache.commons/commons-text@1.9"
                        for item in vulnerability.get("affects", [])),
                "vulnerability mapping mismatch")
        properties = {item["name"]: item["value"] for item in document["metadata"]["properties"]}
        require(properties.get("trident:runtime_status") == "not_run", "runtime status claim missing")
        require(properties.get("trident:dependency_reachability") == "unverified", "reachability claim missing")
        require(properties.get("trident:snapshot_hash") == snapshot_hash, "snapshot hash missing")
        require(str(ROOT) not in first, "SBOM leaked the host project path")

        no_catalog = json.loads(run("sca", "sbom", *common))
        validator.validate(no_catalog)
        require(not no_catalog.get("vulnerabilities"), "unexpected advisory match without a catalog")

        result = subprocess.run([str(binary), "sca", "sbom", "--snapshot", str(snapshot),
                                 "--snapshot-hash", "0" * 64], cwd=ROOT, env=env,
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        require(result.returncode != 0 and not result.stdout.strip(), "wrong snapshot hash accepted")

        require(tree_hashes(snapshot) == snapshot_before, "snapshot changed during SBOM verification")
        require(tree_hashes(FIXTURE) == fixture_before, "fixture changed during SBOM verification")
        print("[01] deterministic CycloneDX 1.5 document: PASS")
        print("[02] official schema validation: PASS")
        print("[03] declaration-only and runtime_status=not_run claims: PASS")
        print("[04] snapshot and fixture are byte-identical; no Maven/Java/model/database execution: PASS")
        print("TRIDENT SBOM acceptance passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
