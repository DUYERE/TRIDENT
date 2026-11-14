"""Offline dependency-upgrade acceptance.

Requires `mvn` plus cached commons-text 1.9/1.10.0 artifacts. The script plans a
version bump, applies it to a fresh workspace, and runs `mvn -o -B -q test`.
Missing caches report a skip instead of faking a result.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-upgrade"
REQUIRED_JARS = (
    Path("org/apache/commons/commons-text/1.9/commons-text-1.9.jar"),
    Path("org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar"),
    Path("org/apache/commons/commons-lang3/3.11/commons-lang3-3.11.jar"),
    Path("org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"),
)


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def maven_local_repository():
    explicit = os.environ.get("TRIDENT_MAVEN_REPO")
    if explicit:
        return Path(explicit)
    mvn = shutil.which("mvn")
    if mvn:
        home = Path(mvn).resolve().parent.parent
        settings = home / "conf" / "settings.xml"
        if settings.is_file():
            text = settings.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"<localRepository>\s*([^<]+?)\s*</localRepository>", text)
            if match:
                return Path(os.path.expandvars(os.path.expanduser(match.group(1))))
    return Path.home() / ".m2" / "repository"


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-upgrade-")
    try:
        yield work
    finally:
        for attempt in range(60):
            try:
                shutil.rmtree(work)
                break
            except FileNotFoundError:
                break
            except OSError:
                if attempt == 59:
                    print(f"WARNING: temporary verification directory retained: {work}", file=sys.stderr)
                else:
                    time.sleep(0.5)


def main():
    if shutil.which("mvn") is None:
        print(json.dumps({"result": "skipped", "reason": "mvn_not_found"}))
        return
    repository = maven_local_repository()
    missing = [str(path) for path in REQUIRED_JARS if not (repository / path).is_file()]
    if missing:
        print(json.dumps({"result": "skipped", "reason": "maven_offline_cache_incomplete",
                          "repository": str(repository), "missing": missing}))
        return
    before = tree_hashes(FIXTURE)
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_MODEL_API_KEY",
                 "TRIDENT_TEST_DATABASE_URL", "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        built = subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                               cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=180)
        require(built.returncode == 0, built.stderr.strip() or "go build failed")
        snapshot = parent / "snapshot"
        imported = subprocess.run([str(binary), "project", "import", "--source", str(FIXTURE),
                                   "--snapshot", str(snapshot)], cwd=ROOT, env=env,
                                  capture_output=True, text=True, encoding="utf-8", timeout=180)
        require(imported.returncode == 0, imported.stderr.strip() or "import failed")
        snapshot_hash = json.loads(imported.stdout)["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        patch_path = parent / "upgrade.patch"
        result = subprocess.run([
            str(binary), "sca", "upgrade",
            "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
            "--module", ".", "--dependency", "org.apache.commons:commons-text",
            "--to", "1.10.0", "--out", str(patch_path),
            "--workspace", str(parent / "workspace"),
            "--profile", "maven-test", "--approve-execution", "--timeout-seconds", "600",
        ], cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=900)
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(result.stderr.strip() or "sca upgrade produced no JSON")
        require(result.returncode == 0, report.get("error", "") or "sca upgrade failed")
        require(report["status"] == "validation_passed", f"upgrade status: {report['status']}")
        require(report["analysis_kind"] == "bounded_dependency_upgrade_plan", "analysis kind mismatch")
        require(report["from_version"] == "1.9" and report["to_version"] == "1.10.0",
                "version transition mismatch")
        require(report["change"]["kind"] == "maven_property"
                and report["change"]["file"] == "pom.xml", "change location mismatch")
        require(report["patch_sha256"] and report["patch_bytes"] == len(report["patch"]),
                "patch metadata mismatch")
        require(patch_path.read_text(encoding="utf-8") == report["patch"], "written patch differs from report")
        require(report["runtime_status"] == "isolated_validation_only", "runtime status mismatch")
        verification = report.get("verification") or {}
        baseline = report.get("baseline") or {}
        require(baseline.get("status") == "validation_passed", "baseline validation did not pass")
        baseline_tests = baseline.get("test_summary") or {}
        require(baseline_tests.get("tests", 0) >= 1 and baseline_tests.get("failures") == 0
                and baseline_tests.get("errors") == 0, "baseline tests did not pass")
        require(verification.get("original_snapshot_intact") is True, "snapshot changed")
        tests = (verification.get("validation") or {}).get("test_summary") or {}
        require(tests.get("tests", 0) >= 1 and tests.get("failures") == 0 and tests.get("errors") == 0,
                "post-upgrade tests did not pass")
        require(tree_hashes(snapshot) == snapshot_before, "upgrade changed the snapshot")
        require(tree_hashes(FIXTURE) == before, "fixture changed")

        rejected = subprocess.run([
            str(binary), "sca", "upgrade",
            "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
            "--module", ".", "--dependency", "org.apache.commons:commons-text",
            "--to", "1.9", "--out", str(parent / "same-version.patch"),
        ], cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=180)
        require(rejected.returncode != 0, "equal target version was accepted")
        print(json.dumps({
            "result": "passed", "snapshot_hash": snapshot_hash,
            "from_version": report["from_version"], "to_version": report["to_version"],
            "tests": tests.get("tests"),
            "checks": ["upgrade_patch", "baseline_passed", "maven_offline_test", "snapshot_unchanged",
                       "fixture_unchanged", "runtime_isolated", "equal_version_rejected"],
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT dependency upgrade verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
