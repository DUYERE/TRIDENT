"""Offline Maven effective-tree acceptance.

Requires `mvn` and a local repository cache containing maven-dependency-plugin.
If Maven or cached plugins are unavailable, the script reports a skip instead of
faking a result. No database, model or target network is used.
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
FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-resolve-")
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
    if shutil.which("mvn") is None:
        print(json.dumps({"result": "skipped", "reason": "mvn_not_found"}))
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
        result = subprocess.run([str(binary), "sca", "resolve", "--snapshot", str(snapshot),
                                 "--snapshot-hash", snapshot_hash, "--approve-maven"],
                                cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
        if result.returncode != 0:
            try:
                report = json.loads(result.stdout)
                error = report.get("error", "")
            except json.JSONDecodeError:
                error = result.stderr.strip()
            if "could not be resolved" in error or "Cannot access" in error or "offline mode" in error:
                print(json.dumps({"result": "skipped", "reason": "maven_offline_cache_incomplete", "detail": error[:300]}))
                return
            raise RuntimeError(error or "sca resolve failed")
        report = json.loads(result.stdout)
        require(report["status"] == "ok" and report["resolution_mode"] == "offline",
                "resolve status/mode mismatch")
        require(report["coverage"]["modules"] >= 3 and report["coverage"]["dependencies"] > 0
                and report["coverage"]["transitive"] > 0,
                "effective tree coverage mismatch")
        require(report["coverage"]["effective_tree"] == "maven_dependency_tree_observed"
                and report["runtime_status"] == "not_run",
                "effective tree claims runtime status")
        require(report["maven"]["executed"] is True, "Maven not executed")
        jdbc = [module for module in report["modules"]
                if module["artifact_id"] == "jdbc-app" and module["dependencies"]]
        require(jdbc and any(dep["artifact_id"] == "commons-lang3" and dep["depth"] == 2
                             for dep in jdbc[0]["dependencies"]),
                "transitive commons-lang3 edge missing")
        require(tree_hashes(snapshot) == snapshot_before, "resolve changed the snapshot")
        require(tree_hashes(FIXTURE) == before, "fixture changed")
        print(json.dumps({
            "result": "passed", "snapshot_hash": snapshot_hash,
            "modules": report["coverage"]["modules"], "dependencies": report["coverage"]["dependencies"],
            "transitive": report["coverage"]["transitive"],
            "checks": ["maven_offline", "effective_tree", "transitive_edge", "snapshot_unchanged",
                       "fixture_unchanged", "runtime_not_run"],
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT Maven resolve verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
