"""Offline Gradle effective dependency-tree acceptance.

Requires a Gradle executable and a local Maven repository containing the
fixture POMs. The script passes an init script that points Gradle at that
repository, so `--offline` never needs network. If Gradle or the cached POMs
are unavailable it reports a skip instead of faking a result.
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
FIXTURE = ROOT / "tests" / "fixtures" / "java-gradle"
REQUIRED_POMS = (
    Path("org/apache/commons/commons-text/1.9/commons-text-1.9.pom"),
    Path("org/apache/commons/commons-lang3/3.11/commons-lang3-3.11.pom"),
)


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def gradle_executable():
    value = os.environ.get("TRIDENT_GRADLE") or shutil.which("gradle")
    if not value:
        return None
    path = Path(value)
    if not path.is_file():
        return None
    return path


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
                value = os.path.expandvars(os.path.expanduser(match.group(1)))
                return Path(value)
    return Path.home() / ".m2" / "repository"


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-gradle-resolve-")
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
    gradle = gradle_executable()
    if gradle is None:
        print(json.dumps({"result": "skipped", "reason": "gradle_not_found"}))
        return
    repository = maven_local_repository()
    missing = [str(path) for path in REQUIRED_POMS if not (repository / path).is_file()]
    if missing:
        print(json.dumps({"result": "skipped", "reason": "gradle_fixture_repository_incomplete",
                          "repository": str(repository), "missing": missing}))
        return
    before = tree_hashes(FIXTURE)
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_MODEL_API_KEY",
                 "TRIDENT_TEST_DATABASE_URL", "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        work_path = Path(work)
        binary = work_path / ("trident.exe" if os.name == "nt" else "trident")
        built = subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                               cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=180)
        require(built.returncode == 0, built.stderr.strip() or "go build failed")
        snapshot = work_path / "snapshot"
        imported = subprocess.run([str(binary), "project", "import", "--source", str(FIXTURE),
                                   "--snapshot", str(snapshot)], cwd=ROOT, env=env,
                                  capture_output=True, text=True, encoding="utf-8", timeout=180)
        require(imported.returncode == 0, imported.stderr.strip() or "import failed")
        snapshot_hash = json.loads(imported.stdout)["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        gradle_home = work_path / "gradle-home"
        gradle_home.mkdir()
        init_script = work_path / "init-repo.gradle"
        init_script.write_text(
            "allprojects {\n"
            "    repositories {\n"
            f"        maven {{ url = uri('{repository.as_uri()}') }}\n"
            "    }\n"
            "}\n",
            encoding="utf-8")
        result = subprocess.run([
            str(binary), "sca", "resolve", "--tool", "gradle",
            "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
            "--approve-gradle", "--gradle", str(gradle),
            "--gradle-user-home", str(gradle_home),
            "--gradle-init-script", str(init_script),
            "--timeout-seconds", "600",
        ], cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=900)
        if result.returncode != 0:
            try:
                report = json.loads(result.stdout)
                error = report.get("error", "")
            except json.JSONDecodeError:
                error = result.stderr.strip()
            raise RuntimeError(error or "sca resolve --tool gradle failed")
        report = json.loads(result.stdout)
        require(report["status"] == "ok", f"resolve status: {report['status']} {report.get('error', '')}")
        require(report["analysis_kind"] == "gradle_effective_dependency_tree", "analysis kind mismatch")
        require(report["resolution_mode"] == "offline", "resolution mode is not offline")
        require(report["runtime_status"] == "not_run", "effective tree claims runtime status")
        require(report["coverage"]["effective_tree"] == "gradle_dependency_report_observed",
                "effective tree marker mismatch")
        require(report["gradle"]["executed"] is True and report["gradle"]["version"],
                "Gradle not executed or version missing")
        require(report["gradle"]["modules_attempted"] == 3 and report["gradle"]["modules_parsed"] == 3,
                "Gradle module count mismatch")
        require(report["coverage"]["modules"] == 3 and report["coverage"]["dependencies"] > 0
                and report["coverage"]["transitive"] > 0, "effective tree coverage mismatch")
        jdbc = [module for module in report["modules"] if module["artifact_id"] == "jdbc-app"]
        require(jdbc, "jdbc-app module missing")
        dependencies = {dependency["artifact_id"]: dependency for dependency in jdbc[0]["dependencies"]}
        require(dependencies.get("commons-text", {}).get("version") == "1.9"
                and dependencies["commons-text"]["direct"] is True, "commons-text edge missing")
        require(dependencies.get("commons-lang3", {}).get("depth") == 2
                and dependencies["commons-lang3"]["direct"] is False, "transitive commons-lang3 edge missing")
        require(dependencies.get(":common", {}).get("type") == "project", "project dependency edge missing")
        require(tree_hashes(snapshot) == snapshot_before, "resolve changed the snapshot")
        require(tree_hashes(FIXTURE) == before, "fixture changed")
        print(json.dumps({
            "result": "passed", "snapshot_hash": snapshot_hash,
            "gradle_version": report["gradle"]["version"],
            "modules": report["coverage"]["modules"], "dependencies": report["coverage"]["dependencies"],
            "transitive": report["coverage"]["transitive"],
            "checks": ["gradle_offline", "effective_tree", "project_edge", "transitive_edge",
                       "snapshot_unchanged", "fixture_unchanged", "runtime_not_run"],
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT Gradle resolve verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
