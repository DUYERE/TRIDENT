#!/usr/bin/env python
"""[01] 构建真实 CLI，验证 R3 隔离工作区、补丁应用与离线 Maven/javac 基线失败/补丁通过。"""
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
FIXTURE = ROOT / "tests" / "fixtures" / "java-patch"
BASELINE_PATCH = FIXTURE / "baseline.patch"
SAFE_PATCH = FIXTURE / "safe.patch"


def tree_hashes(root):
    return {str(path.relative_to(root)).replace(os.sep, "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-r3-")
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
    require(fixture_before, "Missing java-patch fixture")
    for tool in ("java", "javac", "mvn"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required executable missing: {tool}")
    local_repo = Path.home() / ".m2" / "repository"
    junit_jar = local_repo / "junit" / "junit" / "4.12" / "junit-4.12.jar"
    hamcrest_jar = local_repo / "org" / "hamcrest" / "hamcrest-core" / "1.3" / "hamcrest-core-1.3.jar"
    require(junit_jar.is_file() and hamcrest_jar.is_file(), "cached JUnit 4.12/Hamcrest 1.3 jars missing")
    junit_classpath = os.pathsep.join([str(junit_jar), str(hamcrest_jar)])
    env = os.environ.copy()
    env["TRIDENT_MODEL_API_KEY"] = "must-not-leak"
    env["TRIDENT_DATABASE_URL"] = "postgres://must-not-leak"
    for name in ("TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL", "TRIDENT_TEST_ADMIN_TOKEN"):
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

        def verify(workspace, patch, profile, main_class="demo.Main", test_class=None,
                   test_classpath=None, approve=True, hash_value=None):
            args = [str(binary), "patch", "verify", "--snapshot", str(snapshot),
                    "--snapshot-hash", hash_value or snapshot_hash,
                    "--workspace", str(workspace), "--patch", str(patch), "--profile", profile]
            if profile == "junit":
                args += ["--test-class", test_class, "--test-classpath", test_classpath]
            else:
                args += ["--main-class", main_class]
            if approve:
                args.append("--approve-execution")
            result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                                    text=True, encoding="utf-8", timeout=300)
            document = None
            if result.stdout.strip():
                document = json.loads(result.stdout)
            return result, document

        baseline, baseline_doc = verify(parent / "baseline", BASELINE_PATCH, "maven")
        require(baseline.returncode != 0 and baseline_doc is not None, "baseline did not fail as a result")
        require(baseline_doc["status"] == "validation_failed", "baseline status mismatch")
        require(baseline_doc["original_snapshot_intact"] is True, "baseline modified the original snapshot")
        require(baseline_doc["patch"]["files_changed"][0]["path"] == "src/main/java/demo/Vulnerable.java",
                "baseline patch path mismatch")
        last = baseline_doc["validation"]["commands"][-1]
        require(last["exit_code"] == 1 and "injection guard missing" in last.get("stderr", ""),
                "baseline runtime failure missing")

        safe, safe_doc = verify(parent / "safe", SAFE_PATCH, "maven")
        require(safe.returncode == 0 and safe_doc is not None, "safe patch failed")
        require(safe_doc["status"] == "validation_passed" and safe_doc["original_snapshot_intact"] is True,
                "safe patch status mismatch")
        last = safe_doc["validation"]["commands"][-1]
        require(last["exit_code"] == 0 and "safe" in last.get("stdout", ""), "safe runtime output missing")
        require("host secret leaked" not in last.get("stderr", ""), "validation environment leaked host secrets")
        patched = (parent / "safe" / "src/main/java/demo/Vulnerable.java").read_text(encoding="utf-8")
        require('name=?' in patched and "name='\" + name" not in patched, "patch was not applied")
        original = (snapshot / "src/main/java/demo/Vulnerable.java").read_text(encoding="utf-8")
        require("name=?" not in original, "snapshot was modified")

        javac, javac_doc = verify(parent / "javac", SAFE_PATCH, "javac")
        require(javac.returncode == 0 and javac_doc["status"] == "validation_passed",
                "javac profile failed")

        baseline_junit, baseline_junit_doc = verify(
            parent / "baseline-junit", BASELINE_PATCH, "junit",
            test_class="demo.VulnerableTest", test_classpath=junit_classpath)
        require(baseline_junit.returncode != 0 and baseline_junit_doc["status"] == "validation_failed"
                and "Tests run: 1,  Failures: 1" in baseline_junit_doc["validation"]["commands"][-1].get("stdout", ""),
                "baseline JUnit did not fail")
        safe_junit, safe_junit_doc = verify(
            parent / "safe-junit", SAFE_PATCH, "junit",
            test_class="demo.VulnerableTest", test_classpath=junit_classpath)
        require(safe_junit.returncode == 0 and safe_junit_doc["status"] == "validation_passed"
                and "OK (1 test)" in safe_junit_doc["validation"]["commands"][-1].get("stdout", ""),
                "patched JUnit did not pass")

        no_approval, no_approval_doc = verify(parent / "no-approval", SAFE_PATCH, "javac", approve=False)
        require(no_approval.returncode != 0 and no_approval_doc is None
                and not (parent / "no-approval").exists(), "execution without approval was not blocked")

        wrong_hash, wrong_hash_doc = verify(parent / "wrong-hash", SAFE_PATCH, "javac", hash_value="0" * 64)
        require(wrong_hash.returncode != 0 and wrong_hash_doc is not None
                and wrong_hash_doc["status"] == "setup_failed", "wrong snapshot hash accepted")

        traversal_patch = parent / "traversal.patch"
        traversal_patch.write_text(
            "--- a/src/main/java/demo/Vulnerable.java\n"
            "+++ b/../escape.java\n"
            "@@ -1,1 +1,1 @@\n-package demo;\n+package escape;\n", encoding="utf-8")
        traversal, traversal_doc = verify(parent / "traversal", traversal_patch, "javac")
        require(traversal.returncode != 0 and traversal_doc["status"] == "patch_failed",
                "traversal patch accepted")
        require(not (parent / "escape.java").exists(), "traversal patch escaped the workspace")

        mismatch_patch = parent / "mismatch.patch"
        mismatch_patch.write_text(
            "--- a/src/main/java/demo/Vulnerable.java\n"
            "+++ b/src/main/java/demo/Vulnerable.java\n"
            "@@ -1,1 +1,1 @@\n-package wrong;\n+package demo;\n", encoding="utf-8")
        mismatch, mismatch_doc = verify(parent / "mismatch", mismatch_patch, "javac")
        require(mismatch.returncode != 0 and mismatch_doc["status"] == "patch_failed",
                "context mismatch accepted")

        existing, existing_doc = verify(parent, SAFE_PATCH, "javac")
        require(existing.returncode != 0 and existing_doc["status"] == "setup_failed",
                "existing workspace accepted")

        inside, inside_doc = verify(snapshot / "workspace", SAFE_PATCH, "javac")
        require(inside.returncode != 0 and inside_doc["status"] == "setup_failed",
                "workspace inside snapshot accepted")

        require(tree_hashes(snapshot) == snapshot_before, "snapshot changed during R3 verification")
        require(tree_hashes(FIXTURE) == fixture_before, "fixture changed during R3 verification")
        print("[01] isolated workspace copy and unified diff apply: PASS")
        print("[02] baseline Maven/JUnit validation fails; patched Maven/JUnit validation passes: PASS")
        print("[03] patched javac validation passes; host secrets are not forwarded: PASS")
        print("[04] traversal, context mismatch, existing workspace and wrong hash rejected: PASS")
        print("[05] original snapshot and fixture are byte-identical: PASS")
        print("TRIDENT R3 patch acceptance passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
