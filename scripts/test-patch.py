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
                   test_classpath=None, approve=True, hash_value=None, modules=None):
            args = [str(binary), "patch", "verify", "--snapshot", str(snapshot),
                    "--snapshot-hash", hash_value or snapshot_hash,
                    "--workspace", str(workspace), "--patch", str(patch), "--profile", profile]
            if modules:
                for module in modules:
                    args += ["--module", module]
            if profile == "junit":
                args += ["--test-class", test_class, "--test-classpath", test_classpath]
            elif profile != "gradle-test":
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

        original_hash = hashlib.sha256(
            (snapshot / "src/main/java/demo/Vulnerable.java").read_bytes()).hexdigest()
        for document, label in ((baseline_doc, "failed"), (safe_doc, "passed")):
            rollback = document.get("rollback") or {}
            steps = rollback.get("steps") or []
            require(len(steps) == 1 and steps[0]["path"] == "src/main/java/demo/Vulnerable.java"
                    and steps[0]["action"] == "restore_original"
                    and steps[0]["sha256_before"] == original_hash,
                    f"{label} validation rollback plan mismatch: {rollback}")
            require("does not execute" in rollback.get("note", ""),
                    f"{label} rollback is not marked as manual")
            require(document["quality"]["rubric_version"] == "r3-quality-rubric-v2",
                    f"{label} quality rubric version missing")

        modular, modular_doc = verify(parent / "safe-modules", SAFE_PATCH, "maven", modules=["."])
        require(modular.returncode == 0 and modular_doc["status"] == "validation_passed",
                "module-scoped validation failed")
        module_results = modular_doc["validation"].get("modules") or []
        require(len(module_results) == 1 and module_results[0]["module"] == "."
                and module_results[0]["status"] == "validation_passed",
                f"per-module result mismatch: {module_results}")
        require(any(item.get("module") == "." for item in modular_doc["validation"]["commands"]),
                "module label missing from commands")

        unsafe_module, unsafe_module_doc = verify(
            parent / "unsafe-module", SAFE_PATCH, "maven", modules=["../escape"])
        require(unsafe_module.returncode != 0 and unsafe_module_doc is not None
                and unsafe_module_doc["status"] == "validation_error",
                "escaping module selection accepted")

        gradle_source = parent / "gradle-source"
        (gradle_source / "src/main/java/demo").mkdir(parents=True)
        (gradle_source / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
        (gradle_source / "src/main/java/demo/App.java").write_text(
            "package demo;\npublic class App { int x = 1; }\n", encoding="utf-8")
        gradle_snapshot = parent / "gradle-snapshot"
        gradle_import = subprocess.run(
            [str(binary), "project", "import", "--source", str(gradle_source),
             "--snapshot", str(gradle_snapshot)],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        require(gradle_import.returncode == 0, gradle_import.stderr.strip() or "gradle import failed")
        gradle_hash = json.loads(gradle_import.stdout)["snapshot_hash"]
        gradle_patch = parent / "gradle.patch"
        gradle_patch.write_text(
            "--- a/src/main/java/demo/App.java\n"
            "+++ b/src/main/java/demo/App.java\n"
            "@@ -1,2 +1,2 @@\n"
            " package demo;\n"
            "-public class App { int x = 1; }\n"
            "+public class App { int x = 2; }\n", encoding="utf-8")
        stub_bin = parent / "gradle-stub-bin"
        stub_bin.mkdir()
        stub_python = stub_bin / "gradle_stub.py"
        stub_python.write_text(
            "import os, sys\n"
            "target = os.path.join('build', 'test-results', 'test')\n"
            "os.makedirs(target, exist_ok=True)\n"
            "with open(os.path.join(target, 'TEST-demo.xml'), 'w', encoding='utf-8') as handle:\n"
            "    handle.write('<testsuite name=\"demo\" tests=\"1\" failures=\"0\" errors=\"0\" skipped=\"0\">'\n"
            "                 '<testcase name=\"ok\"/></testsuite>')\n"
            "sys.exit(0)\n", encoding="utf-8")
        if os.name == "nt":
            stub = stub_bin / "gradle.cmd"
            stub.write_text('@echo off\r\npython "%~dp0gradle_stub.py" %*\r\n', encoding="ascii")
        else:
            stub = stub_bin / "gradle"
            stub.write_text('#!/usr/bin/env python3\n'
                            'exec(open(__file__.replace("gradle", "gradle_stub.py")).read())\n',
                            encoding="utf-8")
            stub.chmod(0o700)
        gradle_env = env.copy()
        gradle_env["PATH"] = str(stub_bin) + os.pathsep + env.get("PATH", "")
        gradle_run = subprocess.run(
            [str(binary), "patch", "verify", "--snapshot", str(gradle_snapshot),
             "--snapshot-hash", gradle_hash, "--workspace", str(parent / "gradle-workspace"),
             "--patch", str(gradle_patch), "--profile", "gradle-test", "--approve-execution"],
            cwd=ROOT, env=gradle_env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=300)
        require(gradle_run.returncode == 0, gradle_run.stderr.strip() or "gradle profile failed")
        gradle_doc = json.loads(gradle_run.stdout)
        require(gradle_doc["status"] == "validation_passed", "gradle profile status mismatch")
        gradle_command = gradle_doc["validation"]["commands"][0]
        require(gradle_command["command"] == "gradle --offline -q test" and gradle_command["exit_code"] == 0,
                f"gradle command mismatch: {gradle_command}")
        gradle_tests = gradle_doc["validation"].get("test_summary") or {}
        require(gradle_tests.get("tests") == 1 and gradle_tests.get("failures") == 0,
                f"gradle test summary mismatch: {gradle_tests}")
        require(any(item.startswith("gradle_profile_offline")
                    for item in gradle_doc["limitations"]),
                "gradle offline limitation missing")
        require(gradle_doc.get("rollback", {}).get("steps"), "gradle verification has no rollback plan")
        require((gradle_snapshot / "src/main/java/demo/App.java").read_text(encoding="utf-8")
                == "package demo;\npublic class App { int x = 1; }\n",
                "gradle scenario modified the snapshot")

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
        print("[06] rollback plans, quality rubric, module scoping and gradle-test profile (stub toolchain): PASS")
        print("TRIDENT R3 patch acceptance passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
