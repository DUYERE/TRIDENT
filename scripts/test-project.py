#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证只读项目工具；不连接数据库、不运行 Java/Maven。"""
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


def source_hashes():
    """[02] 只校验仓库内合成样本的内容，不读取用户项目或本机凭据。"""
    return {str(path.relative_to(SOURCE)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(SOURCE.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    """[03] Windows may briefly retain a launched executable; retry only our own new directory."""
    work = tempfile.mkdtemp(prefix="trident-project-")
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
    before = source_hashes()
    if not before:
        raise RuntimeError("Missing synthetic Java fixture")
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
                if result.returncode == 0 or result.stdout.strip():
                    raise RuntimeError("Expected failure without success JSON: " + repr(args))
                return None
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "CLI failed")
            return json.loads(result.stdout)

        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(SOURCE), "--snapshot", str(snapshot))
        expected_hash = imported["snapshot_hash"]
        if len(expected_hash) != 64:
            raise RuntimeError("Invalid snapshot hash")
        # [03] 可信摘要留在 snapshot 外；不从被验证的目录读取预期摘要。
        (parent / "import.json").write_text(json.dumps(imported), encoding="utf-8")
        common = ["--snapshot", str(snapshot), "--snapshot-hash", expected_hash]
        inspected = invoke("project", "inspect", *common)
        if not any(entry["path"] == "pom.xml" for entry in inspected["build_files"]):
            raise RuntimeError("Root Maven structure clue missing")
        entries = []
        cursor = ""
        while True:
            page = invoke("project", "list", *common, "--limit", "3",
                          *(["--cursor", cursor] if cursor else []))
            entries.extend(page["entries"])
            next_cursor = page.get("next_cursor", "")
            if not next_cursor:
                break
            if next_cursor == cursor:
                raise RuntimeError("Pagination made no progress")
            cursor = next_cursor
        paths = [entry["path"] for entry in entries]
        if len(paths) != len(set(paths)) or paths != sorted(paths):
            raise RuntimeError("Non-deterministic or duplicate file pagination")
        found = invoke("project", "search", *common, "--query", "SELECT", "--limit", "20")
        if not found["matches"]:
            raise RuntimeError("SQL fixture source evidence missing")
        match = found["matches"][0]
        read = invoke("project", "read", *common, "--path", match["path"],
                      "--start-line", str(match["line"]), "--limit", "1")
        if "SELECT" not in read["lines"][0]["text"] or read["sha256"] != match["sha256"]:
            raise RuntimeError("Read and search evidence disagree")
        invoke("project", "read", *common, "--path", "../outside", failure=True)
        invoke("project", "inspect", "--snapshot", str(snapshot), failure=True)
        invoke("project", "inspect", "--snapshot", str(snapshot),
               "--snapshot-hash", "0" * 64, failure=True)
        invoke("project", "import", "--source", str(SOURCE), "--snapshot", str(snapshot), failure=True)
        if source_hashes() != before:
            raise RuntimeError("Original synthetic source was changed")
        # [04] 已授权创建的临时快照被篡改后，旧摘要不能继续读取内容。
        victim = snapshot.joinpath(*match["path"].split("/"))
        victim.write_bytes(victim.read_bytes() + b"\n// tampered synthetic snapshot\n")
        invoke("project", "read", *common, "--path", match["path"], failure=True)
        print(json.dumps({"result": "passed", "files": len(entries),
                          "snapshot_hash": expected_hash,
                          "checks": ["real_cli", "no_database", "inspect", "pagination", "read",
                                     "literal_search", "source_unchanged", "path_rejection",
                                     "trusted_hash_required", "wrong_hash_rejected", "no_overwrite",
                                     "content_tampering_rejected"],
                          "maven_executed": False, "model_called": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT project verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
