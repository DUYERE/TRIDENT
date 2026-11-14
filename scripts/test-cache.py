"""Derived-index cache acceptance.

Imports the synthetic Maven fixture into temporary snapshots, runs the real
`audit endpoints --cache-dir` command and checks hit, partial, miss, corrupt
entry, cache/snapshot separation and source-free cache contents. No model,
network, Java or Maven execution is used.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"
SOURCE_MARKERS = (b"public class", b"PreparedStatement", b"package example")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, env, timeout=180):
    return subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def import_snapshot(binary, env, source, snapshot):
    result = run([str(binary), "project", "import", "--source", str(source),
                  "--snapshot", str(snapshot)], env)
    require(result.returncode == 0, result.stderr.strip() or "import failed")
    return json.loads(result.stdout)["snapshot_hash"]


def endpoints(binary, env, snapshot, snapshot_hash, cache_dir):
    args = [str(binary), "audit", "endpoints", "--snapshot", str(snapshot),
            "--snapshot-hash", snapshot_hash]
    if cache_dir is not None:
        args += ["--cache-dir", str(cache_dir)]
    result = run(args, env)
    document = json.loads(result.stdout) if result.stdout.strip() else None
    return result, document


def essentials(document):
    return {
        "controllers": document["controllers"],
        "endpoints": document["endpoints"],
        "coverage": {key: value for key, value in document["coverage"].items()
                     if not key.startswith("cache")},
    }


def tree_hash(directory):
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


def main():
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    work = Path(tempfile.mkdtemp(prefix="trident-cache-"))
    try:
        binary = work / ("trident.exe" if os.name == "nt" else "trident")
        built = run(["go", "build", "-o", str(binary), "./cmd/trident"], env)
        require(built.returncode == 0, built.stderr.strip() or "go build failed")

        source_a = work / "source-a"
        shutil.copytree(FIXTURE, source_a)
        snapshot_a = work / "snapshot-a"
        hash_a = import_snapshot(binary, env, source_a, snapshot_a)
        cache = work / "cache"

        cold_result, cold = endpoints(binary, env, snapshot_a, hash_a, cache)
        require(cold_result.returncode == 0, cold_result.stderr.strip() or "cold run failed")
        require(cold["coverage"]["cache"] == "miss", f"cold cache state: {cold['coverage']['cache']}")
        require(cold["coverage"].get("cache_files_miss", 0) > 0, "cold run did not record misses")
        require(len(cold["endpoints"]) > 0, "fixture produced no endpoints")

        warm_result, warm = endpoints(binary, env, snapshot_a, hash_a, cache)
        require(warm_result.returncode == 0, warm_result.stderr.strip() or "warm run failed")
        require(warm["coverage"]["cache"] == "hit", f"warm cache state: {warm['coverage']['cache']}")
        require(warm["coverage"].get("cache_files_miss", 0) == 0, "warm run still parsed files")
        require(essentials(warm) == essentials(cold), "cached endpoints differ from the cold run")
        repeat = run([str(binary), "audit", "endpoints", "--snapshot", str(snapshot_a),
                      "--snapshot-hash", hash_a, "--cache-dir", str(cache)], env)
        require(repeat.stdout == warm_result.stdout, "warm output is not deterministic")

        cache_files = [path for path in cache.rglob("*") if path.is_file()]
        require(cache_files and all(path.suffix == ".json" for path in cache_files),
                "cache contains non-JSON files")
        for path in cache_files:
            data = path.read_bytes()
            for marker in SOURCE_MARKERS:
                require(marker not in data, f"source marker {marker!r} found in {path.name}")

        corrupt_entry = sorted(cache_files)[0]
        corrupt_entry.write_bytes(b"{not-json")
        corrupt_result, corrupt = endpoints(binary, env, snapshot_a, hash_a, cache)
        require(corrupt_result.returncode == 0, corrupt_result.stderr.strip() or "corrupt run failed")
        require(corrupt["coverage"]["cache"] == "partial",
                f"corrupt cache state: {corrupt['coverage']['cache']}")
        require(corrupt["coverage"].get("cache_corrupt", 0) >= 1, "corrupt entry was not counted")
        require(any(item.startswith("cache_entry_corrupt_rebuilt")
                    for item in corrupt["limitations"]), "corrupt rebuild limitation missing")
        require(essentials(corrupt) == essentials(cold), "corrupt entry changed the analysis result")

        source_b = work / "source-b"
        shutil.copytree(source_a, source_b)
        changed = source_b / "jdbc-app/src/main/java/example/synthetic/CustomerController.java"
        changed.write_text(changed.read_text(encoding="utf-8") + "\n// cache-bust\n", encoding="utf-8")
        snapshot_b = work / "snapshot-b"
        hash_b = import_snapshot(binary, env, source_b, snapshot_b)
        partial_result, partial = endpoints(binary, env, snapshot_b, hash_b, cache)
        require(partial_result.returncode == 0, partial_result.stderr.strip() or "partial run failed")
        require(partial["coverage"]["cache"] == "partial",
                f"changed file cache state: {partial['coverage']['cache']}")
        require(partial["coverage"].get("cache_files_hit", 0) > 0
                and partial["coverage"].get("cache_files_miss", 0) > 0,
                f"partial cache counters: {partial['coverage']}")
        changed_rel = "jdbc-app/src/main/java/example/synthetic/CustomerController.java"

        def unrelated(document):
            return {
                "controllers": [item for item in document["controllers"] if item["file"] != changed_rel],
                "endpoints": [item for item in document["endpoints"] if item["file"] != changed_rel],
            }

        require(unrelated(partial) == unrelated(cold),
                "partial rebuild changed unchanged-file results")

        snapshot_before = tree_hash(snapshot_a)
        overlap, overlap_doc = endpoints(binary, env, snapshot_a, hash_a, snapshot_a / "cache")
        require(overlap.returncode != 0 and overlap_doc is None,
                "cache inside snapshot was accepted")
        require(tree_hash(snapshot_a) == snapshot_before, "refused cache write modified the snapshot")

        file_cache = work / "cache-file"
        file_cache.write_text("not a directory", encoding="utf-8")
        invalid, invalid_doc = endpoints(binary, env, snapshot_a, hash_a, file_cache)
        require(invalid.returncode != 0 and invalid_doc is None, "file cache path was accepted")

        print("[01] cold cache miss and warm cache hit: PASS")
        print("[02] cached endpoints equal uncached results and are deterministic: PASS")
        print("[03] cache contains derived JSON only, no source markers: PASS")
        print("[04] corrupt entry is rebuilt and reported as partial: PASS")
        print("[05] changed file triggers partial rebuild without changing other results: PASS")
        print("[06] cache/snapshot overlap and file cache path are rejected: PASS")
        print("TRIDENT cache acceptance passed.")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"TRIDENT cache acceptance failed: {exc}", file=sys.stderr)
        sys.exit(1)
