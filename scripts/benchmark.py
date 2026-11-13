"""Reproducible local benchmark for read-only analysis commands.

The benchmark builds the current CLI, imports the synthetic fixtures into a
temporary directory, and measures wall-clock time and output bytes. It never
uses a database, model, network, Maven or Java execution.
"""
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {
    "java-maven": ROOT / "tests" / "fixtures" / "java-maven",
    "java-advanced-sinks": ROOT / "tests" / "fixtures" / "java-advanced-sinks",
    "java-flow-gaps": ROOT / "tests" / "fixtures" / "java-flow-gaps",
    "gradle-basic": ROOT / "tests" / "fixtures" / "gradle-basic",
}
ADVISORY = FIXTURES["java-maven"] / "advisories" / "CVE-2022-42889.json"


def run(command, env, cwd=ROOT, timeout=180):
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                          text=True, encoding="utf-8", timeout=timeout)


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    if iterations < 1 or iterations > 10:
        raise SystemExit("iterations must be 1..10")
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    work = tempfile.mkdtemp(prefix="trident-bench-")
    try:
        binary = Path(work) / ("trident.exe" if os.name == "nt" else "trident")
        build_started = time.perf_counter()
        built = run(["go", "build", "-o", str(binary), "./cmd/trident"], env)
        if built.returncode != 0:
            raise SystemExit(built.stderr.strip() or "go build failed")
        build_ms = round((time.perf_counter() - build_started) * 1000)

        snapshots = {}
        for name, fixture in FIXTURES.items():
            destination = Path(work) / f"{name}-snapshot"
            imported = run([str(binary), "project", "import", "--source", str(fixture),
                            "--snapshot", str(destination)], env)
            if imported.returncode != 0:
                raise SystemExit(imported.stderr.strip() or f"import failed: {name}")
            snapshots[name] = (destination, json.loads(imported.stdout)["snapshot_hash"])

        cases = {}
        for name in FIXTURES:
            snapshot, snapshot_hash = snapshots[name]
            common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]
            cases[name] = [
                ("sca inspect", ["sca", "inspect", *common, "--advisories", str(ADVISORY)]),
                ("sca tree", ["sca", "tree", *common]),
                ("audit endpoints", ["audit", "endpoints", *common]),
                ("audit dataflow", ["audit", "dataflow", *common]),
                ("audit findings", ["audit", "findings", *common, "--advisories", str(ADVISORY)]),
                ("audit sarif", ["audit", "sarif", *common, "--advisories", str(ADVISORY)]),
                ("audit reachability", ["audit", "reachability", *common]),
            ]
        results = []
        for name, entries in cases.items():
            for label, args in entries:
                durations = []
                output_bytes = 0
                for _ in range(iterations):
                    started = time.perf_counter()
                    completed = run([str(binary), *args], env)
                    durations.append((time.perf_counter() - started) * 1000)
                    if completed.returncode != 0:
                        raise SystemExit(completed.stderr.strip() or f"{name}/{label} failed")
                    output_bytes = len(completed.stdout.encode("utf-8"))
                results.append({
                    "fixture": name,
                    "command": label,
                    "iterations": iterations,
                    "median_ms": round(statistics.median(durations), 1),
                    "min_ms": round(min(durations), 1),
                    "max_ms": round(max(durations), 1),
                    "output_bytes": output_bytes,
                })
        print(json.dumps({
            "result": "passed",
            "go_version": run(["go", "version"], env).stdout.strip(),
            "build_ms": build_ms,
            "iterations": iterations,
            "cases": results,
            "notes": [
                "wall-clock only; no model, network, database, Maven or Java execution",
                "fixtures are synthetic and small; timings do not predict large-project cost",
                "output_bytes includes the JSON report envelope",
            ],
        }, indent=2))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT benchmark failed: {exc}", file=sys.stderr)
        sys.exit(1)
