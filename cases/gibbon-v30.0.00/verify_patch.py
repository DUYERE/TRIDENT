#!/usr/bin/env python3
"""End-to-end verification for the Gibbon case.

Default:
    python verify_patch.py --vuln http://127.0.0.1:8081 --patched http://127.0.0.1:8082

The wrapper runs the two vulnerable-instance PoCs and the patched-instance smoke
check. It intentionally keeps each script independent so a failure is attributable
to one stage.
"""

import argparse
import json
import os
import subprocess
import sys


HERE = os.path.dirname(os.path.abspath(__file__))


def run(script, base_url):
    env = dict(os.environ)
    env["GIBBON_BASE_URL"] = base_url
    completed = subprocess.run(
        [sys.executable, os.path.join(HERE, script)],
        cwd=HERE,
        env=env,
        capture_output=True,
        text=True,
    )
    output = completed.stdout.strip()
    if not output:
        output = completed.stderr.strip()
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        parsed = {"raw_output": output}
    return completed.returncode, parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vuln", default="http://127.0.0.1:8081")
    parser.add_argument("--patched", default="http://127.0.0.1:8082")
    parser.add_argument("--skip-vuln", action="store_true")
    args = parser.parse_args()

    result = {"vuln": args.vuln, "patched": args.patched}
    ok = True

    if not args.skip_vuln:
        lfi_exit, lfi = run("poc_lfi.py", args.vuln)
        sqli_exit, sqli = run("poc_sqli.py", args.vuln)
        result["lfi"] = lfi
        result["sqli"] = sqli
        ok = ok and lfi_exit == 0 and sqli_exit == 0

    patched_exit, patched = run("smoke_patch.py", args.patched)
    result["patched"] = patched
    ok = ok and patched_exit == 0

    result["result"] = "FULL_CASE_VERIFIED" if ok else "VERIFICATION_FAILED"
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
