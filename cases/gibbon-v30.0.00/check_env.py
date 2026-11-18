#!/usr/bin/env python3
"""Check the local Gibbon case environment.

Run from cases/gibbon-v30.0.00:
    python check_env.py
"""

import json
import sys

from case_client import GibbonClient


def main():
    client = GibbonClient()
    status, url, body = client.login()
    login_ok = status == 200 and "loginForm" not in body
    graphs_status, _, graphs_body = client.authenticated_get(
        "/index.php?q=/modules/Tracking/graphing.php"
    )
    reports_status, _, reports_body = client.authenticated_get(
        "/index.php?q=/modules/Reports/archive_manage.php"
    )
    result = {
        "base_url": client.base_url,
        "login_http_status": status,
        "authenticated": login_ok,
        "tracking_http_status": graphs_status,
        "tracking_page_ok": "Graphing" in graphs_body or "Report Data" in graphs_body,
        "reports_http_status": reports_status,
        "reports_page_ok": "Manage Archives" in reports_body or "Archive" in reports_body,
        "result": "ENV_OK" if all([login_ok, graphs_status == 200, reports_status == 200]) else "ENV_CHECK_FAILED",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["result"] == "ENV_OK" else 1


if __name__ == "__main__":
    sys.exit(main())
