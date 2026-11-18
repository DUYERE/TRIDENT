#!/usr/bin/env python3
"""Smoke and block checks for the patched Gibbon instance on 127.0.0.1:8082.

Run with GIBBON_BASE_URL=http://127.0.0.1:8082.
It verifies:
1. login works;
2. Tracking graphing still returns a normal page;
3. a normal /uploads archive can be created and uploaded;
4. the LFI marker is no longer reachable from the uploaded temp path;
5. the SQLi timing payload is neutralized.
"""

import datetime
import io
import json
import os
import re
import sys
import time
import zipfile

from case_client import GibbonClient

BASE = os.environ.get("GIBBON_BASE_URL", "http://127.0.0.1:8082")


def hidden(html, name):
    match = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), html, re.I)
    return match.group(1) if match else ""


def location(headers):
    for key, value in headers.items():
        if key.lower() == "location":
            return value
    return ""


def main():
    client = GibbonClient(BASE)
    _, login_url, login_body = client.login()
    login_ok = "loginForm" not in login_body

    # Normal Tracking graph request.
    tracking_status, _, tracking_body = client.post(
        "/index.php?q=/modules/Tracking/graphing.php",
        {
            "address": "",
            "dataType": "attainment",
            "gibbonDepartmentIDs[]": ["0004"],
            "gibbonPersonIDs[]": ["1875"],
        },
    )
    tracking_ok = tracking_status == 200 and "There are no records" not in tracking_body

    # Timing payload must not add a second SLEEP.
    started = time.monotonic()
    sqli_status, _, _ = client.post(
        "/index.php?q=/modules/Tracking/graphing.php",
        {
            "address": "",
            "dataType": "attainment",
            "gibbonDepartmentIDs[]": ["0005", "0005 OR SLEEP(10)"],
            "gibbonPersonIDs[]": ["1875"],
        },
    )
    sqli_seconds = time.monotonic() - started
    sqli_blocked = sqli_status == 200 and sqli_seconds < 8.0

    # Normal /uploads archive.
    _, _, page = client.authenticated_get("/index.php?q=/modules/Reports/archive_manage_add.php")
    csrf = hidden(page, "csrftoken")
    nonce = hidden(page, "nonce")
    address = hidden(page, "address")
    name = "TRIDENT PATCH SMOKE %s" % datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    status, _, _ = client.post(
        "/modules/Reports/archive_manage_addProcess.php",
        {
            "address": address,
            "csrftoken": csrf,
            "nonce": nonce,
            "name": name,
            "path": "/uploads",
            "readonly": "N",
            "viewableStaff": "Y",
            "viewableStudents": "N",
            "viewableParents": "N",
            "viewableOther": "N",
        },
        follow=False,
    )
    redirect = location(client.last_headers)
    archive_ok = "return=success0" in redirect and "editID=" in redirect
    archive_id = re.search(r"editID=([0-9]+)", redirect).group(1) if archive_ok else ""

    uploaded = ""
    lfi_marker = False
    if archive_ok:
        _, _, upload_page = client.authenticated_get(
            "/index.php?q=/modules/Reports/archive_manage_upload.php&gibbonReportArchiveID=%s" % archive_id
        )
        fields = {
            "address": hidden(upload_page, "address"),
            "csrftoken": hidden(upload_page, "csrftoken"),
            "nonce": hidden(upload_page, "nonce"),
            "gibbonReportArchiveID": archive_id,
            "gibbonSchoolYearID": "025",
            "reportIdentifier": "TRIDENT-PATCH-SMOKE",
            "reportDate": datetime.date.today().isoformat(),
            "fileSeparator": "/",
            "fileSection": "1",
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("1875.pdf", b"%PDF-1.4\n% TRIDENT fixture\n%%EOF\n")
            zip_file.writestr('<?php echo "TRIDENT_LFI_OK"; ?>.pdf', b"fixture")
        status, _, preview = client.post_multipart(
            "/index.php?q=/modules/Reports/archive_manage_uploadPreview.php",
            fields,
            {"file": ("spicy.php.zip", buffer.getvalue())},
        )
        uploaded = hidden(preview, "file")
        if uploaded:
            _, _, body = client.authenticated_get("/index.php?q=/%s" % uploaded.lstrip("/"))
            lfi_marker = "TRIDENT_LFI_OK" in body

    result = {
        "base_url": BASE,
        "login_ok": login_ok,
        "tracking_page_ok": tracking_ok,
        "sqli_neutralized": sqli_blocked,
        "sqli_seconds": round(sqli_seconds, 2),
        "normal_archive_created": archive_ok,
        "archive_id": archive_id,
        "uploaded_temp_path": uploaded,
        "lfi_marker_observed": lfi_marker,
        "lfi_blocked": (not lfi_marker) if uploaded else None,
        "result": "PATCH_VERIFIED" if all([login_ok, tracking_ok, sqli_blocked, archive_ok, not lfi_marker]) else "CHECK_FAILED",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["result"] == "PATCH_VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
