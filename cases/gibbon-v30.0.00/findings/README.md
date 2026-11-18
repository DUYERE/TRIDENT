# Gibbon v30.0.00 — confirmed findings

This directory contains two reproducible findings from the local Gibbon case. The
cases are pinned to the vulnerable commit and were verified against the running
container on `127.0.0.1:8081`; the patched copy runs on `127.0.0.1:8082`.

| ID | CVE | Severity | Chain | Runtime proof |
|---|---|---|---|---|
| TRIDENT-GIBBON-2026-001 | CVE-2026-8208 | Critical | Reports archive path → ZIP temp file → PHP include | `TRIDENT_LFI_OK` in HTTP 200 response |
| TRIDENT-GIBBON-2026-002 | CVE-2026-8207 | High | Duplicate Tracking department IDs → SQL predicate injection | 20.51 s time delta over baseline |

## Evidence files

- `TRIDENT-GIBBON-2026-001-reports-lfi.json` — source anchors, SHA-256, attack chain and runtime proof.
- `TRIDENT-GIBBON-2026-002-tracking-sqli.json` — source anchors, SHA-256, attack chain and timing proof.
- `../evidence/lfi-run.json` — captured LFI run.
- `../evidence/sqli-run.json` — captured SQLi run.
- `../evidence/patch-run.json` — patched-instance smoke and block results.

## Reproduction commands

From `cases/gibbon-v30.0.00`:

```powershell
python .\poc_lfi.py
python .\poc_sqli.py
$env:GIBBON_BASE_URL='http://127.0.0.1:8082'; python .\smoke_patch.py
```

The scripts are local-only and use the disposable demo database. They do not
submit anything upstream.

## Scope and limits

- Both findings require an authenticated account; this is not an unauthenticated
  Internet-facing claim.
- The SQLi proof uses a fixture row and a non-matching department ID to make the
  injected `SLEEP(10)` evaluate. Without the fixture, the page can return the
  normal “no records” state and timing cannot be observed.
- The LFI proof writes a local marker into a ZIP entry name and reads it back
  through the front controller; it does not deploy a persistent webshell.
- The official v30.0.01 diff and public analysis are treated as ground truth, not
  as evidence that TRIDENT was first to discover these issues.
