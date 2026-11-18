# Gibbon v30.0.00 real-target case

This directory contains the first TRIDENT evidence-driven case: a real open-source
school system, a pinned vulnerable commit, two runtime-confirmed findings, a
minimal patch, a second patched instance, and an upstream PR-ready bundle.

## Target

- Repository: `https://github.com/GibbonEdu/core`
- Vulnerable: `v30.0.00`, commit `c431e25fdc874adece5d2dc7e408e9aa2d1abadb`
- Fixed reference: `v30.0.01`, commit `b3b0219f49f2328508b989afd7e9b0843450cb9f`
- Vulnerable source: `target/`
- Patched source: `patched/`

## Running instances

| Service | Container | URL |
|---|---|---|
| MySQL 8 | `trident-gibbon-db` | `127.0.0.1:3307` |
| Vulnerable web | `trident-gibbon-vuln` | `http://127.0.0.1:8081` |
| Patched web | `trident-gibbon-patched` | `http://127.0.0.1:8082` |

Start both:

```powershell
Set-Location 'E:\pentest agent\TRIDENT\cases\gibbon-v30.0.00'
& 'C:\Program Files\Docker\Docker\resources\bin\docker.exe' compose up -d
```

The demo admin is `tridentadmin` / `trident-demo-pass`; the database is a disposable
local demo, not production data.

## Findings

| ID | CVE | Result |
|---|---|---|
| TRIDENT-GIBBON-2026-001 | CVE-2026-8208 | Reports archive LFI -> PHP execution; marker `TRIDENT_LFI_OK` observed |
| TRIDENT-GIBBON-2026-002 | CVE-2026-8207 | Authenticated Tracking SQLi; 20.51 s timing delta over baseline |

Details and SHA-256 anchors: `findings/`.

## Verification commands

```powershell
python .\poc_lfi.py
python .\poc_sqli.py

$env:GIBBON_BASE_URL='http://127.0.0.1:8082'
python .\smoke_patch.py
Remove-Item Env:GIBBON_BASE_URL
```

Expected results:

- LFI: HTTP 200, `TRIDENT_LFI_OK` present, `result: VULNERABLE`.
- SQLi: baseline ~3 s, injected > 20 s, `result: VULNERABLE`.
- Patched: `PATCH_VERIFIED`, normal archive creation succeeds, LFI marker absent,
  SQLi timing neutralized.

Captured evidence lives in `evidence/`.

## Patch bundle

`upstream/` contains the normalized patch, advisory draft, reproduction steps,
test plan and PR body. It is local-only; nothing has been submitted to GitHub.

Apply check:

```powershell
Set-Location .\target
git apply --check --ignore-whitespace ..\upstream\trident-gibbon-cve-2026-8207-8208.patch
```

## Boundaries

- Both findings require authentication.
- The LFI proof uses a local marker, not a persistent webshell.
- The SQLi timing proof needs the seeded Markbook fixture row; without it the
  normal “no records” page state can hide the delay.
- The official v30.0.01 diff and public analysis are ground truth, not a claim of
  first discovery.
