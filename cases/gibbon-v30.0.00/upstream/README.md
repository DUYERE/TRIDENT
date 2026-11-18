# Upstream PR-ready bundle — Gibbon v30.0.00

This directory is a self-contained, local-only submission bundle. It has not been
posted to GitHub or sent to Gibbon maintainers. The project owner must explicitly
approve any upstream action.

## Files

| File | Purpose |
|---|---|
| `trident-gibbon-cve-2026-8207-8208.patch` | Normalized patch for five files, applies to v30.0.00 |
| `advisory.md` | Security advisory draft |
| `repro.md` | Environment, PoCs and expected outputs |
| `test-plan.md` | Static, control, patched and negative checks |
| `pr-body.md` | PR title/body draft |

## Apply check

```powershell
Set-Location 'E:\pentest agent\TRIDENT\cases\gibbon-v30.0.00\target'
git apply --check --ignore-whitespace ..\upstream\trident-gibbon-cve-2026-8207-8208.patch
```

Expected: exit code 0.

## Patch scope

- `src/Data/Validator.php`
- `modules/Tracking/graphing.php`
- `modules/Reports/archive_manage_addProcess.php`
- `modules/Reports/archive_manage_editProcess.php`
- `modules/Reports/archive_manage_uploadProcess.php`

The patch is derived from the official v30.0.01 security changes and independently
verified on the local vulnerable/patched instances. It is a minimal reviewable
bundle, not a claim of upstream authorship.
