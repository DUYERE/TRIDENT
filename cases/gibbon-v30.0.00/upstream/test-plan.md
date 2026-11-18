# Test plan — patch verification

## Static checks

Run PHP lint on every changed file in the patched tree:

```powershell
docker run --rm -v "E:\pentest agent\TRIDENT\cases\gibbon-v30.0.00\patched:/src" `
  trident-gibbon-web:latest sh -c "php -l /src/src/Data/Validator.php; php -l /src/modules/Tracking/graphing.php; php -l /src/modules/Reports/archive_manage_addProcess.php; php -l /src/modules/Reports/archive_manage_editProcess.php; php -l /src/modules/Reports/archive_manage_uploadProcess.php"
```

Expected: `No syntax errors detected` for all five files.

## Patch applicability

From `target/`:

```powershell
git apply --check --ignore-whitespace ..\upstream\trident-gibbon-cve-2026-8207-8208.patch
```

Expected exit code `0`.

## Vulnerable control

1. `python .\poc_lfi.py` returns HTTP 200 with `TRIDENT_LFI_OK`.
2. `python .\poc_sqli.py` returns a timing delta >= 8 s over baseline.

## Patched control

Run `smoke_patch.py` against `http://127.0.0.1:8082`:

| Assertion | Expected |
|---|---|
| Login on patched instance | HTTP 200, authenticated |
| Tracking graph normal request | HTTP 200, normal page |
| `0005` + `0005 OR SLEEP(10)` | HTTP 200 AND elapsed < 8 s |
| Archive at `/uploads` can be created | `return=success0` with an editID |
| Uploaded temp path requested | HTTP response does not contain `TRIDENT_LFI_OK` |
| Overall | `PATCH_VERIFIED` |

## Negative and boundary checks

- Archive path `/legit_files` is rejected with `return=error1` on the patched
  instance (path coerced to `/uploads/legit_files`, then realpath fails).
- Existing `/legit_files` archive row from the vulnerable run cannot be used to
  bypass the patched file operation.
- Normal archive creation with `/uploads` still succeeds, so the fix is not a
  blanket denial of the Reports workflow.
- The Tracking graph still renders for valid `0004`/`1875` input; sanitizing IDs
  must not break the normal query path.

## Out of scope

- Full regression of every Gibbon module.
- Browser UI automation beyond HTTP-level checks.
- Multi-tenant or production database behavior.
