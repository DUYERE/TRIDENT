# Reproduction — local Gibbon case

## Environment

- Vulnerable source: `cases/gibbon-v30.0.00/target` (v30.0.00, commit `c431e25fdc874adece5d2dc7e408e9aa2d1abadb`)
- Patched source: `cases/gibbon-v30.0.00/patched` (local application of the security changes)
- Web: `127.0.0.1:8081` (`trident-gibbon-vuln`), patched control `127.0.0.1:8082` (`trident-gibbon-patched`)
- Database: `127.0.0.1:3307`, database `gibbon`
- Local admin: `tridentadmin` / `trident-demo-pass` (disposable demo credentials)

Start:

```powershell
Set-Location 'E:\pentest agent\TRIDENT\cases\gibbon-v30.0.00'
& 'C:\Program Files\Docker\Docker\resources\bin\docker.exe' compose up -d
```

## CVE-2026-8208 (LFI -> PHP execution)

```powershell
python .\poc_lfi.py
```

The script logs in, creates an archive at `/legit_files`, uploads
`spicy.php.zip` containing `1875.pdf` and a PHP marker entry, then requests the
returned temp path through the front controller. A vulnerable response is HTTP
200 and contains `TRIDENT_LFI_OK`. Captured evidence:
`evidence/lfi-run.json`.

## CVE-2026-8207 (authenticated SQLi)

```powershell
python .\poc_sqli.py
```

Fixture requirement: one `gibbonMarkbookEntry` row for student `1875` in
department `0004` (Science). The baseline uses department `0005`; the injected
request adds `0005 OR SLEEP(10)`. A vulnerable response is delayed by >= 8 s
(observed 20.51 s over a 3.00 s baseline). Captured evidence:
`evidence/sqli-run.json`.

## Patched control

```powershell
$env:GIBBON_BASE_URL='http://127.0.0.1:8082'
python .\smoke_patch.py
Remove-Item Env:GIBBON_BASE_URL
```

Expected: login and normal Tracking/Reports paths work; the LFI marker is absent;
the SQLi request stays below the timing threshold. Captured evidence:
`evidence/patch-run.json`.

## Notes

- Both findings require authentication.
- The LFI proof is a local marker, not a persistent webshell.
- The SQLi timing proof depends on the seeded fixture row; direct SQL confirmation
  alone does not replace the HTTP timing result.
