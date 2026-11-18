# Security advisory draft — Gibbon Reports archive LFI/RCE and Tracking SQLi

**Status:** DRAFT — local PR-ready bundle. This has not been submitted to GitHub or
sent to Gibbon maintainers. Do not publish until the project owner approves.

## Affected product

- Repository: https://github.com/GibbonEdu/core
- Affected version: v30.0.00 (commit `c431e25fdc874adece5d2dc7e408e9aa2d1abadb`)
- Fixed version: v30.0.01 (commit `b3b0219f49f2328508b989afd7e9b0843450cb9f`)

## CVE-2026-8208 — authenticated Reports archive path to PHP include

An authenticated administrator can create a report archive with a path outside
the intended `/uploads` directory. The Reports upload preview writes the uploaded
ZIP to that archive path plus `/temp` and preserves the `.php` substring in the
outer ZIP filename. The front controller's address validator only requires the
requested path to contain `.php`; it blocks `..`, `installer`, `uploads` and
`config.php`, but not an attacker-selected archive directory such as
`/legit_files`. `View::fetchFromFile()` then executes `include $filepath`, so PHP
code embedded in a ZIP entry name is evaluated.

Impact: authenticated remote code execution in the web server context. The
proof uses a non-persistent marker (`TRIDENT_LFI_OK`) and does not install a
webshell.

## CVE-2026-8207 — authenticated Tracking graphing SQL injection

`modules/Tracking/graphing.php` reads `gibbonDepartmentIDs` and
`gibbonPersonIDs` from `$_POST` and derives PDO placeholder names and SQL
predicate fragments from the same values. A duplicate department ID such as
`0005` and `0005 OR SLEEP(10)` reuses `:department_MB0005` and appends
`OR SLEEP(10)`. A department with no matching fixture row makes both predicates
false and forces evaluation of the injected expression. The current guard
checks only `dataType` against `attainment`/`effort`; it does not sanitize the
ID arrays.

Impact: authenticated staff can inject SQL into the graphing query and read
or delay database-backed responses.

## Shared remediation

- Add and use `Validator::sanitizeAlphaNumeric`, `sanitizeNumeric`,
  `sanitizeArrayIDs`, `sanitizeFilename` and `sanitizeFilePath`.
- Force archive paths under `/uploads`, resolve with `realpath`, and reject
  paths outside the application base.
- Sanitize uploaded filenames and all file operations to
  `archive['path'].'/temp/<sanitized filename>'`.
- Sanitize `$_POST` in `graphing.php` and coerce both ID arrays before building
  SQL placeholders.

## Credit / provenance

This bundle was assembled from independent source review and local runtime
verification in the TRIDENT Gibbon case. The public Project Black analysis and
the official v30.0.01 diff are used as ground-truth comparison. This advisory
does not claim that TRIDENT was the first discoverer.
