# PR-ready body — harden Reports archive paths and Tracking graph IDs

> DRAFT, local only. No upstream submission has been made. Project owner approval
> is required before opening a GitHub issue or pull request.

## Summary

This change hardens two authenticated input paths in Gibbon:

1. Reports archives can no longer be created or edited with a path outside the
   application's `/uploads` directory. Archive paths are resolved and checked
   against the application base.
2. Tracking graphing sanitizes POSTed person/department ID arrays and the
   `dataType` token before they are used to build PDO placeholders and SQL
   fragments.

## Root cause

- `archive_manage_addProcess.php` and `archive_manage_editProcess.php` persisted
  `$_POST['path']` with only a leading-slash trim. The Reports preview then
  uploaded a ZIP into that path's `temp` directory. A `.php` substring in the
  outer ZIP name allowed the front controller to `include` it.
- `graphing.php` concatenated values from `gibbonDepartmentIDs` and
  `gibbonPersonIDs` into named placeholders and SQL predicates. The only guard
  checked `dataType`; duplicate IDs allowed an injected expression to reuse a
  placeholder and execute.

## Changes

- `src/Data/Validator.php`: add `sanitizeAlphaNumeric`, `sanitizeNumeric`,
  `sanitizeArrayIDs`, `sanitizeFilename` and `sanitizeFilePath`.
- `modules/Reports/archive_manage_addProcess.php`: force `/uploads`, resolve the
  path, reject paths outside the base, persist the secure relative path.
- `modules/Reports/archive_manage_editProcess.php`: same path controls.
- `modules/Reports/archive_manage_uploadProcess.php`: sanitize the filename and
  perform ZIP read/delete only on `archive['path'].'/temp/<sanitized filename>'`.
- `modules/Tracking/graphing.php`: load the Validator, sanitize `$_POST`, coerce
  both ID arrays with `sanitizeArrayIDs`, and sanitize `dataType` with
  `sanitizeAlphaNumeric`.

## Verification

- `php -l` on all five changed files: no syntax errors.
- `git apply --check` against v30.0.00: patch applies.
- Vulnerable control: LFI marker observed; SQLi timing delta 20.51 s.
- Patched control on `127.0.0.1:8082`: `PATCH_VERIFIED`; normal archive creation
  and Tracking graph still work; LFI marker absent; SQLi timing neutralized.

## Risk and rollout

- The path realpath check rejects non-existent archive target directories. This is
  intentional for the security boundary but may require administrators to create
  a target directory under `/uploads` before selecting it. Existing `/uploads`
  workflows continue to work.
- No schema, API or public route changes.
- No secrets, tokens or local credentials are included in this bundle.

## Review checklist

- [ ] Confirm the `realpath` base check is compatible with the deployment layout.
- [ ] Confirm archive path semantics match maintainer expectations.
- [ ] Run the project's standard PHP lint/test suite.
- [ ] Confirm the advisory credit/provenance wording before publication.
