# Multi-language parity plan

## Scope

This change is phase P0 of the cross-language capability work. It fixes the
false-zero entry view for non-Java projects and exposes application-entry
candidates without claiming that a route has been resolved.

It does not claim full AST, cross-procedural dataflow, framework authz, SCA,
reachability or patch-validation parity for PHP/.NET/Python/JS/Go. Those remain
in the capability matrix and are phased separately.

## Acceptance table

| ID | Required behavior | Exact API/default/boundary | Files and consumers | Observable assertion | Repository-native validation |
|---|---|---|---|---|---|
| P0-1 | Detect known application entry files for 7 code-audit languages | `internal/entrypoint.Inspect(ctx, *project.Snapshot)`; max 128 entries; skip `vendor`, `node_modules`, `tests`, `examples`, `docs`, `target`, `obj`, `bin`, `dist`; read at most 1 MiB per candidate; never execute code | `internal/entrypoint/entrypoint.go`, `internal/entrypoint/entrypoint_test.go` | PHP `public/index.php` -> language `php`, framework `ThinkPHP`, line evidence; .NET `Program.cs`; Python `manage.py`; JS `server.js`; Go `main.go`; vendor copy excluded | `go test ./internal/entrypoint` |
| P0-2 | Expose candidates without changing Java endpoint semantics | Add `application_entries`, `application_entries_partial`, `application_entry_limitations` to `GET /api/endpoints`; add `application_entries` and `application_entry_languages` to overview `analysis`; existing `items`, `total`, `coverage` unchanged | `internal/webui/api.go`, `internal/webui/api.go` overview, `internal/webui/assets/app.js` | Fixture Java response still returns `total=1`; PHP snapshot response has `application_entries` and no false "no HTTP entry" empty state | `go test ./internal/webui`; `python scripts/test-web.py` |
| P0-3 | Show candidates on the HTTP entry page | Render a separate "应用入口候选" table; each row shows language, framework, file:line, reason; click opens source; no route/path claim | `internal/webui/assets/app.js`, `internal/webui/assets/styles.css` if needed | Real PHP project `www.test.com` shows `public/index.php` and `public/router.php`; table notes candidates are not deployed routes | restart console and `GET /api/endpoints`; browser or API evidence |
| P0-4 | Keep overview badge honest | Badge and tile use parsed endpoints + application entries; subtitle states both counts | `internal/webui/assets/app.js`, `internal/webui/api.go` | `/overview` for PHP shows non-zero entry candidates; Java fixture remains unchanged | `go test ./...`; live HTTP check |

## Implementation steps

1. Add `internal/entrypoint` with deterministic path classification and bounded
   framework evidence. No shell, no project execution, no network.
2. Wire the report into `handleEndpoints` and `handleOverview`.
3. Add the entry-candidate table and adjust the endpoint empty state and badge.
4. Run focused tests, then `go build ./...`, `go vet ./...`, and the repository
   web acceptance script.
5. Rebuild the console binary, restart `127.0.0.1:8791`, and verify the real
   ThinkPHP snapshot has visible entry candidates.

## Non-goals for this phase

- Resolving ThinkPHP database-driven `Route::rule` paths.
- Emitting a fabricated route for a controller that is only conventionally
  reachable.
- Treating `public/index.php` as a deployed URL.
- Full per-language AST, authz, SCA, reachability or patch validation.
