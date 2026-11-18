# Capability architecture pilot: unified entry evidence

## Scope

This is the first pilot of the proposed capability-provider architecture. It
does not rewrite any Java analyzer. It introduces a common evidence DTO and an
entry-capability registry that normalizes three existing sources:

1. `internal/audit` Java annotation endpoints;
2. `internal/codescan` declared routes for seven languages;
3. `internal/entrypoint` application-entry file candidates.

The Web `/api/endpoints` response keeps its legacy `items`/`total` fields and
adds a unified `entries` view. The UI consumes the unified view.

## Acceptance table

| ID | Required behavior | Exact API/default/boundary | Files and consumers | Observable assertion | Repository-native validation |
|---|---|---|---|---|---|
| A1 | Common evidence model | `internal/evidence.Report` with `entries`, `coverage`, `partial`, `limitations`, `providers`; entries carry language, source, kind, path, methods, file, line, authz, parameters | `internal/evidence/model.go`, `internal/evidence/model_test.go` | JSON round-trip keeps optional fields; unknown fields absent | `go test ./internal/evidence` |
| A2 | Entry capability registry | `entry.NewRegistry()` registers Java, code-route and application providers; `Build(ctx, Input)` sorts and de-duplicates; provider failure aborts, missing optional report yields explicit limitation | `internal/entry/registry.go`, `internal/entry/providers.go`, `internal/entry/entry_test.go` | Java endpoint maps with authz; PHP route maps as `route_declaration`; application entry maps as `application_entry`; duplicate is suppressed | `go test ./internal/entry` |
| A3 | Web API compatibility | Add `entries`, `entry_total`, `entry_coverage`, `entry_partial`, `entry_limitations`; keep `items`, `total`, `coverage`, `application_entries` unchanged | `internal/webui/api.go`, `internal/webui/application_entries_test.go` | Java fixture still `total=1`; PHP fixture `entry_total>=2`; old application entries still present | `go test ./internal/webui` |
| A4 | Unified UI | Entry page renders unified table with source/language, method, path/file, kind, authz, evidence; legacy Java table remains as compatibility view; unified table notes declaration vs deployment | `internal/webui/assets/app.js`, `internal/webui/assets/styles.css` | `#/endpoints` for PHP shows application entries; Java shows annotation and declared routes | `node --check`; live HTTP assets check |
| A5 | Full verification | No new false route claim; existing Go/API/UI tests pass | build/test/vet/scripts | `go test ./...`, `go vet ./...`, `python scripts/test-web.py` | final-state evidence |

## Implementation steps

1. Add `internal/evidence` (no dependencies on analyzers).
2. Add `internal/entry` providers and registry, depending on `audit`, `authz`,
   `codescan`, `entrypoint`, `evidence`; no new analyzer execution.
3. Wire `handleEndpoints` to build the unified report from the already computed
   state plus cached code audit; never start a full code audit inside the request.
4. Render unified entries in the existing entry page; keep Java detail table.
5. Run focused tests, then full repository checks; rebuild/restart and verify
   `www.test.com`.

## Non-goals

- Full AST or cross-procedural analysis.
- Framework authz for PHP/.NET/Python/JS/Go.
- Multi-ecosystem SCA/SBOM.
- Patch-validation profiles.
- Resolving ThinkPHP database-driven routes; they remain unparsed.
