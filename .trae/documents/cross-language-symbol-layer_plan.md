# Cross-language symbol layer (P2, bounded v1)

## Scope

P2 adds a deterministic, bounded symbol and call index on top of the existing
`codescan` token/statement IR. It does not replace the Java AST model and does
not introduce a type system, import resolution, receiver-type inference,
cross-file call graph, framework binding or runtime proof.

Covered languages: PHP, C#/.NET, Python, JavaScript, TypeScript, Java, Go.

## Acceptance table

| ID | Required behavior | Exact API, default, or boundary | Files and consumers | Observable assertion | Repository-native validation |
|---|---|---|---|---|---|
| A1 | Symbol and call index | `codescan.Symbol` / `Call` / `Unresolved`; limit `MaxSymbols=2000`, `MaxCalls=4000`, `MaxUnresolved=2000`; `Call.Status` is only `same_file` or `external_or_unresolved` | `internal/codescan/symbols.go`, `symbols_test.go`, `analyze.go` | PHP function and local call become one symbol and one `same_file` call; external `mysql_query` is unresolved; Java class/method and Go func are indexed | `go test ./internal/codescan` |
| A2 | Report and coverage integration | `Report.symbols/calls/unresolved`; `Coverage.symbols_found/calls_found/unresolved_found`; `LanguageSummary.symbols/calls/unresolved`; limits set `partial` and a limitation string | `internal/codescan/model.go`, `analyze.go`, existing tests | Existing findings/routes unchanged; empty slices serialize as `[]`; counts are deterministic | `go test ./internal/codescan` |
| A3 | Web API | `/api/code-audit` adds `symbols`, `calls`, `unresolved`, `symbol_languages`; `/api/model` adds cached `symbols`, `calls`, `unresolved`, `symbol_languages`, `symbol_partial`, `symbol_reason`; never starts code audit inside `/api/model` | `internal/webui/code_audit.go`, `model_views.go`, `code_audit_test.go` | Java fixture has at least one symbol; pending code audit returns `symbol_reason`, not fake data | `go test ./internal/webui` |
| A4 | UI | `#/code` renders a language-grouped symbol/call/unresolved card; `#/model` keeps Java AST table but adds a multi-language symbol card and no longer claims the whole page is Java-only | `internal/webui/assets/app.js`, `styles.css` | PHP page shows symbols grouped by language; Java page shows Java AST plus symbol evidence when cached | `node --check`; live API/assets check |
| A5 | Final verification | No regression in findings/routes/entry API | build/test/vet/scripts | `go test ./...`, `go vet ./...`, `python scripts/test-web.py` | final-state evidence |

## Design

1. `symbols.go` consumes `statement`, `relations`, `languageSpec` and existing
   `functionDeclaration` / `callsIn` data. It emits:
   - function/method/type symbols with file, SHA-256, line, container, params;
   - call sites with caller, target, argument count and status;
   - unresolved calls when no same-file symbol has the exact simple name.
2. Function/type declaration kinds are lexical. Nested type bodies and function
   bodies are mapped by existing scope ids; Python remains file-scoped and is
   documented as unresolved for caller attribution.
3. `Analyze` appends index data after route scanning. Caps apply after each file;
   truncation sets `Partial` and `symbol_limit`/`call_limit`/`unresolved_limit`.
4. Web returns only capped lists; full counts remain in coverage/language
   summaries. `/api/model` uses `codeAuditCached` only.
5. No raw string constants or variable values are exposed in this pass; that
   avoids leaking secrets and avoids pretending a value index is a type model.

## Non-goals

- Type resolution, imports, receiver types, overloads, dynamic dispatch.
- Cross-file calls, call graphs, framework binding.
- Full AST/CFG/points-to analysis.
- Variable/string-constant index; reserved for a later P2 increment.
- Runtime verification or exploitability claims.
