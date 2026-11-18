package codescan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"trident/internal/project"
)

var routePathPattern = regexp.MustCompile(`^[A-Za-z0-9/_\-.\[\]{}:+*?&=~%@]{1,256}$`)

// Analyze audits every source file owned by a supported front end in the
// pinned snapshot. It is read-only, offline, deterministic and bounded.
func Analyze(ctx context.Context, snapshot *project.Snapshot, opts Options) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("%w: pinned snapshot required", ErrLimit)
	}
	selected, err := resolveLanguages(opts)
	if err != nil {
		return Report{}, err
	}
	rules, rulesetVersion, err := resolveRules(opts)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		SchemaVersion: SchemaVersion, ToolVersion: ToolVersion,
		SnapshotHash: snapshot.Hash(), AnalysisKind: AnalysisKind,
		RuleSetVersion: rulesetVersion,
		Languages:      []LanguageSummary{}, Files: []FileSummary{},
		Routes: []Route{}, Symbols: []Symbol{}, Calls: []Call{}, Unresolved: []Unresolved{}, Variables: []Variable{}, StringConstants: []StringConstant{}, Findings: []Finding{},
		Coverage: Coverage{RuntimeStatus: "not_run", AnalysisScope: "bounded_intrascope_taint_v2+lexical_symbols_v2"},
		Limitations: []string{
			"lexical_token_ir: analysis uses a bounded token/statement IR, not a full AST, type system, control-flow graph or points-to analysis",
			"intra_file_function_summary: same-file cross-function flows are summarized one level deep by exact simple function name; cross-file flows, overloads, dynamic dispatch, recursion and framework binding are not connected",
			"no_type_resolution: overloads, dynamic dispatch, framework binding, ORM/AOP, reflection and dependency injection are not resolved",
			"no_runtime_verification: runtime_status is always not_run; a finding is static evidence, not proof of exploitability or deployment",
			"rules_are_data_not_semantics: rules are declarative name patterns; a name collision with a local helper can change a result, and renamed framework APIs are not followed",
			"sanitizer_is_pattern_level: a matched sanitizer suppresses taint for the expression containing it; argument-level sanitizer coverage is not proven",
			"safe_call_lookahead_3: a safe/parameter-binding call within 3 statements of a sink suppresses that sink for the same rule; this is a bounded false-positive control, not a safety proof",
			"string_interpolation_bounded: interpolated expressions are extracted for python f-strings (single f/F prefix), C# $\"...\", JS/TS template literals and PHP double quotes; heredoc/nowdoc, python r-strings, go raw strings and format-specifier edge cases stay opaque",
			"python_scope_file_level: Python uses one file-level scope because indentation-based scoping is not modeled",
			"route_declaration_not_deployment: HTTP routes are declarative source observations, not deployed routes or reachable endpoints",
			"symbol_index_lexical: symbols are lexical declarations; parameters are names only and no type system is modeled",
			"symbol_call_cross_file_unique_name: cross-file calls resolve only a unique project-wide function/method name or qualified name; ambiguous names stay explicit and receiver/type dispatch is unresolved",
			"variables_lexical_assignment_targets: variables are assignment targets only; mutation, aliasing, lifetimes and types are not modeled",
			"string_constants_hashed_not_values: string constants are indexed by SHA-256 and length only; raw values are never emitted",
			"absence_is_not_safety: no finding does not mean the code is safe",
			"bounded_token_budget: files exceeding byte, token or statement limits are rejected and reported as partial coverage",
		},
	}

	specs := languageSpecs()
	byLangFindings := map[string]int{}
	byLangRoutes := map[string]int{}
	byLangSymbols := map[string]int{}
	byLangCalls := map[string]int{}
	byLangCallsResolved := map[string]int{}
	byLangUnresolved := map[string]int{}
	byLangVariables := map[string]int{}
	byLangStrings := map[string]int{}
	byLangFiles := map[string]int{}
	byLangRejected := map[string]int{}
	byLangRules := map[string]int{}
	byCategory := map[string]int{}
	active := activeRules(rules, selected)
	for _, rule := range active {
		for _, lang := range rule.Languages {
			if selected[lang] {
				byLangRules[lang]++
			}
		}
	}
	report.Coverage.RulesLoaded = len(rules)
	report.Coverage.RulesActive = len(active)

	entries := append([]project.FileEntry(nil), snapshot.Manifest().Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, entry := range entries {
		if err := contextOK(ctx); err != nil {
			return Report{}, err
		}
		spec, ok := languageForFile(entry.Path, specs)
		if !ok || !selected[spec.Name] {
			continue
		}
		if len(report.Files) >= MaxFiles {
			markPartial(&report, "file_limit")
			break
		}
		byLangFiles[spec.Name]++
		content, err := snapshot.ReadFile(ctx, entry.Path)
		if err != nil {
			return Report{}, err
		}
		digest := sha256.Sum256(content)
		fileSHA := hex.EncodeToString(digest[:])
		if len(content) > MaxFileBytes {
			report.Files = append(report.Files, FileSummary{File: entry.Path, Language: spec.Name, Scope: fileScope(entry.Path), SHA256: fileSHA, Bytes: len(content), Status: "rejected", Reason: "file_too_large"})
			byLangRejected[spec.Name]++
			markPartial(&report, "file_too_large")
			continue
		}
		tokens, lexErr := lex(content, spec, MaxTokensPerFile)
		if lexErr != nil {
			report.Files = append(report.Files, FileSummary{File: entry.Path, Language: spec.Name, Scope: fileScope(entry.Path), SHA256: fileSHA, Bytes: len(content), Status: "rejected", Reason: "lex_rejected"})
			byLangRejected[spec.Name]++
			markPartial(&report, "lex_rejected")
			continue
		}
		statements, relations, parseErr := splitStatements(tokens, spec, MaxStatementsPerFile)
		if parseErr != nil {
			report.Files = append(report.Files, FileSummary{File: entry.Path, Language: spec.Name, Scope: fileScope(entry.Path), SHA256: fileSHA, Bytes: len(content), Tokens: len(tokens), Status: "rejected", Reason: "statement_limit"})
			byLangRejected[spec.Name]++
			markPartial(&report, "statement_limit")
			continue
		}
		report.Files = append(report.Files, FileSummary{File: entry.Path, Language: spec.Name, Scope: fileScope(entry.Path), SHA256: fileSHA, Bytes: len(content), Tokens: len(tokens), Statements: len(statements), Status: "scanned"})
		report.Coverage.FilesScanned++
		report.Coverage.TokensScanned += len(tokens)
		report.Coverage.StatementsScanned += len(statements)
		routes := scanRoutes(statements, spec, entry.Path, fileSHA)
		for _, route := range routes {
			report.Routes = append(report.Routes, route)
			byLangRoutes[route.Language]++
		}
		symbols, calls, unresolved := scanSymbolIndex(statements, relations, spec, entry.Path, fileSHA)
		for _, symbol := range symbols {
			if len(report.Symbols) >= MaxSymbols {
				markPartial(&report, "symbol_limit")
				break
			}
			report.Symbols = append(report.Symbols, symbol)
			byLangSymbols[symbol.Language]++
		}
		variables, stringConstants, variableLimit, stringLimit := scanVariableIndex(statements, spec, entry.Path, fileSHA)
		for _, variable := range variables {
			if len(report.Variables) >= MaxVariables {
				markPartial(&report, "variable_limit")
				break
			}
			report.Variables = append(report.Variables, variable)
			byLangVariables[variable.Language]++
		}
		for _, item := range stringConstants {
			if len(report.StringConstants) >= MaxStringConstants {
				markPartial(&report, "string_constant_limit")
				break
			}
			report.StringConstants = append(report.StringConstants, item)
			byLangStrings[item.Language]++
		}
		if variableLimit {
			markPartial(&report, "variable_limit")
		}
		if stringLimit {
			markPartial(&report, "string_constant_limit")
		}
		for _, call := range calls {
			if len(report.Calls) >= MaxCalls {
				markPartial(&report, "call_limit")
				break
			}
			report.Calls = append(report.Calls, call)
			byLangCalls[call.Language]++
		}
		for _, item := range unresolved {
			if len(report.Unresolved) >= MaxUnresolved {
				markPartial(&report, "unresolved_limit")
				break
			}
			report.Unresolved = append(report.Unresolved, item)
			byLangUnresolved[item.Language]++
		}
		langRules := rulesForLanguage(active, spec.Name)
		findings := scanRules(statements, relations, spec, langRules, entry.Path, fileSHA)
		for _, finding := range findings {
			if len(report.Findings) >= MaxFindings {
				markPartial(&report, "finding_limit")
				break
			}
			report.Findings = append(report.Findings, finding)
			byLangFindings[finding.Language]++
			byCategory[finding.Category]++
		}
	}

	report.Coverage.FilesRejected = len(report.Files) - report.Coverage.FilesScanned
	report.Coverage.RoutesFound = len(report.Routes)
	expandThinkPHPDatabaseRoutes(ctx, snapshot, &report)
	appendThinkPHPConventionRoutes(&report)
	report.Coverage.RoutesFound = len(report.Routes)
	resolveCrossFileCalls(&report)
	for _, call := range report.Calls {
		if call.Status == "same_project" {
			byLangCallsResolved[call.Language]++
		}
	}
	report.Coverage.SymbolsFound = len(report.Symbols)
	report.Coverage.CallsFound = len(report.Calls)
	report.Coverage.CallsResolved = 0
	for _, value := range byLangCallsResolved {
		report.Coverage.CallsResolved += value
	}
	report.Coverage.UnresolvedFound = len(report.Unresolved)
	report.Coverage.VariablesFound = len(report.Variables)
	report.Coverage.StringConstants = len(report.StringConstants)
	report.Coverage.Findings = len(report.Findings)
	report.Coverage.ByLanguage = countsFrom(byLangFindings)
	report.Coverage.ByCategory = countsFrom(byCategory)
	for _, spec := range specs {
		status := "scanned"
		if !selected[spec.Name] {
			status = "skipped_by_filter"
		} else if byLangFiles[spec.Name] == 0 {
			status = "no_source_files"
		}
		report.Languages = append(report.Languages, LanguageSummary{
			Language: spec.Name, Extensions: append([]string(nil), spec.Extensions...),
			FilesScanned:  byLangFiles[spec.Name] - byLangRejected[spec.Name],
			FilesRejected: byLangRejected[spec.Name], RulesActive: byLangRules[spec.Name],
			Findings: byLangFindings[spec.Name], Routes: byLangRoutes[spec.Name],
			Symbols: byLangSymbols[spec.Name], Calls: byLangCalls[spec.Name],
			CallsResolved: byLangCallsResolved[spec.Name],
			Unresolved:    byLangUnresolved[spec.Name],
			Variables:     byLangVariables[spec.Name], Strings: byLangStrings[spec.Name], Status: status,
		})
	}
	sort.Slice(report.Languages, func(i, j int) bool { return report.Languages[i].Language < report.Languages[j].Language })
	sort.Slice(report.Routes, func(i, j int) bool {
		a, b := report.Routes[i], report.Routes[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Symbol < b.Symbol
	})
	sort.Slice(report.Symbols, func(i, j int) bool {
		a, b := report.Symbols[i], report.Symbols[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	sort.Slice(report.Calls, func(i, j int) bool {
		a, b := report.Calls[i], report.Calls[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Callee != b.Callee {
			return a.Callee < b.Callee
		}
		return a.Status < b.Status
	})
	sort.Slice(report.Unresolved, func(i, j int) bool {
		a, b := report.Unresolved[i], report.Unresolved[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Expr < b.Expr
	})
	sort.Slice(report.Variables, func(i, j int) bool {
		a, b := report.Variables[i], report.Variables[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Name < b.Name
	})
	sort.Slice(report.StringConstants, func(i, j int) bool {
		a, b := report.StringConstants[i], report.StringConstants[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Hash < b.Hash
	})
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.ID < b.ID
	})
	report.Limitations = dedupeSorted(report.Limitations)
	return report, nil
}

func contextOK(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func rulesForLanguage(rules []RuleSpec, language string) []RuleSpec {
	out := make([]RuleSpec, 0, len(rules))
	for _, rule := range rules {
		for _, lang := range rule.Languages {
			if lang == language {
				out = append(out, rule)
				break
			}
		}
	}
	return out
}

func scanRoutes(statements []statement, spec languageSpec, file, fileSHA string) []Route {
	routes := make([]Route, 0, 4)
	seen := map[string]int{}
	for _, stmt := range statements {
		for _, chain := range stmt.occurs {
			for _, routeSpec := range spec.Routes {
				if !chainHasName(chain, routeSpec.Names, spec.Name) {
					continue
				}
				path, literal := firstRouteArgumentString(stmt, chain)
				if literal {
					if path == "" || !routePathPattern.MatchString(path) || !routePathAllowed(path, spec, routeSpec) {
						continue
					}
				} else if routeSpec.Kind != "call" || !routeSpec.Dynamic {
					// Annotation names such as PHP's `Route` occur in ordinary
					// class references too; only explicitly dynamic route calls
					// get a placeholder.
					continue
				}
				if path == "" {
					path = "<dynamic>"
				}
				methods := inferHTTPMethod(chain.short, routeSpec.Method)
				pathStatus := "declared"
				reason := "route_declaration_not_deployment"
				if !literal {
					pathStatus = "dynamic_unresolved"
					reason = "route_path_not_literal"
				}
				key := strings.Join([]string{spec.Name, file, fmt.Sprintf("%d", chain.line), path}, ":")
				if previous, ok := seen[key]; ok {
					if len(methods) > 0 && len(routes[previous].HTTPMethods) == 0 {
						routes[previous].HTTPMethods = methods
					}
					break
				}
				seen[key] = len(routes)
				routes = append(routes, Route{
					Language: spec.Name, Path: path, PathStatus: pathStatus, Reason: reason,
					Source: "declaration", HTTPMethods: methods, Symbol: chain.full, File: file, SHA256: fileSHA,
					Line: chain.line, Kind: routeSpec.Kind,
				})
				break
			}
		}
	}
	return routes
}

// firstRouteArgumentString returns the first argument only when it is a literal
// string. A variable first argument (for example ThinkPHP Route::rule($path))
// must not be mistaken for the string in a later argument.
func firstRouteArgumentString(stmt statement, chain chainInfo) (string, bool) {
	for i := chain.end + 1; i < len(stmt.tokens) && i <= chain.end+6; i++ {
		tok := stmt.tokens[i]
		if tok.text == "(" || tok.text == "[" || tok.text == "@" {
			continue
		}
		if tok.kind == tokString {
			return tok.text, true
		}
		return "", false
	}
	return "", false
}

// routePathAllowed rejects unrelated string literals that happen to follow a
// name-shaped match (for example request.args.get('title')). Framework route
// attributes are allowed to use relative paths because that is valid in
// ASP.NET and Spring annotations.
func routePathAllowed(path string, spec languageSpec, routeSpec routeSpec) bool {
	if strings.ContainsAny(path, "/[") {
		return true
	}
	if routeSpec.Kind == "annotation" && (spec.Name == "csharp" || spec.Name == "java") {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Bounded intra-scope taint engine
// ---------------------------------------------------------------------------

type taintValue struct {
	source *Ref
	steps  []FlowStep
	// param is the normalized parameter name when this taint value
	// originates from a function parameter (used by the summary layer).
	param string
}

type scopeState struct {
	vars map[string]taintValue
}

type paramBinding struct {
	key   string
	value taintValue
}

type ruleContext struct {
	rule      RuleSpec
	spec      languageSpec
	file      string
	fileSHA   string
	states    map[int]*scopeState
	relations map[int]scopeRelation
	bindings  map[int][]paramBinding
	safeAt    []bool
	seen      map[string]bool
	findings  []Finding
	summaries []fnSummary
	// currentScope is the scope of the statement being evaluated. It keeps
	// summary call-site matching inside runStatement (single-threaded).
	currentScope int
}

func scanRules(statements []statement, relations map[int]scopeRelation, spec languageSpec, rules []RuleSpec, file, fileSHA string) []Finding {
	out := make([]Finding, 0, 16)
	for i := range rules {
		ctx := &ruleContext{
			rule: rules[i], spec: spec, file: file, fileSHA: fileSHA,
			states: map[int]*scopeState{}, relations: relations,
			bindings: map[int][]paramBinding{},
			safeAt:   make([]bool, len(statements)), seen: map[string]bool{},
			findings: []Finding{},
		}
		for idx, stmt := range statements {
			ctx.safeAt[idx] = statementHasSafeCall(stmt, ctx.rule, spec.Name)
		}
		ctx.bindAnnotationParameters(statements)
		ctx.summaries = ctx.buildSummaries(statements)
		for idx, stmt := range statements {
			ctx.runStatement(idx, stmt)
		}
		out = append(out, ctx.findings...)
	}
	return out
}

func (c *ruleContext) stateFor(scope int) *scopeState {
	if state, ok := c.states[scope]; ok {
		return state
	}
	state := &scopeState{vars: map[string]taintValue{}}
	parent := c.relations[scope].parent
	if parent >= 0 && parent != scope {
		for key, value := range c.stateFor(parent).vars {
			// Method-signature parameters are scoped to that method body, not
			// inherited by sibling methods through the enclosing class scope.
			if !c.isBoundParameter(key) {
				state.vars[key] = value
			}
		}
	}
	for _, binding := range c.bindings[scope] {
		state.vars[binding.key] = binding.value
	}
	c.states[scope] = state
	return state
}

func (c *ruleContext) isBoundParameter(key string) bool {
	for _, bindings := range c.bindings {
		for _, binding := range bindings {
			if binding.key == key {
				return true
			}
		}
	}
	return false
}

func (c *ruleContext) runStatement(index int, stmt statement) {
	if stmt.declaration {
		// A signature header such as `public String exec(@RequestBody String cmd)`
		// is not an executable call; treating its parameter list as sink
		// arguments would produce a duplicate finding.
		return
	}
	c.currentScope = stmt.scope
	state := c.stateFor(stmt.scope)
	sanitized := statementHasSanitizer(stmt, c.rule, c.spec.Name)
	nearbySafe := c.nearbySafeCall(index)

	if stmt.assign != nil {
		value, tainted := c.evalExpr(stmt.assign.rhs, state, stmt.assign.line)
		if tainted && !sanitized && !nearbySafe {
			c.checkAssignSink(stmt.assign, value, stmt)
		}
		key := normalizeName(c.spec.Name, stmt.assign.target)
		if tainted && !sanitized && !nearbySafe {
			step := FlowStep{Kind: "assignment", Detail: stmt.assign.target + " " + stmt.assign.op + " " + expressionText(stmt.assign.rhs), File: c.file, SHA256: c.fileSHA, Line: stmt.assign.line}
			value.steps = append(append([]FlowStep(nil), value.steps...), step)
			state.vars[key] = value
		} else {
			delete(state.vars, key)
		}
	}

	for _, call := range stmt.calls {
		for _, sink := range c.rule.Sinks {
			if sink.Kind != "call" && sink.Kind != "any" {
				continue
			}
			chain := chainInfo{segs: splitSelector(call.full), full: call.full, short: call.short, kind: "call", line: call.line}
			if !patternMatches(sink, chain, c.spec.Name) {
				continue
			}
			args := call.args
			if sink.ArgIndex > 0 {
				if sink.ArgIndex > len(args) {
					continue
				}
				args = [][]token{args[sink.ArgIndex-1]}
			}
			for _, arg := range args {
				value, tainted := c.evalExpr(arg, state, call.line)
				if tainted && !sanitized && !nearbySafe {
					c.emit(call.full, call.short, "call", call.line, value, stmt)
					break
				}
			}
		}
	}
	// Same-file function-summary layer: a call whose tainted argument reaches
	// a rule sink inside the called function produces a finding pinned to both
	// the call site and the in-body sink.
	c.checkSummarySinks(stmt, state)
	// Receiver sinks cover APIs whose dangerous input is the object being read
	// rather than an argument, e.g. ObjectInputStream.readObject().
	for _, sink := range c.rule.Sinks {
		if sink.Kind != "receiver" {
			continue
		}
		for _, call := range stmt.calls {
			chain := chainInfo{segs: splitSelector(call.full), full: call.full, short: call.short, kind: "call", line: call.line}
			if !chainHasName(chain, sink.Names, c.spec.Name) || sanitized || nearbySafe {
				continue
			}
			receiverSegs := chain.segs
			if len(receiverSegs) > 1 {
				receiverSegs = receiverSegs[:len(receiverSegs)-1]
			} else {
				receiverSegs = nil
			}
			for _, segment := range receiverSegs {
				if value, ok := state.vars[normalizeName(c.spec.Name, segment)]; ok {
					c.emit(call.full, call.short, "receiver", call.line, value, stmt)
					break
				}
			}
		}
	}
	for _, sink := range c.rule.Sinks {
		if sink.Kind != "statement" {
			continue
		}
		matched := false
		for _, name := range sink.Names {
			if normalizeName(c.spec.Name, name) == normalizeName(c.spec.Name, stmt.head) {
				matched = true
				break
			}
		}
		if !matched || sanitized || nearbySafe || len(stmt.tokens) < 2 {
			continue
		}
		value, tainted := c.evalExpr(stmt.tokens[1:], state, stmt.line)
		if tainted {
			c.emit(stmt.head, stmt.head, "statement", stmt.line, value, stmt)
		}
	}
}

func (c *ruleContext) checkAssignSink(assign *assignInfo, value taintValue, stmt statement) {
	for _, sink := range c.rule.Sinks {
		if sink.Kind != "assign" {
			continue
		}
		if !chainHasName(chainInfo{segs: splitSelector(assign.full), full: assign.full, short: assign.target, kind: "identifier"}, sink.Names, c.spec.Name) {
			continue
		}
		c.emit(assign.full, assign.target, "assign", assign.line, value, stmt)
	}
}

// bindAnnotationParameters attaches framework-annotated request parameters
// (for example @RequestParam String name) to the method-body scope that owns
// the signature. This prevents one controller method's parameters from
// tainting a sibling method. No framework binding or runtime behavior is
// proven; this is a bounded declaration-level source.
func (c *ruleContext) bindAnnotationParameters(statements []statement) {
	if c.spec.Name != "java" && c.spec.Name != "csharp" {
		return
	}
	for index, stmt := range statements {
		params := c.annotationParameters(stmt)
		if len(params) == 0 {
			continue
		}
		targetScope := -1
		for j := index + 1; j < len(statements) && j <= index+4; j++ {
			candidate := statements[j].scope
			if candidate != stmt.scope && c.relations[candidate].parent == stmt.scope {
				targetScope = candidate
				break
			}
		}
		if targetScope >= 0 {
			c.bindings[targetScope] = append(c.bindings[targetScope], params...)
		}
	}
}

func (c *ruleContext) annotationParameters(stmt statement) []paramBinding {
	out := []paramBinding{}
	for _, chain := range stmt.occurs {
		if !chain.annotated {
			continue
		}
		matched := false
		for _, source := range c.rule.Sources {
			// Annotations may carry arguments (`@RequestParam("id")`), which
			// makes the chain look like a call. Name matching is intentional
			// here; kind is not a meaningful discriminator for declarations.
			if chainHasName(chain, source.Names, c.spec.Name) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		varName := ""
		for i := chain.end + 1; i < len(stmt.tokens) && i <= chain.end+10; i++ {
			tok := stmt.tokens[i]
			if tok.kind == tokSymbol && (tok.text == "," || tok.text == "=" || tok.text == ";") {
				break
			}
			if tok.kind == tokIdent && declarationStopWords[strings.ToLower(tok.text)] {
				break
			}
			if tok.kind == tokIdent && !nonAssignmentHeads[strings.ToLower(tok.text)] {
				varName = tok.text
			}
		}
		if varName == "" {
			continue
		}
		ref := &Ref{Kind: "source", Symbol: chain.short + " " + varName, File: c.file, SHA256: c.fileSHA, Line: chain.line, Detail: c.rule.ID + " (annotated parameter)"}
		step := FlowStep{Kind: "source", Detail: ref.Symbol + " (annotated parameter)", File: c.file, SHA256: c.fileSHA, Line: chain.line}
		out = append(out, paramBinding{
			key:   normalizeName(c.spec.Name, varName),
			value: taintValue{source: ref, steps: []FlowStep{step}},
		})
	}
	return out
}

func (c *ruleContext) nearbySafeCall(index int) bool {
	for i := index - 3; i <= index+3; i++ {
		if i >= 0 && i < len(c.safeAt) && c.safeAt[i] {
			return true
		}
	}
	return false
}

func (c *ruleContext) evalExpr(tokens []token, state *scopeState, line int) (taintValue, bool) {
	return c.evalTokens(tokens, state.vars, line, 0)
}

// evalTokens evaluates an expression against one variable map. depth 0 allows
// the same-file function-summary layer (source wrappers and taint-through
// returns); depth > 0 stops expanding summaries so flows stay one call deep.
func (c *ruleContext) evalTokens(tokens []token, vars map[string]taintValue, line int, depth int) (taintValue, bool) {
	if len(tokens) == 0 {
		return taintValue{}, false
	}
	chains := chainsIn(tokens, c.spec)
	for _, chain := range chains {
		for _, sanitizer := range c.rule.Sanitizers {
			if patternMatches(sanitizer, chain, c.spec.Name) {
				return taintValue{}, false
			}
		}
	}
	for _, chain := range chains {
		for _, source := range c.rule.Sources {
			if patternMatches(source, chain, c.spec.Name) {
				ref := &Ref{Kind: "source", Symbol: chain.full, File: c.file, SHA256: c.fileSHA, Line: chain.line, Detail: c.rule.ID}
				step := FlowStep{Kind: "source", Detail: chain.full + " (source)", File: c.file, SHA256: c.fileSHA, Line: chain.line}
				return taintValue{source: ref, steps: []FlowStep{step}}, true
			}
		}
		key := normalizeName(c.spec.Name, chain.short)
		if value, ok := vars[key]; ok {
			return value, true
		}
		if value, ok := vars[normalizeName(c.spec.Name, chain.full)]; ok {
			return value, true
		}
	}
	if depth == 0 && len(c.summaries) > 0 {
		// Interpolated-string chains are data, never call sites; drop them
		// before matching summary functions.
		occurs := dropFromStringChains(chains)
		for _, call := range callsIn(tokens, c.spec, occurs) {
			if value, ok := c.evalSummaryCall(call, vars, line); ok {
				return value, true
			}
		}
	}
	return taintValue{}, false
}

func (c *ruleContext) emit(symbol, short, kind string, line int, value taintValue, stmt statement) {
	sourceLine := line
	if value.source != nil {
		sourceLine = value.source.Line
	}
	id := strings.Join([]string{c.rule.ID, c.file, fmt.Sprintf("%d", line), short, fmt.Sprintf("%d", sourceLine)}, ":")
	if c.seen[id] {
		return
	}
	c.seen[id] = true
	flow := append([]FlowStep(nil), value.steps...)
	flow = append(flow, FlowStep{Kind: "sink", Detail: symbol + " (" + kind + ")", File: c.file, SHA256: c.fileSHA, Line: line})
	if len(flow) > MaxFlowSteps {
		flow = flow[:MaxFlowSteps]
	}
	evidence := []Ref{}
	if value.source != nil {
		evidence = append(evidence, *value.source)
	}
	evidence = append(evidence, Ref{Kind: "sink", Symbol: symbol, File: c.file, SHA256: c.fileSHA, Line: line, Detail: c.rule.ID})
	for _, step := range flow {
		if step.Kind == "assignment" {
			evidence = append(evidence, Ref{Kind: "propagation", Symbol: step.Detail, File: step.File, SHA256: step.SHA256, Line: step.Line})
		}
	}
	startLine, endLine := line, line
	if value.source != nil {
		startLine = value.source.Line
		if endLine < startLine {
			endLine = startLine
		}
	}
	status := "static_confirmed"
	limitations := []string{
		"bounded_intrascope_taint: source and sink were observed in the same bounded scope; cross-function, framework-bound and runtime flows were not verified",
		"name_based_rule: the sink was matched by a declarative name pattern, not by type resolution or a call graph",
		"no_evidence_of_sanitizer_coverage: absence of an observed sanitizer is not proof that no validation exists",
		"runtime_status_not_run: no request was sent and no exploit was attempted",
	}
	sort.Strings(limitations)
	c.findings = append(c.findings, Finding{
		ID: id, RuleID: c.rule.ID, Language: c.spec.Name, Category: c.rule.Category,
		CWE: c.rule.CWE, Severity: c.rule.Severity, Confidence: c.rule.Confidence,
		Status: status, RuntimeStatus: "not_run", Title: c.rule.Title, Message: c.rule.Message,
		File: c.file, SHA256: c.fileSHA, StartLine: startLine, EndLine: endLine,
		Source: value.source,
		Sink:   &Ref{Kind: "sink", Symbol: symbol, File: c.file, SHA256: c.fileSHA, Line: line, Detail: kind},
		Flow:   flow, Evidence: evidence, Limitations: limitations,
	})
}

func statementHasSafeCall(stmt statement, rule RuleSpec, language string) bool {
	if len(rule.SafeCalls) == 0 {
		return false
	}
	for _, chain := range stmt.occurs {
		if chainHasName(chain, rule.SafeCalls, language) {
			return true
		}
	}
	return false
}

func statementHasSanitizer(stmt statement, rule RuleSpec, language string) bool {
	for _, chain := range stmt.occurs {
		for _, sanitizer := range rule.Sanitizers {
			if patternMatches(sanitizer, chain, language) {
				return true
			}
		}
	}
	return false
}

func expressionText(tokens []token) string {
	parts := make([]string, 0, 8)
	for _, tok := range tokens {
		if len(parts) >= 8 {
			break
		}
		if tok.kind == tokString {
			parts = append(parts, "<string>")
		} else {
			parts = append(parts, tok.text)
		}
	}
	return strings.Join(parts, " ")
}

// markPartial records one bounded-analysis gap and keeps the aggregate Partial
// field for existing CLI/Web consumers. The individual axes let the console
// explain which layer is incomplete without treating a symbol cap as a file
// coverage failure.
func markPartial(report *Report, limitation string) {
	if report == nil {
		return
	}
	report.Partial = true
	switch limitation {
	case "file_limit", "file_too_large", "lex_rejected", "statement_limit":
		report.FilePartial = true
	case "symbol_limit", "call_limit", "unresolved_limit", "variable_limit", "string_constant_limit":
		report.SymbolPartial = true
	case "finding_limit":
		report.FindingPartial = true
	}
	report.Limitations = append(report.Limitations, limitation)
}
