package codescan

import (
	"fmt"
	"sort"
	"strings"
)

// This file implements the bounded same-file function-summary layer (v2).
// Summaries are rule-relative: a function is a "source" when its return
// expression observes a rule source, a "taint-through" when a parameter flows
// to the return value, and a "sink wrapper" when a parameter feeds a rule sink
// inside the body. Matching is exact simple function name within the same
// file, one call level deep; overloads, dynamic dispatch, cross-file calls and
// recursion are not resolved. A sink wrapper finding is still static evidence
// with a name-based limitation, never proof of exploitability.

const MaxFunctionSummaries = 512

type sinkObservation struct {
	symbol string
	short  string
	kind   string
	line   int
	param  string // normalized parameter feeding the sink
}

type fnSummary struct {
	name          string
	scope         int
	line          int
	params        []string // normalized, declaration order
	returnsSource bool
	returnParams  []string // normalized, declaration order
	sinkCalls     []sinkObservation
}

var typeWordHeads = map[string]bool{
	"public": true, "private": true, "protected": true, "static": true,
	"final": true, "abstract": true, "virtual": true, "override": true,
	"async": true, "function": true, "func": true, "def": true,
	"int": true, "string": true, "bool": true, "void": true, "var": true,
	"interface": true, "class": true, "struct": true,
}

// buildSummaries scans the file's function declarations once per rule. Order
// follows statement order, so output is deterministic.
func (c *ruleContext) buildSummaries(statements []statement) []fnSummary {
	out := []fnSummary{}
	byName := map[string]int{}
	for index, stmt := range statements {
		if len(out) >= MaxFunctionSummaries {
			break
		}
		if !stmt.declaration {
			continue
		}
		name, params, ok := functionDeclaration(stmt.tokens, c.spec.Name)
		if !ok || name == "" {
			continue
		}
		name = normalizeName(c.spec.Name, name)
		bodyScope := -1
		for j := index + 1; j < len(statements) && j <= index+4; j++ {
			candidate := statements[j].scope
			if candidate != stmt.scope && c.relations[candidate].parent == stmt.scope {
				bodyScope = candidate
				break
			}
		}
		if bodyScope < 0 {
			continue
		}
		summary := c.summarizeFunction(name, bodyScope, stmt.line, params, statements)
		if !summary.returnsSource && len(summary.returnParams) == 0 && len(summary.sinkCalls) == 0 {
			continue
		}
		if _, exists := byName[name]; exists {
			// First declaration wins so results stay deterministic when the
			// same simple name appears twice (documented limitation).
			continue
		}
		byName[name] = len(out)
		out = append(out, summary)
	}
	return out
}

// functionDeclaration extracts the simple function name and parameter names
// from a declaration statement header. Name extraction takes the identifier
// immediately before the first argument parenthesis (skipping a Go receiver);
// parameter names take the last identifier of each argument segment, except Go
// where the type follows the name so the first identifier is used.
func functionDeclaration(tokens []token, language string) (string, []string, bool) {
	open := -1
	for i, tok := range tokens {
		if tok.kind == tokSymbol && tok.text == "(" {
			open = i
			break
		}
	}
	if open < 0 {
		return "", nil, false
	}
	nameStart := 0
	if language == "go" && len(tokens) > 0 && tokens[0].text == "func" && open == 1 {
		receiverClose := matchingParen(tokens, open)
		if receiverClose < 0 || receiverClose+1 >= len(tokens) {
			return "", nil, false
		}
		if receiverClose+2 >= len(tokens) || tokens[receiverClose+1].kind != tokIdent ||
			tokens[receiverClose+2].kind != tokSymbol || tokens[receiverClose+2].text != "(" {
			return "", nil, false
		}
		nameStart = receiverClose + 1
		open = receiverClose + 2
	}
	name := ""
	for i := nameStart; i < open; i++ {
		if tokens[i].kind == tokIdent && !typeWordHeads[strings.ToLower(tokens[i].text)] &&
			!declarationHeads[strings.ToLower(tokens[i].text)] {
			name = tokens[i].text
		}
	}
	close := matchingParen(tokens, open)
	if close < 0 || name == "" {
		return name, nil, false
	}
	args := splitArgs(tokens[open+1 : close])
	params := []string{}
	for _, arg := range args {
		pick := -1
		for i, tok := range arg {
			if tok.kind == tokIdent {
				pick = i
				if language == "go" {
					break
				}
			}
		}
		if pick >= 0 {
			text := arg[pick].text
			if !typeWordHeads[strings.ToLower(text)] {
				params = append(params, normalizeName(language, text))
			}
		}
	}
	return name, params, true
}

// summarizeFunction walks the function body (own scope plus direct child
// scopes) tracking parameter taint. It never emits findings: direct
// source-to-sink flows inside the body are already covered by the main scan.
func (c *ruleContext) summarizeFunction(name string, bodyScope, declLine int, params []string, statements []statement) fnSummary {
	summary := fnSummary{name: name, scope: bodyScope, line: declLine, params: params}
	vars := map[string]taintValue{}
	for _, param := range params {
		ref := &Ref{Kind: "source", Symbol: param, File: c.file, SHA256: c.fileSHA, Line: declLine, Detail: c.rule.ID + " (parameter)"}
		vars[param] = taintValue{source: ref, param: param, steps: []FlowStep{{
			Kind: "source", Detail: param + " (parameter)", File: c.file, SHA256: c.fileSHA, Line: declLine,
		}}}
	}
	for _, stmt := range statements {
		if !scopeInside(stmt.scope, bodyScope, c.relations) {
			continue
		}
		if stmt.declaration {
			continue
		}
		sanitized := statementHasSanitizer(stmt, c.rule, c.spec.Name)
		if stmt.assign != nil && !sanitized {
			value, tainted := c.evalTokens(stmt.assign.rhs, vars, stmt.assign.line, 1)
			key := normalizeName(c.spec.Name, stmt.assign.target)
			if tainted {
				step := FlowStep{Kind: "assignment", Detail: stmt.assign.target + " " + stmt.assign.op + " " + expressionText(stmt.assign.rhs), File: c.file, SHA256: c.fileSHA, Line: stmt.assign.line}
				value.steps = append(append([]FlowStep(nil), value.steps...), step)
				vars[key] = value
			} else {
				delete(vars, key)
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
					value, tainted := c.evalTokens(arg, vars, call.line, 1)
					if tainted && value.param != "" && !sanitized {
						summary.sinkCalls = append(summary.sinkCalls, sinkObservation{
							symbol: call.full, short: call.short, kind: "call", line: call.line, param: value.param,
						})
						break
					}
				}
			}
		}
		if strings.EqualFold(stmt.head, "return") && len(stmt.tokens) > 1 {
			value, tainted := c.evalTokens(stmt.tokens[1:], vars, stmt.line, 1)
			if tainted && !sanitized {
				if value.param != "" && !containsName(summary.returnParams, value.param) {
					summary.returnParams = append(summary.returnParams, value.param)
				}
				if value.source != nil && value.param == "" {
					summary.returnsSource = true
				}
			}
		}
	}
	sort.Slice(summary.sinkCalls, func(i, j int) bool { return summary.sinkCalls[i].line < summary.sinkCalls[j].line })
	return summary
}

func scopeInside(scope, ancestor int, relations map[int]scopeRelation) bool {
	if scope == ancestor {
		return true
	}
	current := relations[scope].parent
	for depth := 0; current >= 0 && depth < 8; depth++ {
		if current == ancestor {
			return true
		}
		if current == 0 {
			return false
		}
		current = relations[current].parent
	}
	return false
}

func containsName(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// summaryFor returns the first summary matching a call name (exact simple
// name, PHP case-insensitive). Call sites inside the function itself are
// skipped to keep the analysis one level deep and recursion-free.
func (c *ruleContext) summaryFor(chain chainInfo, stmtScope int) *fnSummary {
	if len(c.summaries) == 0 {
		return nil
	}
	key := normalizeName(c.spec.Name, chain.short)
	if key == "" {
		return nil
	}
	for i := range c.summaries {
		summary := &c.summaries[i]
		if summary.name != key {
			continue
		}
		if scopeInside(stmtScope, summary.scope, c.relations) {
			return nil
		}
		return summary
	}
	return nil
}

// evalSummaryCall evaluates a call against the summary layer at depth 0.
// Source wrappers and taint-through returns produce a taint value; sink
// wrappers are handled by checkSummarySinks, not here.
func (c *ruleContext) evalSummaryCall(call callInfo, vars map[string]taintValue, line int) (taintValue, bool) {
	chain := chainInfo{segs: splitSelector(call.full), full: call.full, short: call.short, kind: "call", line: call.line}
	summary := c.summaryFor(chain, c.currentScope)
	if summary == nil {
		return taintValue{}, false
	}
	// Taint-through: a tainted argument feeding a parameter that flows to the
	// return value taints the call result.
	for i, arg := range call.args {
		if i >= len(summary.params) {
			break
		}
		if !containsName(summary.returnParams, summary.params[i]) {
			continue
		}
		value, tainted := c.evalTokens(arg, vars, call.line, 0)
		if tainted {
			step := FlowStep{Kind: "propagation", Detail: call.full + "() returns tainted parameter " + summary.params[i], File: c.file, SHA256: c.fileSHA, Line: call.line}
			value.steps = append(append([]FlowStep(nil), value.steps...), step)
			if value.source == nil && value.param == "" {
				value.param = summary.params[i]
			}
			return value, true
		}
	}
	if summary.returnsSource {
		ref := &Ref{Kind: "source", Symbol: call.full, File: c.file, SHA256: c.fileSHA, Line: summary.line, Detail: c.rule.ID + " (same-file function returns source)"}
		step := FlowStep{Kind: "source", Detail: call.full + "() (same-file function returns source)", File: c.file, SHA256: c.fileSHA, Line: summary.line}
		return taintValue{source: ref, steps: []FlowStep{step}}, true
	}
	return taintValue{}, false
}

// checkSummarySinks emits findings for calls whose tainted argument reaches a
// rule sink inside the called function. The sink ref points into the function
// body; the flow records the call site as a propagation step. This is
// name-based static evidence, not a call-graph result.
func (c *ruleContext) checkSummarySinks(stmt statement, state *scopeState) {
	if len(c.summaries) == 0 {
		return
	}
	for _, call := range stmt.calls {
		chain := chainInfo{segs: splitSelector(call.full), full: call.full, short: call.short, kind: "call", line: call.line}
		summary := c.summaryFor(chain, stmt.scope)
		if summary == nil || len(summary.sinkCalls) == 0 {
			continue
		}
		for i, arg := range call.args {
			if i >= len(summary.params) {
				break
			}
			fed := false
			for _, sink := range summary.sinkCalls {
				if sink.param == summary.params[i] {
					fed = true
					break
				}
			}
			if !fed {
				continue
			}
			value, tainted := c.evalExpr(arg, state, call.line)
			if !tainted {
				continue
			}
			sink := summary.sinkCalls[0]
			for _, observation := range summary.sinkCalls {
				if observation.param == summary.params[i] {
					sink = observation
					break
				}
			}
			c.emitSummarySink(call, sink, value, summary)
			break
		}
	}
}

func (c *ruleContext) emitSummarySink(call callInfo, sink sinkObservation, value taintValue, summary *fnSummary) {
	if value.source == nil {
		return
	}
	sourceLine := value.source.Line
	id := strings.Join([]string{c.rule.ID, c.file, fmt.Sprintf("%d", call.line), call.short, fmt.Sprintf("%d", sourceLine), "fn"}, ":")
	if c.seen[id] {
		return
	}
	c.seen[id] = true
	callStep := FlowStep{Kind: "propagation", Detail: "cross-function call " + call.full + "()", File: c.file, SHA256: c.fileSHA, Line: call.line}
	sinkStep := FlowStep{Kind: "sink", Detail: sink.symbol + " (sink inside " + summary.name + ")", File: c.file, SHA256: c.fileSHA, Line: sink.line}
	flow := append([]FlowStep(nil), value.steps...)
	flow = append(flow, callStep, sinkStep)
	if len(flow) > MaxFlowSteps {
		flow = flow[:MaxFlowSteps]
	}
	evidence := []Ref{*value.source}
	evidence = append(evidence,
		Ref{Kind: "propagation", Symbol: callStep.Detail, File: c.file, SHA256: c.fileSHA, Line: call.line, Detail: "cross_function_call"},
		Ref{Kind: "sink", Symbol: sink.symbol, File: c.file, SHA256: c.fileSHA, Line: sink.line, Detail: c.rule.ID + " (inside " + summary.name + ")"},
	)
	for _, step := range flow {
		if step.Kind == "assignment" {
			evidence = append(evidence, Ref{Kind: "propagation", Symbol: step.Detail, File: step.File, SHA256: step.SHA256, Line: step.Line})
		}
	}
	startLine, endLine := sourceLine, sink.line
	if endLine < startLine {
		endLine = startLine
	}
	limitations := []string{
		"bounded_intrascope_taint: source and sink were observed in the same bounded scope; framework-bound and runtime flows were not verified",
		"name_based_rule: the sink was matched by a declarative name pattern, not by type resolution or a call graph",
		"no_evidence_of_sanitizer_coverage: absence of an observed sanitizer is not proof that no validation exists",
		"runtime_status_not_run: no request was sent and no exploit was attempted",
		"cross_function_wrapper_sink: the sink is inside a same-file function matched by exact simple name, one level deep; overloads and dispatch were not resolved",
	}
	sort.Strings(limitations)
	c.findings = append(c.findings, Finding{
		ID: id, RuleID: c.rule.ID, Language: c.spec.Name, Category: c.rule.Category,
		CWE: c.rule.CWE, Severity: c.rule.Severity, Confidence: c.rule.Confidence,
		Status: "static_confirmed", RuntimeStatus: "not_run", Title: c.rule.Title, Message: c.rule.Message,
		File: c.file, SHA256: c.fileSHA, StartLine: startLine, EndLine: endLine,
		Source: value.source,
		Sink:   &Ref{Kind: "sink", Symbol: sink.symbol, File: c.file, SHA256: c.fileSHA, Line: sink.line, Detail: "call"},
		Flow:   flow, Evidence: evidence, Limitations: limitations,
	})
}
