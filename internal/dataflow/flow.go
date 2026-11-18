package dataflow

import (
	"sort"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"
)

type taint struct {
	source SourceRef
}

func (s *findingState) analyzeMethod(index *projectModel, method *methodModel, tainted map[string]taint, depth int) {
	if method == nil {
		if len(tainted) > 0 {
			s.unresolved = true
			s.addLimitation("missing_method_body")
		}
		return
	}
	if depth > MaxDepth {
		s.depthLimited = true
		s.addLimitation("cross_method_depth_limit")
		return
	}
	key := methodKey(method, tainted)
	if s.visited[key] {
		return
	}
	s.visited[key] = true
	s.addEvidence(method)
	if method.BodyStart < 0 || method.BodyEnd <= method.BodyStart {
		if len(tainted) > 0 {
			s.unresolved = true
			s.addLimitation("method_without_body:" + method.Class.Name + "." + method.Name)
		}
		return
	}
	localTypes := map[string]string{}
	for _, parameter := range method.Params {
		localTypes[parameter.Name] = parameter.Type
	}
	localTainted := copyTaint(tainted)
	s.seedFields(method.Class, localTainted)
	safePrepared := map[string]bool{}
	tokens := method.File.Tokens
	for i := method.BodyStart + 1; i < method.BodyEnd; i++ {
		if tokens[i].Text == "=" {
			s.analyzeAssignment(index, method, tokens, i, localTypes, localTainted, safePrepared, depth)
			continue
		}
		if tokens[i].Text == "return" && method == s.endpoint && s.responseBody && s.category.Key == xssCategory.Key && returnsTextual(method.ReturnType) {
			end := assignmentEnd(tokens, i+1, method.BodyEnd)
			if end > i+1 {
				result := s.evaluateExpressionIn(index, method, localTypes, tokens[i+1:end], localTainted, depth)
				switch {
				case result.dynamic:
					s.observeReflectedReturn("dynamic return expression", method, tokens[i].Line)
				case result.found:
					s.observeReflectedReturn("tainted return value", method, tokens[i].Line)
				}
			}
		}
		if tokens[i].Text != "(" {
			continue
		}
		nameIndex := i - 1
		if nameIndex <= method.BodyStart || tokens[nameIndex].Tok != scanner.Ident {
			continue
		}
		name := tokens[nameIndex].Text
		close := matchDelimiter(tokens, i, "(", ")")
		if close < 0 || close >= method.BodyEnd {
			continue
		}
		args := splitTopLevel(tokens[i+1 : close])
		receiver, _ := callReceiver(tokens, nameIndex, method.BodyStart)
		argEval := s.evaluateArgumentsIn(index, method, localTypes, args, localTainted, depth)
		argTainted := argEval.found
		if argTainted || argEval.dynamic {
			s.pathObserved = true
		}
		line := tokens[nameIndex].Line
		api := callAPI(receiver, name)

		// A MyBatis mapper call is resolved against the SQL statement evidence
		// in Mapper XML / annotation SQL before it becomes an unresolved-call
		// boundary. Only SQL category uses ORM evidence.
		if s.category.Key == sqlCategory.Key && s.ormIndex != nil && argTainted {
			if s.observeMyBatis(s.ormIndex, receiverType(method, receiver, localTypes), name, method, line, argEval) {
				continue
			}
		}

		if isControlKeyword(name) {
			continue
		}
		if nameIndex > method.BodyStart && tokens[nameIndex-1].Text == "new" {
			if s.category.Key == pathCategory.Key && isPathAccessType(name) {
				s.categoryArgumentSink("new "+name, method, line, argEval)
				continue
			}
			if s.category.Key == ssrfCategory.Key && (name == "URL" || name == "URI") {
				// Constructing a URL/URI is not an outbound request; the assigned
				// variable carries the taint to openConnection/openStream.
				continue
			}
			if s.category.Key == deserializationCategory.Key {
				// The stream constructor is where untrusted bytes enter the
				// deserializer; a directly chained readObject is confirmed once
				// at the read site instead.
				if isDeserializationStreamType(name) && !chainedReadObject(tokens, close) {
					s.categoryArgumentSink("new "+name, method, line, argEval)
				}
				continue
			}
			if argTainted || argEval.dynamic {
				s.unresolved = true
				s.addLimitation("constructor_taint_not_modeled")
			}
			continue
		}
		if name == "append" && isBuilderReceiver(method, receiver, localTypes) {
			if argTainted {
				localTainted[receiver] = argEval.taint
				s.recordFlow("builder_append", receiver, method.File.Path, line)
			}
			continue
		}
		if name == "clear" && isCollectionType(receiverType(method, receiver, localTypes)) {
			deleteContainerTaint(localTainted, receiver)
			s.clearFieldCollection(method, receiver, localTypes)
			s.recordFlow("collection_clear", receiver, method.File.Path, line)
			continue
		}
		if isCollectionRemoval(name) && isCollectionType(receiverType(method, receiver, localTypes)) {
			if name == "remove" {
				if index, ok := firstLiteralArgument(args); ok {
					delete(localTainted, elementKey(receiver, index))
					if _, aggregate := localTainted[receiver]; aggregate {
						// The aggregate taint may still cover the removed element
						// because earlier writes had no known index.
						s.addLimitation("collection_remove_flow_insensitive")
					}
					s.recordFlow("collection_remove", receiver+"["+index+"]", method.File.Path, line)
					continue
				}
			}
			// A flow-insensitive container model cannot prove which element was
			// removed, so keeping the aggregate taint is the conservative choice.
			s.addLimitation("collection_remove_flow_insensitive")
			s.recordFlow("collection_remove", receiver+"."+name, method.File.Path, line)
			continue
		}
		if isCollectionMutation(name) && isCollectionType(receiverType(method, receiver, localTypes)) {
			if (name == "add" || name == "set") && len(args) >= 2 {
				if position, ok := firstLiteralArgument(args); ok {
					value := s.evaluateExpressionIn(index, method, localTypes, args[1], localTainted, depth)
					switch {
					case value.dynamic:
						s.unresolved = true
						s.addLimitation("collection_dynamic")
					case value.found:
						if _, isLocal := localTypes[receiver]; isLocal {
							localTainted[elementKey(receiver, position)] = value.taint
						} else {
							localTainted[receiver] = value.taint
							s.writeFieldCollection(method, receiver, localTypes, value.taint)
						}
						s.recordFlow("collection_add", receiver+"["+position+"]", method.File.Path, line)
					}
					continue
				}
			}
			// Adding a tainted value taints the container variable; reads from
			// that variable propagate the taint at the use site.
			switch {
			case argEval.dynamic:
				s.unresolved = true
				s.addLimitation("collection_dynamic")
			case argTainted:
				localTainted[receiver] = argEval.taint
				s.writeFieldCollection(method, receiver, localTypes, argEval.taint)
				s.recordFlow("collection_add", receiver+"."+name, method.File.Path, line)
			}
			continue
		}
		if name == "format" && receiver == "String" {
			// String.format is interpreted where its result is used: a sink
			// argument or an assignment. The call itself never is a SQL sink.
			continue
		}

		if s.category.Key != sqlCategory.Key {
			if s.analyzeCategorySink(index, method, tokens, nameIndex, name, receiver, argEval, localTypes, localTainted, depth) {
				continue
			}
			s.analyzeResolvedCall(index, method, name, receiver, api, args, argEval, localTypes, localTainted, depth, line)
			continue
		}

		switch name {
		case "executeQuery", "executeUpdate", "execute", "addBatch", "prepareStatement":
			if isSQLTemplateType(receiverType(method, receiver, localTypes)) && len(args) > 0 {
				sqlArg := s.evaluateExpressionIn(index, method, localTypes, args[0], localTainted, depth)
				switch {
				case sqlArg.dynamic:
					s.observeFormatBoundary(api, method, line)
				case sqlArg.found:
					s.confirmSink(api, method, line)
				}
				break
			}
			if argEval.dynamic {
				s.observeFormatBoundary(api, method, line)
			} else if argTainted {
				s.confirmSink(api, method, line)
			}
		case "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate", "createQuery", "createNativeQuery":
			typeName := receiverType(method, receiver, localTypes)
			if isSQLTemplateType(typeName) || isJPQLFactoryType(typeName) {
				if len(args) == 0 {
					break
				}
				sqlArg := s.evaluateExpressionIn(index, method, localTypes, args[0], localTainted, depth)
				switch {
				case sqlArg.dynamic:
					s.observeFormatBoundary(api, method, line)
				case sqlArg.found:
					s.confirmSink(api, method, line)
				}
			} else {
				s.analyzeResolvedCall(index, method, name, receiver, api, args, argEval, localTypes, localTainted, depth, line)
			}
		case "setString", "setInt", "setLong", "setObject", "setBoolean", "setFloat", "setDouble", "setDate", "setTimestamp", "setBytes":
			if argEval.dynamic {
				s.observeFormatBoundary(api, method, line)
			} else if argTainted {
				if safePrepared[receiver] {
					s.observeBinding(api, method, line)
				} else {
					s.addLimitation("prepared_statement_source_unknown")
				}
			}
		case "invoke", "newInstance":
			if argEval.dynamic {
				s.observeFormatBoundary(api, method, line)
			} else if argTainted {
				s.observeDynamic(api, method, line, "dynamic_invocation")
			}
		case "forName", "getMethod", "getDeclaredMethod", "getConstructor":
			if argEval.dynamic {
				s.observeFormatBoundary(api, method, line)
			} else if argTainted {
				s.observeDynamic(api, method, line, "dynamic_reflection")
			}
		default:
			s.analyzeResolvedCall(index, method, name, receiver, api, args, argEval, localTypes, localTainted, depth, line)
		}
	}
}

// analyzeResolvedCall follows one tainted call into the bounded project call
// graph, or records the matching unresolved/ambiguous boundary.
func (s *findingState) analyzeResolvedCall(index *projectModel, method *methodModel, name, receiver, api string, args [][]javaToken, argEval exprResult, localTypes map[string]string, tainted map[string]taint, depth, line int) {
	if isKnownFactory(receiver, name) {
		return
	}
	if argEval.dynamic && !argEval.found {
		s.observeFormatBoundary(api, method, line)
		return
	}
	if !argEval.found {
		return
	}
	typeName := receiverType(method, receiver, localTypes)
	argTypes := argumentTypes(index, method, localTypes, args, depth)
	target, _, reason := index.resolveCallWithAST(method.File.Path, line, typeName, method.File.Package, name, argTypes)
	if target == nil {
		switch {
		case reason == "overload":
			s.observeAmbiguousOverload(api, method, line)
		case reason == "dispatch":
			s.observeAmbiguousDispatch(api, method, line)
		case index.hasUnresolvedParent(typeName, method.File.Package):
			s.observeUnresolvedParent(api, method, line)
		default:
			s.unresolved = true
			s.callsUnresolved++
			s.addBoundary("unresolved_call", api, method, line)
			s.recordFlow("unresolved_call", api, method.File.Path, line)
		}
		return
	}
	s.callsResolved++
	targetTainted := map[string]taint{}
	for argumentIndex, arg := range args {
		if argumentIndex >= len(target.Params) {
			break
		}
		resolved := s.evaluateExpressionIn(index, method, localTypes, arg, tainted, depth+1)
		if resolved.found {
			targetTainted[target.Params[argumentIndex].Name] = resolved.taint
		}
	}
	if len(targetTainted) == 0 {
		return
	}
	s.recordFlow("call", method.Class.Name+"."+method.Name+" -> "+target.Class.Name+"."+target.Name, method.File.Path, line)
	if positions := builderArguments(method, localTypes, args, target); len(positions) > 0 {
		effects := s.methodEffects(index, target, targetTainted, depth+1)
		for _, position := range positions {
			mutated, ok := effects.mutated[position]
			if !ok {
				continue
			}
			ident := singleIdent(args[position])
			if ident == "" {
				continue
			}
			tainted[ident] = mutated
			s.addEvidence(target)
			s.recordFlow("builder_mutated", ident, method.File.Path, line)
		}
		if effects.dynamic {
			s.observeFormatBoundary(api, method, line)
		}
		if effects.unresolved {
			s.unresolved = true
			s.addLimitation("callee_effects_unresolved")
		}
	}
	if positions := collectionArguments(method, localTypes, args, target); len(positions) > 0 {
		effects := s.methodEffects(index, target, targetTainted, depth+1)
		for _, position := range positions {
			mutated, ok := effects.mutated[position]
			if !ok {
				continue
			}
			ident := singleIdent(args[position])
			if ident == "" {
				continue
			}
			tainted[ident] = mutated
			s.addEvidence(target)
			s.recordFlow("collection_mutated", ident, method.File.Path, line)
		}
		if effects.dynamic {
			s.observeFormatBoundary(api, method, line)
		}
		if effects.unresolved {
			s.unresolved = true
			s.addLimitation("callee_effects_unresolved")
		}
	}
	s.analyzeMethod(index, target, targetTainted, depth+1)
	s.seedFields(method.Class, tainted)
}

func (s *findingState) analyzeAssignment(index *projectModel, method *methodModel, tokens []javaToken, eq int, localTypes map[string]string, tainted map[string]taint, safePrepared map[string]bool, depth int) {
	if eq > method.BodyStart && isCompoundOrComparison(tokens[eq-1].Text) {
		return
	}
	if eq > method.BodyStart && tokens[eq-1].Text == "]" {
		if name, element, field, ok := indexedTarget(tokens, eq, method.BodyStart); ok {
			rhsEnd := assignmentEnd(tokens, eq+1, method.BodyEnd)
			if rhsEnd <= eq+1 {
				return
			}
			result := s.evaluateExpressionIn(index, method, localTypes, tokens[eq+1:rhsEnd], tainted, depth)
			if result.dynamic {
				s.observeFormatBoundary(name, method, tokens[eq-1].Line)
				return
			}
			if !result.found {
				return
			}
			s.pathObserved = true
			if field {
				if s.writeField(method, name, result.taint) {
					s.recordFlow("array_write", name, method.File.Path, tokens[eq-1].Line)
				}
				return
			}
			if element != "" {
				tainted[elementKey(name, element)] = result.taint
			} else {
				tainted[name] = result.taint
			}
			s.recordFlow("array_write", name, method.File.Path, tokens[eq-1].Line)
		}
		return
	}
	lhsIndex := previousIdent(tokens, eq, method.BodyStart)
	thisField := false
	if lhsIndex < 0 {
		if eq >= 3 && tokens[eq-1].Tok == scanner.Ident && tokens[eq-2].Text == "." && tokens[eq-3].Text == "this" {
			lhsIndex = eq - 1
			thisField = true
		} else {
			return
		}
	}
	if lhsIndex >= 2 && tokens[lhsIndex-1].Text == "." && !thisField {
		return // field or member assignment is not tracked
	}
	lhs := tokens[lhsIndex].Text
	if !thisField {
		if typeName := declarationType(tokens, lhsIndex, method.BodyStart); typeName != "" {
			localTypes[lhs] = typeName
		}
	}
	fieldTarget := thisField
	if !fieldTarget {
		if _, local := localTypes[lhs]; !local && fieldOwner(method.Class, lhs) != nil {
			fieldTarget = true
		}
	}
	if thisField && fieldOwner(method.Class, lhs) == nil {
		if classHasMissingParents(method.Class) {
			s.observeUnresolvedParent("this."+lhs, method, tokens[lhsIndex].Line)
		}
		return
	}
	rhsEnd := assignmentEnd(tokens, eq+1, method.BodyEnd)
	if rhsEnd <= eq+1 {
		return
	}
	rhs := tokens[eq+1 : rhsEnd]
	result := s.evaluateExpressionIn(index, method, localTypes, rhs, tainted, depth)
	if !fieldTarget {
		if call := firstCall(rhs, "prepareStatement"); call != nil {
			resolved := s.evaluateArgumentsIn(index, method, localTypes, splitTopLevel(call.args), tainted, depth)
			if !resolved.found && !resolved.dynamic {
				safePrepared[lhs] = true
			}
		}
	}
	if result.dynamic {
		s.observeFormatBoundary(lhs, method, tokens[lhsIndex].Line)
		return
	}
	if !result.found {
		return
	}
	s.pathObserved = true
	if fieldTarget {
		if s.writeField(method, lhs, result.taint) {
			s.recordFlow("field_write", lhs, method.File.Path, tokens[lhsIndex].Line)
		}
		return
	}
	switch {
	case isDirectTaint(rhs, tainted):
		tainted[lhs] = result.taint
		s.recordFlow("assign", lhs, method.File.Path, tokens[lhsIndex].Line)
	case containsToken(rhs, "+"):
		tainted[lhs] = result.taint
		s.recordFlow("concat", lhs, method.File.Path, tokens[lhsIndex].Line)
	case result.kind == "builder_to_string":
		tainted[lhs] = result.taint
		s.recordFlow("builder_to_string", lhs, method.File.Path, tokens[lhsIndex].Line)
	case result.kind == "string_format":
		tainted[lhs] = result.taint
		s.recordFlow("string_format", lhs, method.File.Path, tokens[lhsIndex].Line)
	case result.kind == "collection_read":
		tainted[lhs] = result.taint
		s.recordFlow("collection_read", lhs, method.File.Path, tokens[lhsIndex].Line)
	case result.kind == "array_read":
		tainted[lhs] = result.taint
		s.recordFlow("array_read", lhs, method.File.Path, tokens[lhsIndex].Line)
	case result.kind == "return":
		tainted[lhs] = result.taint
		s.recordFlow("return", lhs, method.File.Path, tokens[lhsIndex].Line)
	case isFieldRead(rhs):
		tainted[lhs] = result.taint
		s.recordFlow("field_read", lhs, method.File.Path, tokens[lhsIndex].Line)
	case result.kind == "constructor":
		tainted[lhs] = result.taint
		s.recordFlow("constructor", lhs, method.File.Path, tokens[lhsIndex].Line)
	default:
		// Any other expression shape (ternary, parenthesised pair, cast,
		// multi-identifier select) still carries the taint of the operands the
		// scan already found. Dropping it here used to turn a common defensive
		// idiom into a silent "no observation".
		tainted[lhs] = result.taint
		s.recordFlow("expression", lhs, method.File.Path, tokens[lhsIndex].Line)
	}
}

func (s *findingState) confirmSink(api string, method *methodModel, line int) {
	if s.confirmed {
		return
	}
	s.confirmed = true
	s.sink = &SinkRef{API: api, File: method.File.Path, SHA256: method.File.SHA256, Line: line}
	s.recordFlow("sink", api, method.File.Path, line)
}

func (s *findingState) observeBinding(api string, method *methodModel, line int) {
	if s.binding {
		return
	}
	s.binding = true
	s.protection = &ProtectionRef{API: api, File: method.File.Path, SHA256: method.File.SHA256, Line: line, Detail: "value binding on a constant-structure PreparedStatement"}
	s.recordFlow("value_binding", api, method.File.Path, line)
}

func (s *findingState) observeDynamic(api string, method *methodModel, line int, kind string) {
	s.dynamic = true
	s.dynamicBoundaries++
	s.addBoundary(kind, api, method, line)
	s.recordFlow(kind, api, method.File.Path, line)
}

// observeFormatBoundary records a String.format whose result cannot be decided
// from a literal pattern. The value is still request-controlled, so the finding
// must stay inconclusive rather than being promoted to a sink or dropped.
func (s *findingState) observeFormatBoundary(detail string, method *methodModel, line int) {
	s.unresolved = true
	s.addBoundary("string_format_dynamic", detail, method, line)
	s.addLimitation("string_format_dynamic")
	s.recordFlow("string_format_dynamic", detail, method.File.Path, line)
}

// observeAmbiguousDispatch records an interface/abstract call whose concrete
// implementation is not unique. The value must not be promoted to a sink.
func (s *findingState) observeAmbiguousDispatch(api string, method *methodModel, line int) {
	s.unresolved = true
	s.callsUnresolved++
	s.addBoundary("ambiguous_dispatch", api, method, line)
	s.addLimitation("ambiguous_dispatch")
	s.recordFlow("ambiguous_dispatch", api, method.File.Path, line)
}

// observeAmbiguousOverload records a call whose overloads cannot be selected
// from the inferred simple argument types.
func (s *findingState) observeAmbiguousOverload(api string, method *methodModel, line int) {
	s.unresolved = true
	s.callsUnresolved++
	s.addBoundary("ambiguous_overload", api, method, line)
	s.addLimitation("ambiguous_overload")
	s.recordFlow("ambiguous_overload", api, method.File.Path, line)
}

// observeUnresolvedParent records a call or field that may live on a parent
// type outside the snapshot.
func (s *findingState) observeUnresolvedParent(api string, method *methodModel, line int) {
	s.unresolved = true
	s.callsUnresolved++
	s.addBoundary("unresolved_parent", api, method, line)
	s.addLimitation("unresolved_parent_type")
	s.recordFlow("unresolved_parent", api, method.File.Path, line)
}

// analyzeCategorySink recognizes the sinks of the active non-SQL category. It
// reports whether the call was consumed, so unhandled calls still flow through
// the bounded project call graph.
func (s *findingState) analyzeCategorySink(index *projectModel, method *methodModel, tokens []javaToken, nameIndex int, name, receiver string, argEval exprResult, localTypes map[string]string, tainted map[string]taint, depth int) bool {
	line := tokens[nameIndex].Line
	typeName := receiverType(method, receiver, localTypes)
	switch s.category.Key {
	case commandCategory.Key:
		if name == "exec" && isRuntimeExec(tokens, nameIndex) {
			s.categoryArgumentSink("Runtime.getRuntime().exec", method, line, argEval)
			return true
		}
		if name == "command" && typeName == "ProcessBuilder" {
			// A tainted command is only executed by start(); the receiver is
			// marked instead of confirming at command().
			if argEval.dynamic {
				s.observeCategoryBoundary(callAPI(receiver, name), method, line)
				return true
			}
			if argEval.found {
				tainted[receiver] = argEval.taint
				s.recordFlow("command_append", receiver, method.File.Path, line)
			}
			return true
		}
		if name == "start" && typeName == "ProcessBuilder" {
			if _, ok := tainted[receiver]; ok {
				s.confirmCategorySink(callAPI(receiver, name), method, line)
			}
			return true
		}
		return false
	case ssrfCategory.Key:
		if name == "openConnection" || name == "openStream" {
			if isURLType(typeName) {
				if _, ok := tainted[receiver]; ok {
					s.confirmCategorySink(typeName+"."+name, method, line)
				}
				return true
			}
			if typeName == "" && receiver != "" {
				if _, ok := tainted[receiver]; ok {
					s.observeCategoryBoundary(callAPI(receiver, name), method, line)
					return true
				}
			}
			return false
		}
		if isRestTemplateCall(name) {
			if typeName == "RestTemplate" {
				s.categoryArgumentSink("RestTemplate."+name, method, line, argEval)
				return true
			}
			if typeName == "" && receiver != "" && argEval.found {
				s.observeCategoryBoundary(callAPI(receiver, name), method, line)
				return true
			}
			return false
		}
		if name == "uri" {
			chainType := ""
			if receiver != "" {
				chainType = receiverType(method, receiver, localTypes)
			}
			if chainType == "" {
				chainType = receiverChainType(method, tokens, nameIndex, localTypes)
			}
			if isHTTPClientBuilderType(chainType) {
				s.categoryArgumentSink(chainType+".uri", method, line, argEval)
				return true
			}
		}
		return false
	case pathCategory.Key:
		if receiver == "Files" && isFilesAccess(name) {
			s.categoryArgumentSink("Files."+name, method, line, argEval)
			return true
		}
		return false
	case templateCategory.Key:
		if name == "parseExpression" && isSpelParserType(typeName) {
			s.categoryArgumentSink(typeName+".parseExpression", method, line, argEval)
			return true
		}
		if name == "process" && isTemplateEngineType(typeName) {
			s.categoryArgumentSink(typeName+".process", method, line, argEval)
			return true
		}
		if name == "parseExpression" && typeName == "" && receiver != "" && argEval.found {
			s.observeCategoryBoundary(callAPI(receiver, name), method, line)
			return true
		}
		return false
	case xssCategory.Key:
		if isWriterMethod(name) {
			if isWriterTypeName(typeName) {
				s.categoryArgumentSink(typeName+"."+name, method, line, argEval)
				return true
			}
			if isResponseWriterChain(tokens, nameIndex) {
				s.categoryArgumentSink("getWriter()."+name, method, line, argEval)
				return true
			}
		}
		return false
	case deserializationCategory.Key:
		if name == "readObject" {
			if isDeserializationStreamType(typeName) {
				if _, ok := tainted[receiver]; ok {
					s.confirmCategorySink(typeName+".readObject", method, line)
				}
				return true
			}
			if constructorArgs, streamType := chainedDeserialization(tokens, nameIndex); constructorArgs != nil {
				resolved := s.evaluateArgumentsIn(index, method, localTypes, constructorArgs, tainted, depth)
				if resolved.dynamic {
					s.observeCategoryBoundary("new "+streamType+"(...).readObject", method, line)
				} else if resolved.found {
					s.confirmCategorySink("new "+streamType+"(...).readObject", method, line)
				}
				return true
			}
		}
		return false
	case xxeCategory.Key:
		if (name == "parse" || name == "read") && isXMLParserType(typeName) {
			s.categoryArgumentSink(typeName+"."+name, method, line, argEval)
			return true
		}
		if (name == "createXMLStreamReader" || name == "createXMLEventReader") && typeName == "XMLInputFactory" {
			s.categoryArgumentSink(typeName+"."+name, method, line, argEval)
			return true
		}
		if name == "unmarshal" && typeName == "Unmarshaller" {
			s.categoryArgumentSink(typeName+".unmarshal", method, line, argEval)
			return true
		}
		if name == "transform" && typeName == "Transformer" {
			s.categoryArgumentSink(typeName+".transform", method, line, argEval)
			return true
		}
		if name == "build" && typeName == "SAXBuilder" {
			s.categoryArgumentSink(typeName+".build", method, line, argEval)
			return true
		}
		if name == "parse" && typeName == "Digester" {
			s.categoryArgumentSink(typeName+".parse", method, line, argEval)
			return true
		}
		if receiver == "DocumentHelper" && name == "parseText" {
			s.categoryArgumentSink("DocumentHelper.parseText", method, line, argEval)
			return true
		}
		return false
	case ldapCategory.Key:
		if isLDAPQueryName(name) && isLDAPContextType(typeName) {
			s.categoryArgumentSink(typeName+"."+name, method, line, argEval)
			return true
		}
		return false
	case uploadCategory.Key:
		if name == "transferTo" && typeName == "MultipartFile" {
			s.categoryArgumentSink("MultipartFile.transferTo", method, line, argEval)
			return true
		}
		if name == "write" && typeName == "Part" {
			s.categoryArgumentSink("Part.write", method, line, argEval)
			return true
		}
		return false
	}
	return false
}

// confirmCategorySink marks the active category as observed and records the
// first confirmed sink.
func (s *findingState) confirmCategorySink(api string, method *methodModel, line int) {
	s.categoryObserved = true
	if s.confirmed {
		return
	}
	s.confirmed = true
	s.sink = &SinkRef{API: api, File: method.File.Path, SHA256: method.File.SHA256, Line: line}
	s.recordFlow(s.category.SinkKind, api, method.File.Path, line)
}

// categoryArgumentSink confirms or bounds one sink call from its argument taint.
func (s *findingState) categoryArgumentSink(api string, method *methodModel, line int, argEval exprResult) {
	switch {
	case argEval.dynamic:
		s.observeCategoryBoundary(api, method, line)
	case argEval.found:
		s.confirmCategorySink(api, method, line)
	}
}

// observeReflectedReturn judges a tainted response-body return from the
// declared produces media type. HTML is confirmed because Spring writes String
// values without escaping; an explicit non-HTML type is refuted for this
// return; absent or unresolved types stay inconclusive.
func (s *findingState) observeReflectedReturn(detail string, method *methodModel, line int) {
	if !s.responseBody {
		return
	}
	s.categoryObserved = true
	s.recordFlow("reflected_return", detail, method.File.Path, line)
	switch {
	case s.producesUnresolved:
		s.unresolved = true
		s.addBoundary("reflected_return", detail, method, line)
		s.addLimitation("produces_unresolved")
		s.addLimitation("reflected_return_content_type_unverified")
	case hasHTMLProduces(s.produces):
		s.confirmCategorySink("return:"+htmlProduces(s.produces), method, line)
	case len(s.produces) > 0:
		s.encoded = true
		s.protection = &ProtectionRef{
			API:    "return",
			File:   method.File.Path,
			SHA256: method.File.SHA256,
			Line:   line,
			Detail: "produces=" + strings.Join(s.produces, ",") + " does not render HTML",
		}
		s.recordFlow("return_content_type", strings.Join(s.produces, ","), method.File.Path, line)
	default:
		s.unresolved = true
		s.addBoundary("reflected_return", detail, method, line)
		s.addLimitation("reflected_return_content_type_unverified")
	}
}

func hasHTMLProduces(produces []string) bool {
	return htmlProduces(produces) != ""
}

func htmlProduces(produces []string) string {
	for _, mediaType := range produces {
		lower := strings.ToLower(strings.TrimSpace(strings.SplitN(mediaType, ";", 2)[0]))
		if lower == "text/html" || lower == "application/xhtml+xml" {
			return lower
		}
	}
	return ""
}

// observeCategoryBoundary records a known non-SQL sink whose receiver type or
// argument cannot be resolved. The finding stays inconclusive.
func (s *findingState) observeCategoryBoundary(api string, method *methodModel, line int) {
	s.categoryObserved = true
	s.unresolved = true
	s.addBoundary("unresolved_sink", api, method, line)
	s.addLimitation("unresolved_sink")
	s.recordFlow("unresolved_sink", api, method.File.Path, line)
}

func isRuntimeExec(tokens []javaToken, nameIndex int) bool {
	if nameIndex < 6 {
		return false
	}
	return tokens[nameIndex-1].Text == "." &&
		tokens[nameIndex-2].Text == ")" &&
		tokens[nameIndex-3].Text == "(" &&
		tokens[nameIndex-4].Text == "getRuntime" &&
		tokens[nameIndex-5].Text == "." &&
		tokens[nameIndex-6].Text == "Runtime"
}

func isPathAccessType(name string) bool {
	switch name {
	case "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile":
		return true
	}
	return false
}

func isFilesAccess(name string) bool {
	switch name {
	case "readAllBytes", "readString", "readAllLines", "newInputStream", "newOutputStream",
		"newBufferedReader", "newBufferedWriter", "write", "copy", "move", "delete", "deleteIfExists":
		return true
	}
	return false
}

func isURLType(typeName string) bool {
	return typeName == "URL" || typeName == "URI"
}

// isKnownFactory lists the static factory calls whose taint is modeled
// directly, so they never become unresolved library boundaries.
func isKnownFactory(receiver, name string) bool {
	return (receiver == "Paths" && name == "get") ||
		(receiver == "Path" && name == "of") ||
		(receiver == "URI" && name == "create")
}

func isRestTemplateCall(name string) bool {
	switch name {
	case "getForObject", "getForEntity", "postForObject", "postForEntity", "put", "patchForObject", "delete", "exchange", "headForHeaders", "optionsForAllow":
		return true
	}
	return false
}

func isSQLTemplateType(typeName string) bool {
	switch typeName {
	case "JdbcTemplate", "NamedParameterJdbcTemplate", "JdbcOperations", "NamedParameterJdbcOperations":
		return true
	}
	return false
}

func isJPQLFactoryType(typeName string) bool {
	switch typeName {
	case "EntityManager", "Session", "StatelessSession":
		return true
	}
	return false
}

func isHTTPClientBuilderType(typeName string) bool {
	switch typeName {
	case "HttpRequest", "HttpRequest.Builder", "WebClient", "WebClient.Builder":
		return true
	}
	return false
}

// receiverChainType walks back over a fluent chain to find the nearest typed
// receiver. It is bounded and stops at statement/block delimiters.
func receiverChainType(method *methodModel, tokens []javaToken, nameIndex int, localTypes map[string]string) string {
	if method == nil {
		return ""
	}
	start := nameIndex - 16
	if start < method.BodyStart+1 {
		start = method.BodyStart + 1
	}
	for i := nameIndex - 1; i >= start; i-- {
		switch tokens[i].Text {
		case ";", "{", "}":
			return ""
		}
		if tokens[i].Tok != scanner.Ident {
			continue
		}
		if typeName := receiverType(method, tokens[i].Text, localTypes); typeName != "" {
			return typeName
		}
	}
	return ""
}

func isSpelParserType(typeName string) bool {
	return typeName == "SpelExpressionParser" || typeName == "ExpressionParser"
}

func isTemplateEngineType(typeName string) bool {
	switch typeName {
	case "SpringTemplateEngine", "TemplateEngine", "StringTemplateEngine", "ThymeleafTemplateEngine":
		return true
	}
	return false
}

func isWriterMethod(name string) bool {
	switch name {
	case "write", "print", "println", "append":
		return true
	}
	return false
}

func isWriterTypeName(typeName string) bool {
	switch typeName {
	case "PrintWriter", "JspWriter", "ServletOutputStream", "Writer":
		return true
	}
	return false
}

// isResponseWriterChain matches resp.getWriter().write(...) where the writer is
// created inline and never stored in a typed local.
func isResponseWriterChain(tokens []javaToken, nameIndex int) bool {
	if nameIndex < 6 {
		return false
	}
	if tokens[nameIndex-1].Text != "." || tokens[nameIndex-2].Text != ")" ||
		tokens[nameIndex-3].Text != "(" || tokens[nameIndex-4].Text != "getWriter" ||
		tokens[nameIndex-5].Text != "." {
		return false
	}
	receiver := tokens[nameIndex-6]
	return receiver.Tok == scanner.Ident || receiver.Text == ")" || receiver.Text == "]"
}

func isDeserializationStreamType(name string) bool {
	switch name {
	case "ObjectInputStream", "XMLDecoder":
		return true
	}
	return false
}

func isXMLParserType(typeName string) bool {
	switch typeName {
	case "DocumentBuilder", "SAXParser", "SAXReader", "XMLReader":
		return true
	}
	return false
}

// returnsTextual limits reflected-return observation to body types that Spring
// may write to the response without an explicit writer.
func returnsTextual(typeName string) bool {
	return typeName == "String" || typeName == "CharSequence"
}

func isLDAPQueryName(name string) bool {
	switch name {
	case "search", "lookup", "authenticate":
		return true
	}
	return false
}

func isLDAPContextType(typeName string) bool {
	switch typeName {
	case "InitialDirContext", "DirContext", "LdapContext", "LdapTemplate", "LdapOperations":
		return true
	}
	return false
}

// isCollectionMutation lists the calls that store a value into a container.
// Only the receiver is marked tainted: the mutation itself is never a sink.
func isCollectionMutation(name string) bool {
	switch name {
	case "add", "addAll", "addFirst", "addLast", "offer", "push", "set",
		"put", "putIfAbsent", "putAll":
		return true
	}
	return false
}

// isCollectionRead lists the calls that return an element or view of a
// container so taint stored through collection_add reaches the use site.
func isCollectionRead(name string) bool {
	switch name {
	case "get", "getOrDefault", "values", "keySet", "entrySet", "toArray",
		"iterator", "peek", "poll", "pop", "first", "last":
		return true
	}
	return false
}

func isCollectionType(typeName string) bool {
	switch typeName {
	case "List", "ArrayList", "LinkedList", "Set", "HashSet", "LinkedHashSet",
		"TreeSet", "Map", "HashMap", "LinkedHashMap", "TreeMap", "Collection",
		"Queue", "Deque", "ArrayDeque":
		return true
	}
	return false
}

// isCollectionRemoval lists the calls that delete elements. The container
// model has no per-element taint, so removal never clears the container.
func isCollectionRemoval(name string) bool {
	switch name {
	case "remove", "removeAll", "retainAll", "removeIf":
		return true
	}
	return false
}

func isArrayType(typeName string) bool {
	return strings.HasSuffix(typeName, "[]")
}

// writeFieldCollection records container taint on a field receiver. A local or
// parameter with the same name always shadows the field.
func (s *findingState) writeFieldCollection(method *methodModel, name string, localTypes map[string]string, value taint) {
	if _, isLocal := localTypes[name]; isLocal {
		return
	}
	if method == nil || method.Class == nil {
		return
	}
	if fieldOwner(method.Class, name) == nil {
		return
	}
	s.writeField(method, name, value)
}

func (s *findingState) clearFieldCollection(method *methodModel, name string, localTypes map[string]string) {
	if _, isLocal := localTypes[name]; isLocal {
		return
	}
	if method == nil || method.Class == nil {
		return
	}
	owner := fieldOwner(method.Class, name)
	if owner == nil || s.fields == nil {
		return
	}
	delete(s.fields, owner.Symbol+"."+name)
}

func chainedReadObject(tokens []javaToken, close int) bool {
	return close+2 < len(tokens) && tokens[close+1].Text == "." && tokens[close+2].Text == "readObject"
}

// chainedDeserialization matches new ObjectInputStream(...).readObject() and
// new XMLDecoder(...).readObject() where the stream is never stored.
func chainedDeserialization(tokens []javaToken, nameIndex int) ([][]javaToken, string) {
	if nameIndex < 3 || tokens[nameIndex-1].Text != "." || tokens[nameIndex-2].Text != ")" {
		return nil, ""
	}
	closeIndex := nameIndex - 2
	depth := 0
	openIndex := -1
	for i := closeIndex; i >= 0; i-- {
		switch tokens[i].Text {
		case ")":
			depth++
		case "(":
			depth--
			if depth == 0 {
				openIndex = i
			}
		}
		if openIndex >= 0 {
			break
		}
	}
	if openIndex < 2 || tokens[openIndex-1].Tok != scanner.Ident || tokens[openIndex-2].Text != "new" {
		return nil, ""
	}
	streamType := tokens[openIndex-1].Text
	if !isDeserializationStreamType(streamType) {
		return nil, ""
	}
	return splitTopLevel(tokens[openIndex+1 : closeIndex]), streamType
}

func (s *findingState) addBoundary(kind, detail string, method *methodModel, line int) {
	if s.boundary != nil {
		return
	}
	s.boundary = &BoundaryRef{Kind: kind, Detail: detail, File: method.File.Path, SHA256: method.File.SHA256, Line: line}
}

func (s *findingState) addLimitation(code string) {
	s.limitations[code] = true
}

func (s *findingState) recordFlow(kind, detail, file string, line int) {
	for _, step := range s.flow {
		if step.Kind == kind && step.File == file && step.Line == line {
			return
		}
	}
	if len(s.flow) >= MaxFlowSteps {
		return
	}
	s.flow = append(s.flow, FlowStep{Kind: kind, Detail: detail, File: file, Line: line})
}

func (s *findingState) addEvidence(method *methodModel) {
	if len(s.evidence) >= MaxEvidence {
		return
	}
	key := method.File.Path + ":" + strconv.Itoa(method.Line) + ":" + strconv.Itoa(method.EndLine)
	if _, exists := s.evidence[key]; exists {
		return
	}
	anchor, anchorLine := findAnchor(method.File.Comments, method.Line, method.EndLine)
	s.evidence[key] = Evidence{
		File:       method.File.Path,
		SHA256:     method.File.SHA256,
		StartLine:  method.Line,
		EndLine:    method.EndLine,
		Anchor:     anchor,
		AnchorLine: anchorLine,
	}
}

type callExpression struct {
	name     string
	receiver string
	args     []javaToken
	line     int
}

func firstCall(tokens []javaToken, name string) *callExpression {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Text != "(" || i == 0 || tokens[i-1].Tok != scanner.Ident || tokens[i-1].Text != name {
			continue
		}
		close := matchDelimiter(tokens, i, "(", ")")
		if close < 0 {
			return nil
		}
		receiver, _ := callReceiver(tokens, i-1, 0)
		return &callExpression{name: name, receiver: receiver, args: tokens[i+1 : close], line: tokens[i-1].Line}
	}
	return nil
}

func callReceiver(tokens []javaToken, nameIndex, bodyStart int) (string, int) {
	if nameIndex <= bodyStart || tokens[nameIndex-1].Text != "." {
		return "", -1
	}
	receiverIndex := nameIndex - 2
	if receiverIndex <= bodyStart || tokens[receiverIndex].Tok != scanner.Ident {
		return "", -1
	}
	return tokens[receiverIndex].Text, receiverIndex
}

func receiverType(method *methodModel, receiver string, localTypes map[string]string) string {
	if receiver == "" || receiver == "this" {
		return method.Class.Name
	}
	if typeName := localTypes[receiver]; typeName != "" {
		return typeName
	}
	if typeName := method.Class.Fields[receiver]; typeName != "" {
		return typeName
	}
	if first := []rune(receiver); len(first) > 0 && unicode.IsUpper(first[0]) {
		return receiver
	}
	return ""
}

func callAPI(receiver, name string) string {
	if receiver == "" {
		return name
	}
	return receiver + "." + name
}

// exprResult is the bounded result of evaluating one expression. dynamic marks
// a String.format whose pattern is not a literal: the result cannot be decided
// statically and must be reported as a boundary, not as clean data.
type exprResult struct {
	found   bool
	dynamic bool
	taint   taint
	kind    string
}

func evaluateArguments(args [][]javaToken, tainted map[string]taint) exprResult {
	result := exprResult{}
	for _, arg := range args {
		result = mergeExpr(result, evaluateExpression(arg, tainted))
	}
	return result
}

func evaluateExpression(tokens []javaToken, tainted map[string]taint) exprResult {
	tokens = trimParens(tokens)
	if len(tokens) == 0 {
		return exprResult{}
	}
	if name, index, ok := indexedBase(tokens); ok {
		if index != "" {
			if value, taintedValue := tainted[elementKey(name, index)]; taintedValue {
				return exprResult{found: true, taint: value, kind: "array_read"}
			}
		}
		if value, taintedValue := tainted[name]; taintedValue {
			return exprResult{found: true, taint: value, kind: "array_read"}
		}
		return exprResult{}
	}
	name, receiver, open, close, ok := fullCall(tokens)
	if !ok {
		return scanExpression(tokens, tainted)
	}
	args := splitTopLevel(tokens[open+1 : close])
	switch {
	case receiver == "String" && name == "format":
		return evaluateFormat(args, tainted)
	case name == "toString" && receiver != "":
		if value, ok := tainted[receiver]; ok {
			return exprResult{found: true, taint: value, kind: "builder_to_string"}
		}
		return exprResult{}
	case isCollectionRead(name) && receiver != "":
		if index, ok := firstLiteralArgument(args); ok {
			if value, taintedValue := tainted[elementKey(receiver, index)]; taintedValue {
				return exprResult{found: true, taint: value, kind: "collection_read"}
			}
		}
		if value, ok := tainted[receiver]; ok {
			return exprResult{found: true, taint: value, kind: "collection_read"}
		}
		return exprResult{}
	default:
		return scanExpression(tokens, tainted)
	}
}

func evaluateFormat(args [][]javaToken, tainted map[string]taint) exprResult {
	if len(args) == 0 {
		return exprResult{}
	}
	pattern := trimParens(args[0])
	if len(pattern) != 1 || pattern[0].Tok != scanner.String {
		// A computed pattern prevents knowing which arguments are consumed.
		return exprResult{dynamic: true, kind: "string_format"}
	}
	if !hasFormatSpecifier(pattern[0].Text) {
		// Without a conversion specifier Java ignores trailing arguments, so
		// those arguments do not flow into the result.
		return exprResult{}
	}
	for _, arg := range args[1:] {
		resolved := evaluateExpression(arg, tainted)
		if resolved.dynamic {
			return exprResult{dynamic: true, kind: "string_format"}
		}
		if resolved.found {
			return exprResult{found: true, taint: resolved.taint, kind: "string_format"}
		}
	}
	return exprResult{}
}

func scanExpression(tokens []javaToken, tainted map[string]taint) exprResult {
	result := exprResult{}
	concat := false
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token.Text == "+" {
			concat = true
			continue
		}
		if token.Text == "(" && i > 0 && tokens[i-1].Tok == scanner.Ident {
			close := matchDelimiter(tokens, i, "(", ")")
			if close > i {
				name := tokens[i-1].Text
				receiver := ""
				if i >= 3 && tokens[i-2].Text == "." && tokens[i-3].Tok == scanner.Ident {
					receiver = tokens[i-3].Text
				}
				if receiver == "String" && name == "format" {
					result = mergeExpr(result, evaluateFormat(splitTopLevel(tokens[i+1:close]), tainted))
					i = close
					continue
				}
				if name == "toString" && receiver != "" {
					if value, ok := tainted[receiver]; ok {
						result = mergeExpr(result, exprResult{found: true, taint: value, kind: "builder_to_string"})
					}
					i = close
					continue
				}
				if isCollectionRead(name) && receiver != "" {
					inner := splitTopLevel(tokens[i+1 : close])
					if index, ok := firstLiteralArgument(inner); ok {
						if value, taintedValue := tainted[elementKey(receiver, index)]; taintedValue {
							result = mergeExpr(result, exprResult{found: true, taint: value, kind: "collection_read"})
							i = close
							continue
						}
					}
					if value, ok := tainted[receiver]; ok {
						result = mergeExpr(result, exprResult{found: true, taint: value, kind: "collection_read"})
						i = close
						continue
					}
				}
				result = mergeExpr(result, scanExpression(tokens[i+1:close], tainted))
				i = close
				continue
			}
		}
		if token.Text == "[" {
			// An element access consults its literal index before falling back to
			// the aggregate container taint; the index expression itself is not
			// a value source.
			if close := matchDelimiter(tokens, i, "[", "]"); close > i {
				if i > 0 && tokens[i-1].Tok == scanner.Ident {
					if index, ok := literalIndex(tokens[i+1 : close]); ok {
						if value, taintedValue := tainted[elementKey(tokens[i-1].Text, index)]; taintedValue {
							result = mergeExpr(result, exprResult{found: true, taint: value, kind: "array_read"})
						}
					}
				}
				i = close
				continue
			}
		}
		if token.Tok != scanner.Ident {
			continue
		}
		if value, ok := tainted[token.Text]; ok {
			result = mergeExpr(result, exprResult{found: true, taint: value, kind: "assign"})
		}
	}
	if result.found && concat {
		result.kind = "concat"
	}
	return result
}

func mergeExpr(destination, source exprResult) exprResult {
	destination.dynamic = destination.dynamic || source.dynamic
	if source.found && !destination.found {
		destination.found = true
		destination.taint = source.taint
		destination.kind = source.kind
	}
	return destination
}

func trimParens(tokens []javaToken) []javaToken {
	for len(tokens) >= 2 && tokens[0].Text == "(" {
		close := matchDelimiter(tokens, 0, "(", ")")
		if close != len(tokens)-1 {
			break
		}
		tokens = tokens[1 : len(tokens)-1]
	}
	return tokens
}

// fullCall reports a call expression that spans the whole token range.
func fullCall(tokens []javaToken) (name, receiver string, open, close int, ok bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Text != "(" || i == 0 || tokens[i-1].Tok != scanner.Ident {
			continue
		}
		end := matchDelimiter(tokens, i, "(", ")")
		if end != len(tokens)-1 {
			continue
		}
		receiver = ""
		if i >= 3 && tokens[i-2].Text == "." && tokens[i-3].Tok == scanner.Ident {
			receiver = tokens[i-3].Text
		}
		return tokens[i-1].Text, receiver, i, end, true
	}
	return "", "", 0, 0, false
}

func hasFormatSpecifier(literal string) bool {
	value := literal
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
		value = value[1 : len(value)-1]
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+1 < len(value) && value[i+1] == '%' {
			i++
			continue
		}
		j := i + 1
		for j < len(value) && strings.ContainsRune("-#+ 0,(<", rune(value[j])) {
			j++
		}
		for j < len(value) && value[j] >= '0' && value[j] <= '9' {
			j++
		}
		if j < len(value) && value[j] == '$' {
			j++
		}
		if j < len(value) && value[j] == '.' {
			j++
		}
		for j < len(value) && value[j] >= '0' && value[j] <= '9' {
			j++
		}
		if j < len(value) && strings.ContainsRune("bBhHsScCdoxXeEfgGaAtTn", rune(value[j])) {
			return true
		}
		// Unknown conversion: Java throws before the SQL statement runs.
	}
	return false
}

func isBuilderReceiver(method *methodModel, receiver string, localTypes map[string]string) bool {
	if receiver == "" {
		return false
	}
	return isBuilderType(receiverType(method, receiver, localTypes))
}

func isBuilderType(typeName string) bool {
	return typeName == "StringBuilder" || typeName == "StringBuffer"
}

// seedFields copies tainted fields of the class and its bases into the local
// taint map so reads such as this.field or a bare field name are visible.
func (s *findingState) seedFields(class *classModel, tainted map[string]taint) {
	if class == nil || len(s.fields) == 0 {
		return
	}
	for _, current := range classLineage(class) {
		prefix := current.Symbol + "."
		for key, value := range s.fields {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			name := strings.TrimPrefix(key, prefix)
			if _, exists := tainted[name]; !exists {
				tainted[name] = value
			}
		}
	}
}

func (s *findingState) writeField(method *methodModel, name string, value taint) bool {
	if method == nil || method.Class == nil {
		return false
	}
	owner := fieldOwner(method.Class, name)
	if owner == nil {
		return false
	}
	if s.fields == nil {
		s.fields = map[string]taint{}
	}
	s.fields[owner.Symbol+"."+name] = value
	return true
}

func isFieldRead(tokens []javaToken) bool {
	tokens = trimParens(tokens)
	return len(tokens) == 3 && tokens[0].Text == "this" && tokens[1].Text == "." && tokens[2].Tok == scanner.Ident
}

// argumentTypes infers simple Java types for overload selection. Unknown
// results are empty strings and never disqualify a candidate.
func argumentTypes(index *projectModel, method *methodModel, localTypes map[string]string, args [][]javaToken, depth int) []string {
	types := make([]string, len(args))
	for i, arg := range args {
		types[i] = inferType(index, method, localTypes, arg, depth)
	}
	return types
}

func inferType(index *projectModel, method *methodModel, localTypes map[string]string, tokens []javaToken, depth int) string {
	tokens = trimParens(tokens)
	if len(tokens) == 0 {
		return ""
	}
	if isLambdaExpression(tokens) {
		return "lambda"
	}
	if tokens[0].Text == "(" && len(tokens) >= 4 && tokens[1].Tok == scanner.Ident {
		if close := matchDelimiter(tokens, 0, "(", ")"); close == 2 {
			return tokens[1].Text
		}
	}
	if tokens[0].Text == "new" && len(tokens) > 1 && tokens[1].Tok == scanner.Ident {
		return tokens[1].Text
	}
	if name, receiver, open, close, ok := fullCall(tokens); ok {
		switch {
		case receiver == "String" && name == "format":
			return "String"
		case name == "toString":
			return "String"
		}
		if depth < MaxDepth {
			callArgs := splitTopLevel(tokens[open+1 : close])
			argTypes := argumentTypes(index, method, localTypes, callArgs, depth+1)
			target, _, _ := index.resolveCallWithTypes(receiverType(method, receiver, localTypes), method.File.Package, name, argTypes)
			if target != nil {
				return index.substituteReturnType(target, argTypes)
			}
		}
		return ""
	}
	if len(tokens) == 1 {
		token := tokens[0]
		switch token.Tok {
		case scanner.String:
			return "String"
		case scanner.Char:
			return "char"
		case scanner.Int:
			if strings.HasSuffix(token.Text, "l") || strings.HasSuffix(token.Text, "L") {
				return "long"
			}
			return "int"
		case scanner.Float:
			if strings.HasSuffix(token.Text, "f") || strings.HasSuffix(token.Text, "F") {
				return "float"
			}
			return "double"
		case scanner.Ident:
			switch token.Text {
			case "true", "false":
				return "boolean"
			case "null":
				return "null"
			}
			if typeName := localTypes[token.Text]; typeName != "" {
				return typeName
			}
			if owner := fieldOwner(method.Class, token.Text); owner != nil {
				return owner.Fields[token.Text]
			}
		}
		return ""
	}
	if len(tokens) == 3 && tokens[0].Text == "this" && tokens[1].Text == "." && tokens[2].Tok == scanner.Ident {
		if owner := fieldOwner(method.Class, tokens[2].Text); owner != nil {
			return owner.Fields[tokens[2].Text]
		}
		return ""
	}
	if containsToken(tokens, "+") && hasStringOperand(tokens, localTypes) {
		return "String"
	}
	return ""
}

func hasStringOperand(tokens []javaToken, localTypes map[string]string) bool {
	for _, token := range tokens {
		if token.Tok == scanner.String {
			return true
		}
		if token.Tok == scanner.Ident && localTypes[token.Text] == "String" {
			return true
		}
	}
	return false
}

// isLambdaExpression detects both tokenized ("-", ">") and combined arrow
// forms, plus method references.
func isLambdaExpression(tokens []javaToken) bool {
	for i := 0; i < len(tokens); i++ {
		switch tokens[i].Text {
		case "->", "::":
			return true
		case "-":
			if i+1 < len(tokens) && tokens[i+1].Text == ">" {
				return true
			}
		case ":":
			if i+1 < len(tokens) && tokens[i+1].Text == ":" {
				return true
			}
		}
	}
	return false
}

func singleIdent(tokens []javaToken) string {
	tokens = trimParens(tokens)
	if len(tokens) == 1 && tokens[0].Tok == scanner.Ident {
		return tokens[0].Text
	}
	return ""
}

// indexedBase matches an expression whose only value is an array/container
// element access: name[...] or this.name[...]. The literal index is returned
// when it is a compile-time integer so element-level taint can be consulted.
func indexedBase(tokens []javaToken) (string, string, bool) {
	tokens = trimParens(tokens)
	if len(tokens) < 3 {
		return "", "", false
	}
	baseIndex := -1
	switch {
	case tokens[0].Tok == scanner.Ident && tokens[1].Text == "[":
		baseIndex = 0
	case len(tokens) >= 4 && tokens[0].Text == "this" && tokens[1].Text == "." &&
		tokens[2].Tok == scanner.Ident && tokens[3].Text == "[":
		baseIndex = 2
	}
	if baseIndex < 0 {
		return "", "", false
	}
	open := baseIndex + 1
	close := matchDelimiter(tokens, open, "[", "]")
	if close != len(tokens)-1 {
		return "", "", false
	}
	index := ""
	if literal, ok := literalIndex(tokens[open+1 : close]); ok {
		index = literal
	}
	return tokens[baseIndex].Text, index, true
}

// indexedTarget matches the left side of an element assignment: name[...] = or
// this.name[...] =. The returned field flag reflects an explicit this.receiver.
func indexedTarget(tokens []javaToken, eq, bodyStart int) (string, string, bool, bool) {
	if eq <= bodyStart || tokens[eq-1].Text != "]" {
		return "", "", false, false
	}
	depth := 0
	open := -1
	for i := eq - 1; i > bodyStart; i-- {
		switch tokens[i].Text {
		case "]":
			depth++
		case "[":
			depth--
			if depth == 0 {
				open = i
			}
		}
		if open >= 0 {
			break
		}
	}
	if open < 1 || tokens[open-1].Tok != scanner.Ident {
		return "", "", false, false
	}
	nameIndex := open - 1
	field := nameIndex >= 2 && tokens[nameIndex-1].Text == "." && tokens[nameIndex-2].Text == "this"
	index := ""
	if literal, ok := literalIndex(tokens[open+1 : eq-1]); ok {
		index = literal
	}
	return tokens[nameIndex].Text, index, field, true
}

func literalIndex(tokens []javaToken) (string, bool) {
	tokens = trimParens(tokens)
	if len(tokens) == 1 && tokens[0].Tok == scanner.Int {
		return tokens[0].Text, true
	}
	return "", false
}

func firstLiteralArgument(args [][]javaToken) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	return literalIndex(args[0])
}

func elementKey(name, index string) string {
	return name + "[" + index + "]"
}

func deleteContainerTaint(tainted map[string]taint, name string) {
	delete(tainted, name)
	prefix := name + "["
	for key := range tainted {
		if strings.HasPrefix(key, prefix) {
			delete(tainted, key)
		}
	}
}

func hasElementTaint(tainted map[string]taint, name string) bool {
	prefix := name + "["
	for key := range tainted {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func builderArguments(method *methodModel, localTypes map[string]string, args [][]javaToken, target *methodModel) []int {
	var positions []int
	for i := 0; i < len(args) && i < len(target.Params); i++ {
		if !isBuilderType(target.Params[i].Type) {
			continue
		}
		ident := singleIdent(args[i])
		if ident == "" || !isBuilderReceiver(method, ident, localTypes) {
			continue
		}
		positions = append(positions, i)
	}
	return positions
}

// collectionArguments identifies collection or array parameters whose tainted
// contents may be written by the resolved callee.
func collectionArguments(method *methodModel, localTypes map[string]string, args [][]javaToken, target *methodModel) []int {
	var positions []int
	for i := 0; i < len(args) && i < len(target.Params); i++ {
		paramType := target.Params[i].Type
		if !isCollectionType(paramType) && !isArrayType(paramType) {
			continue
		}
		ident := singleIdent(args[i])
		if ident == "" {
			continue
		}
		callerType := receiverType(method, ident, localTypes)
		if isArrayType(paramType) {
			if !isArrayType(callerType) {
				continue
			}
		} else if !isCollectionType(callerType) {
			continue
		}
		positions = append(positions, i)
	}
	return positions
}

// methodEffects is the bounded summary of a method for its caller: which return
// expressions carry taint, which builder parameters receive taint, and whether
// unresolved or dynamic boundaries prevent a closed answer.
type methodEffects struct {
	returns    []exprResult
	mutated    map[int]taint
	dynamic    bool
	unresolved bool
}

func (s *findingState) evaluateArgumentsIn(index *projectModel, method *methodModel, localTypes map[string]string, args [][]javaToken, tainted map[string]taint, depth int) exprResult {
	result := exprResult{}
	for _, arg := range args {
		result = mergeExpr(result, s.evaluateExpressionIn(index, method, localTypes, arg, tainted, depth))
	}
	return result
}

// evaluateExpressionIn evaluates an expression with the bounded project call
// graph: a call that resolves to a project method is summarized through its
// tainted returns instead of the purely lexical fallback. Unresolved calls keep
// the lexical behavior; a resolved call with a clean return is not treated as
// tainted just because one of its arguments was.
func (s *findingState) evaluateExpressionIn(index *projectModel, method *methodModel, localTypes map[string]string, tokens []javaToken, tainted map[string]taint, depth int) exprResult {
	tokens = trimParens(tokens)
	if len(tokens) == 0 {
		return exprResult{}
	}
	if depth > MaxDepth {
		s.depthLimited = true
		s.unresolved = true
		s.addLimitation("cross_method_depth_limit")
		return exprResult{}
	}
	if name, index, ok := indexedBase(tokens); ok {
		if index != "" {
			if value, taintedValue := tainted[elementKey(name, index)]; taintedValue {
				return exprResult{found: true, taint: value, kind: "array_read"}
			}
		}
		if value, taintedValue := tainted[name]; taintedValue {
			return exprResult{found: true, taint: value, kind: "array_read"}
		}
		return exprResult{}
	}
	if len(tokens) >= 4 && tokens[0].Text == "new" && tokens[1].Tok == scanner.Ident && tokens[2].Text == "(" {
		if close := matchDelimiter(tokens, 2, "(", ")"); close == len(tokens)-1 {
			resolved := s.evaluateArgumentsIn(index, method, localTypes, splitTopLevel(tokens[3:close]), tainted, depth)
			if resolved.found {
				return exprResult{found: true, taint: resolved.taint, kind: "constructor"}
			}
			return resolved
		}
	}
	name, receiver, open, close, ok := fullCall(tokens)
	if !ok {
		return evaluateExpression(tokens, tainted)
	}
	args := splitTopLevel(tokens[open+1 : close])
	switch {
	case receiver == "String" && name == "format":
		return evaluateFormat(args, tainted)
	case (receiver == "Paths" && name == "get") || (receiver == "Path" && name == "of") || (receiver == "URI" && name == "create"):
		resolved := s.evaluateArgumentsIn(index, method, localTypes, args, tainted, depth)
		if resolved.found {
			return exprResult{found: true, taint: resolved.taint, kind: "constructor"}
		}
		return resolved
	case name == "toString" && receiver != "":
		if value, ok := tainted[receiver]; ok {
			return exprResult{found: true, taint: value, kind: "builder_to_string"}
		}
		return exprResult{}
	case isCollectionRead(name) && receiver != "":
		if index, ok := firstLiteralArgument(args); ok {
			if value, taintedValue := tainted[elementKey(receiver, index)]; taintedValue {
				return exprResult{found: true, taint: value, kind: "collection_read"}
			}
		}
		if value, ok := tainted[receiver]; ok {
			return exprResult{found: true, taint: value, kind: "collection_read"}
		}
		return exprResult{}
	}
	typeName := receiverType(method, receiver, localTypes)
	argTypes := argumentTypes(index, method, localTypes, args, depth)
	target, _, reason := index.resolveCallWithAST(method.File.Path, tokens[open-1].Line, typeName, method.File.Package, name, argTypes)
	if target == nil {
		switch {
		case reason == "overload":
			s.observeAmbiguousOverload(callAPI(receiver, name), method, tokens[open-1].Line)
			return exprResult{}
		case reason == "dispatch":
			s.observeAmbiguousDispatch(callAPI(receiver, name), method, tokens[open-1].Line)
			return exprResult{}
		case index.hasUnresolvedParent(typeName, method.File.Package):
			s.observeUnresolvedParent(callAPI(receiver, name), method, tokens[open-1].Line)
			return exprResult{}
		}
		return evaluateExpression(tokens, tainted)
	}
	params := map[string]taint{}
	for argumentIndex, arg := range args {
		if argumentIndex >= len(target.Params) {
			break
		}
		resolved := s.evaluateExpressionIn(index, method, localTypes, arg, tainted, depth+1)
		if resolved.found {
			params[target.Params[argumentIndex].Name] = resolved.taint
		}
	}
	effects := s.methodEffects(index, target, params, depth+1)
	if effects.dynamic {
		return exprResult{dynamic: true, kind: "return"}
	}
	for _, returned := range effects.returns {
		if returned.dynamic {
			return exprResult{dynamic: true, kind: "return"}
		}
		if returned.found {
			s.addEvidence(target)
			return exprResult{found: true, taint: returned.taint, kind: "return"}
		}
	}
	if effects.unresolved {
		s.unresolved = true
		s.addLimitation("return_value_unresolved")
	}
	return exprResult{}
}

func (s *findingState) methodEffects(index *projectModel, method *methodModel, params map[string]taint, depth int) methodEffects {
	effects := methodEffects{mutated: map[int]taint{}}
	if method == nil || method.BodyStart < 0 || method.BodyEnd <= method.BodyStart {
		effects.unresolved = true
		return effects
	}
	if depth > MaxDepth {
		s.depthLimited = true
		effects.unresolved = true
		return effects
	}
	key := "effects:" + methodKey(method, params)
	if s.effectCache == nil {
		s.effectCache = map[string]methodEffects{}
	}
	if cached, ok := s.effectCache[key]; ok {
		return cached
	}
	if s.effectsActive == nil {
		s.effectsActive = map[string]bool{}
	}
	if s.effectsActive[key] {
		effects.unresolved = true
		return effects
	}
	s.effectsActive[key] = true
	defer delete(s.effectsActive, key)

	localTypes := map[string]string{}
	paramIndex := map[string]int{}
	for position, parameter := range method.Params {
		localTypes[parameter.Name] = parameter.Type
		paramIndex[parameter.Name] = position
	}
	local := copyTaint(params)
	s.seedFields(method.Class, local)
	tokens := method.File.Tokens
	for i := method.BodyStart + 1; i < method.BodyEnd; i++ {
		token := tokens[i]
		switch {
		case token.Text == "=":
			if i > method.BodyStart && isCompoundOrComparison(tokens[i-1].Text) {
				continue
			}
			if i > method.BodyStart && tokens[i-1].Text == "]" {
				if name, element, _, ok := indexedTarget(tokens, i, method.BodyStart); ok {
					rhsEnd := assignmentEnd(tokens, i+1, method.BodyEnd)
					if rhsEnd <= i+1 {
						continue
					}
					result := s.evaluateExpressionIn(index, method, localTypes, tokens[i+1:rhsEnd], local, depth+1)
					if result.dynamic {
						effects.dynamic = true
						continue
					}
					if !result.found {
						continue
					}
					if element != "" {
						local[elementKey(name, element)] = result.taint
					} else {
						local[name] = result.taint
					}
					if position, ok := paramIndex[name]; ok && isArrayType(method.Params[position].Type) {
						effects.mutated[position] = result.taint
					}
				}
				continue
			}
			lhsIndex := previousIdent(tokens, i, method.BodyStart)
			if lhsIndex < 0 || (lhsIndex >= 2 && tokens[lhsIndex-1].Text == ".") {
				continue
			}
			lhs := tokens[lhsIndex].Text
			if typeName := declarationType(tokens, lhsIndex, method.BodyStart); typeName != "" {
				localTypes[lhs] = typeName
			}
			rhsEnd := assignmentEnd(tokens, i+1, method.BodyEnd)
			if rhsEnd <= i+1 {
				continue
			}
			rhs := tokens[i+1 : rhsEnd]
			result := s.evaluateExpressionIn(index, method, localTypes, rhs, local, depth+1)
			if result.dynamic {
				effects.dynamic = true
				continue
			}
			if !result.found {
				continue
			}
			switch {
			case isDirectTaint(rhs, local), containsToken(rhs, "+"), isFieldRead(rhs), result.kind == "builder_to_string", result.kind == "string_format", result.kind == "return", result.kind == "constructor", result.kind == "collection_read", result.kind == "array_read":
				local[lhs] = result.taint
			default:
				effects.unresolved = true
			}
		case token.Text == "return":
			end := assignmentEnd(tokens, i+1, method.BodyEnd)
			if end <= i+1 {
				continue
			}
			result := s.evaluateExpressionIn(index, method, localTypes, tokens[i+1:end], local, depth+1)
			if result.dynamic {
				effects.dynamic = true
			}
			effects.returns = append(effects.returns, result)
		case token.Text == "(":
			nameIndex := i - 1
			if nameIndex <= method.BodyStart || tokens[nameIndex].Tok != scanner.Ident {
				continue
			}
			name := tokens[nameIndex].Text
			if isControlKeyword(name) {
				continue
			}
			close := matchDelimiter(tokens, i, "(", ")")
			if close < 0 || close >= method.BodyEnd {
				continue
			}
			args := splitTopLevel(tokens[i+1 : close])
			receiver, _ := callReceiver(tokens, nameIndex, method.BodyStart)
			argEval := s.evaluateArgumentsIn(index, method, localTypes, args, local, depth+1)
			if nameIndex > method.BodyStart && tokens[nameIndex-1].Text == "new" {
				if argEval.found || argEval.dynamic {
					effects.unresolved = true
				}
				continue
			}
			if name == "append" && isBuilderReceiver(method, receiver, localTypes) {
				if argEval.found {
					local[receiver] = argEval.taint
					if position, ok := paramIndex[receiver]; ok {
						effects.mutated[position] = argEval.taint
					}
				}
				continue
			}
			if name == "clear" && isCollectionType(receiverType(method, receiver, localTypes)) {
				deleteContainerTaint(local, receiver)
				if position, ok := paramIndex[receiver]; ok {
					delete(effects.mutated, position)
				}
				continue
			}
			if isCollectionRemoval(name) && isCollectionType(receiverType(method, receiver, localTypes)) {
				if name == "remove" {
					if position, ok := firstLiteralArgument(args); ok {
						delete(local, elementKey(receiver, position))
						continue
					}
				}
				// Keeping the aggregate taint matches the flow-insensitive fallback.
				continue
			}
			if isCollectionMutation(name) && isCollectionType(receiverType(method, receiver, localTypes)) {
				if (name == "add" || name == "set") && len(args) >= 2 {
					if element, ok := firstLiteralArgument(args); ok {
						value := s.evaluateExpressionIn(index, method, localTypes, args[1], local, depth+1)
						switch {
						case value.dynamic:
							effects.dynamic = true
						case value.found:
							if _, isParam := paramIndex[receiver]; isParam {
								local[receiver] = value.taint
							} else {
								local[elementKey(receiver, element)] = value.taint
							}
							if position, ok := paramIndex[receiver]; ok {
								effects.mutated[position] = value.taint
							}
						}
						continue
					}
				}
				switch {
				case argEval.dynamic:
					effects.unresolved = true
				case argEval.found:
					local[receiver] = argEval.taint
					if position, ok := paramIndex[receiver]; ok {
						effects.mutated[position] = argEval.taint
					}
				}
				continue
			}
			if name == "format" && receiver == "String" {
				continue
			}
			typeName := receiverType(method, receiver, localTypes)
			argTypes := argumentTypes(index, method, localTypes, args, depth)
			target, _, reason := index.resolveCallWithTypes(typeName, method.File.Package, name, argTypes)
			if target == nil {
				if reason != "" || argEval.found || argEval.dynamic || index.hasUnresolvedParent(typeName, method.File.Package) {
					effects.unresolved = true
				}
				continue
			}
			targetTainted := map[string]taint{}
			for argumentIndex, arg := range args {
				if argumentIndex >= len(target.Params) {
					break
				}
				resolved := s.evaluateExpressionIn(index, method, localTypes, arg, local, depth+1)
				if resolved.found {
					targetTainted[target.Params[argumentIndex].Name] = resolved.taint
				}
				if resolved.dynamic {
					effects.dynamic = true
				}
			}
			if len(targetTainted) == 0 {
				continue
			}
			targetEffects := s.methodEffects(index, target, targetTainted, depth+1)
			for argumentIndex, arg := range args {
				if argumentIndex >= len(target.Params) {
					break
				}
				mutated, ok := targetEffects.mutated[argumentIndex]
				if !ok {
					continue
				}
				ident := singleIdent(arg)
				if ident == "" {
					continue
				}
				local[ident] = mutated
				if position, ok := paramIndex[ident]; ok {
					effects.mutated[position] = mutated
				}
			}
			if targetEffects.dynamic {
				effects.dynamic = true
			}
			if targetEffects.unresolved {
				effects.unresolved = true
			}
		}
	}
	s.effectCache[key] = effects
	return effects
}

func methodKey(method *methodModel, tainted map[string]taint) string {
	names := make([]string, 0, len(tainted))
	for name := range tainted {
		names = append(names, name)
	}
	sort.Strings(names)
	return method.Class.Symbol + "." + method.Name + ":" + strings.Join(names, ",")
}

func copyTaint(tainted map[string]taint) map[string]taint {
	out := make(map[string]taint, len(tainted))
	for name, value := range tainted {
		out[name] = value
	}
	return out
}

func isDirectTaint(tokens []javaToken, tainted map[string]taint) bool {
	idents := 0
	taintedIdent := false
	for _, token := range tokens {
		if token.Tok != scanner.Ident {
			if token.Text == "(" || token.Text == ")" {
				continue
			}
			return false
		}
		idents++
		if _, ok := tainted[token.Text]; ok {
			taintedIdent = true
		}
	}
	return idents == 1 && taintedIdent
}

func containsToken(tokens []javaToken, text string) bool {
	for _, token := range tokens {
		if token.Text == text {
			return true
		}
	}
	return false
}

func previousIdent(tokens []javaToken, eq, bodyStart int) int {
	for i := eq - 1; i > bodyStart; i-- {
		switch tokens[i].Text {
		case ";", "{", "}":
			return -1
		case "]", ")":
			return -1
		}
		if tokens[i].Tok == scanner.Ident {
			if i >= 1 && tokens[i-1].Text == "." {
				return -1
			}
			return i
		}
	}
	return -1
}

func declarationType(tokens []javaToken, nameIndex, bodyStart int) string {
	start := nameIndex - 1
	generic := 0
	for start > bodyStart {
		switch tokens[start].Text {
		case ">":
			generic++
		case "<":
			if generic > 0 {
				generic--
			}
		case ";", "(", "{", "}", ",":
			// A comma inside Map<K, V> or a nested generic is part of the type,
			// not a declaration separator.
			if generic == 0 {
				start++
				goto found
			}
		}
		start--
	}
	start = bodyStart + 1
found:
	for i := start; i < nameIndex; i++ {
		if tokens[i].Tok == scanner.Ident && !isModifier(tokens[i].Text) {
			typeName := tokens[i].Text
			for j := i + 1; j < nameIndex; j++ {
				if tokens[j].Text == "<" || tokens[j].Text == "," {
					break
				}
				if tokens[j].Text == "[" {
					typeName += "[]"
				}
			}
			return typeName
		}
	}
	return ""
}

func assignmentEnd(tokens []javaToken, start, end int) int {
	depth := 0
	for i := start; i < end; i++ {
		switch tokens[i].Text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			if depth == 0 {
				return i
			}
			depth--
		}
		if tokens[i].Text == ";" && depth == 0 {
			return i
		}
	}
	return end
}

func isCompoundOrComparison(text string) bool {
	switch text {
	case "=", "!", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^":
		return true
	}
	return false
}

func isControlKeyword(text string) bool {
	switch text {
	case "if", "for", "while", "switch", "catch", "try", "synchronized", "return", "new", "throw", "assert", "do", "else", "case":
		return true
	}
	return false
}

func findAnchor(comments []javaToken, startLine, endLine int) (string, int) {
	for _, comment := range comments {
		if comment.Line < startLine || comment.Line > endLine {
			continue
		}
		index := strings.Index(comment.Text, "fixture:")
		if index < 0 {
			continue
		}
		value := comment.Text[index:]
		stop := strings.IndexFunc(value, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';' || r == ',' || r == '*' || r == '/'
		})
		if stop >= 0 {
			value = value[:stop]
		}
		return value, comment.Line
	}
	return "", 0
}
