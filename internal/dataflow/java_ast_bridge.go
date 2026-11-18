package dataflow

import (
	"fmt"
	"strings"

	"trident/internal/javaast"
)

// astCallHint is one resolved AST call edge projected onto the lexer model.
// The AST target is authoritative only for the exact file/line/call name; it
// never widens the lexer's method set or bypasses argument compatibility.
type astCallHint struct {
	class  string
	method string
}

func astCallKey(file string, line int, api string) string {
	return fmt.Sprintf("%s|%d|%s", file, line, api)
}

func (p *projectModel) applyJavaAST(model javaast.Model) {
	if p.astHints == nil {
		p.astHints = map[string]astCallHint{}
	}
	for _, call := range model.Calls {
		if call.Status != javaast.CallResolved || call.Target == "" || call.Line < 1 {
			continue
		}
		class, method := splitJavaASTTarget(call.Target)
		if class == "" || method == "" {
			continue
		}
		hint := astCallHint{class: class, method: method}
		p.astHints[astCallKey(call.File, call.Line, call.API)] = hint
		if leaf := lastSegment(call.API); leaf != call.API {
			p.astHints[astCallKey(call.File, call.Line, leaf)] = hint
		}
	}
}

func splitJavaASTTarget(target string) (string, string) {
	hash := strings.Index(target, "#")
	if hash <= 0 {
		return "", ""
	}
	class := strings.TrimSpace(target[:hash])
	method := strings.TrimSpace(target[hash+1:])
	if open := strings.Index(method, "("); open >= 0 {
		method = method[:open]
	}
	return class, method
}

func (p *projectModel) resolveCallWithAST(file string, line int, typeName, currentPackage, methodName string, argTypes []string) (*methodModel, int, string) {
	target, ambiguous, reason := p.resolveCallWithTypes(typeName, currentPackage, methodName, argTypes)
	if target != nil || len(p.astHints) == 0 {
		return target, ambiguous, reason
	}
	hint, ok := p.astHints[astCallKey(file, line, methodName)]
	if !ok {
		return target, ambiguous, reason
	}
	if method := p.methodForASTHint(hint); method != nil {
		return method, 0, "java_ast_resolved"
	}
	return target, ambiguous, reason
}

func (p *projectModel) methodForASTHint(hint astCallHint) *methodModel {
	class := p.classes[hint.class]
	if class == nil {
		if candidates := p.simple[lastSegment(hint.class)]; len(candidates) == 1 {
			class = candidates[0]
		}
	}
	if class == nil {
		return nil
	}
	for _, method := range class.Methods {
		if method.Name == hint.method {
			return method
		}
	}
	return nil
}

func lastSegment(value string) string {
	if index := strings.LastIndex(value, "."); index >= 0 {
		return value[index+1:]
	}
	return value
}
