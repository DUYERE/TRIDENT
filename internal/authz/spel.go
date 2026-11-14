package authz

import (
	"fmt"
	"strings"
)

// parseSpelExpression evaluates a bounded subset of Spring Security's method
// expression language: constant booleans, permitAll/denyAll,
// isAuthenticated()/isAnonymous(), hasRole/hasAuthority predicates and simple
// and/or/not combinations. Anything else is unknown rather than guessed.
func parseSpelExpression(expression string) (string, []string, string) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return RequirementUnknown, nil, "empty_expression"
	}
	parser := &spelParser{input: expression}
	requirement, roles, err := parser.parseOr()
	if err != nil {
		return RequirementUnknown, nil, err.Error()
	}
	parser.skipSpace()
	if parser.pos < len(parser.input) {
		return RequirementUnknown, nil, "unparsed_expression"
	}
	return requirement, uniqueStrings(roles), ""
}

type spelParser struct {
	input string
	pos   int
}

func (p *spelParser) parseOr() (string, []string, error) {
	requirement, roles, err := p.parseAnd()
	if err != nil {
		return "", nil, err
	}
	for {
		p.skipSpace()
		if !p.consumeOperator("||", "or") {
			break
		}
		rightRequirement, rightRoles, err := p.parseAnd()
		if err != nil {
			return "", nil, err
		}
		requirement, roles = combineOr(requirement, roles, rightRequirement, rightRoles)
	}
	return requirement, roles, nil
}

func (p *spelParser) parseAnd() (string, []string, error) {
	requirement, roles, err := p.parseUnary()
	if err != nil {
		return "", nil, err
	}
	for {
		p.skipSpace()
		if !p.consumeOperator("&&", "and") {
			break
		}
		rightRequirement, rightRoles, err := p.parseUnary()
		if err != nil {
			return "", nil, err
		}
		requirement = combineAnd(requirement, rightRequirement)
		roles = unionRoles(roles, rightRoles)
	}
	return requirement, roles, nil
}

func (p *spelParser) parseUnary() (string, []string, error) {
	p.skipSpace()
	if p.pos < len(p.input) && p.input[p.pos] == '!' {
		p.pos++
		requirement, roles, err := p.parseUnary()
		if err != nil {
			return "", nil, err
		}
		return negateRequirement(requirement), roles, nil
	}
	return p.parsePrimary()
}

func (p *spelParser) parsePrimary() (string, []string, error) {
	p.skipSpace()
	if p.pos < len(p.input) && p.input[p.pos] == '(' {
		p.pos++
		requirement, roles, err := p.parseOr()
		if err != nil {
			return "", nil, err
		}
		p.skipSpace()
		if p.pos >= len(p.input) || p.input[p.pos] != ')' {
			return "", nil, fmt.Errorf("unbalanced_parentheses")
		}
		p.pos++
		return requirement, roles, nil
	}
	name := p.identifier()
	switch name {
	case "true":
		return RequirementPublic, nil, nil
	case "false":
		return RequirementDeny, nil, nil
	case "permitAll":
		return RequirementPublic, nil, nil
	case "denyAll":
		return RequirementDeny, nil, nil
	case "isAuthenticated", "isFullyAuthenticated", "fullyAuthenticated", "authenticated":
		if err := p.requireEmptyArguments(); err != nil {
			return "", nil, err
		}
		return RequirementAuthenticated, nil, nil
	case "isAnonymous", "anonymous":
		if err := p.requireEmptyArguments(); err != nil {
			return "", nil, err
		}
		return RequirementPublic, nil, nil
	case "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority":
		values, err := p.literalArguments()
		if err != nil {
			return "", nil, err
		}
		if name == "hasRole" || name == "hasAnyRole" {
			values = rolePrefix(values)
		}
		return RequirementRole, values, nil
	default:
		return "", nil, fmt.Errorf("unsupported_spel:%s", name)
	}
}

func (p *spelParser) identifier() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.input) {
		character := p.input[p.pos]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '.' || character == '$' {
			p.pos++
			continue
		}
		break
	}
	return p.input[start:p.pos]
}

func (p *spelParser) requireEmptyArguments() error {
	values, err := p.literalArguments()
	if err != nil {
		return err
	}
	if len(values) > 0 {
		return fmt.Errorf("unexpected_arguments")
	}
	return nil
}

func (p *spelParser) literalArguments() ([]string, error) {
	p.skipSpace()
	if p.pos >= len(p.input) || p.input[p.pos] != '(' {
		return nil, fmt.Errorf("expected_argument_list")
	}
	p.pos++
	var values []string
	for {
		p.skipSpace()
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("unterminated_argument_list")
		}
		if p.input[p.pos] == ')' {
			p.pos++
			return values, nil
		}
		if p.input[p.pos] != '\'' && p.input[p.pos] != '"' {
			return nil, fmt.Errorf("non_literal_argument")
		}
		quote := p.input[p.pos]
		p.pos++
		start := p.pos
		for p.pos < len(p.input) && p.input[p.pos] != quote {
			p.pos++
		}
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("unterminated_string_literal")
		}
		values = append(values, p.input[start:p.pos])
		p.pos++
		p.skipSpace()
		if p.pos < len(p.input) && p.input[p.pos] == ',' {
			p.pos++
			continue
		}
	}
}

func (p *spelParser) consumeOperator(symbol, word string) bool {
	if strings.HasPrefix(p.input[p.pos:], symbol) {
		p.pos += len(symbol)
		return true
	}
	rest := p.input[p.pos:]
	if !strings.HasPrefix(rest, word) {
		return false
	}
	if len(rest) > len(word) {
		next := rest[len(word)]
		if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') || next == '_' {
			return false
		}
	}
	p.pos += len(word)
	return true
}

func (p *spelParser) skipSpace() {
	for p.pos < len(p.input) {
		switch p.input[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func negateRequirement(requirement string) string {
	switch requirement {
	case RequirementPublic:
		return RequirementAuthenticated
	case RequirementAuthenticated:
		return RequirementPublic
	case RequirementDeny:
		return RequirementPublic
	case RequirementRole:
		return RequirementAuthenticated
	default:
		return RequirementUnknown
	}
}

func rolePrefix(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "ROLE_") {
			value = "ROLE_" + value
		}
		out = append(out, value)
	}
	return uniqueStrings(out)
}

func combineOr(left string, leftRoles []string, right string, rightRoles []string) (string, []string) {
	switch {
	case left == RequirementUnknown || right == RequirementUnknown:
		return RequirementUnknown, nil
	case left == RequirementDeny:
		return right, rightRoles
	case right == RequirementDeny:
		return left, leftRoles
	case left == RequirementPublic || right == RequirementPublic:
		return RequirementPublic, nil
	case left == RequirementRole && right == RequirementRole:
		return RequirementRole, unionRoles(leftRoles, rightRoles)
	case left == RequirementRole || right == RequirementRole:
		return RequirementRole, unionRoles(leftRoles, rightRoles)
	case left == RequirementAuthenticated || right == RequirementAuthenticated:
		return RequirementAuthenticated, nil
	}
	return RequirementUnknown, nil
}
