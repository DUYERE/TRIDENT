package sca

import (
	"fmt"
	"strconv"
	"strings"
)

// semver is a deliberately small comparator for Maven-style versions. It is
// sufficient for caller-supplied advisory ranges such as ">=1.9,<1.10.0" and
// does not implement Maven's full ComparableVersion ordering.
type semver struct {
	nums []int
	pre  string
}

func parseSemver(value string) (semver, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "v"), "V")
	if value == "" {
		return semver{}, false
	}
	if index := strings.IndexByte(value, '+'); index >= 0 {
		value = value[:index]
	}
	pre := ""
	if index := strings.IndexByte(value, '-'); index >= 0 {
		pre = value[index+1:]
		value = value[:index]
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 8 {
		return semver{}, false
	}
	nums := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return semver{}, false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return semver{}, false
		}
		nums = append(nums, number)
	}
	return semver{nums: nums, pre: pre}, true
}

func compareSemver(a, b semver) int {
	length := len(a.nums)
	if len(b.nums) > length {
		length = len(b.nums)
	}
	for i := 0; i < length; i++ {
		left, right := 0, 0
		if i < len(a.nums) {
			left = a.nums[i]
		}
		if i < len(b.nums) {
			right = b.nums[i]
		}
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	case a.pre < b.pre:
		return -1
	default:
		return 1
	}
}

type versionConstraint struct {
	operator string
	version  semver
}

type versionRange struct {
	lower      *versionConstraint
	upper      *versionConstraint
	exact      *semver
	bracketed  bool
	constraint []versionConstraint
}

func parseVersionRange(value string) (versionRange, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return versionRange{}, fmt.Errorf("empty version range")
	}
	if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "(") {
		return parseBracketRange(value)
	}
	parts := strings.Split(value, ",")
	constraints := make([]versionConstraint, 0, len(parts))
	for _, part := range parts {
		constraint, err := parseConstraint(part)
		if err != nil {
			return versionRange{}, err
		}
		constraints = append(constraints, constraint)
	}
	return versionRange{constraint: constraints}, nil
}

func parseBracketRange(value string) (versionRange, error) {
	if len(value) < 2 {
		return versionRange{}, fmt.Errorf("invalid bracketed range")
	}
	open := value[0]
	close := value[len(value)-1]
	if (open != '[' && open != '(') || (close != ']' && close != ')') {
		return versionRange{}, fmt.Errorf("invalid bracketed range")
	}
	body := strings.TrimSpace(value[1 : len(value)-1])
	if body == "" {
		return versionRange{}, fmt.Errorf("empty bracketed range")
	}
	if !strings.Contains(body, ",") {
		if open != '[' || close != ']' {
			return versionRange{}, fmt.Errorf("single-version range must be inclusive")
		}
		exact, ok := parseSemver(body)
		if !ok {
			return versionRange{}, fmt.Errorf("invalid version")
		}
		return versionRange{exact: &exact, bracketed: true}, nil
	}
	parts := strings.SplitN(body, ",", 2)
	low := strings.TrimSpace(parts[0])
	high := strings.TrimSpace(parts[1])
	result := versionRange{bracketed: true}
	if low != "" {
		version, ok := parseSemver(low)
		if !ok {
			return versionRange{}, fmt.Errorf("invalid lower bound")
		}
		operator := ">"
		if open == '[' {
			operator = ">="
		}
		result.lower = &versionConstraint{operator: operator, version: version}
	}
	if high != "" {
		version, ok := parseSemver(high)
		if !ok {
			return versionRange{}, fmt.Errorf("invalid upper bound")
		}
		operator := "<"
		if close == ']' {
			operator = "<="
		}
		result.upper = &versionConstraint{operator: operator, version: version}
	}
	if result.lower == nil && result.upper == nil {
		return versionRange{}, fmt.Errorf("empty bracketed range")
	}
	return result, nil
}

func parseConstraint(value string) (versionConstraint, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return versionConstraint{}, fmt.Errorf("empty constraint")
	}
	operators := []string{">=", "<=", "==", ">", "<", "="}
	for _, operator := range operators {
		if strings.HasPrefix(value, operator) {
			versionText := strings.TrimSpace(value[len(operator):])
			version, ok := parseSemver(versionText)
			if !ok {
				return versionConstraint{}, fmt.Errorf("invalid version")
			}
			if operator == "==" {
				operator = "="
			}
			return versionConstraint{operator: operator, version: version}, nil
		}
	}
	version, ok := parseSemver(value)
	if !ok {
		return versionConstraint{}, fmt.Errorf("invalid version")
	}
	return versionConstraint{operator: "=", version: version}, nil
}

func (r versionRange) contains(version semver) bool {
	if r.exact != nil {
		return compareSemver(version, *r.exact) == 0
	}
	if r.lower != nil && !matchesConstraint(version, *r.lower) {
		return false
	}
	if r.upper != nil && !matchesConstraint(version, *r.upper) {
		return false
	}
	for _, constraint := range r.constraint {
		if !matchesConstraint(version, constraint) {
			return false
		}
	}
	return true
}

func matchesConstraint(version semver, constraint versionConstraint) bool {
	comparison := compareSemver(version, constraint.version)
	switch constraint.operator {
	case ">=":
		return comparison >= 0
	case "<=":
		return comparison <= 0
	case ">":
		return comparison > 0
	case "<":
		return comparison < 0
	case "=":
		return comparison == 0
	}
	return false
}
