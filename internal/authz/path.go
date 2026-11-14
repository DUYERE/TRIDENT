package authz

import (
	"regexp"
	"strings"
)

// matchPath implements the bounded Ant-style subset used by Spring MVC
// interceptors, servlet filters and Spring Security matchers. Unsupported
// pattern syntax is treated literally rather than guessed.
func matchPath(pattern, path string) bool {
	pattern = normalizePath(pattern)
	path = normalizePath(path)
	if pattern == "/**" {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if prefix == "" {
			return true
		}
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	expression := antExpression(pattern)
	return expression.MatchString(path)
}

func normalizePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return value
}

func antExpression(pattern string) *regexp.Regexp {
	var builder strings.Builder
	builder.WriteString("^")
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				builder.WriteString(".*")
				index++
			} else {
				builder.WriteString("[^/]*")
			}
		case '?':
			builder.WriteString("[^/]")
		default:
			builder.WriteString(regexp.QuoteMeta(string(pattern[index])))
		}
	}
	builder.WriteString("$")
	return regexp.MustCompile(builder.String())
}
