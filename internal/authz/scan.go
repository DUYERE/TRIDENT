package authz

import (
	"regexp"
	"sort"
	"strings"
)

var (
	xmlInterceptorBlock = regexp.MustCompile(`(?s)<(?:[A-Za-z0-9_.-]+:)?interceptor\b[^>]*>(.*?)</(?:[A-Za-z0-9_.-]+:)?interceptor>`)
	xmlMappingPath      = regexp.MustCompile(`<(?:[A-Za-z0-9_.-]+:)?mapping\b[^>]*\bpath\s*=\s*["']([^"']+)["']`)
	xmlExcludePath      = regexp.MustCompile(`<(?:[A-Za-z0-9_.-]+:)?exclude-mapping\b[^>]*\bpath\s*=\s*["']([^"']+)["']`)
	xmlRefBean          = regexp.MustCompile(`<(?:[A-Za-z0-9_.-]+:)?ref\b[^>]*\bbean\s*=\s*["']([^"']+)["']`)
	xmlBeanClass        = regexp.MustCompile(`<(?:[A-Za-z0-9_.-]+:)?bean\b[^>]*\bclass\s*=\s*["']([^"']+)["']`)
	xmlInterceptURL     = regexp.MustCompile(`<(?:[A-Za-z0-9_.-]+:)?intercept-url\b([^>]*)>`)
	xmlFilterBlock      = regexp.MustCompile(`(?s)<filter\b[^>]*>(.*?)</filter>`)
	xmlFilterMapping    = regexp.MustCompile(`(?s)<filter-mapping\b[^>]*>(.*?)</filter-mapping>`)
	xmlFilterName       = regexp.MustCompile(`(?s)<filter-name>\s*([^<]+?)\s*</filter-name>`)
	xmlFilterClass      = regexp.MustCompile(`(?s)<filter-class>\s*([^<]+?)\s*</filter-class>`)
	xmlURLPattern       = regexp.MustCompile(`(?s)<url-pattern>\s*([^<]+?)\s*</url-pattern>`)
	xmlSecurityBlock    = regexp.MustCompile(`(?s)<security-constraint\b[^>]*>(.*?)</security-constraint>`)
	xmlAuthConstraint   = regexp.MustCompile(`(?s)<auth-constraint\b[^>]*>(.*?)</auth-constraint>`)
	xmlRoleName         = regexp.MustCompile(`(?s)<role-name>\s*([^<]+?)\s*</role-name>`)
	webFilterPattern    = regexp.MustCompile(`@WebFilter\s*\(([^)]*)\)`)
	addInterceptor      = regexp.MustCompile(`addInterceptor\s*\(\s*(?:new\s+([A-Za-z_][\w.]*)\s*\(\s*\)|([A-Za-z_][\w.]*))\s*\)`)
	addPathPatterns     = regexp.MustCompile(`\.addPathPatterns\s*\(([^)]*)\)`)
	excludePathPatterns = regexp.MustCompile(`\.excludePathPatterns\s*\(([^)]*)\)`)
	securityConfigStart = regexp.MustCompile(`authorizeRequests\s*\(|authorizeHttpRequests\s*\(`)
	matcherCall         = regexp.MustCompile(`(?:antMatchers|mvcMatchers|requestMatchers|regexMatchers)\s*\(([^()]*)\)\s*\.\s*([A-Za-z]+)\s*(?:\(([^()]*)\))?`)
	anyRequestCall      = regexp.MustCompile(`anyRequest\s*\(\s*\)\s*\.\s*([A-Za-z]+)\s*(?:\(([^()]*)\))?`)
)

func scanXMLControls(files map[string]string, lookup classLookup, sources map[string]javaSource) []Control {
	var controls []Control
	var paths []string
	for file := range files {
		paths = append(paths, file)
	}
	sort.Strings(paths)
	beans := map[string]string{}
	for _, file := range paths {
		for _, match := range beanPattern.FindAllStringSubmatch(files[file], -1) {
			if len(match) < 2 {
				continue
			}
			attributes := xmlAttributes(match[1])
			id, class := attributes["id"], attributes["class"]
			if id != "" && class != "" {
				beans[id] = class
			}
		}
	}
	order := 0
	for _, file := range paths {
		content := files[file]
		for _, match := range xmlInterceptorBlock.FindAllStringSubmatchIndex(content, -1) {
			if len(match) < 4 {
				continue
			}
			block := content[match[2]:match[3]]
			paths := uniqueValues(xmlMappingPath.FindAllStringSubmatch(block, -1))
			excluded := uniqueValues(xmlExcludePath.FindAllStringSubmatch(block, -1))
			if len(paths) == 0 {
				paths = []string{"/**"}
			}
			class := ""
			if ref := xmlRefBean.FindStringSubmatch(block); ref != nil {
				class = beans[strings.TrimSpace(ref[1])]
				if class == "" {
					class = strings.TrimSpace(ref[1])
				}
			}
			if class == "" {
				if bean := xmlBeanClass.FindStringSubmatch(block); bean != nil {
					class = strings.TrimSpace(bean[1])
				}
			}
			requirement, note := requirementForClass(class, lookup, sources)
			status := "observed"
			if requirement == RequirementUnknown {
				status = "unresolved"
			}
			order++
			controls = append(controls, Control{
				Kind: "mvc_interceptor", File: file, Line: lineOf(content, match[0]), Order: order,
				Paths: paths, Excluded: excluded, Requirement: requirement,
				SourceClass: class, Status: status, Note: note,
				Declarations: []string{"mvc:interceptor"},
			})
		}
		for _, match := range xmlInterceptURL.FindAllStringSubmatchIndex(content, -1) {
			if len(match) < 4 {
				continue
			}
			attributes := xmlAttributes(content[match[2]:match[3]])
			pattern := strings.TrimSpace(attributes["pattern"])
			if pattern == "" {
				continue
			}
			requirement, roles := requirementFromAccess(attributes["access"] + " " + attributes["filters"])
			order++
			controls = append(controls, Control{
				Kind: "spring_security_xml", File: file, Line: lineOf(content, match[0]), Order: order,
				Paths: []string{pattern}, Requirement: requirement, Roles: roles,
				Status: "observed", Declarations: []string{"intercept-url"},
			})
		}
		if strings.EqualFold(baseName(file), "web.xml") {
			filterClasses := map[string]string{}
			for _, match := range xmlFilterBlock.FindAllStringSubmatch(content, -1) {
				if len(match) < 2 {
					continue
				}
				name := firstSubmatch(xmlFilterName, match[1])
				class := firstSubmatch(xmlFilterClass, match[1])
				if name != "" && class != "" {
					filterClasses[name] = class
				}
			}
			for _, match := range xmlFilterMapping.FindAllStringSubmatchIndex(content, -1) {
				if len(match) < 4 {
					continue
				}
				block := content[match[2]:match[3]]
				name := firstSubmatch(xmlFilterName, block)
				patterns := uniqueValues(xmlURLPattern.FindAllStringSubmatch(block, -1))
				if name == "" || len(patterns) == 0 {
					continue
				}
				class := filterClasses[name]
				requirement, note := requirementForClass(class, lookup, sources)
				status := "observed"
				if requirement == RequirementUnknown {
					status = "unresolved"
				}
				order++
				controls = append(controls, Control{
					Kind: "servlet_filter", File: file, Line: lineOf(content, match[0]), Order: order,
					Paths: patterns, Requirement: requirement, SourceClass: class,
					Status: status, Note: note, Declarations: []string{"filter-mapping:" + name},
				})
			}
			for _, match := range xmlSecurityBlock.FindAllStringSubmatchIndex(content, -1) {
				if len(match) < 4 {
					continue
				}
				block := content[match[2]:match[3]]
				patterns := uniqueValues(xmlURLPattern.FindAllStringSubmatch(block, -1))
				auth := xmlAuthConstraint.FindStringSubmatch(block)
				if len(patterns) == 0 || auth == nil {
					continue
				}
				roles := uniqueValues(xmlRoleName.FindAllStringSubmatch(auth[1], -1))
				order++
				requirement := RequirementAuthenticated
				if len(roles) > 0 {
					requirement = RequirementRole
				}
				controls = append(controls, Control{
					Kind: "servlet_security_constraint", File: file, Line: lineOf(content, match[0]), Order: order,
					Paths: patterns, Roles: roles, Requirement: requirement,
					Status: "observed", Declarations: []string{"security-constraint"},
				})
			}
		}
	}
	return controls
}

func scanJavaControls(sources map[string]javaSource, lookup classLookup) []Control {
	var controls []Control
	var files []string
	for file := range sources {
		files = append(files, file)
	}
	sort.Strings(files)
	order := 0
	for _, file := range files {
		source := sources[file]
		content := source.Content
		for _, match := range webFilterPattern.FindAllStringSubmatchIndex(content, -1) {
			if len(match) < 4 {
				continue
			}
			args := content[match[2]:match[3]]
			patterns := filterPatterns(args)
			if len(patterns) == 0 {
				continue
			}
			class := classAfter(content, match[1])
			requirement, note := requirementForSource(content)
			if class == "" {
				class = source.Class
			}
			status := "observed"
			if requirement == RequirementUnknown {
				status = "unresolved"
			}
			order++
			controls = append(controls, Control{
				Kind: "servlet_filter", File: file, Line: lineOf(content, match[0]), Order: order,
				Paths: patterns, Requirement: requirement, SourceClass: class,
				Status: status, Note: note, Declarations: []string{"@WebFilter"},
			})
		}
		for _, match := range addInterceptor.FindAllStringSubmatchIndex(content, -1) {
			class := ""
			if len(match) >= 4 {
				if match[2] >= 0 {
					class = content[match[2]:match[3]]
				} else if match[4] >= 0 {
					class = content[match[4]:match[5]]
				}
			}
			window := content[match[1]:]
			if len(window) > 4096 {
				window = window[:4096]
			}
			patterns := patternsAfter(addPathPatterns, window)
			excluded := patternsAfter(excludePathPatterns, window)
			if len(patterns) == 0 {
				continue
			}
			requirement, note := requirementForClass(class, lookup, sources)
			status := "observed"
			if requirement == RequirementUnknown {
				status = "unresolved"
			}
			order++
			controls = append(controls, Control{
				Kind: "mvc_interceptor", File: file, Line: lineOf(content, match[0]), Order: order,
				Paths: patterns, Excluded: excluded, Requirement: requirement,
				SourceClass: class, Status: status, Note: note, Declarations: []string{"addInterceptor"},
			})
		}
		for _, start := range securityConfigStart.FindAllStringIndex(content, -1) {
			window := content[start[1]:]
			if end := strings.IndexByte(window, ';'); end >= 0 {
				window = window[:end]
			}
			if len(window) > 8192 {
				window = window[:8192]
			}
			for _, match := range matcherCall.FindAllStringSubmatchIndex(window, -1) {
				if len(match) < 8 {
					continue
				}
				patterns := quotedValues(window[match[2]:match[3]])
				if len(patterns) == 0 {
					continue
				}
				method := window[match[4]:match[5]]
				args := ""
				if match[6] >= 0 {
					args = window[match[6]:match[7]]
				}
				requirement, roles := requirementFromSpringMethod(method, args)
				order++
				controls = append(controls, Control{
					Kind: "spring_security_java", File: file, Line: lineOf(content, start[0]+match[0]), Order: order,
					Paths: patterns, Methods: nil, Requirement: requirement, Roles: roles,
					Status: "observed", Declarations: []string{"spring_security_java:" + method},
				})
			}
			for _, match := range anyRequestCall.FindAllStringSubmatchIndex(window, -1) {
				if len(match) < 6 {
					continue
				}
				method := window[match[2]:match[3]]
				args := ""
				if match[4] >= 0 {
					args = window[match[4]:match[5]]
				}
				requirement, roles := requirementFromSpringMethod(method, args)
				order++
				controls = append(controls, Control{
					Kind: "spring_security_java", File: file, Line: lineOf(content, start[0]+match[0]), Order: order,
					Paths: []string{"/**"}, Requirement: requirement, Roles: roles,
					Status: "observed", Declarations: []string{"spring_security_java:anyRequest"},
				})
			}
		}
	}
	return controls
}

func requirementForClass(class string, lookup classLookup, sources map[string]javaSource) (string, string) {
	class = strings.TrimSpace(class)
	if class == "" {
		return RequirementUnknown, "control_class_unresolved"
	}
	normalized := strings.ReplaceAll(class, "$", ".")
	file := lookup.byName[normalized]
	if file == "" {
		simple := normalized
		if index := strings.LastIndexByte(simple, '.'); index >= 0 {
			simple = simple[index+1:]
		}
		if lookup.ambiguous[simple] {
			return RequirementUnknown, "control_class_ambiguous:" + class
		}
		file = lookup.byName[simple]
	}
	if file == "" {
		return RequirementUnknown, "control_class_source_not_found:" + class
	}
	source, ok := sources[file]
	if !ok {
		return RequirementUnknown, "control_class_source_unreadable:" + class
	}
	return requirementForSource(source.Content)
}

func requirementForSource(content string) (string, string) {
	lower := strings.ToLower(content)
	interceptor := strings.Contains(lower, "handlerinterceptor") || strings.Contains(lower, "implements filter") ||
		strings.Contains(lower, "onceperrequestfilter") || strings.Contains(lower, "dofilter")
	auth := strings.Contains(lower, "getsession") || strings.Contains(lower, "getattribute") ||
		strings.Contains(lower, "sendredirect") || strings.Contains(lower, "securitycontextholder") ||
		strings.Contains(lower, "isauthenticated")
	switch {
	case interceptor && auth:
		return RequirementAuthenticated, ""
	case interceptor:
		return RequirementUnknown, "control_class_has_no_observed_auth_token"
	case auth:
		return RequirementUnknown, "auth_tokens_without_recognized_interceptor_or_filter"
	default:
		return RequirementUnknown, "control_class_not_recognized_as_auth_control"
	}
}

func requirementFromAccess(value string) (string, []string) {
	lower := strings.ToLower(value)
	roles := roleValues(value)
	switch {
	case strings.Contains(lower, "permitall") || strings.Contains(lower, "isanonymous") ||
		strings.Contains(lower, "isauthenticatedanonymously") || strings.Contains(lower, "filters=\"none\""):
		return RequirementPublic, nil
	case strings.Contains(lower, "denyall"):
		return RequirementDeny, nil
	case strings.Contains(lower, "hasrole") || strings.Contains(lower, "hasauthority") ||
		strings.Contains(lower, "role_") || strings.Contains(lower, "hasanyrole"):
		return RequirementRole, roles
	case strings.Contains(lower, "isauthenticated") || strings.Contains(lower, "fullyauthenticated"):
		return RequirementAuthenticated, nil
	default:
		return RequirementUnknown, nil
	}
}

func requirementFromSpringMethod(method, args string) (string, []string) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "permitall":
		return RequirementPublic, nil
	case "denyall":
		return RequirementDeny, nil
	case "authenticated", "fullyauthenticated":
		return RequirementAuthenticated, nil
	case "hasrole", "hasanyrole", "hasauthority", "hasanyauthority":
		return RequirementRole, roleValues(args)
	case "access":
		return requirementFromAccess(args)
	default:
		return RequirementUnknown, nil
	}
}

func roleValues(value string) []string {
	var roles []string
	for _, match := range quotedValuePattern.FindAllStringSubmatch(value, -1) {
		if len(match) >= 2 && strings.TrimSpace(match[1]) != "" {
			roles = append(roles, strings.TrimSpace(match[1]))
		}
	}
	return uniqueStrings(roles)
}

func filterPatterns(args string) []string {
	if match := regexp.MustCompile(`(?:urlPatterns|value)\s*=\s*(\{[^}]*\}|["'][^"']*["'])`).FindStringSubmatch(args); match != nil {
		return quotedValues(match[1])
	}
	return quotedValues(args)
}

func patternsAfter(pattern *regexp.Regexp, window string) []string {
	match := pattern.FindStringSubmatch(window)
	if match == nil {
		return nil
	}
	return quotedValues(match[1])
}

func uniqueValues(matches [][]string) []string {
	var values []string
	for _, match := range matches {
		if len(match) >= 2 && strings.TrimSpace(match[1]) != "" {
			values = append(values, strings.TrimSpace(match[1]))
		}
	}
	return uniqueStrings(values)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func firstSubmatch(pattern *regexp.Regexp, value string) string {
	match := pattern.FindStringSubmatch(value)
	if match == nil {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func baseName(file string) string {
	index := strings.LastIndexAny(file, "/\\")
	if index < 0 {
		return file
	}
	return file[index+1:]
}
