package httpverify

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Role defines one caller-supplied account: an ordered login sequence and an
// optional CSRF token source. Passwords may use ${ENV:NAME} placeholders so the
// plan file never stores credentials.
type Role struct {
	ID      string    `json:"id"`
	Session string    `json:"session,omitempty"`
	Login   []Request `json:"login,omitempty"`
	CSRF    *CSRF     `json:"csrf,omitempty"`
}

type CSRF struct {
	Selector string `json:"selector"`
	Field    string `json:"field,omitempty"`
	Header   string `json:"header,omitempty"`
}

// MatrixCase is one role x request x expectation cell.
type MatrixCase struct {
	Role    string `json:"role"`
	Request string `json:"request"`
	Expect  Expect `json:"expect"`
}

type RoleCoverage struct {
	Requests     int    `json:"requests"`
	Passed       int    `json:"passed"`
	Failed       int    `json:"failed"`
	Inconclusive int    `json:"inconclusive"`
	LoginStatus  string `json:"login_status"`
}

type roleState struct {
	role        Role
	session     string
	token       string
	tokenFound  bool
	loginFailed bool
}

var (
	csrfSelectorPattern   = regexp.MustCompile(`^(meta|input)\[name=["']?([A-Za-z0-9_.:-]+)["']?\]$`)
	htmlTagPattern        = regexp.MustCompile(`(?is)<(?:meta|input)\b[^>]*>`)
	htmlAttributePattern  = regexp.MustCompile(`([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
	envPlaceholderPattern = regexp.MustCompile(`\$\{ENV:([A-Z0-9_]{1,64})\}`)
)

func validateRolesAndMatrix(plan *Plan) error {
	total := len(plan.Requests) + len(plan.Matrix)
	roles := map[string]bool{}
	sessions := map[string]string{}
	requests := map[string]bool{}
	for _, request := range plan.Requests {
		requests[request.ID] = true
	}
	for _, role := range plan.Roles {
		if strings.TrimSpace(role.ID) == "" || len(role.ID) > 64 || roles[role.ID] {
			return fmt.Errorf("role IDs must be unique and at most 64 characters")
		}
		roles[role.ID] = true
		session := roleSession(role)
		if other, exists := sessions[session]; exists {
			return fmt.Errorf("roles %q and %q must use distinct sessions", other, role.ID)
		}
		sessions[session] = role.ID
		if len(role.Login) > MaxRoleLogins {
			return fmt.Errorf("role %q has more than %d login requests", role.ID, MaxRoleLogins)
		}
		total += len(role.Login)
		loginIDs := map[string]bool{}
		for _, login := range role.Login {
			if strings.TrimSpace(login.ID) == "" || len(login.ID) > 128 || loginIDs[login.ID] {
				return fmt.Errorf("role %q login request IDs must be unique and at most 128 characters", role.ID)
			}
			loginIDs[login.ID] = true
			if !validMethod(login.Method) {
				return fmt.Errorf("role %q login %q has an unsupported method", role.ID, login.ID)
			}
			if !validPath(login.Path) {
				return fmt.Errorf("role %q login %q path must be a bounded relative path starting with /", role.ID, login.ID)
			}
			if len(login.Form) > 0 && len(login.JSON) > 0 {
				return fmt.Errorf("role %q login %q cannot set both form and json", role.ID, login.ID)
			}
			if login.Expect.Status < 100 || login.Expect.Status > 599 {
				return fmt.Errorf("role %q login %q must declare an expected HTTP status", role.ID, login.ID)
			}
		}
		if role.CSRF != nil {
			if _, _, err := parseCSRFSelector(role.CSRF.Selector); err != nil {
				return fmt.Errorf("role %q csrf selector: %w", role.ID, err)
			}
			if role.CSRF.Field == "" && role.CSRF.Header == "" {
				return fmt.Errorf("role %q csrf requires a form field or header name", role.ID)
			}
			if role.CSRF.Field != "" && !validTokenName(role.CSRF.Field) {
				return fmt.Errorf("role %q csrf field name is invalid", role.ID)
			}
			if role.CSRF.Header != "" && !validHeaderName(role.CSRF.Header) {
				return fmt.Errorf("role %q csrf header name is invalid", role.ID)
			}
		}
	}
	seenMatrix := map[string]bool{}
	for _, cell := range plan.Matrix {
		if !roles[cell.Role] {
			return fmt.Errorf("matrix references unknown role %q", cell.Role)
		}
		if !requests[cell.Request] {
			return fmt.Errorf("matrix references unknown request %q", cell.Request)
		}
		key := cell.Role + "\x00" + cell.Request
		if seenMatrix[key] {
			return fmt.Errorf("matrix cell %q/%q is duplicated", cell.Role, cell.Request)
		}
		seenMatrix[key] = true
		if cell.Expect.Status < 100 || cell.Expect.Status > 599 {
			return fmt.Errorf("matrix cell %q/%q must declare an expected HTTP status", cell.Role, cell.Request)
		}
	}
	if total > MaxRequests {
		return fmt.Errorf("plan would execute %d requests; maximum is %d", total, MaxRequests)
	}
	return nil
}

func runRolesAndMatrix(ctx context.Context, client *http.Client, origin *url.URL, plan Plan, sessions map[string]map[string]string, report *Report) {
	if len(plan.Roles) > 0 {
		report.Coverage.Roles = map[string]RoleCoverage{}
	}
	states := map[string]*roleState{}
	for _, role := range plan.Roles {
		state := &roleState{role: role, session: roleSession(role)}
		states[role.ID] = state
		for _, login := range role.Login {
			result := Result{
				ID: "role:" + role.ID + ":" + login.ID, Method: strings.ToUpper(login.Method),
				Path: login.Path, Session: state.session, Role: role.ID,
				Status: "error", Assertions: []Assertion{},
			}
			request, err := resolvePlaceholders(login)
			if err != nil {
				result.Error = "credential_placeholder_unresolved"
				appendResult(report, result)
				state.loginFailed = true
				break
			}
			request.Session = state.session
			if requiresCSRF(request, state) && !state.tokenFound {
				result.Status = "inconclusive"
				result.Error = "csrf_token_not_found"
				appendResult(report, result)
				state.loginFailed = true
				break
			}
			request = injectCSRF(request, state)
			injected := requiresCSRF(request, state) && state.tokenFound
			observed, body := executeRequest(ctx, client, origin, request, sessions)
			observed.ID = result.ID
			observed.Role = role.ID
			if state.role.CSRF != nil {
				if !state.tokenFound {
					if token, ok := extractCSRFToken(state.role.CSRF.Selector, body); ok {
						state.token = token
						state.tokenFound = true
					}
				}
				switch {
				case injected:
					observed.CSRF = "token_injected"
				case state.tokenFound:
					observed.CSRF = "token_observed"
				default:
					observed.CSRF = "token_missing"
				}
			}
			appendResult(report, observed)
			if observed.Status != "passed" {
				state.loginFailed = true
				break
			}
		}
	}
	for _, cell := range plan.Matrix {
		state := states[cell.Role]
		base, found := findRequest(plan.Requests, cell.Request)
		result := Result{
			ID: "matrix:" + cell.Role + ":" + cell.Request, Method: strings.ToUpper(base.Method),
			Path: base.Path, Session: state.session, Role: cell.Role, Matrix: cell.Request,
			Status: "error", Assertions: []Assertion{},
		}
		switch {
		case !found:
			result.Error = "matrix_request_not_found"
		case state.loginFailed:
			result.Status = "inconclusive"
			result.Error = "role_login_incomplete"
		default:
			request := cloneRequest(base)
			request.Session = state.session
			request.Expect = cloneExpect(cell.Expect)
			if requiresCSRF(request, state) && !state.tokenFound {
				result.Status = "inconclusive"
				result.Error = "csrf_token_not_found"
				break
			}
			request = injectCSRF(request, state)
			observed, _ := executeRequest(ctx, client, origin, request, sessions)
			observed.ID = result.ID
			observed.Role = cell.Role
			observed.Matrix = cell.Request
			if state.role.CSRF != nil {
				if state.tokenFound {
					if requiresCSRF(request, state) {
						observed.CSRF = "token_injected"
					} else {
						observed.CSRF = "token_available"
					}
				} else {
					observed.CSRF = "token_missing"
				}
			}
			result = observed
		}
		appendResult(report, result)
	}
	for _, role := range plan.Roles {
		entry := report.Coverage.Roles[role.ID]
		switch {
		case len(role.Login) == 0:
			entry.LoginStatus = "not_declared"
		case states[role.ID].loginFailed:
			entry.LoginStatus = "incomplete"
		default:
			entry.LoginStatus = "complete"
		}
		report.Coverage.Roles[role.ID] = entry
	}
}

func appendResult(report *Report, result Result) {
	if result.Assertions == nil {
		result.Assertions = []Assertion{}
	}
	report.Results = append(report.Results, result)
	switch result.Status {
	case "passed":
		report.Coverage.Passed++
	case "inconclusive":
		report.Coverage.Inconclusive++
	default:
		report.Coverage.Failed++
	}
	if result.Role == "" {
		return
	}
	if report.Coverage.Roles == nil {
		report.Coverage.Roles = map[string]RoleCoverage{}
	}
	entry := report.Coverage.Roles[result.Role]
	entry.Requests++
	switch result.Status {
	case "passed":
		entry.Passed++
	case "inconclusive":
		entry.Inconclusive++
	default:
		entry.Failed++
	}
	report.Coverage.Roles[result.Role] = entry
}

func roleSession(role Role) string {
	if strings.TrimSpace(role.Session) != "" {
		return role.Session
	}
	return role.ID
}

func requiresCSRF(request Request, state *roleState) bool {
	if state.role.CSRF == nil {
		return false
	}
	switch strings.ToUpper(request.Method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return state.role.CSRF.Field != "" || state.role.CSRF.Header != ""
}

func injectCSRF(request Request, state *roleState) Request {
	if state.token == "" || state.role.CSRF == nil {
		return request
	}
	request = cloneRequest(request)
	if field := state.role.CSRF.Field; field != "" {
		if request.Form == nil {
			request.Form = map[string]string{}
		}
		request.Form[field] = state.token
	}
	if header := state.role.CSRF.Header; header != "" {
		if request.Headers == nil {
			request.Headers = map[string]string{}
		}
		request.Headers[header] = state.token
	}
	return request
}

func parseCSRFSelector(selector string) (string, string, error) {
	match := csrfSelectorPattern.FindStringSubmatch(strings.TrimSpace(selector))
	if match == nil {
		return "", "", fmt.Errorf("selector must be meta[name=...] or input[name=...]")
	}
	return strings.ToLower(match[1]), match[2], nil
}

func extractCSRFToken(selector, body string) (string, bool) {
	tag, name, err := parseCSRFSelector(selector)
	if err != nil {
		return "", false
	}
	for _, match := range htmlTagPattern.FindAllString(body, -1) {
		if !strings.HasPrefix(strings.ToLower(match), "<"+tag) {
			continue
		}
		attributes := htmlAttributes(match)
		if attributes["name"] != name {
			continue
		}
		value := attributes["value"]
		if tag == "meta" {
			value = attributes["content"]
		}
		if value == "" || len(value) > MaxCSRFTokenLen || strings.ContainsAny(value, "<>\"' \t\r\n") {
			continue
		}
		return value, true
	}
	return "", false
}

func htmlAttributes(tag string) map[string]string {
	attributes := map[string]string{}
	for _, match := range htmlAttributePattern.FindAllStringSubmatch(tag, -1) {
		value := match[3]
		if value == "" {
			value = match[4]
		}
		if value == "" {
			value = match[5]
		}
		attributes[strings.ToLower(match[1])] = htmlUnescape(value)
	}
	return attributes
}

func htmlUnescape(value string) string {
	replacer := strings.NewReplacer("&amp;", "&", "&quot;", "\"", "&#39;", "'", "&lt;", "<", "&gt;", ">")
	return replacer.Replace(value)
}

func resolvePlaceholders(request Request) (Request, error) {
	request = cloneRequest(request)
	for key, value := range request.Form {
		resolved, err := expandPlaceholders(value)
		if err != nil {
			return Request{}, err
		}
		request.Form[key] = resolved
	}
	for key, value := range request.Headers {
		resolved, err := expandPlaceholders(value)
		if err != nil {
			return Request{}, err
		}
		request.Headers[key] = resolved
	}
	return request, nil
}

func expandPlaceholders(value string) (string, error) {
	if !strings.Contains(value, "${ENV:") {
		return value, nil
	}
	var resolveErr error
	resolved := envPlaceholderPattern.ReplaceAllStringFunc(value, func(match string) string {
		name := envPlaceholderPattern.FindStringSubmatch(match)[1]
		secret, ok := os.LookupEnv(name)
		if !ok || secret == "" {
			resolveErr = fmt.Errorf("credential placeholder %s is not set", name)
			return ""
		}
		return secret
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	if strings.Contains(resolved, "${ENV:") {
		return "", fmt.Errorf("malformed credential placeholder")
	}
	return resolved, nil
}

func cloneRequest(request Request) Request {
	out := request
	if request.Headers != nil {
		out.Headers = map[string]string{}
		for key, value := range request.Headers {
			out.Headers[key] = value
		}
	}
	if request.Form != nil {
		out.Form = map[string]string{}
		for key, value := range request.Form {
			out.Form[key] = value
		}
	}
	if request.JSON != nil {
		out.JSON = append([]byte{}, request.JSON...)
	}
	out.Expect = cloneExpect(request.Expect)
	return out
}

func cloneExpect(expect Expect) Expect {
	out := expect
	if expect.HeaderContains != nil {
		out.HeaderContains = map[string]string{}
		for key, value := range expect.HeaderContains {
			out.HeaderContains[key] = value
		}
	}
	return out
}

func findRequest(requests []Request, id string) (Request, bool) {
	for _, request := range requests {
		if request.ID == id {
			return request, true
		}
	}
	return Request{}, false
}

func validTokenName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for index, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' {
			continue
		}
		if index == 0 {
			return false
		}
		return false
	}
	return true
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}
