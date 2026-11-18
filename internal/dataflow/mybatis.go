package dataflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"text/scanner"

	"trident/internal/project"
)

// MyBatis modelling is intentionally bounded: it reads Mapper XML and
// annotation SQL from the pinned snapshot and turns #{} / ${} observations
// into evidence. It does not build SQL, expand <foreach>, resolve providers,
// or claim runtime behaviour.

const (
	MaxOrmFiles      = 500
	MaxOrmFileBytes  = 2 << 20
	MaxOrmStatements = 2000
)

var (
	mapperNamespaceRE = regexp.MustCompile(`<mapper[^>]*\bnamespace\s*=\s*["']([^"']+)["']`)
	mapperTagRE       = regexp.MustCompile(`<(select|insert|update|delete|sql)\b([^>]*)>`)
	mapperAttrRE      = regexp.MustCompile(`\bid\s*=\s*["']([^"']+)["']`)
	bindRE            = regexp.MustCompile(`#\{\s*([^}]*)\}`)
	substitutionRE    = regexp.MustCompile(`\$\{\s*([^}]*)\}`)
	xmlCommentRE      = regexp.MustCompile(`(?s)<!--.*?-->`)
	annotationSQLRE   = regexp.MustCompile(`^(Select|Insert|Update|Delete|SelectProvider|UpdateProvider|InsertProvider|DeleteProvider)$`)
)

// OrmStatement is one observed SQL statement or shared fragment.
type OrmStatement struct {
	Namespace       string   `json:"namespace"`
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Assessment      string   `json:"assessment"`
	File            string   `json:"file"`
	SHA256          string   `json:"sha256"`
	Line            int      `json:"line"`
	BindCount       int      `json:"bind_count"`
	SubstituteCount int      `json:"substitute_count"`
	Bindings        []string `json:"bindings,omitempty"`
	Substitutions   []string `json:"substitutions,omitempty"`
	Detail          string   `json:"detail,omitempty"`
}

// OrmMapper groups statements by namespace.
type OrmMapper struct {
	Namespace  string `json:"namespace"`
	File       string `json:"file"`
	SHA256     string `json:"sha256"`
	Statements int    `json:"statements"`
}

// OrmReport is the deterministic ORM evidence inventory.
type OrmReport struct {
	Mappers     []OrmMapper    `json:"mappers"`
	Statements  []OrmStatement `json:"statements"`
	Limitations []string       `json:"limitations"`
}

// OrmRef points one finding to the SQL statement that produced its evidence.
type OrmRef struct {
	Namespace  string `json:"namespace"`
	ID         string `json:"id"`
	Assessment string `json:"assessment"`
	File       string `json:"file"`
	SHA256     string `json:"sha256"`
	Line       int    `json:"line"`
}

// OrmIndex resolves mapper calls to statements.
type OrmIndex struct {
	Statements []OrmStatement
	byFull     map[string][]int
	bySimple   map[string][]int
}

func newOrmIndex(statements []OrmStatement) *OrmIndex {
	index := &OrmIndex{Statements: statements, byFull: map[string][]int{}, bySimple: map[string][]int{}}
	for i := range statements {
		stmt := &statements[i]
		index.byFull[stmt.Namespace+"."+stmt.ID] = append(index.byFull[stmt.Namespace+"."+stmt.ID], i)
		if stmt.Kind != "fragment" && stmt.Kind != "sql" {
			index.bySimple[stmt.ID] = append(index.bySimple[stmt.ID], i)
		}
	}
	return index
}

// Lookup resolves a Java mapper call. A unique simple id wins; otherwise the
// receiver type is matched against the namespace suffix. Ambiguity is never
// resolved by picking the first candidate.
func (o *OrmIndex) Lookup(typeName, methodName string) (*OrmStatement, string) {
	if o == nil || methodName == "" {
		return nil, "not_found"
	}
	if ids := o.bySimple[methodName]; len(ids) == 1 {
		return &o.Statements[ids[0]], "resolved"
	}
	candidates := append([]int(nil), o.bySimple[methodName]...)
	if len(candidates) == 0 && typeName != "" {
		for key, ids := range o.byFull {
			if strings.HasSuffix(key, "."+methodName) && strings.Contains(key, typeName) {
				candidates = append(candidates, ids...)
			}
		}
	}
	if typeName != "" && len(candidates) > 1 {
		filtered := candidates[:0]
		for _, id := range candidates {
			if strings.HasSuffix(o.Statements[id].Namespace, "."+typeName) ||
				strings.EqualFold(path.Base(o.Statements[id].Namespace), typeName) {
				filtered = append(filtered, id)
			}
		}
		candidates = filtered
	}
	if len(candidates) == 1 {
		return &o.Statements[candidates[0]], "resolved"
	}
	if len(candidates) > 1 {
		return nil, "ambiguous"
	}
	return nil, "not_found"
}

func emptyOrmReport() OrmReport {
	return OrmReport{Mappers: []OrmMapper{}, Statements: []OrmStatement{}, Limitations: []string{
		"mybatis_declarative_only: Mapper XML and annotation SQL are read as text; runtime SQL, <foreach> expansion, providers, interceptors and dialects are not modeled",
		"mybatis_substitution_not_automatically_vulnerable: ${} inside generated <sql> fragments or condition expressions is treated as framework-internal and never confirmed as injection",
		"mybatis_refuted_is_local: #{} evidence refutes only the observed statement and parameter, not the whole application",
	}}
}

// scanOrm reads Mapper XML and annotation SQL from the same pinned snapshot.
func scanOrm(ctx context.Context, snapshot *project.Snapshot, files []*fileModel) (OrmReport, *OrmIndex, error) {
	report := emptyOrmReport()
	statements := []OrmStatement{}
	mapperSeen := map[string]bool{}
	entries := append([]project.FileEntry(nil), snapshot.Manifest().Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	xmlCount := 0
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return report, nil, ctx.Err()
		default:
		}
		ext := strings.ToLower(path.Ext(entry.Path))
		if ext == ".xml" {
			if xmlCount >= MaxOrmFiles {
				report.Limitations = append(report.Limitations, "mybatis_file_limit")
				break
			}
			data, err := snapshot.ReadFile(ctx, entry.Path)
			if err != nil {
				return report, nil, err
			}
			if len(data) > MaxOrmFileBytes {
				report.Limitations = append(report.Limitations, "mybatis_file_too_large")
				continue
			}
			xmlCount++
			digest := sha256.Sum256(data)
			hash := hex.EncodeToString(digest[:])
			found := parseMapperXML(entry.Path, hash, string(data))
			for _, stmt := range found {
				statements = append(statements, stmt)
				key := stmt.Namespace + "|" + stmt.File
				if !mapperSeen[key] {
					mapperSeen[key] = true
					report.Mappers = append(report.Mappers, OrmMapper{Namespace: stmt.Namespace, File: stmt.File, SHA256: stmt.SHA256})
				}
			}
		}
	}
	// Annotation SQL is stored in Java files already tokenized by parseProject.
	for _, file := range files {
		for _, stmt := range parseAnnotationSQL(file) {
			statements = append(statements, stmt)
		}
	}
	if len(statements) > MaxOrmStatements {
		statements = statements[:MaxOrmStatements]
		report.Limitations = append(report.Limitations, "mybatis_statement_limit")
	}
	sort.Slice(statements, func(i, j int) bool {
		a, b := statements[i], statements[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.ID < b.ID
	})
	report.Statements = statements
	for i := range report.Mappers {
		count := 0
		for _, stmt := range statements {
			if stmt.Namespace == report.Mappers[i].Namespace && stmt.File == report.Mappers[i].File {
				count++
			}
		}
		report.Mappers[i].Statements = count
	}
	sort.Slice(report.Mappers, func(i, j int) bool { return report.Mappers[i].Namespace < report.Mappers[j].Namespace })
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, newOrmIndex(statements), nil
}

func parseMapperXML(file, hash, source string) []OrmStatement {
	// Comments can contain #{} / ${}; remove them before scanning.
	clean := xmlCommentRE.ReplaceAllString(source, "")
	lines := strings.Split(clean, "\n")
	namespace := ""
	if match := mapperNamespaceRE.FindStringSubmatch(clean); len(match) > 1 {
		namespace = match[1]
	}
	if namespace == "" {
		return nil
	}
	out := []OrmStatement{}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		matches := mapperTagRE.FindAllStringSubmatchIndex(line, -1)
		for _, m := range matches {
			kind, attrs := line[m[2]:m[3]], line[m[4]:m[5]]
			id := ""
			if attr := mapperAttrRE.FindStringSubmatch(attrs); len(attr) > 1 {
				id = attr[1]
			}
			if id == "" {
				continue
			}
			closing := "</" + kind + ">"
			body := []string{line[m[1]:]}
			endLine := i + 1
			if !strings.Contains(line[m[1]:], closing) {
				for j := i + 1; j < len(lines) && j < i+400; j++ {
					body = append(body, lines[j])
					if strings.Contains(lines[j], closing) {
						break
					}
				}
			}
			text := strings.Join(body, "\n")
			binds := matchesOf(bindRE, text)
			subs := matchesOf(substitutionRE, text)
			stmt := OrmStatement{
				Namespace: namespace, ID: id, Kind: kind,
				File: file, SHA256: hash, Line: endLine,
				BindCount: len(binds), SubstituteCount: len(subs),
				Bindings: binds, Substitutions: subs,
			}
			stmt.Assessment, stmt.Detail = assessMyBatis(kind, binds, subs)
			out = append(out, stmt)
		}
	}
	return out
}

func matchesOf(re *regexp.Regexp, text string) []string {
	found := re.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(found))
	seen := map[string]bool{}
	for _, match := range found {
		value := strings.TrimSpace(match[1])
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func assessMyBatis(kind string, binds, subs []string) (string, string) {
	if kind == "sql" {
		if len(subs) > 0 {
			return "framework_fragment", "shared <sql> fragment substitution; not a mapper method parameter"
		}
		return "fragment", "shared <sql> fragment"
	}
	frameworkInternal := false
	for _, item := range subs {
		if strings.Contains(item, ".") || strings.HasPrefix(item, "criterion") || strings.HasPrefix(item, "ew.") || strings.HasPrefix(item, "wrapper.") {
			frameworkInternal = true
		}
	}
	switch {
	case len(subs) > 0 && frameworkInternal && len(binds) > 0:
		return "framework_fragment", "generated condition/column substitution mixed with #{} bindings"
	case len(subs) > 0 && !frameworkInternal:
		return "substitution", "direct ${} substitution of a mapper parameter"
	case len(subs) > 0:
		return "framework_fragment", "substitution expression is framework-internal"
	case len(binds) > 0:
		return "parameterized", "only #{} bindings observed"
	default:
		return "unknown", "no binding or substitution observed"
	}
}

func parseAnnotationSQL(file *fileModel) []OrmStatement {
	out := []OrmStatement{}
	if file == nil {
		return out
	}
	tokens := file.Tokens
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok.Text != "@" || i+1 >= len(tokens) || tokens[i+1].Tok != scanner.Ident {
			continue
		}
		name := tokens[i+1].Text
		if !annotationSQLRE.MatchString(name) {
			continue
		}
		literal := ""
		for j := i + 2; j < len(tokens) && j <= i+8; j++ {
			if tokens[j].Tok == scanner.String {
				literal = strings.Trim(tokens[j].Text, "\"`")
				break
			}
			if tokens[j].Text == "(" || tokens[j].Text == ")" {
				continue
			}
			if tokens[j].Tok == scanner.Ident {
				break
			}
		}
		if literal == "" || (!strings.Contains(literal, "#{") && !strings.Contains(literal, "${")) {
			continue
		}
		className := "Unknown"
		if len(file.Classes) > 0 {
			className = file.Classes[0].Symbol
		}
		// Interface mapper methods may have no body and therefore no
		// methodModel; resolve the annotated method from the next '(' instead.
		methodName := "annotation"
		for j := i + 2; j < len(tokens) && j < i+20; j++ {
			if tokens[j].Text == "(" && j-1 > i && tokens[j-1].Tok == scanner.Ident {
				methodName = tokens[j-1].Text
				break
			}
		}
		binds := matchesOf(bindRE, literal)
		subs := matchesOf(substitutionRE, literal)
		assessment, detail := assessMyBatis("select", binds, subs)
		if assessment == "framework_fragment" {
			assessment, detail = "substitution", "annotation SQL with ${} is string substitution"
		}
		out = append(out, OrmStatement{
			Namespace: className, ID: methodName, Kind: "annotation",
			Assessment: assessment, File: file.Path, SHA256: file.SHA256, Line: tok.Line,
			BindCount: len(binds), SubstituteCount: len(subs),
			Bindings: binds, Substitutions: subs, Detail: detail,
		})
	}
	return out
}

func ormRef(stmt *OrmStatement) *OrmRef {
	if stmt == nil {
		return nil
	}
	return &OrmRef{
		Namespace: stmt.Namespace, ID: stmt.ID, Assessment: stmt.Assessment,
		File: stmt.File, SHA256: stmt.SHA256, Line: stmt.Line,
	}
}

func ormKey(stmt *OrmStatement) string {
	if stmt == nil {
		return ""
	}
	return fmt.Sprintf("%s.%s (mybatis)", stmt.Namespace, stmt.ID)
}

// observeMyBatis turns one resolved mapper call into binding, substitution or
// framework-boundary evidence. It returns true when the call was consumed so
// the generic analyzer does not also record it as an unresolved library call.
func (s *findingState) observeMyBatis(index *OrmIndex, typeName, name string, method *methodModel, line int, argEval exprResult) bool {
	if !argEval.found {
		return false
	}
	stmt, status := index.Lookup(typeName, name)
	if status == "not_found" {
		return false
	}
	if status == "ambiguous" || stmt == nil {
		s.addBoundary("mybatis_ambiguous_method", callAPI(typeName, name), method, line)
		s.addLimitation("mybatis_ambiguous_method")
		return true
	}
	s.orm = ormRef(stmt)
	s.recordFlow("mybatis_call", ormKey(stmt), method.File.Path, line)
	switch stmt.Assessment {
	case "parameterized":
		before := s.binding
		s.observeBinding(ormKey(stmt)+" (#{})", method, line)
		if !before && s.protection != nil {
			s.protection.File = stmt.File
			s.protection.SHA256 = stmt.SHA256
			s.protection.Line = stmt.Line
			s.protection.Detail = "MyBatis #{} parameter binding on " + stmt.Namespace + "." + stmt.ID
		}
		s.recordFlow("mybatis_binding", stmt.Namespace+"."+stmt.ID, stmt.File, stmt.Line)
		return true
	case "substitution", "mixed":
		before := s.confirmed
		s.confirmSink(ormKey(stmt)+" (${})", method, line)
		if !before && s.sink != nil {
			s.sink.File = stmt.File
			s.sink.SHA256 = stmt.SHA256
			s.sink.Line = stmt.Line
		}
		s.recordFlow("mybatis_substitution", stmt.Namespace+"."+stmt.ID+" ${}", stmt.File, stmt.Line)
		return true
	default:
		s.addBoundary("mybatis_internal_substitution", ormKey(stmt), method, line)
		s.addLimitation("mybatis_framework_fragment")
		s.recordFlow("mybatis_fragment", stmt.Namespace+"."+stmt.ID, stmt.File, stmt.Line)
		return true
	}
}
