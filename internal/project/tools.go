package project

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// [01] These limits apply to each invocation, including serialized JSON overhead.
const (
	DefaultToolLimit           = 50
	MaxToolLimit               = 200
	MaxToolResponseBytes       = 256 << 10
	MaxToolLineBytes           = 16 << 10
	MaxSearchFiles             = 256
	MaxSearchBytes       int64 = 16 << 20
	MaxSearchQueryBytes        = 256
	toolResponseReserve        = 2048 // Space for a continuation cursor and partial reasons.
)

var (
	ErrToolOptions = errors.New("invalid project tool options")
	ErrToolCursor  = errors.New("invalid project tool cursor")
)

type InspectOptions struct{}

type ListOptions struct {
	Prefix string `json:"prefix,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type ReadOptions struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

type SearchOptions struct {
	Query  string `json:"query"`
	Prefix string `json:"prefix,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type ToolLimits struct {
	Limit            int   `json:"limit"`
	MaxLimit         int   `json:"max_limit"`
	MaxResponseBytes int   `json:"max_response_bytes"`
	MaxLineBytes     int   `json:"max_line_bytes"`
	MaxSearchFiles   int   `json:"max_search_files"`
	MaxSearchBytes   int64 `json:"max_search_bytes"`
	MaxQueryBytes    int   `json:"max_query_bytes"`
}

// ToolMetadata describes this page, not an assertion that every file was read.
// A partial result may have no cursor: binary data, exclusions and truncated lines
// are intentionally not recoverable by requesting another page.
type ToolMetadata struct {
	SnapshotHash string     `json:"snapshot_hash"`
	Verification string     `json:"verification"`
	Partial      bool       `json:"partial"`
	Reasons      []string   `json:"reasons"`
	Limits       ToolLimits `json:"limits"`
	NextCursor   string     `json:"next_cursor,omitempty"`
}

type PathCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type InspectResult struct {
	ToolMetadata
	TotalFiles          int         `json:"total_files"`
	TotalBytes          int64       `json:"total_bytes"`
	ExcludedCount       int         `json:"excluded_count"`
	Exclusions          []Exclusion `json:"exclusions"`
	ExclusionsTruncated bool        `json:"exclusions_truncated"`
	Extensions          []PathCount `json:"extensions"`
	Directories         []PathCount `json:"directories"`
	BuildFiles          []FileEntry `json:"build_files"`
}

type ListResult struct {
	ToolMetadata
	Entries []FileEntry `json:"entries"`
	Total   int         `json:"total"`
}

type SourceLine struct {
	Number    int    `json:"number"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
	Bytes     int    `json:"bytes"` // Original line bytes, excluding CRLF/LF.
}

type ReadResult struct {
	ToolMetadata
	Path       string       `json:"path"`
	Size       int64        `json:"size"`
	SHA256     string       `json:"sha256"`
	UTF8       bool         `json:"utf8"`
	Binary     bool         `json:"binary"`
	TotalLines int          `json:"total_lines"`
	StartLine  int          `json:"start_line"`
	EndLine    int          `json:"end_line"`
	Lines      []SourceLine `json:"lines"`
}

type SearchMatch struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Line      int    `json:"line"`
	Column    int    `json:"column"` // One-based Unicode code-point column.
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
	LineBytes int    `json:"line_bytes"`
}

type SearchResult struct {
	ToolMetadata
	Query            string        `json:"query"`
	Matches          []SearchMatch `json:"matches"`
	ScannedFiles     int           `json:"scanned_files"` // Successfully verified reads on this page only.
	ScannedBytes     int64         `json:"scanned_bytes"` // Includes full-file hash verification, even on resumed files.
	SkippedBinary    int           `json:"skipped_binary"`
	SkippedOversized int           `json:"skipped_oversized"`
}

// [02] Inspect reports bounded, sorted path clues only: no parsing, execution or
// reads from the original source directory. Open has verified the pinned manifest.
func (s *Snapshot) Inspect(ctx context.Context, _ InspectOptions) (InspectResult, error) {
	if err := s.toolReady(ctx); err != nil {
		return InspectResult{}, err
	}
	m := s.Manifest()
	r := InspectResult{ToolMetadata: s.toolMetadata(0, false), TotalFiles: m.TotalFiles,
		TotalBytes: m.TotalBytes, ExcludedCount: len(m.Excluded),
		Exclusions: append([]Exclusion{}, m.Excluded...), BuildFiles: []FileEntry{}}
	sort.Slice(r.Exclusions, func(i, j int) bool {
		if r.Exclusions[i].Path == r.Exclusions[j].Path {
			return r.Exclusions[i].Reason < r.Exclusions[j].Reason
		}
		return r.Exclusions[i].Path < r.Exclusions[j].Path
	})
	extensions, directories := map[string]int{}, map[string]int{}
	for _, e := range s.toolEntries("") {
		if err := contextOK(ctx); err != nil {
			return InspectResult{}, err
		}
		ext := strings.ToLower(path.Ext(e.Path))
		if ext == "" {
			ext = "(none)"
		}
		extensions[ext]++
		dir := "."
		if n := strings.IndexByte(e.Path, '/'); n >= 0 {
			dir = e.Path[:n]
		}
		directories[dir]++
		if toolBuildFile(path.Base(e.Path)) {
			r.BuildFiles = append(r.BuildFiles, e)
		}
	}
	r.Extensions, r.Directories = toolCounts(extensions), toolCounts(directories)
	if len(r.Exclusions) > MaxToolLimit {
		r.Exclusions = r.Exclusions[:MaxToolLimit]
	}
	if len(r.Extensions) > MaxToolLimit {
		r.Extensions = r.Extensions[:MaxToolLimit]
		r.omit("inspection_limit")
	}
	if len(r.Directories) > MaxToolLimit {
		r.Directories = r.Directories[:MaxToolLimit]
		r.omit("inspection_limit")
	}
	if len(r.BuildFiles) > MaxToolLimit {
		r.BuildFiles = r.BuildFiles[:MaxToolLimit]
		r.omit("inspection_limit")
	}
	// Bound even unusually long manifest paths/reasons, not merely entry counts.
	for !toolResponseFits(r) {
		switch {
		case len(r.Exclusions) > 0:
			r.Exclusions = r.Exclusions[:len(r.Exclusions)-1]
		case len(r.BuildFiles) > 0:
			r.BuildFiles = r.BuildFiles[:len(r.BuildFiles)-1]
		case len(r.Directories) > 0:
			r.Directories = r.Directories[:len(r.Directories)-1]
		case len(r.Extensions) > 0:
			r.Extensions = r.Extensions[:len(r.Extensions)-1]
		default:
			return InspectResult{}, fmt.Errorf("%w: inspection metadata exceeds response limit", ErrToolOptions)
		}
		r.omit("response_bytes")
	}
	r.ExclusionsTruncated = len(r.Exclusions) < r.ExcludedCount
	if r.ExclusionsTruncated {
		r.omit("inspection_limit")
	}
	return r, nil
}

func (s *Snapshot) List(ctx context.Context, opts ListOptions) (ListResult, error) {
	limit, err := toolLimit(opts.Limit)
	if err != nil {
		return ListResult{}, err
	}
	prefix, err := toolPrefix(opts.Prefix)
	if err != nil {
		return ListResult{}, err
	}
	if err := s.toolReady(ctx); err != nil {
		return ListResult{}, err
	}
	entries := s.toolEntries(prefix)
	binding := s.toolBinding("list", prefix, "", "", limit)
	position := toolPosition{}
	if opts.Cursor != "" {
		position, err = toolDecodeCursor(opts.Cursor, binding)
		if err != nil || position.File >= len(entries) || position.Line != 0 || position.Origin != 0 {
			return ListResult{}, ErrToolCursor
		}
	}
	r := ListResult{ToolMetadata: s.toolMetadata(limit, false), Entries: []FileEntry{}, Total: len(entries)}
	i := position.File
	for ; i < len(entries) && len(r.Entries) < limit; i++ {
		if err := contextOK(ctx); err != nil {
			return ListResult{}, err
		}
		r.Entries = append(r.Entries, entries[i])
		if !toolResponseFits(r) {
			r.Entries = r.Entries[:len(r.Entries)-1]
			r.omit("response_bytes")
			break
		}
	}
	if i < len(entries) {
		if len(r.Entries) == 0 {
			return ListResult{}, fmt.Errorf("%w: manifest entry exceeds response limit", ErrToolOptions)
		}
		r.continueAt(binding, toolPosition{File: i})
	}
	return r, nil
}

// [03] ReadFile is the sole content access boundary. In particular, do not open
// manifest paths with os.ReadFile: every invocation must recheck size and SHA256.
func (s *Snapshot) Read(ctx context.Context, opts ReadOptions) (ReadResult, error) {
	if err := s.toolReady(ctx); err != nil {
		return ReadResult{}, err
	}
	limit, err := toolLimit(opts.Limit)
	if err != nil {
		return ReadResult{}, err
	}
	if err := toolPath(opts.Path); err != nil {
		return ReadResult{}, err
	}
	if opts.StartLine < 0 || (opts.Cursor != "" && opts.StartLine != 0) {
		return ReadResult{}, fmt.Errorf("%w: start_line and cursor are mutually exclusive", ErrToolOptions)
	}
	binding := s.toolBinding("read", "", opts.Path, "", limit)
	position := toolPosition{}
	if opts.Cursor != "" {
		position, err = toolDecodeCursor(opts.Cursor, binding)
		if err != nil || position.File != 0 || position.Origin > position.Line {
			return ReadResult{}, ErrToolCursor
		}
	} else if opts.StartLine > 0 {
		position.Line, position.Origin = opts.StartLine-1, opts.StartLine-1
	}
	entry, ok := s.toolEntry(opts.Path)
	if !ok {
		// Preserve the safe reader's not-found/path/closed error semantics.
		_, err := s.ReadFile(ctx, opts.Path)
		if err == nil {
			err = fmt.Errorf("%w: file absent from manifest", ErrToolOptions)
		}
		return ReadResult{}, err
	}
	data, err := s.ReadFile(ctx, opts.Path)
	if err != nil {
		return ReadResult{}, err
	}
	r := ReadResult{ToolMetadata: s.toolMetadata(limit, true), Path: entry.Path, Size: entry.Size,
		SHA256: entry.SHA256, UTF8: utf8.Valid(data), StartLine: position.Line + 1, Lines: []SourceLine{}}
	r.Binary = !r.UTF8 || bytes.IndexByte(data, 0) >= 0
	if r.Binary {
		if opts.Cursor != "" || position.Line != 0 {
			return ReadResult{}, fmt.Errorf("%w: binary files have no source line positions", ErrToolOptions)
		}
		r.omit("binary_file")
		return r, nil
	}
	r.TotalLines = toolLineCount(data)
	if position.Line > r.TotalLines || (opts.Cursor != "" && position.Line >= r.TotalLines) {
		return ReadResult{}, fmt.Errorf("%w: line position outside file", ErrToolCursor)
	}
	if r.TotalLines != 0 && position.Line == r.TotalLines {
		return ReadResult{}, fmt.Errorf("%w: start_line outside file", ErrToolOptions)
	}
	if r.TotalLines == 0 && position.Line != 0 {
		return ReadResult{}, fmt.Errorf("%w: start_line outside empty file", ErrToolOptions)
	}
	offset := toolLineOffset(data, position.Line)
	line := position.Line
	for line < r.TotalLines && len(r.Lines) < limit {
		if err := contextOK(ctx); err != nil {
			return ReadResult{}, err
		}
		text, next := toolNextLine(data, offset)
		clipped, truncated := toolClip(text)
		r.Lines = append(r.Lines, SourceLine{Number: line + 1, Text: clipped, Truncated: truncated, Bytes: len(text)})
		if !toolResponseFits(r) {
			r.Lines = r.Lines[:len(r.Lines)-1]
			r.omit("response_bytes")
			break
		}
		if truncated {
			r.omit("line_bytes")
		}
		line++
		offset = next
	}
	if len(r.Lines) > 0 {
		r.EndLine = r.Lines[len(r.Lines)-1].Number
	}
	if line < r.TotalLines {
		if len(r.Lines) == 0 {
			return ReadResult{}, fmt.Errorf("%w: source line exceeds response limit", ErrToolOptions)
		}
		r.continueAt(binding, toolPosition{Line: line, Origin: position.Origin})
	}
	return r, nil
}

// [04] Search is a case-sensitive, single-line literal search, one match per
// matching line. Cursors resume after the returned line, never from file zero.
// Scanned counters are per invocation, not cumulative audit-coverage claims.
func (s *Snapshot) Search(ctx context.Context, opts SearchOptions) (SearchResult, error) {
	limit, err := toolLimit(opts.Limit)
	if err != nil {
		return SearchResult{}, err
	}
	prefix, err := toolPrefix(opts.Prefix)
	if err != nil {
		return SearchResult{}, err
	}
	if len(opts.Query) == 0 || len(opts.Query) > MaxSearchQueryBytes || !utf8.ValidString(opts.Query) || strings.ContainsAny(opts.Query, "\r\n\x00") {
		return SearchResult{}, fmt.Errorf("%w: query must be a nonempty UTF-8 single-line literal of at most %d bytes", ErrToolOptions, MaxSearchQueryBytes)
	}
	if err := s.toolReady(ctx); err != nil {
		return SearchResult{}, err
	}
	binding := s.toolBinding("search", prefix, "", opts.Query, limit)
	entries := s.toolEntries(prefix)
	position := toolPosition{}
	if opts.Cursor != "" {
		position, err = toolDecodeCursor(opts.Cursor, binding)
		if err != nil || position.File >= len(entries) || position.Origin != 0 {
			return SearchResult{}, ErrToolCursor
		}
	}
	r := SearchResult{ToolMetadata: s.toolMetadata(limit, true), Query: opts.Query, Matches: []SearchMatch{}}
	visited := 0
	for file := position.File; file < len(entries); file++ {
		if err := contextOK(ctx); err != nil {
			return SearchResult{}, err
		}
		start := 0
		if file == position.File {
			start = position.Line
		}
		e := entries[file]
		if visited >= MaxSearchFiles {
			r.omit("search_file_budget")
			r.continueAt(binding, toolPosition{File: file, Line: start})
			return r, nil
		}
		visited++
		if e.Size > MaxSearchBytes {
			if start != 0 {
				return SearchResult{}, ErrToolCursor
			}
			r.SkippedOversized++
			r.omit("oversized_files_skipped")
			continue
		}
		if r.ScannedBytes+e.Size > MaxSearchBytes {
			r.omit("search_byte_budget")
			r.continueAt(binding, toolPosition{File: file, Line: start})
			return r, nil
		}
		data, err := s.ReadFile(ctx, e.Path)
		if err != nil {
			return SearchResult{}, err // Never turn integrity errors into silent skips or matches.
		}
		r.ScannedFiles++
		r.ScannedBytes += int64(len(data))
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			if start != 0 {
				return SearchResult{}, ErrToolCursor
			}
			r.SkippedBinary++
			r.omit("binary_files_skipped")
			continue
		}
		total := toolLineCount(data)
		if start > total || (start > 0 && start == total) {
			return SearchResult{}, ErrToolCursor
		}
		offset := toolLineOffset(data, start)
		for line := start; line < total; line++ {
			if err := contextOK(ctx); err != nil {
				return SearchResult{}, err
			}
			text, next := toolNextLine(data, offset)
			offset = next
			column := bytes.Index(text, []byte(opts.Query))
			if column < 0 {
				continue
			}
			clipped, truncated := toolClip(text)
			r.Matches = append(r.Matches, SearchMatch{Path: e.Path, SHA256: e.SHA256, Line: line + 1,
				Column: utf8.RuneCount(text[:column]) + 1, Text: clipped, Truncated: truncated, LineBytes: len(text)})
			if !toolResponseFits(r) {
				r.Matches = r.Matches[:len(r.Matches)-1]
				if len(r.Matches) == 0 {
					return SearchResult{}, fmt.Errorf("%w: search match exceeds response limit", ErrToolOptions)
				}
				r.omit("response_bytes")
				r.continueAt(binding, toolPosition{File: file, Line: line})
				return r, nil
			}
			if truncated {
				r.omit("line_bytes")
			}
			if len(r.Matches) == limit {
				if line+1 < total {
					r.continueAt(binding, toolPosition{File: file, Line: line + 1})
				} else if file+1 < len(entries) {
					r.continueAt(binding, toolPosition{File: file + 1})
				}
				return r, nil
			}
		}
	}
	return r, nil
}

func (s *Snapshot) toolReady(ctx context.Context) error {
	if err := contextOK(ctx); err != nil {
		return err
	}
	if s == nil {
		return os.ErrClosed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.root == nil {
		return os.ErrClosed
	}
	return nil
}

func (s *Snapshot) toolMetadata(limit int, content bool) ToolMetadata {
	r := ToolMetadata{SnapshotHash: s.Hash(), Verification: "manifest_only", Reasons: []string{},
		Limits: ToolLimits{Limit: limit, MaxLimit: MaxToolLimit, MaxResponseBytes: MaxToolResponseBytes,
			MaxLineBytes: MaxToolLineBytes, MaxSearchFiles: MaxSearchFiles, MaxSearchBytes: MaxSearchBytes, MaxQueryBytes: MaxSearchQueryBytes}}
	if content {
		r.Verification = "content_sha256"
	}
	if s.Manifest().Partial {
		r.omit("snapshot_exclusions")
	}
	return r
}

func (r *ToolMetadata) omit(reason string) {
	r.Partial = true
	for _, old := range r.Reasons {
		if old == reason {
			return
		}
	}
	r.Reasons = append(r.Reasons, reason)
}

func toolLimit(n int) (int, error) {
	if n == 0 {
		return DefaultToolLimit, nil
	}
	if n < 0 || n > MaxToolLimit {
		return 0, fmt.Errorf("%w: limit must be between 1 and %d", ErrToolOptions, MaxToolLimit)
	}
	return n, nil
}

func toolPath(p string) error {
	if err := validateRelative(p); err != nil {
		return fmt.Errorf("%w: %w", ErrToolOptions, err)
	}
	return nil
}

func toolPrefix(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	p = strings.TrimSuffix(p, "/")
	return p, toolPath(p)
}

func (s *Snapshot) toolEntries(prefix string) []FileEntry {
	entries := []FileEntry{}
	for _, e := range s.Manifest().Entries {
		if prefix == "" || e.Path == prefix || strings.HasPrefix(e.Path, prefix+"/") {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}

func (s *Snapshot) toolEntry(p string) (FileEntry, bool) {
	for _, e := range s.Manifest().Entries {
		if e.Path == p {
			return e, true
		}
	}
	return FileEntry{}, false
}

func toolResponseFits(v any) bool {
	b, err := json.Marshal(v)
	return err == nil && len(b) <= MaxToolResponseBytes-toolResponseReserve
}

func toolLineCount(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

func toolLineOffset(data []byte, line int) int {
	offset := 0
	for i := 0; i < line; i++ {
		n := bytes.IndexByte(data[offset:], '\n')
		if n < 0 {
			return len(data)
		}
		offset += n + 1
	}
	return offset
}

func toolNextLine(data []byte, offset int) ([]byte, int) {
	end := len(data)
	next := end
	if n := bytes.IndexByte(data[offset:], '\n'); n >= 0 {
		end, next = offset+n, offset+n+1
	}
	text := data[offset:end]
	if next > end && len(text) > 0 && text[len(text)-1] == '\r' {
		text = text[:len(text)-1]
	}
	return text, next
}

func toolClip(data []byte) (string, bool) {
	if len(data) <= MaxToolLineBytes {
		return string(data), false
	}
	n := MaxToolLineBytes
	for n > 0 && !utf8.RuneStart(data[n]) {
		n--
	}
	return string(data[:n]), true
}

func toolCounts(m map[string]int) []PathCount {
	r := make([]PathCount, 0, len(m))
	for name, count := range m {
		r = append(r, PathCount{Name: name, Count: count})
	}
	sort.Slice(r, func(i, j int) bool { return r[i].Name < r[j].Name })
	return r
}

func toolBuildFile(name string) bool {
	switch name {
	case "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
		"go.mod", "Cargo.toml", "package.json", "pyproject.toml", "setup.py", "setup.cfg",
		"requirements.txt", "Gemfile", "composer.json", "Makefile", "CMakeLists.txt", "Dockerfile":
		return true
	}
	return false
}

// [05] A cursor is a bounded continuation record, NOT a MAC or an authorization
// token. SHA256 detects accidental edits and binds options across CLI processes;
// every decoded offset is range-checked and content still passes ReadFile.
type toolPosition struct {
	File   int `json:"file"`
	Line   int `json:"line"`
	Origin int `json:"origin"`
}

type toolCursor struct {
	Version int          `json:"version"`
	Binding string       `json:"binding"`
	At      toolPosition `json:"at"`
	Digest  string       `json:"digest"`
}

func (s *Snapshot) toolBinding(method, prefix, file, query string, limit int) string {
	b, _ := json.Marshal([]any{1, s.Hash(), method, prefix, file, query, limit})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func toolCursorDigest(c toolCursor) string {
	c.Digest = ""
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (r *ToolMetadata) continueAt(binding string, at toolPosition) {
	c := toolCursor{Version: 1, Binding: binding, At: at}
	c.Digest = toolCursorDigest(c)
	b, _ := json.Marshal(c)
	r.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	r.omit("pagination")
}

func toolDecodeCursor(token, binding string) (toolPosition, error) {
	if len(token) > 2048 {
		return toolPosition{}, ErrToolCursor
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return toolPosition{}, ErrToolCursor
	}
	var c toolCursor
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return toolPosition{}, ErrToolCursor
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return toolPosition{}, ErrToolCursor
	}
	if c.Version != 1 || c.Binding != binding || c.Digest != toolCursorDigest(c) ||
		c.At.File < 0 || c.At.Line < 0 || c.At.Origin < 0 {
		return toolPosition{}, ErrToolCursor
	}
	return c.At, nil
}
