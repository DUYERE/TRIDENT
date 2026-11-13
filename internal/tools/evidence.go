package tools

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"trident/internal/project"
)

// Evidence cites inclusive, one-based source lines, not manifest-only path clues.
// Partial pages can supply evidence, but truncated lines cannot. Evidence does
// not assert that a file, project, or vulnerability was exhaustively examined.
type Evidence struct {
	SnapshotHash string `json:"snapshot_hash"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
}

type evidenceFile struct {
	snapshotHash string
	path         string
	sha256       string
}

type lineRange struct{ start, end int }

// [01] ExtractEvidence is a pure parser, NOT an authenticity check on supplied
// JSON. ValidateEvidence uses only results of this registry's own Execute calls;
// passing fabricated JSON here never grants evidence to a registry.
func ExtractEvidence(toolName string, result json.RawMessage) ([]Evidence, error) {
	evidence := []Evidence{}
	switch toolName {
	case "inspect_project", "list_files":
		return evidence, nil // Metadata never establishes that source was seen.
	case "read_source":
		var r project.ReadResult
		if err := decodeResult(result, &r); err != nil {
			return nil, err
		}
		if !validContentMetadata(r.ToolMetadata) || !validEvidencePath(r.Path) || !validDigest(r.SHA256) ||
			r.TotalLines < 0 || len(r.Lines) > project.MaxToolLimit {
			return nil, fmt.Errorf("%w: invalid read metadata", ErrEvidence)
		}
		if len(r.Lines) == 0 {
			return evidence, nil
		}
		if r.Binary || !r.UTF8 || r.StartLine < 1 || r.EndLine < r.StartLine ||
			r.EndLine > r.TotalLines || r.EndLine-r.StartLine != len(r.Lines)-1 {
			return nil, fmt.Errorf("%w: invalid read line range", ErrEvidence)
		}
		for i, line := range r.Lines {
			if line.Number != r.StartLine+i {
				return nil, fmt.Errorf("%w: noncontiguous read lines", ErrEvidence)
			}
			if line.Truncated {
				continue
			}
			e := Evidence{SnapshotHash: r.SnapshotHash, Path: r.Path, SHA256: r.SHA256, StartLine: line.Number, EndLine: line.Number}
			if n := len(evidence); n > 0 && evidence[n-1].EndLine == line.Number-1 {
				evidence[n-1].EndLine = line.Number
			} else {
				evidence = append(evidence, e)
			}
		}
	case "search_source":
		var r project.SearchResult
		if err := decodeResult(result, &r); err != nil {
			return nil, err
		}
		if !validContentMetadata(r.ToolMetadata) || len(r.Matches) > project.MaxToolLimit {
			return nil, fmt.Errorf("%w: invalid search metadata", ErrEvidence)
		}
		for _, match := range r.Matches {
			if !validEvidencePath(match.Path) || !validDigest(match.SHA256) || match.Line < 1 || match.Column < 1 {
				return nil, fmt.Errorf("%w: invalid search location", ErrEvidence)
			}
			if !match.Truncated {
				evidence = append(evidence, Evidence{SnapshotHash: r.SnapshotHash, Path: match.Path,
					SHA256: match.SHA256, StartLine: match.Line, EndLine: match.Line})
			}
		}
	default:
		return nil, ErrUnknownTool
	}
	return evidence, nil
}

func decodeResult(raw json.RawMessage, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(raw) > project.MaxToolResponseBytes || len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(raw) {
		return fmt.Errorf("%w: invalid result JSON or byte budget", ErrEvidence)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("%w: invalid result JSON", ErrEvidence)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%w: trailing result data", ErrEvidence)
	}
	return nil
}

func validContentMetadata(m project.ToolMetadata) bool {
	return validDigest(m.SnapshotHash) && m.Verification == "content_sha256"
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validEvidencePath(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.HasPrefix(value, "../") &&
		!strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\\:\x00") && path.Clean(value) == value
}

// [02] Keep only merged line intervals, never source text or mutable result bytes.
// The key binds snapshot, exact portable path and full-file content SHA256.
func (r *Registry) remember(evidence []Evidence) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.observed == nil {
		r.observed = make(map[evidenceFile][]lineRange)
	}
	changed := make(map[evidenceFile]bool)
	for _, e := range evidence {
		key := evidenceFile{e.SnapshotHash, e.Path, e.SHA256}
		r.observed[key] = append(r.observed[key], lineRange{e.StartLine, e.EndLine})
		changed[key] = true
	}
	for key := range changed {
		ranges := r.observed[key]
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
		merged := ranges[:0]
		for _, next := range ranges {
			if n := len(merged); n > 0 && (next.start <= merged[n-1].end || next.start-1 == merged[n-1].end) {
				if next.end > merged[n-1].end {
					merged[n-1].end = next.end
				}
			} else {
				merged = append(merged, next)
			}
		}
		r.observed[key] = merged
	}
}

// ValidateEvidence accepts subranges and contiguous unions of actual returned
// lines. It never reads a file to "validate" a citation to previously unseen
// content, and never fills gaps between isolated search matches or read pages.
func (r *Registry) ValidateEvidence(e Evidence) error {
	if r == nil || e.StartLine < 1 || e.EndLine < e.StartLine || e.SnapshotHash == "" || e.SnapshotHash != r.SnapshotHash() {
		return ErrEvidence
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, seen := range r.observed[evidenceFile{e.SnapshotHash, e.Path, e.SHA256}] {
		if seen.start <= e.StartLine && e.EndLine <= seen.end {
			return nil
		}
	}
	return ErrEvidence
}
