// Package r3 creates isolated writable copies of a pinned snapshot, applies
// caller-supplied unified diffs, and runs bounded validation commands. It never
// writes the original snapshot and does not claim OS-level sandboxing.
package r3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxPatchBytes = 1 << 20
	MaxPatchFiles = 100
	MaxFileBytes  = 2 << 20
)

type FileChange struct {
	Path         string `json:"path"`
	Additions    int    `json:"additions"`
	Deletions    int    `json:"deletions"`
	SHA256Before string `json:"sha256_before"`
	SHA256After  string `json:"sha256_after"`
}

type PatchResult struct {
	SHA256 string       `json:"sha256"`
	Files  []FileChange `json:"files_changed"`
}

type hunkLine struct {
	kind byte
	text string
}

type hunk struct {
	oldStart int
	oldCount int
	newStart int
	newCount int
	lines    []hunkLine
}

type filePatch struct {
	path  string
	hunks []hunk
}

// Apply validates and applies one or more text-only unified diffs to files that
// already exist inside the workspace. Context must match exactly; there is no
// fuzz factor, binary patch, rename, creation or deletion support.
func Apply(workspace string, patch []byte) (PatchResult, error) {
	sum := sha256.Sum256(patch)
	result := PatchResult{SHA256: hex.EncodeToString(sum[:]), Files: []FileChange{}}
	if len(patch) == 0 || len(patch) > MaxPatchBytes {
		return result, fmt.Errorf("patch must contain 1 to %d bytes", MaxPatchBytes)
	}
	if !utf8.Valid(patch) {
		return result, fmt.Errorf("patch is not valid UTF-8")
	}
	patches, err := parsePatch(string(patch))
	if err != nil {
		return result, err
	}
	if len(patches) == 0 || len(patches) > MaxPatchFiles {
		return result, fmt.Errorf("patch must touch 1 to %d files", MaxPatchFiles)
	}
	seen := map[string]bool{}
	for _, file := range patches {
		if seen[file.path] {
			return result, fmt.Errorf("duplicate patch path %q", file.path)
		}
		seen[file.path] = true
	}
	root, err := filepath.Abs(workspace)
	if err != nil {
		return result, err
	}
	if info, statErr := os.Stat(root); statErr != nil || !info.IsDir() {
		return result, fmt.Errorf("workspace does not exist or is not a directory")
	}
	for _, file := range patches {
		change, applyErr := applyFile(root, file)
		if applyErr != nil {
			return result, applyErr
		}
		result.Files = append(result.Files, change)
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	return result, nil
}

func parsePatch(content string) ([]filePatch, error) {
	lines := strings.Split(content, "\n")
	var patches []filePatch
	for i := 0; i < len(lines); {
		line := strings.TrimSuffix(lines[i], "\r")
		switch {
		case strings.HasPrefix(line, "--- "):
			if i+1 >= len(lines) || !strings.HasPrefix(strings.TrimSuffix(lines[i+1], "\r"), "+++ ") {
				return nil, fmt.Errorf("patch header without +++ line")
			}
			oldPath, err := patchPath(strings.TrimPrefix(line, "--- "))
			if err != nil {
				return nil, err
			}
			newPath, err := patchPath(strings.TrimPrefix(strings.TrimSuffix(lines[i+1], "\r"), "+++ "))
			if err != nil {
				return nil, err
			}
			if oldPath != newPath {
				return nil, fmt.Errorf("rename, creation and deletion patches are not supported")
			}
			i += 2
			file := filePatch{path: oldPath}
			for i < len(lines) && strings.HasPrefix(strings.TrimSuffix(lines[i], "\r"), "@@") {
				parsed, next, err := parseHunk(lines, i)
				if err != nil {
					return nil, err
				}
				file.hunks = append(file.hunks, parsed)
				i = next
			}
			if len(file.hunks) == 0 {
				return nil, fmt.Errorf("file %q has no hunks", file.path)
			}
			patches = append(patches, file)
		case line == "" || strings.HasPrefix(line, "diff --git ") || strings.HasPrefix(line, "index ") ||
			strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "deleted file mode ") ||
			strings.HasPrefix(line, "similarity index ") || strings.HasPrefix(line, "rename from ") ||
			strings.HasPrefix(line, "rename to "):
			i++
		default:
			return nil, fmt.Errorf("unsupported patch line %q", line)
		}
	}
	return patches, nil
}

var hunkHeaderPattern = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@`)

func parseHunk(lines []string, start int) (hunk, int, error) {
	header := strings.TrimSuffix(lines[start], "\r")
	match := hunkHeaderPattern.FindStringSubmatch(header)
	if match == nil {
		return hunk{}, start, fmt.Errorf("invalid hunk header %q", header)
	}
	oldStart, _ := strconv.Atoi(match[1])
	oldCount, newStart, newCount := 1, 0, 1
	if match[2] != "" {
		oldCount, _ = strconv.Atoi(match[2])
	}
	newStart, _ = strconv.Atoi(match[3])
	if match[4] != "" {
		newCount, _ = strconv.Atoi(match[4])
	}
	if oldStart < 0 || newStart < 0 || oldCount < 0 || newCount < 0 || oldCount > 10000 || newCount > 10000 {
		return hunk{}, start, fmt.Errorf("invalid hunk range")
	}
	current := hunk{oldStart: oldStart, oldCount: oldCount, newStart: newStart, newCount: newCount}
	seenOld, seenNew := 0, 0
	i := start + 1
	for i < len(lines) {
		line := strings.TrimSuffix(lines[i], "\r")
		if strings.HasPrefix(line, "@@") {
			break
		}
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "\\ No newline at end of file") {
			i++
			continue
		}
		kind := line[0]
		if kind != ' ' && kind != '+' && kind != '-' {
			return hunk{}, start, fmt.Errorf("invalid hunk line %q", line)
		}
		current.lines = append(current.lines, hunkLine{kind: kind, text: line[1:]})
		switch kind {
		case ' ':
			seenOld++
			seenNew++
		case '+':
			seenNew++
		case '-':
			seenOld++
		}
		i++
	}
	if seenOld != oldCount || seenNew != newCount {
		return hunk{}, start, fmt.Errorf("hunk line counts do not match header")
	}
	return current, i, nil
}

func patchPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if tab := strings.IndexByte(value, '\t'); tab >= 0 {
		value = value[:tab]
	}
	if strings.HasPrefix(value, "a/") || strings.HasPrefix(value, "b/") {
		value = value[2:]
	}
	if value == "/dev/null" {
		return "", fmt.Errorf("creation and deletion patches are not supported")
	}
	if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\\:\x00\"'") ||
		strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.HasPrefix(value, "../") {
		return "", fmt.Errorf("unsafe patch path %q", value)
	}
	return value, nil
}

func applyFile(root string, file filePatch) (FileChange, error) {
	target, err := safeWorkspacePath(root, file.path)
	if err != nil {
		return FileChange{}, err
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		return FileChange{}, fmt.Errorf("patch target %q is not an existing regular file", file.path)
	}
	before, err := os.ReadFile(target)
	if err != nil {
		return FileChange{}, err
	}
	if len(before) > MaxFileBytes || !utf8.Valid(before) || strings.IndexByte(string(before), 0) >= 0 {
		return FileChange{}, fmt.Errorf("patch target %q is not a bounded UTF-8 text file", file.path)
	}
	lines := strings.Split(string(before), "\n")
	var out []string
	cursor := 0
	additions, deletions := 0, 0
	for _, current := range file.hunks {
		start := current.oldStart - 1
		if current.oldCount == 0 {
			start = current.oldStart
		}
		if start < cursor || start > len(lines) {
			return FileChange{}, fmt.Errorf("overlapping or out-of-range hunk in %q", file.path)
		}
		out = append(out, lines[cursor:start]...)
		index := start
		for _, line := range current.lines {
			switch line.kind {
			case ' ':
				if index >= len(lines) || lines[index] != line.text {
					return FileChange{}, fmt.Errorf("context mismatch in %q at line %d", file.path, index+1)
				}
				out = append(out, lines[index])
				index++
			case '-':
				if index >= len(lines) || lines[index] != line.text {
					return FileChange{}, fmt.Errorf("removal mismatch in %q at line %d", file.path, index+1)
				}
				index++
				deletions++
			case '+':
				out = append(out, line.text)
				additions++
			}
		}
		cursor = index
	}
	out = append(out, lines[cursor:]...)
	after := []byte(strings.Join(out, "\n"))
	if len(after) > MaxFileBytes {
		return FileChange{}, fmt.Errorf("patched file %q exceeds size budget", file.path)
	}
	if err = writePatchFile(root, file.path, after); err != nil {
		return FileChange{}, err
	}
	beforeSum := sha256.Sum256(before)
	afterSum := sha256.Sum256(after)
	return FileChange{
		Path: file.path, Additions: additions, Deletions: deletions,
		SHA256Before: hex.EncodeToString(beforeSum[:]), SHA256After: hex.EncodeToString(afterSum[:]),
	}, nil
}

func safeWorkspacePath(root, relative string) (string, error) {
	full := filepath.Join(root, filepath.FromSlash(relative))
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("patch path escapes the workspace")
	}
	return full, nil
}

func writePatchFile(root, relative string, content []byte) error {
	target, err := safeWorkspacePath(root, relative)
	if err != nil {
		return err
	}
	dir := filepath.Dir(target)
	temp, err := os.CreateTemp(dir, ".trident-patch-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, target)
}
