package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"trident/internal/project"
)

// runProject 仅接收显式目录，不把读取许可扩展为外发、执行或修改原目录许可。
func runProject(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident project <import|inspect|list|read|search> --snapshot <dir>; queries also require --snapshot-hash <sha256>")
	}
	command := args[0]
	switch command {
	case "import", "inspect", "list", "read", "search":
	default:
		return fmt.Errorf("unknown project command %q", command)
	}
	flags := flag.NewFlagSet("project "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	snapshotDir := flags.String("snapshot", "", "new snapshot directory for import, existing directory for queries")
	var sourceDir, expectedHash, path, query, prefix, cursor string
	var limit, startLine int
	if command == "import" {
		flags.StringVar(&sourceDir, "source", "", "explicitly permitted local source directory")
	} else {
		flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	}
	if command == "list" || command == "read" || command == "search" {
		flags.IntVar(&limit, "limit", 50, "page size (1 to 200)")
		flags.StringVar(&cursor, "cursor", "", "continuation cursor for the same snapshot and query")
	}
	if command == "read" {
		flags.StringVar(&path, "path", "", "canonical relative source path using slash separators")
		flags.IntVar(&startLine, "start-line", 0, "first line (default 1); cannot be combined with cursor")
	}
	if command == "list" || command == "search" {
		flags.StringVar(&prefix, "prefix", "", "optional relative path prefix")
	}
	if command == "search" {
		flags.StringVar(&query, "query", "", "case-sensitive literal text (1 to 256 bytes)")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("invalid project arguments: %w", err)
	}
	if flags.NArg() != 0 || *snapshotDir == "" {
		return fmt.Errorf("project command requires --snapshot and no positional arguments")
	}
	if command == "import" {
		if sourceDir == "" {
			return fmt.Errorf("project import requires --source and a new --snapshot directory")
		}
		result, err := project.Import(ctx, sourceDir, *snapshotDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			SchemaVersion int              `json:"schema_version"`
			SnapshotHash  string           `json:"snapshot_hash"`
			Manifest      project.Manifest `json:"manifest"`
		}{1, result.Hash, result.Manifest})
	}
	// [01] 预期摘要必须由调用方提供，不能从同目录的可替换 hash 文件自证完整性。
	if expectedHash == "" {
		return fmt.Errorf("project query requires --snapshot-hash from a trusted record outside the snapshot")
	}
	if (command == "list" || command == "read" || command == "search") && (limit < 1 || limit > 200) {
		return fmt.Errorf("limit must be between 1 and 200")
	}
	if command == "read" && (path == "" || startLine < 0 || (cursor != "" && startLine != 0)) {
		return fmt.Errorf("read requires --path; --start-line must be positive and cannot be combined with --cursor")
	}
	if command == "search" && (len(query) == 0 || len(query) > 256) {
		return fmt.Errorf("search requires --query containing 1 to 256 bytes")
	}
	snapshot, err := project.Open(ctx, *snapshotDir, expectedHash)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	var result any
	switch command {
	case "inspect":
		result, err = snapshot.Inspect(ctx, project.InspectOptions{})
	case "list":
		result, err = snapshot.List(ctx, project.ListOptions{Prefix: prefix, Limit: limit, Cursor: cursor})
	case "read":
		result, err = snapshot.Read(ctx, project.ReadOptions{Path: path, StartLine: startLine, Limit: limit, Cursor: cursor})
	case "search":
		result, err = snapshot.Search(ctx, project.SearchOptions{Query: query, Prefix: prefix, Limit: limit, Cursor: cursor})
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
