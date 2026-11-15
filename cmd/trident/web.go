package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"trident/internal/webui"
)

const webUsage = "usage: trident web [--workspace <dir>] [--project <dir> | --snapshot <dir> --snapshot-hash <sha256>] [--advisories <file|dir>] [--package-map <file>] [--runtime-report <file>] [--addr 127.0.0.1:8787] [--token <value> | --tokens <file>] [--access-log <file>]"

// webFlags lists the flags that accept a value. It backs the "forgot the --"
// diagnostic: `trident web workspace .trident` stops flag parsing at the first
// positional token and otherwise only prints a generic usage line.
var webFlags = map[string]string{
	"workspace": "--workspace", "project": "--project", "snapshot": "--snapshot",
	"snapshot-hash": "--snapshot-hash", "advisories": "--advisories",
	"package-map": "--package-map", "runtime-report": "--runtime-report",
	"addr": "--addr", "token": "--token", "tokens": "--tokens", "access-log": "--access-log",
}

// explainPositional turns stray arguments into an actionable error. Flag parsing
// stops at the first non-flag token, so a missing dash silently swallows every
// following flag as a positional argument.
func explainPositional(args []string) error {
	quoted := make([]string, 0, len(args))
	hints := make([]string, 0, 2)
	for _, arg := range args {
		quoted = append(quoted, strconv.Quote(arg))
		if flagName, ok := webFlags[strings.TrimLeft(arg, "-")]; ok && !strings.HasPrefix(arg, "-") {
			hints = append(hints, fmt.Sprintf("%s 应该是 %s", strconv.Quote(arg), flagName))
		}
	}
	message := fmt.Sprintf("无法识别的参数：%s", strings.Join(quoted, " "))
	if len(hints) > 0 {
		message += "（" + strings.Join(hints, "；") + "，缺少 --）"
	}
	return fmt.Errorf("%s\n用法：%s", message, webUsage)
}

// runWeb starts the analysis console. It never executes project code, calls a
// model or exposes an execution route; it only reads one pinned snapshot.
//
// One-click mode: `trident web --project <dir>` imports the source into the
// workspace, computes the snapshot digest and serves it, so no second command
// and no hand-written flag file are required.
func runWeb(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("web", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, advisoryPath, addr, token, tokensFile, accessLog, packageMap, runtimeReport, agentDSN, projectSource, workspace string
	var agentToken, agentEndpoint, agentModel, agentKeyEnv string
	var enableAgentChat bool
	flags.StringVar(&projectSource, "project", "", "local source directory to import and serve (one-click mode)")
	flags.StringVar(&workspace, "workspace", "", "console state directory for snapshots and saved configuration; defaults to .trident when --project is used")
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&advisoryPath, "advisories", "", "advisory catalog JSON file, or a directory of catalogs")
	flags.StringVar(&addr, "addr", "127.0.0.1:8787", "loopback listen address")
	flags.StringVar(&token, "token", "", "single access token; generated when omitted")
	flags.StringVar(&tokensFile, "tokens", "", "multi-user token file JSON [{id, role, token_hash=sha256(token) hex}]")
	flags.StringVar(&accessLog, "access-log", "", "append-only JSONL access log path; token values are never recorded")
	flags.StringVar(&packageMap, "package-map", "", "optional JSON map from group:artifact to package prefixes; enables the reachability view")
	flags.StringVar(&runtimeReport, "runtime-report", "", "optional correlation report file from 'runtime http correlate --out'; displayed read-only")
	flags.StringVar(&agentDSN, "agent-dsn", "", "Agent database DSN; enables the Agent runs view (read-only unless chat is enabled)")
	flags.BoolVar(&enableAgentChat, "enable-agent-chat", false, "turn the console into an Agent control plane: the page may create runs and call the model (requires --agent-dsn, --agent-token and a model binding)")
	flags.StringVar(&agentToken, "agent-token", "", "principal token used by the console to create Agent runs; prefer TRIDENT_AGENT_TOKEN")
	flags.StringVar(&agentEndpoint, "agent-endpoint", "", "model API base URL used by chat, for example https://api.deepseek.com/v1")
	flags.StringVar(&agentModel, "agent-model", "", "model identifier used by chat, for example deepseek-v4-pro")
	flags.StringVar(&agentKeyEnv, "agent-key-env", "TRIDENT_MODEL_API_KEY", "environment variable holding the model key; the key is never persisted")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid web arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return explainPositional(flags.Args())
	}
	if workspace == "" && projectSource != "" {
		workspace = ".trident"
	}
	if token != "" {
		// Name the flag and the actual length: "console token must contain 16 to
		// 256 bytes" alone does not tell the user which argument is wrong.
		if len(token) < 16 || len(token) > 256 || strings.ContainsAny(token, "\r\n\x00") {
			example := workspace
			if example == "" {
				example = ".trident"
			}
			return fmt.Errorf("--token 不合法：需要 16–256 字节且不含控制字符，当前 %d 字节。省略 --token 可自动生成，例如：trident web --workspace %s", len(token), example)
		}
	}
	if projectSource != "" && snapshotDir != "" {
		return fmt.Errorf("use either --project or --snapshot, not both")
	}
	if projectSource == "" && (snapshotDir == "" || expectedHash == "") && workspace != "" {
		// Reopen the last imported project so a second start needs one flag. A
		// fresh workspace starts empty on purpose: the project is chosen in the
		// browser instead of being passed on the command line.
		source, dir, hash, err := webui.WorkspaceProject(workspace)
		if err != nil {
			return err
		}
		if dir != "" && hash != "" {
			projectSource, snapshotDir, expectedHash = source, dir, hash
			fmt.Fprintf(out, "Reusing workspace project: %s\n", source)
		}
	}
	if projectSource != "" && snapshotDir == "" {
		dir, hash, err := webui.ImportProject(ctx, workspace, projectSource)
		if err != nil {
			return fmt.Errorf("import project: %w", err)
		}
		snapshotDir, expectedHash = dir, hash
		fmt.Fprintf(out, "Imported source: %s\nSnapshot: %s\nDigest: %s\nWorkspace: %s\n", projectSource, dir, hash, workspace)
	}
	if (snapshotDir == "") != (expectedHash == "") {
		return fmt.Errorf("--snapshot and --snapshot-hash must be supplied together")
	}
	if snapshotDir == "" && workspace == "" {
		return fmt.Errorf("%s", webUsage)
	}
	// Workspace-held defaults remove the remaining manual flags: catalogs in
	// <workspace>/advisories and a map at <workspace>/package-map.json are picked
	// up automatically.
	var advisoryDir string
	if advisoryPath == "" && workspace != "" {
		candidate := filepath.Join(workspace, "advisories")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			advisoryDir = candidate
		}
	}
	if advisoryPath != "" {
		if info, err := os.Stat(advisoryPath); err == nil && info.IsDir() {
			advisoryDir, advisoryPath = advisoryPath, ""
		}
	}
	if packageMap == "" && workspace != "" {
		candidate := filepath.Join(workspace, "package-map.json")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			packageMap = candidate
		}
	}
	listenAddr, err := validateLoopbackAddr(addr)
	if err != nil {
		return err
	}
	console, err := webui.New(ctx, webui.Options{
		SnapshotDir: snapshotDir, SnapshotHash: expectedHash,
		AdvisoryPath: advisoryPath, AdvisoryDir: advisoryDir,
		Token: token, TokensFile: tokensFile, AccessLog: accessLog,
		PackageMap: packageMap, RuntimeReport: runtimeReport, AgentDSN: agentDSN,
		AgentToken:      firstNonEmpty(agentToken, os.Getenv("TRIDENT_AGENT_TOKEN")),
		EnableAgentChat: enableAgentChat, AgentEndpoint: agentEndpoint, AgentModel: agentModel, AgentKeyEnv: agentKeyEnv,
		Workspace: workspace, ProjectSource: projectSource,
		Version: productVersion,
	})
	if err != nil {
		return err
	}
	defer console.Close()
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("console listen failed: %w", err)
	}
	server := &http.Server{
		Handler:           console.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	fmt.Fprintf(out, "TRIDENT console: http://%s\n", listener.Addr().String())
	if console.MultiToken() {
		fmt.Fprintf(out, "Token file: %s (users: %s; tokens stored as SHA-256 hashes)\n", tokensFile, strings.Join(console.TokenIDs(), ", "))
	} else {
		fmt.Fprintf(out, "Access token (required): %s\n", console.Token())
	}
	if accessLog != "" {
		fmt.Fprintf(out, "Access log: %s (JSONL: time, token_id, method, path, status; no token values)\n", accessLog)
	}
	if snapshotDir == "" {
		fmt.Fprintln(out, "No project selected yet: open the console and choose a local source directory under 项目.")
	}
	if enableAgentChat {
		fmt.Fprintf(out, "Agent chat: ENABLED · model %s @ %s · key from %s · one run at a time\n", agentModel, agentEndpoint, agentKeyEnv)
		fmt.Fprintln(out, "Chat sends the current project snapshot and your goal to that model endpoint after you approve it per run.")
	}
	fmt.Fprintln(out, "Snapshot analysis itself never calls a model or executes Java/Maven; only the chat runs do, and only when approved.")
	shutdown := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		case <-shutdown:
		}
	}()
	err = server.Serve(listener)
	close(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// validateLoopbackAddr rejects wildcard or non-loopback listeners so the
// console cannot be exposed to a network by accident.
func validateLoopbackAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || strings.TrimSpace(port) == "" {
		return "", fmt.Errorf("--addr must be a loopback host:port, for example 127.0.0.1:8787")
	}
	if host == "localhost" {
		return addr, nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("--addr must bind a numeric loopback address or localhost")
	}
	return addr, nil
}

// firstNonEmpty returns the first non-empty value so a flag can default to an
// environment variable without hiding which source won.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
