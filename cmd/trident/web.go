package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"trident/internal/webui"
)

const webUsage = "usage: trident web --snapshot <dir> --snapshot-hash <sha256> [--advisories <file>] [--addr 127.0.0.1:8787] [--token <value> | --tokens <file>] [--access-log <file>]"

// runWeb starts the read-only analysis console. It does not connect to the
// database, call a model or expose any execution/control route.
func runWeb(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("web", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var snapshotDir, expectedHash, advisoryPath, addr, token, tokensFile, accessLog string
	flags.StringVar(&snapshotDir, "snapshot", "", "existing trusted snapshot directory")
	flags.StringVar(&expectedHash, "snapshot-hash", "", "trusted SHA-256 returned by import; keep outside snapshot")
	flags.StringVar(&advisoryPath, "advisories", "", "optional explicit local advisory catalog JSON")
	flags.StringVar(&addr, "addr", "127.0.0.1:8787", "loopback listen address")
	flags.StringVar(&token, "token", "", "single access token; generated when omitted")
	flags.StringVar(&tokensFile, "tokens", "", "multi-user token file JSON [{id, role, token_hash=sha256(token) hex}]")
	flags.StringVar(&accessLog, "access-log", "", "append-only JSONL access log path; token values are never recorded")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("invalid web arguments: %w", err)
	}
	if flags.NArg() != 0 || snapshotDir == "" || expectedHash == "" {
		return fmt.Errorf("%s", webUsage)
	}
	listenAddr, err := validateLoopbackAddr(addr)
	if err != nil {
		return err
	}
	console, err := webui.New(ctx, webui.Options{SnapshotDir: snapshotDir, SnapshotHash: expectedHash, AdvisoryPath: advisoryPath, Token: token, TokensFile: tokensFile, AccessLog: accessLog, Version: productVersion})
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
	fmt.Fprintf(out, "TRIDENT read-only console: http://%s\n", listener.Addr().String())
	if console.MultiToken() {
		fmt.Fprintf(out, "Token file: %s (users: %s; tokens stored as SHA-256 hashes)\n", tokensFile, strings.Join(console.TokenIDs(), ", "))
	} else {
		fmt.Fprintf(out, "Access token (required): %s\n", console.Token())
	}
	if accessLog != "" {
		fmt.Fprintf(out, "Access log: %s (JSONL: time, token_id, method, path, status; no token values)\n", accessLog)
	}
	fmt.Fprintln(out, "Static evidence only: no model call, no Java/Maven execution, no runtime control API.")
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
