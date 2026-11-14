package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// accessLogger appends one JSONL line per API/export request. It records the
// audit identity, method, path and status only; token and cookie values are
// never written.
type accessLogger struct {
	mu     sync.Mutex
	file   *os.File
	warnMu sync.Mutex
	warned bool
}

type accessRecord struct {
	Time    string `json:"time"`
	TokenID string `json:"token_id"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
}

func newAccessLogger(path string) (*accessLogger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open access log: %w", err)
	}
	return &accessLogger{file: file}, nil
}

// auditPath reports whether the request path is subject to the audit trail.
func auditPath(path string) bool {
	return len(path) >= 5 && path[:5] == "/api/" || len(path) >= 8 && path[:8] == "/export/"
}

func (l *accessLogger) record(entry TokenEntry, r *http.Request, status int) {
	if l == nil || r == nil {
		return
	}
	record := accessRecord{
		Time:    time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
		TokenID: entry.ID,
		Method:  r.Method,
		Path:    r.URL.Path,
		Status:  status,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	data = append(data, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(data); err != nil {
		l.warnLocked(err)
	}
}

func (l *accessLogger) warnLocked(err error) {
	l.warnMu.Lock()
	defer l.warnMu.Unlock()
	if !l.warned {
		l.warned = true
		fmt.Fprintf(os.Stderr, "TRIDENT web: access log write failed, continuing best-effort: %v\n", err)
	}
}

func (l *accessLogger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// statusRecorder captures the response status for the audit trail without
// changing any header or body behavior.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(payload)
}

// recorded returns the captured status, defaulting to 200 when the handler
// only set headers.
func (w *statusRecorder) recorded() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
