package webui

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Session exchange throttling. The custom request header stops cross-origin
// browsers, but a local script can still post unlimited token guesses; this
// counter is the bound. It is per client host and per process: a restart
// clears it, which is acceptable for a loopback console.
const (
	sessionFailureLimit  = 5
	sessionFailureWindow = time.Minute
	sessionLockout       = 30 * time.Second
)

type sessionAttempt struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

type sessionLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]sessionAttempt
}

func newSessionLimiter() *sessionLimiter {
	return &sessionLimiter{now: time.Now, entries: map[string]sessionAttempt{}}
}

// retryAfter returns zero when the client may try, or the remaining lockout.
func (l *sessionLimiter) retryAfter(key string) time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt, ok := l.entries[key]
	if !ok {
		return 0
	}
	now := l.now()
	if attempt.lockedUntil.After(now) {
		return attempt.lockedUntil.Sub(now)
	}
	return 0
}

func (l *sessionLimiter) fail(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	attempt := l.entries[key]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) > sessionFailureWindow {
		attempt = sessionAttempt{windowStart: now}
	}
	attempt.failures++
	if attempt.failures >= sessionFailureLimit {
		attempt.lockedUntil = now.Add(sessionLockout)
	}
	l.entries[key] = attempt
}

func (l *sessionLimiter) reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// sessionClientKey groups attempts by host, ignoring the ephemeral source port.
func sessionClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return "unknown"
	}
	return host
}
