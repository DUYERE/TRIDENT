package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trident/internal/domain"
)

func TestSessionLimiterLocksAfterRepeatedFailures(t *testing.T) {
	limiter := newSessionLimiter()
	clock := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return clock }
	for i := 0; i < sessionFailureLimit-1; i++ {
		if wait := limiter.retryAfter("127.0.0.1"); wait != 0 {
			t.Fatalf("locked too early at attempt %d: %v", i+1, wait)
		}
		limiter.fail("127.0.0.1")
	}
	if wait := limiter.retryAfter("127.0.0.1"); wait != 0 {
		t.Fatalf("locked before the limit: %v", wait)
	}
	limiter.fail("127.0.0.1")
	if wait := limiter.retryAfter("127.0.0.1"); wait <= 0 || wait > sessionLockout {
		t.Fatalf("limit not enforced: %v", wait)
	}
	if wait := limiter.retryAfter("10.0.0.9"); wait != 0 {
		t.Fatalf("lockout leaked to another client: %v", wait)
	}
	clock = clock.Add(sessionLockout + time.Second)
	if wait := limiter.retryAfter("127.0.0.1"); wait != 0 {
		t.Fatalf("lockout did not expire: %v", wait)
	}
}

func TestSessionLimiterResetsOnSuccess(t *testing.T) {
	limiter := newSessionLimiter()
	for i := 0; i < sessionFailureLimit-1; i++ {
		limiter.fail("127.0.0.1")
	}
	limiter.reset("127.0.0.1")
	for i := 0; i < sessionFailureLimit-1; i++ {
		if wait := limiter.retryAfter("127.0.0.1"); wait != 0 {
			t.Fatalf("successful login did not clear failures: %v", wait)
		}
		limiter.fail("127.0.0.1")
	}
}

// The endpoint must stop accepting guesses once the limit is reached, even for
// a correct token: guessing is bounded, not just penalised after the fact.
func TestSessionEndpointRateLimitsFailures(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	post := func(token string) *http.Response {
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/session",
			strings.NewReader(`{"token":"`+token+`"}`))
		request.Header.Set(RequestHeader, "console")
		request.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response
	}
	for i := 0; i < sessionFailureLimit; i++ {
		if response := post("wrong-token-0123456789"); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, response.StatusCode)
		}
	}
	response := post(console.Token())
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("correct token accepted while locked out: %d", response.StatusCode)
	}
	if response.Header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
}

func TestSteerAllowedState(t *testing.T) {
	for _, state := range []domain.OrchestrationState{domain.OrchestrationCreated, domain.OrchestrationRunning} {
		if !steerAllowedState(state) {
			t.Fatalf("%s must accept steering", state)
		}
	}
	for _, state := range []domain.OrchestrationState{
		domain.OrchestrationCompleted, domain.OrchestrationCancelled, domain.OrchestrationFailed,
	} {
		if steerAllowedState(state) {
			t.Fatalf("%s must reject steering", state)
		}
	}
}
