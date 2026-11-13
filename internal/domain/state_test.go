package domain

import (
	"strings"
	"testing"
)

func TestValidateTransitionMatrix(t *testing.T) {
	// [01] 测试独立列出基线边，不从实现矩阵生成期望值，枚举全部状态对。
	cases := []struct {
		kind   string
		states []string
		edges  []string
	}{
		{
			kind:   "task",
			states: []string{"running", "paused", "done", "failed", "timeout", "stopped"},
			edges: []string{
				"running->paused", "running->done", "running->failed", "running->timeout", "running->stopped",
				"paused->running", "paused->stopped", "paused->timeout", "paused->failed",
			},
		},
		{
			kind:   "intent",
			states: []string{"open", "running", "done", "exhausted", "blocked", "stopped", "parked"},
			edges: []string{
				"open->running", "open->blocked", "open->parked", "open->stopped",
				"running->done", "running->exhausted", "running->blocked", "running->stopped", "running->parked",
				"blocked->open", "parked->open", "exhausted->open",
			},
		},
		{
			kind:   "mission",
			states: []string{"pending", "running", "done", "exhausted", "blocked", "stopped", "killed", "failed", "retry_pending"},
			edges: []string{
				"pending->running", "pending->stopped", "pending->blocked", "pending->failed",
				"running->done", "running->exhausted", "running->blocked", "running->stopped", "running->killed", "running->failed",
				"failed->retry_pending", "blocked->retry_pending",
				"retry_pending->running", "retry_pending->stopped", "retry_pending->blocked", "retry_pending->failed",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			allowed := make(map[string]bool, len(tc.edges))
			for _, edge := range tc.edges {
				allowed[edge] = true
			}
			for _, from := range tc.states {
				for _, to := range tc.states {
					edge := from + "->" + to
					t.Run(edge, func(t *testing.T) {
						err := ValidateTransition(tc.kind, from, to)
						if (err == nil) != allowed[edge] {
							t.Fatalf("allowed=%v, got error=%v", allowed[edge], err)
						}
					})
				}
			}
		})
	}
}

func TestValidateTransitionInvalidInput(t *testing.T) {
	cases := []struct {
		kind string
		from string
		to   string
	}{
		{"", "running", "done"},
		{"unknown", "running", "done"},
		{"Task", "running", "done"},
		{" task", "running", "done"},
		{"task ", "running", "done"},
		{"tasks", "running", "done"},
		{"authorization", "draft", "active"},
		{"task", "", "running"},
		{"task", "running", ""},
		{"task", "RUNNING", "done"},
		{"task", "running", "DONE"},
		{"task", " running", "done"},
		{"task", "running", "done "},
		{"task", "pending", "running"},
		{"task", "running", "killed"},
		{"intent", "pending", "running"},
		{"intent", "running", "retry_pending"},
		{"mission", "paused", "running"},
		{"mission", "running", "timeout"},
		{"mission", "retry-pending", "running"},
		{"mission", "running", "unknown"},
		{"mission", "running\x00", "done"},
		{"任务", "running", "done"},
	}
	for _, tc := range cases {
		t.Run(tc.kind+"/"+tc.from+"/"+tc.to, func(t *testing.T) {
			if err := ValidateTransition(tc.kind, tc.from, tc.to); err == nil {
				t.Fatalf("invalid input accepted: %#v", tc)
			}
		})
	}
}

func TestValidateTransitionTerminalCannotRunDirectly(t *testing.T) {
	// [02] 可重试/可重开的状态也必须经过显式中间态，不允许直接恢复执行。
	for kind, states := range map[string][]string{
		"task":    {"done", "failed", "timeout", "stopped"},
		"intent":  {"done", "exhausted", "blocked", "stopped", "parked"},
		"mission": {"done", "exhausted", "blocked", "stopped", "killed", "failed"},
	} {
		for _, state := range states {
			t.Run(kind+"/"+state, func(t *testing.T) {
				if err := ValidateTransition(kind, state, "running"); err == nil {
					t.Fatal("terminal or blocked state resumed without intermediate state")
				}
			})
		}
	}
}

func TestValidateTransitionErrorsHaveContext(t *testing.T) {
	err := ValidateTransition("mission", "done", "running")
	if err == nil {
		t.Fatal("invalid transition accepted")
	}
	for _, text := range []string{"mission", "done", "running"} {
		if !strings.Contains(err.Error(), text) {
			t.Errorf("error %q lacks %q", err, text)
		}
	}
}
