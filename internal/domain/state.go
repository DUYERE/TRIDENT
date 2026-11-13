package domain

import "fmt"

// ValidateTransition 只校验显式状态矩阵，不执行持久化或业务前置条件检查。
// Mission 的 failed/blocked -> retry_pending 仍需外层确认授权有效、可安全重试、
// 无不确定副作用以及预算/重试次数；Intent 重开同样需外层检查依赖、预算和授权。
// 状态名及 kind 必须使用精确小写值，不自动修正非法输入，不允许自迁移。
func ValidateTransition(kind, from, to string) error {
	// [01] 只接受基线中的三个聚合类型，不允许未知类型复用其他矩阵。
	var transitions map[string][]string
	switch kind {
	case "task":
		transitions = taskStateTransitions
	case "intent":
		transitions = intentStateTransitions
	case "mission":
		transitions = missionStateTransitions
	default:
		return fmt.Errorf("unknown transition kind %q", kind)
	}
	// [02] 先校验两端状态；终态保留空边表，不得直接重新进入 running。
	targets, ok := transitions[from]
	if !ok {
		return fmt.Errorf("unknown %s source state %q", kind, from)
	}
	if _, ok := transitions[to]; !ok {
		return fmt.Errorf("unknown %s destination state %q", kind, to)
	}
	// [03] 严格匹配一条显式边；重试或重开不是绕过外层安全条件的授权。
	for _, target := range targets {
		if target == to {
			return nil
		}
	}
	return fmt.Errorf("invalid %s transition %q -> %q", kind, from, to)
}

var taskStateTransitions = map[string][]string{
	"running": {"paused", "done", "failed", "timeout", "stopped"},
	"paused":  {"running", "stopped", "timeout", "failed"},
	"done":    nil,
	"failed":  nil,
	"timeout": nil,
	"stopped": nil,
}

var intentStateTransitions = map[string][]string{
	"open":      {"running", "blocked", "parked", "stopped"},
	"running":   {"done", "exhausted", "blocked", "stopped", "parked"},
	"blocked":   {"open"},
	"parked":    {"open"},
	"exhausted": {"open"},
	"done":      nil,
	"stopped":   nil,
}

var missionStateTransitions = map[string][]string{
	"pending":       {"running", "stopped", "blocked", "failed"},
	"running":       {"done", "exhausted", "blocked", "stopped", "killed", "failed"},
	"failed":        {"retry_pending"},
	"blocked":       {"retry_pending"},
	"retry_pending": {"running", "stopped", "blocked", "failed"},
	"done":          nil,
	"exhausted":     nil,
	"stopped":       nil,
	"killed":        nil,
}
