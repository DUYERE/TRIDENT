package domain

import "time"

// ConversationMode records how the conversation was started. A conversation
// opened as chat can still accept an orchestration task later; mode is a
// presentation hint, not a permission boundary.
type ConversationMode string

const (
	ConversationChat        ConversationMode = "chat"
	ConversationOrchestrate ConversationMode = "orchestrate"
)

// AgentConversation is the user-visible thread above agent runs and tasks.
// Runs and tasks remain independent durable records; this entity only groups
// them so the console does not expose every planner/worker run as a thread.
type AgentConversation struct {
	ID           int64            `json:"id"`
	OwnerID      int64            `json:"owner_id"`
	SnapshotHash string           `json:"snapshot_hash"`
	Title        string           `json:"title"`
	Mode         ConversationMode `json:"mode"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

// AgentConversationSummary is the bounded list projection returned to the
// console. LastRunState/LastTaskState are empty when the conversation has no
// matching execution unit yet.
type AgentConversationSummary struct {
	AgentConversation
	RunCount      int64  `json:"run_count"`
	TaskCount     int64  `json:"task_count"`
	LastRunState  string `json:"last_run_state,omitempty"`
	LastTaskState string `json:"last_task_state,omitempty"`
}
