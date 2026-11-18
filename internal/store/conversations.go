package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trident/internal/domain"
)

// Conversations group user-visible turns. They intentionally live beside
// agent_runs/orchestration_tasks instead of adding columns to those governed
// tables: old rows stay valid, and a run/task can be linked without changing
// its immutable binding.

type CreateConversationParams struct {
	Key          string
	SnapshotHash string
	Title        string
	Mode         string
}

func normalizeConversationCreate(p CreateConversationParams) (CreateConversationParams, error) {
	p.Title = strings.TrimSpace(p.Title)
	p.SnapshotHash = strings.ToLower(strings.TrimSpace(p.SnapshotHash))
	if !agentKey(p.Key) || !agentText(p.Title, 512, true) || len(p.SnapshotHash) != 64 {
		return p, ErrDenied
	}
	if _, err := hex.DecodeString(p.SnapshotHash); err != nil {
		return p, ErrDenied
	}
	if p.Mode != string(domain.ConversationChat) && p.Mode != string(domain.ConversationOrchestrate) {
		return p, ErrDenied
	}
	return p, nil
}

func normalizeConversationTitle(title string) (string, error) {
	title = strings.TrimSpace(title)
	if title == "" || len([]byte(title)) > 512 || strings.ContainsAny(title, "\r\n\x00") {
		return "", ErrDenied
	}
	return title, nil
}

const conversationColumns = `id,owner_id,snapshot_hash,title,mode,created_at,updated_at`

func scanConversation(row pgx.Row) (domain.AgentConversation, error) {
	var c domain.AgentConversation
	var mode string
	err := row.Scan(&c.ID, &c.OwnerID, &c.SnapshotHash, &c.Title, &mode, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrDenied
	}
	c.Mode = domain.ConversationMode(mode)
	return c, err
}

func classifyConversationConflict(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}

// CreateConversation creates one owner-scoped conversation. Creation keys are
// unique per owner so a retried browser request cannot create duplicates.
func (s *Store) CreateConversation(ctx context.Context, ss Session, params CreateConversationParams) (domain.AgentConversation, error) {
	p, err := normalizeConversationCreate(params)
	if err != nil {
		return domain.AgentConversation{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AgentConversation{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.AgentConversation{}, err
	}
	row := tx.QueryRow(ctx, `INSERT INTO agent_conversations
		(owner_id,creation_key,snapshot_hash,title,mode)
		VALUES($1,$2,$3,$4,$5) RETURNING `+conversationColumns,
		a.id, p.Key, p.SnapshotHash, p.Title, p.Mode)
	conversation, err := scanConversation(row)
	if err != nil {
		return domain.AgentConversation{}, classifyConversationConflict(err)
	}
	return conversation, tx.Commit(ctx)
}

// UpdateConversationTitle renames an owner-scoped conversation. It is the only
// mutable field; mode/snapshot stay immutable so history cannot be regrouped.
func (s *Store) UpdateConversationTitle(ctx context.Context, ss Session, conversationID int64, title string) (domain.AgentConversation, error) {
	title, err := normalizeConversationTitle(title)
	if err != nil || conversationID < 1 {
		return domain.AgentConversation{}, ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AgentConversation{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.AgentConversation{}, err
	}
	conversation, err := scanConversation(tx.QueryRow(ctx,
		`UPDATE agent_conversations SET title=$1, updated_at=clock_timestamp()
		 WHERE id=$2 AND owner_id=$3 RETURNING `+conversationColumns,
		title, conversationID, a.id))
	if err != nil {
		return domain.AgentConversation{}, err
	}
	return conversation, tx.Commit(ctx)
}

func (s *Store) GetConversation(ctx context.Context, ss Session, conversationID int64) (domain.AgentConversation, error) {
	if conversationID < 1 {
		return domain.AgentConversation{}, ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AgentConversation{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.AgentConversation{}, err
	}
	conversation, err := scanConversation(tx.QueryRow(ctx,
		`SELECT `+conversationColumns+` FROM agent_conversations WHERE id=$1 AND owner_id=$2`,
		conversationID, a.id))
	if err != nil {
		return domain.AgentConversation{}, err
	}
	return conversation, tx.Commit(ctx)
}

// ListConversations returns the rail projection: counts and the latest execution
// state, never full run/task payloads.
func (s *Store) ListConversations(ctx context.Context, ss Session, snapshotHash string, limit int) ([]domain.AgentConversationSummary, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	snapshotHash = strings.ToLower(strings.TrimSpace(snapshotHash))
	if snapshotHash != "" {
		if len(snapshotHash) != 64 {
			return nil, ErrDenied
		}
		if _, err := hex.DecodeString(snapshotHash); err != nil {
			return nil, ErrDenied
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT c.id,c.owner_id,c.snapshot_hash,c.title,c.mode,c.created_at,c.updated_at,
		(SELECT count(*) FROM agent_conversation_runs r WHERE r.conversation_id=c.id),
		(SELECT count(*) FROM agent_conversation_tasks t WHERE t.conversation_id=c.id),
		COALESCE((SELECT ar.state FROM agent_conversation_runs r JOIN agent_runs ar ON ar.id=r.run_id
			WHERE r.conversation_id=c.id ORDER BY r.created_at DESC, r.run_id DESC LIMIT 1),''),
		COALESCE((SELECT ot.state FROM agent_conversation_tasks t JOIN orchestration_tasks ot ON ot.id=t.task_id
			WHERE t.conversation_id=c.id ORDER BY t.created_at DESC, t.task_id DESC LIMIT 1),'')
		FROM agent_conversations c
		WHERE c.owner_id=$1 AND ($2='' OR c.snapshot_hash=$2)
		ORDER BY c.updated_at DESC, c.id DESC LIMIT $3`, a.id, snapshotHash, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.AgentConversationSummary, 0)
	for rows.Next() {
		var c domain.AgentConversationSummary
		var mode string
		if err := rows.Scan(&c.ID, &c.OwnerID, &c.SnapshotHash, &c.Title, &mode, &c.CreatedAt, &c.UpdatedAt,
			&c.RunCount, &c.TaskCount, &c.LastRunState, &c.LastTaskState); err != nil {
			return nil, err
		}
		c.Mode = domain.ConversationMode(mode)
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return items, nil
}

// qualifySQLColumns prefixes each unqualified column for joined SELECTs where
// both sides carry common names such as id and created_at.
func qualifySQLColumns(alias, columns string) string {
	parts := strings.Split(columns, ",")
	for i := range parts {
		parts[i] = alias + "." + strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
}

// ConversationDetail returns conversation metadata plus its main chat runs and
// orchestration tasks. Planner/worker runs are still reached through task node
// payloads, not listed as conversation turns.
func (s *Store) ConversationDetail(ctx context.Context, ss Session, conversationID int64) (domain.AgentConversation, []domain.AgentRun, []domain.OrchestrationTask, error) {
	if conversationID < 1 {
		return domain.AgentConversation{}, nil, nil, ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AgentConversation{}, nil, nil, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.AgentConversation{}, nil, nil, err
	}
	conversation, err := scanConversation(tx.QueryRow(ctx,
		`SELECT `+conversationColumns+` FROM agent_conversations WHERE id=$1 AND owner_id=$2`,
		conversationID, a.id))
	if err != nil {
		return domain.AgentConversation{}, nil, nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+qualifySQLColumns("ar", agentRunColumns)+` FROM agent_conversation_runs cr
		JOIN agent_runs ar ON ar.id=cr.run_id
		WHERE cr.conversation_id=$1 AND ar.owner_id=$2
		ORDER BY cr.created_at, cr.run_id`, conversationID, a.id)
	if err != nil {
		return domain.AgentConversation{}, nil, nil, err
	}
	runs := make([]domain.AgentRun, 0)
	for rows.Next() {
		run, scanErr := scanAgentRun(rows)
		if scanErr != nil {
			rows.Close()
			return domain.AgentConversation{}, nil, nil, scanErr
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.AgentConversation{}, nil, nil, err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `SELECT `+qualifySQLColumns("ot", orchestrationTaskColumns)+` FROM agent_conversation_tasks ct
		JOIN orchestration_tasks ot ON ot.id=ct.task_id
		WHERE ct.conversation_id=$1 AND ot.owner_id=$2
		ORDER BY ct.created_at, ct.task_id`, conversationID, a.id)
	if err != nil {
		return domain.AgentConversation{}, nil, nil, err
	}
	tasks := make([]domain.OrchestrationTask, 0)
	for rows.Next() {
		task, scanErr := scanOrchestrationTask(rows)
		if scanErr != nil {
			rows.Close()
			return domain.AgentConversation{}, nil, nil, scanErr
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.AgentConversation{}, nil, nil, err
	}
	rows.Close()
	return conversation, runs, tasks, tx.Commit(ctx)
}

func (s *Store) LinkConversationRun(ctx context.Context, ss Session, conversationID, runID int64) error {
	if conversationID < 1 || runID < 1 {
		return ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return err
	}
	if err := ownedConversation(ctx, tx, a, conversationID); err != nil {
		return err
	}
	if _, err := ownedAgentRun(ctx, tx, a, runID, false); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_conversation_runs(conversation_id,run_id) VALUES($1,$2)
		ON CONFLICT (conversation_id,run_id) DO NOTHING`, conversationID, runID); err != nil {
		return classifyConversationConflict(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_conversations SET updated_at=clock_timestamp() WHERE id=$1`, conversationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) LinkConversationTask(ctx context.Context, ss Session, conversationID, taskID int64) error {
	if conversationID < 1 || taskID < 1 {
		return ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return err
	}
	if err := ownedConversation(ctx, tx, a, conversationID); err != nil {
		return err
	}
	if _, err := scanOrchestrationTask(tx.QueryRow(ctx,
		`SELECT `+orchestrationTaskColumns+` FROM orchestration_tasks WHERE id=$1 AND owner_id=$2`,
		taskID, a.id)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_conversation_tasks(conversation_id,task_id) VALUES($1,$2)
		ON CONFLICT (conversation_id,task_id) DO NOTHING`, conversationID, taskID); err != nil {
		return classifyConversationConflict(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_conversations SET updated_at=clock_timestamp() WHERE id=$1`, conversationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func ownedConversation(ctx context.Context, tx pgx.Tx, a actor, conversationID int64) error {
	var id int64
	err := tx.QueryRow(ctx, `SELECT id FROM agent_conversations WHERE id=$1 AND owner_id=$2`, conversationID, a.id).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDenied
	}
	return err
}

// ConversationIDForTask returns 0 when the task predates the conversation model
// or was never started from a conversation.
func (s *Store) ConversationIDForTask(ctx context.Context, ss Session, taskID int64) (int64, error) {
	if taskID < 1 {
		return 0, ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return 0, err
	}
	if _, err := scanOrchestrationTask(tx.QueryRow(ctx,
		`SELECT `+orchestrationTaskColumns+` FROM orchestration_tasks WHERE id=$1 AND owner_id=$2`,
		taskID, a.id)); err != nil {
		return 0, err
	}
	var conversationID int64
	err = tx.QueryRow(ctx, `SELECT conversation_id FROM agent_conversation_tasks WHERE task_id=$1`, taskID).Scan(&conversationID)
	if errors.Is(err, pgx.ErrNoRows) {
		conversationID = 0
		err = nil
	}
	if err != nil {
		return 0, err
	}
	return conversationID, tx.Commit(ctx)
}
