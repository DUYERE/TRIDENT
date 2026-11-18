-- [01] A conversation groups user-visible turns: single agent runs and orchestration
-- tasks. Runs/tasks keep their own schemas; relations live in link tables so old
-- rows and old clients remain valid.
CREATE TABLE agent_conversations (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 owner_id BIGINT NOT NULL REFERENCES principals(id),
 creation_key TEXT NOT NULL CHECK(length(creation_key) BETWEEN 1 AND 200),
 snapshot_hash TEXT NOT NULL CHECK(snapshot_hash ~ '^[0-9a-f]{64}$'),
 title TEXT NOT NULL CHECK(octet_length(title) BETWEEN 1 AND 512),
 mode TEXT NOT NULL CHECK(mode IN ('chat','orchestrate')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(owner_id, creation_key)
);
CREATE INDEX agent_conversations_owner ON agent_conversations(owner_id, updated_at DESC);

-- [02] A run belongs to at most one conversation. Planner/worker runs are not
-- linked here; they remain drill-down details of their task.
CREATE TABLE agent_conversation_runs (
 conversation_id BIGINT NOT NULL REFERENCES agent_conversations(id),
 run_id BIGINT NOT NULL REFERENCES agent_runs(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (conversation_id, run_id),
 UNIQUE (run_id)
);
CREATE INDEX agent_conversation_runs_conversation ON agent_conversation_runs(conversation_id, created_at);

-- [03] A task belongs to at most one conversation; a chat turn can start it.
CREATE TABLE agent_conversation_tasks (
 conversation_id BIGINT NOT NULL REFERENCES agent_conversations(id),
 task_id BIGINT NOT NULL REFERENCES orchestration_tasks(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (conversation_id, task_id),
 UNIQUE (task_id)
);
CREATE INDEX agent_conversation_tasks_conversation ON agent_conversation_tasks(conversation_id, created_at);
