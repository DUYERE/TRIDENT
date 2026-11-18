-- [01] Multi-agent orchestration: exploration graph for one autonomous audit task.
-- Runs for planner/worker sessions stay in agent_runs (same governance, same budget
-- hard limits); this schema stores only the task and its exploration graph.
CREATE TABLE orchestration_tasks (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 owner_id BIGINT NOT NULL REFERENCES principals(id),
 creation_key TEXT NOT NULL CHECK(length(creation_key) BETWEEN 1 AND 200),
 snapshot_path TEXT NOT NULL CHECK(octet_length(snapshot_path) BETWEEN 1 AND 4096),
 snapshot_hash TEXT NOT NULL CHECK(snapshot_hash ~ '^[0-9a-f]{64}$'),
 title TEXT NOT NULL CHECK(octet_length(title) BETWEEN 1 AND 512),
 goal TEXT NOT NULL CHECK(octet_length(goal) BETWEEN 1 AND 16384),
 state TEXT NOT NULL CHECK(state IN ('created','running','completed','cancelled','failed')),
 reason TEXT NOT NULL DEFAULT '' CHECK(octet_length(reason)<=4096),
 config_text TEXT NOT NULL CHECK(octet_length(config_text)<=16384 AND jsonb_typeof(config_text::jsonb)='object'),
 max_planner_rounds INT NOT NULL CHECK(max_planner_rounds BETWEEN 1 AND 24),
 max_intents INT NOT NULL CHECK(max_intents BETWEEN 1 AND 48),
 max_workers INT NOT NULL CHECK(max_workers BETWEEN 1 AND 4),
 planner_rounds INT NOT NULL DEFAULT 0 CHECK(planner_rounds>=0),
 intents_spawned INT NOT NULL DEFAULT 0 CHECK(intents_spawned>=0),
 deadline_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(owner_id,creation_key)
);
CREATE INDEX orchestration_tasks_owner ON orchestration_tasks(owner_id,id);

-- [02] Exploration graph nodes. Nodes are append-only in semantics; state/payload
-- updates are engine-driven transitions (never LLM writes).
CREATE TABLE orchestration_nodes (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL REFERENCES orchestration_tasks(id),
 kind TEXT NOT NULL CHECK(kind IN ('goal','intent','fact','finding_candidate','digest')),
 state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','running','done','met','exhausted','blocked','cancelled','invalid')),
 summary TEXT NOT NULL CHECK(octet_length(summary) BETWEEN 1 AND 2048),
 confidence TEXT NOT NULL DEFAULT '' CHECK(confidence IN ('','observed','inferred')),
 payload_text TEXT NOT NULL DEFAULT '{}' CHECK(octet_length(payload_text)<=32768 AND jsonb_typeof(payload_text::jsonb)='object'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX orchestration_nodes_task ON orchestration_nodes(task_id,id);

-- [03] Edges: From is the upstream/parent, To the downstream/child.
CREATE TABLE orchestration_edges (
 task_id BIGINT NOT NULL REFERENCES orchestration_tasks(id),
 from_id BIGINT NOT NULL REFERENCES orchestration_nodes(id),
 rel TEXT NOT NULL CHECK(rel IN ('spawns','derived_from','yields')),
 to_id BIGINT NOT NULL REFERENCES orchestration_nodes(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(from_id,rel,to_id)
);
CREATE INDEX orchestration_edges_to ON orchestration_edges(to_id);

-- [04] Task-level operation constraints (allow/deny), injected into planner and
-- worker goal text each round. Highest priority boundary.
CREATE TABLE orchestration_constraints (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL REFERENCES orchestration_tasks(id),
 kind TEXT NOT NULL CHECK(kind IN ('allow','deny')),
 text TEXT NOT NULL CHECK(octet_length(text) BETWEEN 1 AND 512),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(task_id, kind, text)
);
