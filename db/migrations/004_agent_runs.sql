-- [01] Local Agent Runs are independent of Tasks/Missions/leases/outbox. No legacy data changes.
CREATE TABLE agent_runs (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 owner_id BIGINT NOT NULL REFERENCES principals(id),
 creation_key TEXT NOT NULL CHECK(length(creation_key) BETWEEN 1 AND 200),
 creation_digest TEXT NOT NULL CHECK(creation_digest ~ '^[0-9a-f]{64}$'),
 snapshot_path TEXT NOT NULL CHECK(octet_length(snapshot_path) BETWEEN 1 AND 4096),
 snapshot_hash TEXT NOT NULL CHECK(snapshot_hash ~ '^[0-9a-f]{64}$'),
 goal TEXT NOT NULL CHECK(octet_length(goal) BETWEEN 1 AND 16384),
 config_text TEXT NOT NULL CHECK(octet_length(config_text)<=16384 AND jsonb_typeof(config_text::jsonb)='object'),
 config_hash TEXT NOT NULL CHECK(config_hash ~ '^[0-9a-f]{64}$'),
 state TEXT NOT NULL CHECK(state IN ('ready','running','paused','unknown','completed','failed','cancelled','budget_exhausted')),
 reason TEXT NOT NULL DEFAULT '' CHECK(octet_length(reason)<=4096),
 version BIGINT NOT NULL CHECK(version>=1),
 last_seq BIGINT NOT NULL CHECK(last_seq=version),
 checkpoint_text TEXT NOT NULL DEFAULT '{}' CHECK(octet_length(checkpoint_text)<=65536 AND jsonb_typeof(checkpoint_text::jsonb)='object'),
 model_calls BIGINT NOT NULL DEFAULT 0 CHECK(model_calls>=0),
 tool_calls BIGINT NOT NULL DEFAULT 0 CHECK(tool_calls>=0),
 tokens_reserved BIGINT NOT NULL DEFAULT 0 CHECK(tokens_reserved>=0),
 tokens_used BIGINT NOT NULL DEFAULT 0 CHECK(tokens_used>=0),
 stored_bytes BIGINT NOT NULL DEFAULT 0 CHECK(stored_bytes>=0),
 max_model_calls BIGINT NOT NULL CHECK(max_model_calls BETWEEN 0 AND 64),
 max_tool_calls BIGINT NOT NULL CHECK(max_tool_calls BETWEEN 0 AND 256),
 max_tokens BIGINT NOT NULL CHECK(max_tokens BETWEEN 0 AND 100000000),
 max_stored_bytes BIGINT NOT NULL CHECK(max_stored_bytes BETWEEN 131072 AND 67108864),
 deadline_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(owner_id,creation_key),
 CHECK(model_calls<=max_model_calls AND tool_calls<=max_tool_calls),
 -- [01a] Known provider usage can exceed its estimate/cap; preserve actual usage and deny future preparation.
 CHECK(tokens_reserved<=max_tokens),
 CHECK(stored_bytes<=max_stored_bytes)
);
CREATE INDEX agent_runs_owner_id ON agent_runs(owner_id,id);

-- [02] Exact canonical bytes are TEXT, never JSONB. Request digest and original result allow CAS-safe replay.
CREATE TABLE agent_run_steps (
 run_id BIGINT NOT NULL REFERENCES agent_runs(id),
 seq BIGINT NOT NULL CHECK(seq>=1),
 version BIGINT NOT NULL CHECK(version=seq),
 idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
 request_digest TEXT NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 request_text TEXT NOT NULL CHECK(jsonb_typeof(request_text::jsonb)='object'),
 kind TEXT NOT NULL CHECK(kind IN ('run.created','run.started','model.prepared','model.completed','tool.started','tool.completed','run.checkpoint','run.paused','run.resumed','run.unknown','run.completed','run.failed','run.cancelled','run.budget_exhausted')),
 payload_text TEXT NOT NULL CHECK(octet_length(payload_text)<=262144 AND jsonb_typeof(payload_text::jsonb)='object'),
 payload_hash TEXT NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
 result_text TEXT NOT NULL CHECK(jsonb_typeof(result_text::jsonb)='object'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(run_id,seq),
 UNIQUE(run_id,idempotency_key)
);
CREATE TRIGGER agent_run_steps_immutable BEFORE UPDATE OR DELETE ON agent_run_steps
 FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

-- [03] Bindings/limits never change; every aggregate update must advance the append cursor exactly once.
CREATE FUNCTION protect_agent_run() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'agent run deletion forbidden' USING ERRCODE='23514';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','reason','version','last_seq','checkpoint_text','model_calls','tool_calls','tokens_reserved','tokens_used','stored_bytes','updated_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','reason','version','last_seq','checkpoint_text','model_calls','tool_calls','tokens_reserved','tokens_used','stored_bytes','updated_at']) THEN
  RAISE EXCEPTION 'agent run binding immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.version<>OLD.version+1 OR NEW.last_seq<>OLD.last_seq+1 OR NEW.stored_bytes<OLD.stored_bytes OR NEW.model_calls<OLD.model_calls OR NEW.tool_calls<OLD.tool_calls OR NEW.tokens_used<OLD.tokens_used THEN
  RAISE EXCEPTION 'agent run version or counter conflict' USING ERRCODE='23514';
 END IF;
 IF OLD.state IN ('completed','failed','cancelled','budget_exhausted') THEN
  RAISE EXCEPTION 'terminal agent run immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.state<>OLD.state AND NOT (
  (OLD.state='ready' AND NEW.state IN ('running','paused','failed','cancelled','budget_exhausted')) OR
  (OLD.state='running' AND NEW.state IN ('paused','unknown','completed','failed','cancelled','budget_exhausted')) OR
  (OLD.state IN ('paused','unknown') AND NEW.state IN ('running','failed','cancelled','budget_exhausted'))
 ) THEN
  RAISE EXCEPTION 'illegal agent run transition' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER agent_runs_protected BEFORE UPDATE OR DELETE ON agent_runs
 FOR EACH ROW EXECUTE FUNCTION protect_agent_run();

-- [04] Deferred two-way checks forbid committed aggregate-only or step-only writes, including sequence gaps.
CREATE FUNCTION validate_agent_run_cursor() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r agent_runs%ROWTYPE; n BIGINT; top_seq BIGINT;
BEGIN
 IF TG_TABLE_NAME='agent_runs' THEN
  SELECT * INTO r FROM agent_runs WHERE id=NEW.id;
 ELSE
  SELECT * INTO r FROM agent_runs WHERE id=NEW.run_id;
 END IF;
 SELECT count(*),max(seq) INTO n,top_seq FROM agent_run_steps WHERE run_id=r.id;
 IF n<>r.last_seq OR top_seq IS DISTINCT FROM r.last_seq THEN
  RAISE EXCEPTION 'agent run and append cursor mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER agent_runs_cursor AFTER INSERT OR UPDATE ON agent_runs
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_agent_run_cursor();
CREATE CONSTRAINT TRIGGER agent_run_steps_cursor AFTER INSERT ON agent_run_steps
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_agent_run_cursor();
