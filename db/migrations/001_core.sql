-- [01] 首批 P0：独立新库显式迁移；审计数据统一 RESTRICT，不随 Task 级联删除。
CREATE TABLE principals (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 issuer TEXT NOT NULL DEFAULT 'local-cli', subject TEXT NOT NULL UNIQUE,
 principal_type TEXT NOT NULL CHECK (principal_type IN ('human','service','organization')),
 role TEXT NOT NULL CHECK (role IN ('admin','scheduler','worker','reconciler')),
 status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
 credential_hash TEXT NOT NULL UNIQUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE authorization_contracts (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 principal_id BIGINT NOT NULL REFERENCES principals(id),
 approved_by_principal_id BIGINT REFERENCES principals(id),
 status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','active','revoked','expired')),
 valid_from TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
 single_operator_mode BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK(expires_at > valid_from)
);
CREATE TABLE authorization_proofs (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 authorization_id BIGINT NOT NULL REFERENCES authorization_contracts(id),
 proof_type TEXT NOT NULL CHECK(proof_type IN ('manual_attestation','signed_document','ticket','email_attestation')),
 storage_ref TEXT NOT NULL, content_hash TEXT NOT NULL CHECK(length(content_hash)=64),
 verified_by_principal_id BIGINT NOT NULL REFERENCES principals(id),
 verification_status TEXT NOT NULL CHECK(verification_status IN ('verified','rejected','expired')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(authorization_id,id)
);
CREATE TABLE authorization_versions (
 authorization_id BIGINT NOT NULL REFERENCES authorization_contracts(id),
 version INT NOT NULL CHECK(version>0), scope_document JSONB NOT NULL,
 scope_hash TEXT NOT NULL CHECK(length(scope_hash)=64),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','superseded','revoked')),
 created_by BIGINT NOT NULL REFERENCES principals(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(authorization_id,version)
);
CREATE UNIQUE INDEX authorization_one_active ON authorization_versions(authorization_id) WHERE status='active';
CREATE TABLE authorization_events (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 authorization_id BIGINT NOT NULL REFERENCES authorization_contracts(id),
 actor_id BIGINT NOT NULL REFERENCES principals(id),
 event_type TEXT NOT NULL, payload JSONB NOT NULL,
 previous_event_hash TEXT NOT NULL, event_hash TEXT NOT NULL CHECK(length(event_hash)=64),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE tasks (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 authorization_id BIGINT NOT NULL, current_scope_ver INT NOT NULL,
 goal TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running'
 CHECK(status IN ('running','paused','done','failed','timeout','stopped')),
 deadline_at TIMESTAMPTZ NOT NULL, version BIGINT NOT NULL DEFAULT 1,
 UNIQUE(id,authorization_id),
 FOREIGN KEY(authorization_id,current_scope_ver) REFERENCES authorization_versions(authorization_id,version)
);
CREATE TABLE assets (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL REFERENCES tasks(id), asset_key TEXT NOT NULL,
 scope_status TEXT NOT NULL DEFAULT 'pending_review' CHECK(scope_status IN ('pending_review','in_scope','excluded')),
 UNIQUE(task_id,id), UNIQUE(task_id,asset_key)
);
CREATE TABLE nodes (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL REFERENCES tasks(id),
 kind TEXT NOT NULL CHECK(kind IN ('intent','mission','fact')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(task_id,id), UNIQUE(task_id,id,kind)
);
CREATE TABLE edges (
 task_id BIGINT NOT NULL, src_id BIGINT NOT NULL, dst_id BIGINT NOT NULL,
 rel TEXT NOT NULL CHECK(rel IN ('spawns','yields','derived_from')),
 PRIMARY KEY(task_id,src_id,rel,dst_id), CHECK(src_id<>dst_id),
 FOREIGN KEY(task_id,src_id) REFERENCES nodes(task_id,id),
 FOREIGN KEY(task_id,dst_id) REFERENCES nodes(task_id,id)
);
CREATE TABLE intents (
 id BIGINT PRIMARY KEY, task_id BIGINT NOT NULL,
 node_kind TEXT NOT NULL DEFAULT 'intent' CHECK(node_kind='intent'),
 target_asset_id BIGINT NOT NULL, title TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','running','done','exhausted','blocked','stopped','parked')),
 version BIGINT NOT NULL DEFAULT 1,
 UNIQUE(task_id,id),
 FOREIGN KEY(task_id,id,node_kind) REFERENCES nodes(task_id,id,kind),
 FOREIGN KEY(task_id,target_asset_id) REFERENCES assets(task_id,id)
);
CREATE TABLE missions (
 id BIGINT PRIMARY KEY, task_id BIGINT NOT NULL,
 node_kind TEXT NOT NULL DEFAULT 'mission' CHECK(node_kind='mission'),
 intent_id BIGINT NOT NULL, target_asset_id BIGINT NOT NULL,
 authorization_id BIGINT NOT NULL, scope_version INT NOT NULL,
 scope_hash TEXT NOT NULL, scope_snapshot JSONB NOT NULL,
 angle TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending'
 CHECK(state IN ('pending','running','done','exhausted','blocked','stopped','killed','failed','retry_pending')),
 deadline_at TIMESTAMPTZ NOT NULL, version BIGINT NOT NULL DEFAULT 1,
 attempt_count INT NOT NULL DEFAULT 0, max_attempts INT NOT NULL DEFAULT 2,
 UNIQUE(task_id,id),
 FOREIGN KEY(task_id,id,node_kind) REFERENCES nodes(task_id,id,kind),
 FOREIGN KEY(task_id,intent_id) REFERENCES intents(task_id,id),
 FOREIGN KEY(task_id,target_asset_id) REFERENCES assets(task_id,id),
 FOREIGN KEY(task_id,authorization_id) REFERENCES tasks(id,authorization_id),
 FOREIGN KEY(authorization_id,scope_version) REFERENCES authorization_versions(authorization_id,version)
);
CREATE UNIQUE INDEX mission_active_angle ON missions(intent_id,angle) WHERE state IN ('pending','running','retry_pending');
CREATE TABLE resource_pools (
 resource_key TEXT PRIMARY KEY, capacity INT NOT NULL CHECK(capacity>=0),
 next_fencing_token BIGINT NOT NULL DEFAULT 0 CHECK(next_fencing_token>=0)
);
CREATE TABLE execution_leases (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL, mission_id BIGINT NOT NULL,
 resource_key TEXT NOT NULL REFERENCES resource_pools(resource_key),
 holder BIGINT NOT NULL REFERENCES principals(id), runtime_id TEXT NOT NULL,
 fencing_token BIGINT NOT NULL CHECK(fencing_token>0),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','expired','released','revoked')),
 lease_until TIMESTAMPTZ NOT NULL, heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 released_at TIMESTAMPTZ, UNIQUE(resource_key,fencing_token), UNIQUE(task_id,mission_id,id),
 FOREIGN KEY(task_id,mission_id) REFERENCES missions(task_id,id)
);
CREATE UNIQUE INDEX lease_active_mission ON execution_leases(mission_id) WHERE status='active';
CREATE INDEX lease_active_expiry ON execution_leases(resource_key,lease_until) WHERE status='active';
CREATE TABLE budget_ledgers (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL REFERENCES tasks(id), kind TEXT NOT NULL
 CHECK(kind IN ('wall_clock','tokens','http_requests','steps','storage')),
 allocated BIGINT NOT NULL CHECK(allocated>=0), reserved BIGINT NOT NULL DEFAULT 0 CHECK(reserved>=0),
 consumed BIGINT NOT NULL DEFAULT 0 CHECK(consumed>=0),
 UNIQUE(task_id,id), UNIQUE(task_id,kind), CHECK(reserved+consumed<=allocated)
);
CREATE TABLE budget_reservations (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL, mission_id BIGINT NOT NULL, ledger_id BIGINT NOT NULL,
 amount BIGINT NOT NULL CHECK(amount>0), consumed BIGINT NOT NULL DEFAULT 0 CHECK(consumed>=0 AND consumed<=amount),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','settled','released')),
 UNIQUE(mission_id,ledger_id),
 FOREIGN KEY(task_id,mission_id) REFERENCES missions(task_id,id),
 FOREIGN KEY(task_id,ledger_id) REFERENCES budget_ledgers(task_id,id)
);
CREATE TABLE facts (
 id BIGINT PRIMARY KEY, task_id BIGINT NOT NULL,
 node_kind TEXT NOT NULL DEFAULT 'fact' CHECK(node_kind='fact'),
 mission_id BIGINT NOT NULL, actor_id BIGINT NOT NULL REFERENCES principals(id),
 confidence TEXT NOT NULL CHECK(confidence IN ('observed','inferred')),
 validation TEXT NOT NULL DEFAULT 'unreviewed' CHECK(validation IN ('unreviewed','validated','rejected')),
 content JSONB NOT NULL, UNIQUE(task_id,id),
 FOREIGN KEY(task_id,id,node_kind) REFERENCES nodes(task_id,id,kind),
 FOREIGN KEY(task_id,mission_id) REFERENCES missions(task_id,id)
);
CREATE TABLE intent_fact_deps (
 task_id BIGINT NOT NULL, intent_id BIGINT NOT NULL, fact_id BIGINT NOT NULL,
 PRIMARY KEY(intent_id,fact_id),
 FOREIGN KEY(task_id,intent_id) REFERENCES intents(task_id,id),
 FOREIGN KEY(task_id,fact_id) REFERENCES facts(task_id,id)
);
-- [02] 幂等结果与账本/状态同事务保存；相同键不同请求摘要必须拒绝。
CREATE TABLE operation_results (
 actor_id BIGINT NOT NULL REFERENCES principals(id), operation TEXT NOT NULL,
 idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL, result JSONB NOT NULL,
 PRIMARY KEY(actor_id,operation,idempotency_key)
);
CREATE TABLE activities (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, task_id BIGINT NOT NULL REFERENCES tasks(id),
 actor_id BIGINT NOT NULL REFERENCES principals(id), kind TEXT NOT NULL, detail JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE aggregate_versions (
 task_id BIGINT NOT NULL REFERENCES tasks(id), kind TEXT NOT NULL, aggregate_id BIGINT NOT NULL,
 version BIGINT NOT NULL, PRIMARY KEY(task_id,kind,aggregate_id)
);
CREATE TABLE outbox_events (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, task_id BIGINT NOT NULL REFERENCES tasks(id),
 aggregate_kind TEXT NOT NULL, aggregate_id BIGINT NOT NULL, aggregate_version BIGINT NOT NULL,
 event_type TEXT NOT NULL, payload JSONB NOT NULL,
 available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 locked_by TEXT, locked_until TIMESTAMPTZ, claim_generation BIGINT NOT NULL DEFAULT 0,
 attempts INT NOT NULL DEFAULT 0, last_error TEXT, dead_lettered_at TIMESTAMPTZ, published_at TIMESTAMPTZ,
 UNIQUE(task_id,aggregate_kind,aggregate_id,aggregate_version)
);
CREATE TABLE stale_execution_results (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, task_id BIGINT NOT NULL REFERENCES tasks(id),
 mission_id BIGINT NOT NULL, lease_id BIGINT NOT NULL, fencing_token BIGINT NOT NULL,
 actor_id BIGINT NOT NULL REFERENCES principals(id), reason TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(task_id,mission_id,lease_id) REFERENCES execution_leases(task_id,mission_id,id)
);
-- [03] 历史证明与事件不可原地改写；Scope 只允许生命周期字段变化。
CREATE FUNCTION reject_immutable_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'immutable audit record' USING ERRCODE='23514'; END $$;
CREATE TRIGGER proofs_immutable BEFORE UPDATE OR DELETE ON authorization_proofs FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
CREATE TRIGGER auth_events_immutable BEFORE UPDATE OR DELETE ON authorization_events FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
CREATE FUNCTION protect_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'scope deletion forbidden' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.authorization_id,NEW.version,NEW.scope_document,NEW.scope_hash,NEW.created_by,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.authorization_id,OLD.version,OLD.scope_document,OLD.scope_hash,OLD.created_by,OLD.created_at)
 THEN RAISE EXCEPTION 'scope snapshot immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER scope_immutable BEFORE UPDATE OR DELETE ON authorization_versions FOR EACH ROW EXECUTE FUNCTION protect_scope();
