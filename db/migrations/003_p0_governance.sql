-- [01] P0.2 向前迁移；事务与历史校验和由 runner 管理，不回填旧 Task 成员。
-- [02] 升级风险：撤销旧 active 租约，阻塞关联 running Mission/Intent；预算与 Scope 快照不变。
CREATE TABLE task_members (
 task_id BIGINT NOT NULL REFERENCES tasks(id),
 principal_id BIGINT NOT NULL REFERENCES principals(id),
 role TEXT NOT NULL CHECK(role IN ('admin','scheduler','worker','reconciler')),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
 granted_by BIGINT NOT NULL REFERENCES principals(id),
 reason TEXT NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(task_id,principal_id)
);

-- [03] 仅扩充生命周期 CHECK；保留 authorization_one_active 原有部分唯一索引。
ALTER TABLE authorization_versions DROP CONSTRAINT authorization_versions_status_check;
ALTER TABLE authorization_versions ADD CONSTRAINT authorization_versions_status_check
 CHECK(status IN ('draft','active','superseded','revoked'));

-- [04] 提案及其基线均绑定同一合同的版本；证明与提案不可原地修改或删除。
CREATE TABLE authorization_scope_proposals (
 authorization_id BIGINT NOT NULL,
 version INT NOT NULL,
 base_version INT NOT NULL,
 scope_hash TEXT NOT NULL CHECK(length(scope_hash)=64),
 proof_ref TEXT NOT NULL,
 proof_hash TEXT NOT NULL CHECK(length(proof_hash)=64),
 submitted_by BIGINT NOT NULL REFERENCES principals(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(authorization_id,version),
 FOREIGN KEY(authorization_id,version) REFERENCES authorization_versions(authorization_id,version),
 FOREIGN KEY(authorization_id,base_version) REFERENCES authorization_versions(authorization_id,version)
);
CREATE TRIGGER scope_proposals_immutable BEFORE UPDATE OR DELETE ON authorization_scope_proposals
 FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

-- [05] 调用绑定精确的租约身份、运行时及 Mission 授权快照，禁止跨 Task/Mission 拼接。
ALTER TABLE execution_leases ADD CONSTRAINT execution_leases_runtime_binding_key
 UNIQUE(task_id,mission_id,id,fencing_token,holder,runtime_id);
ALTER TABLE missions ADD CONSTRAINT missions_scope_binding_key
 UNIQUE(task_id,id,authorization_id,scope_version,scope_hash);
CREATE TABLE tool_calls (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL,
 mission_id BIGINT NOT NULL,
 lease_id BIGINT NOT NULL,
 fencing_token BIGINT NOT NULL,
 runtime_id TEXT NOT NULL,
 requester_id BIGINT NOT NULL REFERENCES principals(id),
 authorization_id BIGINT NOT NULL,
 scope_version INT NOT NULL,
 scope_hash TEXT NOT NULL,
 tool_name TEXT NOT NULL,
 tool_version TEXT NOT NULL,
 target TEXT NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('http','https')),
 port INT NOT NULL CHECK(port BETWEEN 1 AND 65535),
 action TEXT NOT NULL,
 arguments JSONB NOT NULL,
 policy_version TEXT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
 -- [05a] 规范字节按文本保存，JSONB会改变数字词法，不能重建同一请求摘要。
 request_snapshot TEXT NOT NULL CHECK(jsonb_typeof(request_snapshot::jsonb)='object'),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','admitted','revoked')),
 admitted_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(task_id,mission_id,id),
 UNIQUE(task_id,mission_id,id,lease_id,fencing_token,requester_id,request_digest),
 FOREIGN KEY(task_id,mission_id,lease_id) REFERENCES execution_leases(task_id,mission_id,id),
 FOREIGN KEY(task_id,mission_id) REFERENCES missions(task_id,id),
 FOREIGN KEY(authorization_id,scope_version) REFERENCES authorization_versions(authorization_id,version),
 FOREIGN KEY(task_id,mission_id,lease_id,fencing_token,requester_id,runtime_id)
  REFERENCES execution_leases(task_id,mission_id,id,fencing_token,holder,runtime_id),
 FOREIGN KEY(task_id,mission_id,authorization_id,scope_version,scope_hash)
  REFERENCES missions(task_id,id,authorization_id,scope_version,scope_hash)
);

-- [06] 审批请求者必须为 service worker 的规则由业务层执行；数据库锁定请求七元组。
CREATE TABLE approvals (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL,
 mission_id BIGINT NOT NULL,
 tool_call_id BIGINT NOT NULL UNIQUE,
 lease_id BIGINT NOT NULL,
 fencing_token BIGINT NOT NULL,
 requester_id BIGINT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
 approver_id BIGINT REFERENCES principals(id),
 status TEXT NOT NULL DEFAULT 'pending'
  CHECK(status IN ('pending','approved','rejected','expired','consumed','revoked')),
 expires_at TIMESTAMPTZ NOT NULL,
 decided_at TIMESTAMPTZ,
 consumed_at TIMESTAMPTZ,
 reason TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(task_id,mission_id,id,tool_call_id,request_digest),
 FOREIGN KEY(task_id,mission_id,tool_call_id,lease_id,fencing_token,requester_id,request_digest)
  REFERENCES tool_calls(task_id,mission_id,id,lease_id,fencing_token,requester_id,request_digest),
 CHECK(status<>'approved' OR approver_id IS NOT NULL),
 CHECK(status<>'consumed' OR (consumed_at IS NOT NULL AND approver_id IS NOT NULL)),
 CHECK(approver_id IS NULL OR requester_id<>approver_id)
);

-- [07] 一次调用只能准入一次，一份审批只能消费一次；五元组确保审批及摘要一致。
CREATE TABLE tool_admissions (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 task_id BIGINT NOT NULL,
 mission_id BIGINT NOT NULL,
 tool_call_id BIGINT NOT NULL UNIQUE,
 approval_id BIGINT NOT NULL UNIQUE REFERENCES approvals(id),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(task_id,mission_id,tool_call_id) REFERENCES tool_calls(task_id,mission_id,id),
 FOREIGN KEY(task_id,mission_id,approval_id,tool_call_id,request_digest)
  REFERENCES approvals(task_id,mission_id,id,tool_call_id,request_digest)
);

-- [08] 调用仅允许更新 status/admitted_at；包含未来新增列在内的其他绑定均不可修改。
CREATE FUNCTION protect_tool_call_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'tool call deletion forbidden' USING ERRCODE='23514';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['status','admitted_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','admitted_at']) THEN
  RAISE EXCEPTION 'tool call binding immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER tool_calls_binding_immutable BEFORE UPDATE OR DELETE ON tool_calls
 FOR EACH ROW EXECUTE FUNCTION protect_tool_call_binding();

-- [09] 审批仅允许变更决策字段；expires_at、请求绑定及创建时间均不可修改。
CREATE FUNCTION protect_approval_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'approval deletion forbidden' USING ERRCODE='23514';
 END IF;
 IF (to_jsonb(NEW)-ARRAY['approver_id','status','decided_at','consumed_at','reason'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['approver_id','status','decided_at','consumed_at','reason']) THEN
  RAISE EXCEPTION 'approval binding immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER approvals_binding_immutable BEFORE UPDATE OR DELETE ON approvals
 FOR EACH ROW EXECUTE FUNCTION protect_approval_binding();
CREATE TRIGGER tool_admissions_immutable BEFORE UPDATE OR DELETE ON tool_admissions
 FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();

-- [10] 保留原 locked_by 兼容字段；新增可验证的领取主体，历史记录保持 NULL。
ALTER TABLE outbox_events ADD COLUMN claimed_by_principal_id BIGINT REFERENCES principals(id);

-- [11] 锁住升级涉及的写入；未领取的 pending Mission 保留，后续调度必须检查成员资格。
LOCK TABLE tasks, execution_leases, missions, intents IN SHARE ROW EXCLUSIVE MODE;
WITH revoked_leases AS (
 UPDATE execution_leases SET status='revoked', released_at=clock_timestamp()
 WHERE status='active'
 RETURNING task_id,mission_id,id,holder,fencing_token,runtime_id
), blocked_missions AS (
 UPDATE missions AS m SET state='blocked', version=m.version+1
 WHERE m.state='running' AND EXISTS (
  SELECT 1 FROM revoked_leases AS l WHERE l.task_id=m.task_id AND l.mission_id=m.id
 )
 RETURNING m.task_id,m.id,m.intent_id,m.version
), blocked_intents AS (
 UPDATE intents AS i SET state='blocked', version=i.version+1
 WHERE i.state='running' AND EXISTS (
  SELECT 1 FROM blocked_missions AS m WHERE m.task_id=i.task_id AND m.intent_id=i.id
 )
 RETURNING i.task_id,i.id,i.version
), affected_tasks AS (
 SELECT task_id,min(holder) AS actor_id,
  jsonb_agg(jsonb_build_object(
   'lease_id',id,'mission_id',mission_id,'holder',holder,
   'fencing_token',fencing_token,'runtime_id',runtime_id
  ) ORDER BY id) AS leases
 FROM revoked_leases GROUP BY task_id
), audit_payloads AS (
 SELECT a.task_id,a.actor_id,jsonb_build_object(
  'reason','P0.2 upgrade requires explicit task membership',
  'members_backfilled',false,
  'budget_unchanged',true,
  'revoked_leases',a.leases,
  'blocked_missions',COALESCE((
   SELECT jsonb_agg(jsonb_build_object('id',m.id,'version',m.version) ORDER BY m.id)
   FROM blocked_missions AS m WHERE m.task_id=a.task_id
  ),'[]'::jsonb),
  'blocked_intents',COALESCE((
   SELECT jsonb_agg(jsonb_build_object('id',i.id,'version',i.version) ORDER BY i.id)
   FROM blocked_intents AS i WHERE i.task_id=a.task_id
  ),'[]'::jsonb)
 ) AS payload FROM affected_tasks AS a
), bumped_aggregates AS (
 INSERT INTO aggregate_versions(task_id,kind,aggregate_id,version)
 SELECT task_id,'task',task_id,1 FROM affected_tasks
 ON CONFLICT(task_id,kind,aggregate_id) DO UPDATE
 SET version=aggregate_versions.version+1
 RETURNING task_id,kind,aggregate_id,version
), audit_activities AS (
 INSERT INTO activities(task_id,actor_id,kind,detail)
 SELECT task_id,actor_id,'p0.membership_upgrade_isolated',payload FROM audit_payloads
 RETURNING id
)
-- [12] 每个受影响 Task 仅写一条活动及 Outbox；runner 原子登记迁移，重跑不会二次隔离。
INSERT INTO outbox_events(task_id,aggregate_kind,aggregate_id,aggregate_version,event_type,payload)
SELECT a.task_id,v.kind,v.aggregate_id,v.version,'p0.membership_upgrade_isolated',
 a.payload || jsonb_build_object('actor_id',a.actor_id)
FROM audit_payloads AS a JOIN bumped_aggregates AS v ON v.task_id=a.task_id;
