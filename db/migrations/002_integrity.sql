-- [01] 最小图只允许 Intent -> Mission -> Fact -> Intent；依赖边加入前串行锁 Task 防并发成环。
CREATE FUNCTION validate_edge() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE src_kind TEXT; dst_kind TEXT; creates_cycle BOOLEAN;
BEGIN
 PERFORM 1 FROM tasks WHERE id=NEW.task_id FOR UPDATE;
 SELECT kind INTO src_kind FROM nodes WHERE task_id=NEW.task_id AND id=NEW.src_id;
 SELECT kind INTO dst_kind FROM nodes WHERE task_id=NEW.task_id AND id=NEW.dst_id;
 IF NOT ((NEW.rel='spawns' AND src_kind='intent' AND dst_kind='mission') OR
         (NEW.rel='yields' AND src_kind='mission' AND dst_kind='fact') OR
         (NEW.rel='derived_from' AND src_kind='fact' AND dst_kind='intent'))
 THEN RAISE EXCEPTION 'invalid edge type matrix' USING ERRCODE='23514'; END IF;
 WITH RECURSIVE reachable(id) AS (
  SELECT NEW.dst_id UNION
  SELECT e.dst_id FROM edges e JOIN reachable r ON e.src_id=r.id WHERE e.task_id=NEW.task_id
 ) SELECT EXISTS(SELECT 1 FROM reachable WHERE id=NEW.src_id) INTO creates_cycle;
 IF creates_cycle THEN RAISE EXCEPTION 'graph cycle forbidden' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER edge_type_cycle BEFORE INSERT OR UPDATE ON edges FOR EACH ROW EXECUTE FUNCTION validate_edge();

CREATE FUNCTION validate_node_extension() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n nodes%ROWTYPE; ext_count INT;
BEGIN
 SELECT * INTO n FROM nodes WHERE id=NEW.id;
 IF NOT FOUND THEN RETURN NEW; END IF;
 SELECT (SELECT count(*) FROM intents WHERE id=n.id)+(SELECT count(*) FROM missions WHERE id=n.id)+(SELECT count(*) FROM facts WHERE id=n.id) INTO ext_count;
 IF ext_count<>1 THEN RAISE EXCEPTION 'node requires exactly one typed extension' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER node_extension_complete AFTER INSERT OR UPDATE ON nodes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_node_extension();

-- [02] 状态变更需递增版本，终态不能被直接覆盖回 running。
CREATE FUNCTION validate_mission_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state=OLD.state THEN RETURN NEW; END IF;
 IF NEW.version<>OLD.version+1 THEN RAISE EXCEPTION 'mission version conflict' USING ERRCODE='23514'; END IF;
 IF NOT ((OLD.state='pending' AND NEW.state IN ('running','blocked','stopped','failed')) OR
 (OLD.state='running' AND NEW.state IN ('done','exhausted','blocked','stopped','killed','failed')) OR
 (OLD.state IN ('blocked','failed') AND NEW.state='retry_pending') OR
 (OLD.state='retry_pending' AND NEW.state IN ('running','blocked','stopped','failed')))
 THEN RAISE EXCEPTION 'illegal mission transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mission_transition BEFORE UPDATE ON missions FOR EACH ROW EXECUTE FUNCTION validate_mission_transition();

CREATE FUNCTION protect_mission_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ver authorization_versions%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' AND ROW(NEW.task_id,NEW.authorization_id,NEW.scope_version,NEW.scope_hash,NEW.scope_snapshot,NEW.intent_id,NEW.target_asset_id)
 IS DISTINCT FROM ROW(OLD.task_id,OLD.authorization_id,OLD.scope_version,OLD.scope_hash,OLD.scope_snapshot,OLD.intent_id,OLD.target_asset_id)
 THEN RAISE EXCEPTION 'mission binding immutable' USING ERRCODE='23514'; END IF;
 SELECT * INTO ver FROM authorization_versions WHERE authorization_id=NEW.authorization_id AND version=NEW.scope_version;
 IF NOT FOUND OR ver.scope_hash<>NEW.scope_hash OR ver.scope_document<>NEW.scope_snapshot THEN
 RAISE EXCEPTION 'mission scope mismatch' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mission_scope BEFORE INSERT OR UPDATE ON missions FOR EACH ROW EXECUTE FUNCTION protect_mission_scope();
