#!/usr/bin/env python
"""[01] 生产数据量级的备份恢复演练与 RTO/RPO 实测（P2-3）。

一次性 PostgreSQL 18 容器 + 真实迁移 Schema；按规模参数灌入合成数据（默认
50 万 principals + 100 万 activities + 20 万 outbox_events，约数百 MB），计时
pg_dump(custom) -> pg_restore -> trident check + 行数核对，并演示 RPO 语义：
dump 之后、下一次备份之前写入的行不会出现在恢复库中（丢失窗口上限）。

演练库是一次性容器，不是生产环境；实测数字只覆盖本机磁盘与该数据量，
生产 RTO/RPO 承诺必须用生产设施重新测。角色密码随机生成，不落盘不打印。
"""
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "postgres:18@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42"
CONTAINER = "trident-backup-scale-drill"
DRILL_DB = "trident_scale_drill"
RESTORE_DB = "trident_scale_restore"

SCALE = {"principals": 500_000, "activities": 1_000_000, "outbox_events": 200_000, "tasks": 2_000}


def docker(*args, stdin=None, check=True):
    result = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {args[0]} failed: {(result.stderr or result.stdout).strip()}")
    return result


def psql(user, database, sql, password=None, check=True):
    command = ["exec", "-i"]
    if password:
        command += ["-e", f"PGPASSWORD={password}"]
    command += [CONTAINER, "psql", "-h", "127.0.0.1", "-U", user, "-d", database,
                "-v", "ON_ERROR_STOP=1", "-tAc", sql]
    return docker(*command, check=check)


def trident(*args, dsn):
    env = {**os.environ.copy(), "TRIDENT_DATABASE_URL": dsn, "TRIDENT_MIGRATION_ACTOR": "scale-migrator"}
    return subprocess.run(["go", "run", "./cmd/trident", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True)


def count(database, table):
    return int(psql("postgres", database, f"SELECT count(*) FROM {table}").stdout.strip())


def size_mb(database):
    raw = psql("postgres", database,
               f"SELECT pg_size_pretty(pg_database_size('{database}'))").stdout.strip()
    return raw


def main():
    super_password = secrets.token_hex(24)
    passwords = {role: secrets.token_hex(24) for role in ("trident_migrator", "trident_runtime")}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    started = False
    timings = {}
    try:
        docker("run", "-d", "--rm", "--name", CONTAINER,
               "--security-opt", "no-new-privileges:true",
               "-e", f"POSTGRES_PASSWORD={super_password}",
               "-p", f"127.0.0.1:{port}:5432", IMAGE)
        started = True
        for _ in range(60):
            if docker("exec", CONTAINER, "pg_isready", "-U", "postgres", "-d", "postgres",
                      check=False).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("postgres container did not become ready")

        psql("postgres", "postgres", "\n".join(
            f"CREATE ROLE {role} LOGIN PASSWORD '{password}';" for role, password in passwords.items()))
        psql("postgres", "postgres", f"CREATE DATABASE {DRILL_DB} OWNER trident_migrator;")
        psql("postgres", "postgres", f"CREATE DATABASE {RESTORE_DB} OWNER trident_migrator;")
        psql("postgres", DRILL_DB, f"""
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE {DRILL_DB} TO trident_migrator, trident_runtime;
GRANT USAGE, CREATE ON SCHEMA public TO trident_migrator;
GRANT USAGE ON SCHEMA public TO trident_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trident_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO trident_runtime;""")

        def dsn(role, database=DRILL_DB):
            return (f"postgres://{role}:{quote(passwords[role], safe='')}"
                    f"@127.0.0.1:{port}/{database}?sslmode=disable")

        for attempt in ("first", "second"):
            result = trident("migrate", dsn=dsn("trident_migrator"))
            if result.returncode != 0:
                raise RuntimeError(f"migrate ({attempt}) failed: {result.stderr.strip()}")
        print("PASS schema migrated (idempotent)")

        # [02] 合成数据灌入：真实迁移 Schema + 生产量级行数。
        insert_started = time.perf_counter()
        psql("trident_migrator", DRILL_DB,
             f"""INSERT INTO principals(subject, principal_type, role, credential_hash)
                 SELECT 'svc-'||g, 'service', 'worker',
                        md5('h'||g)||md5('t'||g)
                 FROM generate_series(1, {SCALE['principals']}) g""", passwords["trident_migrator"])
        psql("trident_migrator", DRILL_DB,
             """INSERT INTO authorization_contracts(principal_id, valid_from, expires_at)
                SELECT 1, now(), now() + interval '365 days'""", passwords["trident_migrator"])
        psql("trident_migrator", DRILL_DB,
             """INSERT INTO authorization_versions(authorization_id, version, scope_document, scope_hash, created_by)
                VALUES (1, 1, '{}'::jsonb, md5('scope')||md5('scope2'), 1)""", passwords["trident_migrator"])
        psql("trident_migrator", DRILL_DB,
             f"""INSERT INTO tasks(authorization_id, current_scope_ver, goal, deadline_at)
                SELECT 1, 1, 'synthetic task '||g, now() + interval '30 days'
                FROM generate_series(1, {SCALE['tasks']}) g""", passwords["trident_migrator"])
        psql("trident_runtime", DRILL_DB,
             f"""INSERT INTO activities(task_id, actor_id, kind, detail)
                SELECT (g % {SCALE['tasks']}) + 1, 1, 'synthetic',
                       jsonb_build_object('seq', g, 'note', repeat('x', 200))
                FROM generate_series(1, {SCALE['activities']}) g""",
             passwords["trident_runtime"])
        psql("trident_runtime", DRILL_DB,
             f"""INSERT INTO outbox_events(task_id, aggregate_kind, aggregate_id, aggregate_version,
                                           event_type, payload)
                SELECT (g % {SCALE['tasks']}) + 1, 'task', g, 1,
                       'synthetic_event', jsonb_build_object('seq', g, 'body', repeat('y', 300))
                FROM generate_series(1, {SCALE['outbox_events']}) g""",
             passwords["trident_runtime"])
        timings["seed_seconds"] = round(time.perf_counter() - insert_started, 1)
        volume = size_mb(DRILL_DB)
        print(f"PASS synthetic data seeded in {timings['seed_seconds']}s; drill database size {volume}")
        print(f"     rows: principals={count(DRILL_DB, 'principals')} "
              f"activities={count(DRILL_DB, 'activities')} "
              f"outbox_events={count(DRILL_DB, 'outbox_events')} tasks={count(DRILL_DB, 'tasks')}")

        # [03] 备份计时：custom 格式压缩导出。
        backup_started = time.perf_counter()
        docker("exec", CONTAINER, "pg_dump", "-U", "postgres", "--format=custom",
               "--compress=6", f"--file=/tmp/{DRILL_DB}.dump", "-d", DRILL_DB)
        timings["backup_seconds"] = round(time.perf_counter() - backup_started, 1)
        dump_bytes = int(docker("exec", CONTAINER, "sh", "-c",
                                f"stat -c %s /tmp/{DRILL_DB}.dump").stdout.strip())
        print(f"PASS pg_dump(custom, compress=6) in {timings['backup_seconds']}s; "
              f"archive {dump_bytes} bytes ({dump_bytes // (1 << 20)} MB)")

        # [04] RPO 语义演示：两次备份之间的写入不在恢复库中。
        rpo_started = time.perf_counter()
        psql("trident_runtime", DRILL_DB,
             """INSERT INTO activities(task_id, actor_id, kind, detail)
                SELECT (g % 2000) + 1, 1, 'after_backup',
                       jsonb_build_object('seq', g)
                FROM generate_series(1, 5000) g""", passwords["trident_runtime"])
        timings["rpo_writes_seconds"] = round(time.perf_counter() - rpo_started, 1)
        after_backup_count = count(DRILL_DB, "activities")

        # [05] 恢复计时 + 校验：restore -> check -> 行数核对（RPO 窗口行不在）。
        restore_started = time.perf_counter()
        docker("exec", CONTAINER, "pg_restore", "-U", "postgres",
               "-d", RESTORE_DB, f"/tmp/{DRILL_DB}.dump")
        timings["restore_seconds"] = round(time.perf_counter() - restore_started, 1)
        verify_started = time.perf_counter()
        check = trident("check", dsn=dsn("trident_migrator", RESTORE_DB))
        if check.returncode != 0:
            raise RuntimeError(f"check on restored database failed: {check.stderr.strip()}")
        mismatches = {}
        for table in ("principals", "activities", "outbox_events", "tasks",
                      "schema_migrations"):
            source, restored = count(DRILL_DB, table), count(RESTORE_DB, table)
            expected = source - (5000 if table == "activities" else 0)
            if restored != expected:
                mismatches[table] = (restored, expected)
        timings["verify_seconds"] = round(time.perf_counter() - verify_started, 1)
        if mismatches:
            raise RuntimeError(f"restore mismatch: {mismatches}")
        lost = after_backup_count - count(RESTORE_DB, "activities")
        if lost != 5000:
            raise RuntimeError(f"RPO window mismatch: {lost}")
        print(f"PASS pg_restore in {timings['restore_seconds']}s; check + row counts verified "
              f"in {timings['verify_seconds']}s")
        print(f"PASS RPO semantics: {lost} post-backup rows are outside the restore point "
              f"(max data loss window for backup-only strategy)")

        timings["rto_seconds"] = round(timings["restore_seconds"] + timings["verify_seconds"], 1)
        print("TIMINGS " + json.dumps(timings, ensure_ascii=False))
        print("     measured RTO (restore + verify) on this host: "
              f"{timings['rto_seconds']}s for ~{volume}; scale linearly and re-measure on production hardware.")
        print("TRIDENT backup scale drill passed.")
    finally:
        if started:
            docker("rm", "-f", CONTAINER, check=False)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT backup scale drill failed: {exc}", file=sys.stderr)
        sys.exit(1)
