#!/usr/bin/env python
"""[01] 在一次性 PostgreSQL 18 容器中演练最小权限账号、迁移/运行分离与备份恢复。

演练库是本地临时容器，不是生产环境；脚本不会触碰既有测试库或用户数据。
角色密码在内存中随机生成，不写入磁盘，也不打印。
"""
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "postgres:18@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42"
CONTAINER = "trident-db-governance-drill"
DRILL_DB = "trident_drill"
RESTORE_DB = "trident_drill_restore"


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


def expect_failure(result, needle, label):
    text = (result.stdout + result.stderr).lower()
    if result.returncode == 0 or needle not in text:
        raise RuntimeError(f"{label}: expected failure containing {needle!r}")


def trident(*args, dsn, extra_env=None):
    env = os.environ.copy()
    env["TRIDENT_DATABASE_URL"] = dsn
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["go", "run", "./cmd/trident", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True)


def count(database, table):
    return int(psql("postgres", database, f"SELECT count(*) FROM {table}").stdout.strip())


def main():
    super_password = secrets.token_hex(24)
    passwords = {role: secrets.token_hex(24) for role in
                 ("trident_migrator", "trident_runtime", "trident_readonly")}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    started = False
    try:
        docker("run", "-d", "--rm", "--name", CONTAINER,
               "--security-opt", "no-new-privileges:true",
               "-e", f"POSTGRES_PASSWORD={super_password}",
               "-p", f"127.0.0.1:{port}:5432", IMAGE)
        started = True
        for _ in range(60):
            ready = docker("exec", CONTAINER, "pg_isready", "-U", "postgres", "-d", "postgres", check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("postgres container did not become ready")

        # [02] 角色与库由超级用户创建；演练后随容器一起销毁。
        psql("postgres", "postgres", "\n".join(
            f"CREATE ROLE {role} LOGIN PASSWORD '{password}';" for role, password in passwords.items()))
        psql("postgres", "postgres", f"CREATE DATABASE {DRILL_DB} OWNER trident_migrator;")
        psql("postgres", DRILL_DB, f"""
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE {DRILL_DB} TO trident_migrator, trident_runtime, trident_readonly;
GRANT USAGE, CREATE ON SCHEMA public TO trident_migrator;
GRANT USAGE ON SCHEMA public TO trident_runtime, trident_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trident_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO trident_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT SELECT ON TABLES TO trident_readonly;
""")
        print("PASS roles created; migrate/runtime/readonly separated")

        def dsn(role, database=DRILL_DB):
            return (f"postgres://{role}:{quote(passwords[role], safe='')}"
                    f"@127.0.0.1:{port}/{database}?sslmode=disable")

        actor = {"TRIDENT_MIGRATION_ACTOR": "drill-migrator"}

        # [03] 迁移只能由 migrator 执行；重复执行必须幂等。
        for attempt in ("first", "second"):
            result = trident("migrate", dsn=dsn("trident_migrator"), extra_env=actor)
            if result.returncode != 0:
                raise RuntimeError(f"migrate as migrator ({attempt}) failed: {result.stderr.strip()}")
        print("PASS migrate as trident_migrator (idempotent)")

        # [04] runtime/readonly 可校验 Schema，但不能建表或执行 DDL。
        for role in ("trident_runtime", "trident_readonly"):
            result = trident("check", dsn=dsn(role))
            if result.returncode != 0:
                raise RuntimeError(f"check as {role} failed: {result.stderr.strip()}")
        print("PASS check as trident_runtime and trident_readonly")

        expect_failure(trident("migrate", dsn=dsn("trident_runtime"), extra_env=actor),
                       "permission denied", "migrate as runtime")
        expect_failure(psql("trident_runtime", DRILL_DB, "CREATE TABLE drill_denied(id int)",
                            passwords["trident_runtime"], check=False),
                       "permission denied", "runtime DDL")
        expect_failure(psql("trident_runtime", DRILL_DB, "CREATE ROLE drill_escalation LOGIN",
                            passwords["trident_runtime"], check=False),
                       "permission denied", "runtime role escalation")
        expect_failure(psql("trident_readonly", DRILL_DB,
                            "INSERT INTO principals(subject,principal_type,role,credential_hash) VALUES('x','human','admin','x')",
                            passwords["trident_readonly"], check=False),
                       "permission denied", "readonly write")
        print("PASS runtime/readonly denied DDL, role creation and writes")

        # [05] 新表继承默认权限：runtime 可 DML，readonly 只读。
        psql("trident_migrator", DRILL_DB,
             "CREATE TABLE drill_probe(id bigint generated always as identity primary key, note text)",
             passwords["trident_migrator"])
        psql("trident_runtime", DRILL_DB,
             "INSERT INTO drill_probe(note) VALUES('runtime-write'); UPDATE drill_probe SET note='runtime-update'",
             passwords["trident_runtime"])
        if psql("trident_readonly", DRILL_DB, "SELECT count(*) FROM drill_probe",
                passwords["trident_readonly"]).stdout.strip() != "1":
            raise RuntimeError("readonly could not read drill_probe")
        print("PASS default privileges: runtime DML, readonly SELECT")

        # [06] 真实应用写入路径（bootstrap + demo-offline）在 runtime 账号下可用。
        env = {"TRIDENT_CONFIRM_TEST_DATABASE": "yes"}
        boot = trident("bootstrap", "drill-admin", dsn=dsn("trident_runtime"), extra_env=env)
        if boot.returncode != 0:
            raise RuntimeError(f"bootstrap as runtime failed: {boot.stderr.strip()}")
        import json
        token = json.loads(boot.stdout)["token"]
        env["TRIDENT_TOKEN"] = token
        demo = trident("demo-offline", dsn=dsn("trident_runtime"), extra_env=env)
        if demo.returncode != 0:
            raise RuntimeError(f"demo-offline as runtime failed: {demo.stderr.strip()}")
        if count(DRILL_DB, "principals") < 2:
            raise RuntimeError("demo-offline did not persist principals")
        print("PASS application writes as trident_runtime (bootstrap + demo-offline)")

        # [07] 备份恢复演练：custom 格式导出，恢复到新库后校验 Schema 与行数。
        docker("exec", CONTAINER, "pg_dump", "-U", "postgres", "--format=custom",
               f"--file=/tmp/{DRILL_DB}.dump", "-d", DRILL_DB)
        docker("exec", CONTAINER, "sh", "-c", f"test -s /tmp/{DRILL_DB}.dump")
        psql("postgres", "postgres", f"CREATE DATABASE {RESTORE_DB} OWNER trident_migrator;")
        docker("exec", CONTAINER, "pg_restore", "-U", "postgres",
               "-d", RESTORE_DB, f"/tmp/{DRILL_DB}.dump")
        restored_check = trident("check", dsn=dsn("trident_migrator", RESTORE_DB))
        if restored_check.returncode != 0:
            raise RuntimeError(f"check on restored database failed: {restored_check.stderr.strip()}")
        for table in ("principals", "tasks", "tool_calls", "approvals", "schema_migrations"):
            before, after = count(DRILL_DB, table), count(RESTORE_DB, table)
            if before != after:
                raise RuntimeError(f"restore mismatch for {table}: {before} != {after}")
        print("PASS pg_dump/pg_restore drill; schema checksum and row counts match")

        print("TRIDENT database governance drill passed.")
    finally:
        if started:
            docker("rm", "-f", CONTAINER, check=False)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT database governance drill failed: {exc}", file=sys.stderr)
        sys.exit(1)
