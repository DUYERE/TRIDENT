#!/usr/bin/env python
"""[01] 使用独立 Compose 测试库运行真实 PG 验收；不清理/重置既有数据。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--race", action="store_true")
    args = parser.parse_args()
    env_file = ROOT / ".env"
    if not env_file.is_file():
        raise RuntimeError("Missing .env; configure TRIDENT_POSTGRES_PASSWORD first")
    values = dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines()
                  if line.strip() and not line.lstrip().startswith("#") and "=" in line)
    password = values.get("TRIDENT_POSTGRES_PASSWORD", "")
    if not password or password == "replace-with-a-random-local-password":
        raise RuntimeError("Configure a random test database password")
    env = os.environ.copy()
    dsn = f"postgres://trident_test:{quote(password, safe='')}@127.0.0.1:55432/trident_test?sslmode=disable"
    env["TRIDENT_DATABASE_URL"] = dsn
    env["TRIDENT_TEST_DATABASE_URL"] = dsn
    env["TRIDENT_MIGRATION_ACTOR"] = "local-test-runner"
    subprocess.run(["go", "run", "./cmd/trident", "migrate"], cwd=ROOT, env=env, check=True)
    # [02] 只在显式专属测试库初始化一次，凭据缓存被 .gitignore 排除；不输出 Token。
    secret = ROOT / "secrets" / "test-admin.json"
    if secret.exists():
        admin = json.loads(secret.read_text(encoding="utf-8"))
    else:
        result = subprocess.run(["go", "run", "./cmd/trident", "bootstrap", "local-test-admin"],
                                cwd=ROOT, env=env, check=True, capture_output=True, text=True)
        admin = json.loads(result.stdout)
        secret.parent.mkdir(exist_ok=True)
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(admin, stream)
        if os.name == "nt":
            # [03] Windows 不依赖 chmod 的兼容语义，用 DACL 限定当前用户。
            who = subprocess.run(["whoami"], check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["icacls", str(secret), "/inheritance:r", "/grant:r", f"{who}:(F)"],
                           check=True, capture_output=True, text=True)
    env["TRIDENT_TEST_ADMIN_TOKEN"] = admin["token"]
    env["TRIDENT_TOKEN"] = admin["token"]
    env["TRIDENT_CONFIRM_TEST_DATABASE"] = "yes"
    command = ["go", "test", "-tags=integration", "-count=1", "-timeout=180s", "-v"]
    if args.race:
        command.append("-race")
    subprocess.run(command + ["./..."], cwd=ROOT, env=env, check=True)
    subprocess.run(["go", "run", "./cmd/trident", "demo-offline"], cwd=ROOT, env=env, check=True)
    subprocess.run(["go", "run", "./cmd/trident", "check"], cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"TRIDENT local tests failed: {exc}", file=sys.stderr)
        sys.exit(1)
