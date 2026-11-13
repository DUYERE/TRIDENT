#!/usr/bin/env python
"""[01] 在一次性 Linux Go 容器中执行真实数据库 -race 验收，不暴露凭据到进程参数。"""
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "golang:1.26.3-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b"


def main():
    values = dict(line.split("=", 1) for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines()
                  if line.strip() and not line.startswith("#") and "=" in line)
    admin = json.loads((ROOT / "secrets" / "test-admin.json").read_text(encoding="utf-8"))
    env = os.environ.copy()
    env["TRIDENT_TEST_DATABASE_URL"] = (
        "postgres://trident_test:" + quote(values["TRIDENT_POSTGRES_PASSWORD"], safe="") +
        "@postgres:5432/trident_test?sslmode=disable")
    env["TRIDENT_TEST_ADMIN_TOKEN"] = admin["token"]
    env["TRIDENT_TEST_DATABASE_NETWORK"] = "isolated-compose"
    # [02] 源码只读挂载，独立构建缓存；环境变量按名称转发，Token/DSN 不进入 argv。
    command = ["docker", "run", "--rm", "--network", "trident-p0_default",
               "--mount", f"type=bind,source={ROOT},target=/workspace,readonly",
               "--mount", "type=volume,source=trident-p0-go-mod,target=/go/pkg/mod",
               "--mount", "type=volume,source=trident-p0-go-build,target=/root/.cache/go-build",
               "-w", "/workspace", "-e", "TRIDENT_TEST_DATABASE_URL", "-e", "TRIDENT_TEST_ADMIN_TOKEN",
               "-e", "TRIDENT_TEST_DATABASE_NETWORK",
               "-e", "GOPROXY=https://goproxy.cn,direct", IMAGE,
               # [03] 串行包执行，避免遗留 wall-clock/DB-lock 用例在并行包负载下抖动；
               # 这是测试调度，不放宽任何断言或安全边界。
               "go", "test", "-mod=readonly", "-race", "-tags=integration", "-count=1", "-timeout=240s", "-p", "1", "./..."]
    subprocess.run(command, env=env, check=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"TRIDENT Linux tests failed: {exc}", file=sys.stderr)
        sys.exit(1)
