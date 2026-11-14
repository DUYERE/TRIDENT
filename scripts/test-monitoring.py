#!/usr/bin/env python
"""[01] 用真实 Prometheus + Alertmanager 容器联调控制台指标与告警管道（P2-3）。

拓扑：控制台只绑定宿主机 loopback（安全边界，绝不放宽）；Prometheus 容器经
host.docker.internal 抓取宿主 loopback 的 /metrics（Bearer 令牌经 credentials_file
注入，不落仓库）；告警经 Alertmanager 分组后回调到本脚本起的本地 webhook，
端到端验证「评估 -> 分组 -> 通知」。

前提：Docker Desktop（Windows/macOS）语义的 host.docker.internal；Linux 需改用
socat sidecar 或宿主网络，不要放宽控制台的 loopback 绑定。
镜像为 tag pin（prom/prometheus:v2.53.0、prom/alertmanager:v0.27.0）；生产部署
必须按仓库密钥管理标准改为 digest pin。
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"
OPS = ROOT / "ops" / "monitoring"
GENERATED = OPS / "generated"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def get_json(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class WebhookReceiver(ThreadingHTTPServer):
    """Collects Alertmanager webhook payloads for the delivery assertion."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), self.Handler)
        self.payloads = []
        self.lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            with self.server.lock:
                self.server.payloads.append(body)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass


@contextmanager
def webhook_server():
    receiver = WebhookReceiver()
    thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    thread.start()
    try:
        yield receiver
    finally:
        receiver.shutdown()


def compose(*args):
    for command in (["docker", "compose"], ["docker-compose"]):
        probe = subprocess.run(command + ["version"], capture_output=True, text=True)
        if probe.returncode == 0:
            return subprocess.run(command + list(args), cwd=OPS, capture_output=True, text=True, timeout=600)
    raise RuntimeError("docker compose is not available")


def wait_until(predicate, timeout_seconds, describe):
    deadline = time.time() + timeout_seconds
    last_error = None
    while time.time() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except Exception as error:  # noqa: BLE001 - probe errors are retried
            last_error = error
        time.sleep(1)
    raise RuntimeError(f"{describe} timed out" + (f": {last_error}" if last_error else ""))


def main():
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)

    # ops/monitoring/prometheus.yml scrapes host.docker.internal:8787, so the
    # console must listen on the fixed loopback port for this drill.
    port = 8787
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", port))
    except OSError:
        raise RuntimeError(f"loopback port {port} is already in use; free it and rerun")
    finally:
        probe.close()

    token = "monitor-" + secrets.token_hex(24)
    alertmanager_port = free_port()
    payload = {"alerts": []}

    with webhook_server() as receiver:
        receiver_port = receiver.server_address[1]
        GENERATED.mkdir(parents=True, exist_ok=True)
        (GENERATED / "scrape-token").write_text(token, encoding="utf-8")
        (GENERATED / "alertmanager.yml").write_text(
            "route:\n"
            "  receiver: drill\n"
            "  group_by: [alertname]\n"
            "  group_wait: 0s\n"
            "  group_interval: 5s\n"
            "  repeat_interval: 1h\n"
            "receivers:\n"
            "  - name: drill\n"
            "    webhook_configs:\n"
            f"      - url: http://host.docker.internal:{receiver_port}/alert\n",
            encoding="utf-8")

        work = Path(tempfile.mkdtemp(prefix="trident-monitor-"))
        server = None
        compose_up = False
        try:
            binary = work / ("trident.exe" if os.name == "nt" else "trident")
            subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                           cwd=ROOT, env=env, check=True, timeout=180)
            snapshot = work / "snapshot"
            imported = subprocess.run(
                [str(binary), "project", "import", "--source", str(FIXTURE), "--snapshot", str(snapshot)],
                cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
            require(imported.returncode == 0, imported.stderr.strip() or "import failed")
            snapshot_hash = json.loads(imported.stdout)["snapshot_hash"]

            access_log = work / "access.jsonl"
            server = subprocess.Popen(
                [str(binary), "web", "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
                 "--advisories", str(FIXTURE / "advisories" / "CVE-2022-42889.json"),
                 "--addr", f"127.0.0.1:{port}", "--token", token, "--access-log", str(access_log)],
                cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            base = f"http://127.0.0.1:{port}"
            wait_until(lambda: get_json(f"{base}/healthz").get("status") == "ok",
                       20, "console readiness")

            up = compose("up", "-d", "--quiet-pull")
            require(up.returncode == 0, (up.stderr or up.stdout).strip() or "compose up failed")
            compose_up = True

            prometheus = "http://127.0.0.1:9090"
            targets = wait_until(lambda: [
                target for target in get_json(f"{prometheus}/api/v1/targets?state=active")
                .get("data", {}).get("activeTargets", [])
                if target.get("health") == "up"
            ] or None, 180, "prometheus target up")

            result = get_json(
                f"{prometheus}/api/v1/query?query=trident_console_analysis_cached")
            require(result.get("status") == "success" and result["data"]["result"],
                    f"metric not scraped: {json.dumps(result)[:300]}")

            alertmanager = "http://127.0.0.1:9093"
            # Prometheus fires the probe immediately, but its first notify attempt
            # races the Alertmanager gossip settle and the retry backoff can take
            # a few minutes; wait for the alert to appear in Alertmanager first.
            wait_until(lambda: any(
                alert["labels"].get("alertname") == "TridentAlertDeliveryProbe"
                for alert in get_json(f"{alertmanager}/api/v2/alerts")
            ) or None, 300, "alertmanager receiving the probe alert")

            wait_until(lambda: any(
                json.loads(item).get("alerts")
                and any(alert["labels"].get("alertname") == "TridentAlertDeliveryProbe"
                        for alert in json.loads(item)["alerts"])
                for item in list(receiver.payloads)
            ) or None, 180, "alertmanager webhook delivery")

            delivered = [json.loads(item) for item in receiver.payloads]
            payload = {"alerts": [alert["labels"].get("alertname") for item in delivered
                                  for alert in item.get("alerts", [])]}
            require("TridentAlertDeliveryProbe" in payload["alerts"],
                    f"probe alert missing from delivery: {payload}")

            lines = [line for line in access_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            scrape_records = [json.loads(line) for line in lines if json.loads(line)["path"] == "/metrics"]
            require(scrape_records and all(record["token_id"] == "local" for record in scrape_records),
                    f"scrape access records missing: {len(scrape_records)}")
            require(all(record["status"] == 200 for record in scrape_records),
                    f"scrape statuses: {[record['status'] for record in scrape_records]}")

            print("[01] prometheus scraped /metrics with bearer token (target up): PASS")
            print("[02] trident_console_* metrics queryable in prometheus: PASS")
            print("[03] alert rule evaluated and delivered through alertmanager webhook: PASS")
            print("[04] scrape requests recorded in the JSONL access audit with token ids: PASS")
            print("TRIDENT monitoring drill passed.")
        finally:
            if compose_up:
                down = compose("down", "-v")
                if down.returncode != 0:
                    print(f"WARNING: compose down failed: {(down.stderr or '').strip()}", file=sys.stderr)
            if server is not None and server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
            shutil.rmtree(GENERATED, ignore_errors=True)
            shutil.rmtree(work, ignore_errors=True)
            print(f"delivered alert groups: {payload.get('alerts', [])}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
