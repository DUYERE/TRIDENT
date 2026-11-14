#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证只读 Web 控制台；不执行 Java/模型/数据库。"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"
ADVISORY = FIXTURE / "advisories" / "CVE-2022-42889.json"
TOKEN = "web-acceptance-token-0123456789"


def tree_hashes(root):
    return {str(path.relative_to(root)).replace(os.sep, "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-web-")
    try:
        yield work
    finally:
        for attempt in range(40):
            try:
                shutil.rmtree(work)
                break
            except FileNotFoundError:
                break
            except OSError:
                if attempt == 39:
                    print(f"WARNING: temporary verification directory retained: {work}", file=sys.stderr)
                else:
                    time.sleep(0.25)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def request(base, path, method="GET", headers=None, body=None):
    request_headers = dict(headers or {})
    data = None
    if body is not None:
        data = body.encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    call = urllib.request.Request(base + path, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(call, timeout=30) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def token_sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before, "Missing synthetic Java fixture")
    require(ADVISORY.is_file(), "Missing synthetic advisory fixture")
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                       cwd=ROOT, env=env, check=True, timeout=180)
        snapshot = parent / "snapshot"
        imported = subprocess.run(
            [str(binary), "project", "import", "--source", str(FIXTURE), "--snapshot", str(snapshot)],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
        require(imported.returncode == 0, imported.stderr.strip() or "import failed")
        snapshot_hash = json.loads(imported.stdout)["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)

        port = free_port()
        base = f"http://127.0.0.1:{port}"
        server = subprocess.Popen(
            [str(binary), "web", "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
             "--advisories", str(ADVISORY), "--addr", f"127.0.0.1:{port}", "--token", TOKEN],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        try:
            ready = False
            for _ in range(80):
                if server.poll() is not None:
                    break
                try:
                    status, _, _ = request(base, "/")
                    if status == 200:
                        ready = True
                        break
                except (urllib.error.URLError, ConnectionError):
                    pass
                time.sleep(0.1)
            require(ready, "console did not become ready: " + (server.stderr.read() if server.poll() is not None else "timeout"))

            status, headers, body = request(base, "/")
            require(status == 200 and b"TRIDENT" in body, "console shell missing")
            require(header(headers, "Content-Security-Policy") and header(headers, "X-Content-Type-Options") == "nosniff",
                    "security headers missing")
            status, _, body = request(base, "/assets/app.js")
            require(status == 200 and b"read-only console" in body, "console script missing")
            for asset in ("/assets/brand.png", "/assets/favicon.png"):
                status, asset_headers, asset_body = request(base, asset)
                require(status == 200 and header(asset_headers, "Content-Type") == "image/png"
                        and len(asset_body) > 512, f"brand asset missing: {asset}")
            status, _, _ = request(base, "/assets/")
            require(status == 404, "asset directory listing must be rejected")

            console = {"X-Trident-Request": "console"}
            status, _, body = request(base, "/api/overview", headers=console)
            require(status == 401 and b"unauthorized" in body, "missing token must be rejected")
            status, _, _ = request(base, "/api/overview", headers={"X-Trident-Token": TOKEN})
            require(status == 403, "missing console header must be rejected")
            status, _, _ = request(base, "/api/overview", headers={**console, "X-Trident-Token": "wrong-token-0123456789"})
            require(status == 401, "wrong token must be rejected")

            status, headers, _ = request(base, "/api/session", method="POST", headers=console,
                                         body=json.dumps({"token": TOKEN}))
            require(status == 204, f"session exchange failed: {status}")
            cookie_header = header(headers, "Set-Cookie")
            require("HttpOnly" in cookie_header and "SameSite=Strict" in cookie_header,
                    "session cookie flags missing")
            cookie = cookie_header.split(";", 1)[0]
            authorized = {**console, "Cookie": cookie}

            status, _, body = request(base, "/api/health", headers=authorized)
            require(status == 200 and json.loads(body)["status"] == "ok", "health failed")

            status, _, body = request(base, "/api/overview", headers=authorized)
            require(status == 200, f"overview failed: {status}")
            overview = json.loads(body)
            require(overview["schema_version"] == 1 and overview["snapshot"]["hash"] == snapshot_hash,
                    "overview snapshot identity mismatch")
            require(overview["snapshot"]["total_files"] == 14, "overview file count mismatch")
            require(overview["counts"]["total"] == 7 and overview["counts"]["static_confirmed"] == 1,
                    "overview finding counts mismatch")
            require(overview["analysis"]["runtime_status"] == "not_run", "runtime status must stay not_run")
            categories = {item["key"]: item for item in overview["categories"]}
            require(categories["sql"]["static_confirmed"] == 1 and categories["dependency"]["total"] == 1
                    and categories["authz"]["total"] == 3,
                    "category counts mismatch")

            status, _, body = request(base, "/api/findings?status=static_confirmed&limit=10", headers=authorized)
            require(status == 200, "findings request failed")
            listing = json.loads(body)
            require(listing["filtered"] == 1 and listing["items"][0]["kind"] == "sql_injection",
                    "confirmed finding filter mismatch")
            finding_id = listing["items"][0]["id"]
            status, _, body = request(base, "/api/finding?id=" + urllib.parse.quote(finding_id, safe=""), headers=authorized)
            require(status == 200, "finding detail failed")
            detail = json.loads(body)
            require(detail["runtime_status"] == "not_run" and detail["evidence"] and detail["hypotheses"],
                    "finding detail evidence missing")

            status, _, body = request(base, "/api/endpoints", headers=authorized)
            endpoints = json.loads(body)
            require(status == 200 and endpoints["total"] == 3, "endpoint inventory mismatch")
            require(endpoints["items"][0]["path"].startswith("/synthetic/customers/"), "endpoint path mismatch")

            status, _, body = request(base, "/api/dependencies", headers=authorized)
            dependencies = json.loads(body)["report"]
            require(status == 200 and dependencies["project"]["build_system"] == "Maven",
                    "dependency build system mismatch")
            require(any(match["finding_status"] == "candidate" for match in dependencies["advisory_matches"]),
                    "advisory candidate missing")

            status, _, body = request(base, "/api/files?limit=50", headers=authorized)
            files = json.loads(body)
            require(status == 200 and files["total"] == 14, "file list mismatch")
            status, _, body = request(base, "/api/file?path=pom.xml&limit=20", headers=authorized)
            require(status == 200 and json.loads(body)["sha256"], "file read missing digest")
            status, _, _ = request(base, "/api/file?path=" + urllib.parse.quote("../pom.xml"), headers=authorized)
            require(status == 400, "path traversal must be rejected")
            status, _, _ = request(base, "/api/file?path=missing.java", headers=authorized)
            require(status == 404, "missing file must be 404")
            status, _, body = request(base, "/api/search?q=RestController", headers=authorized)
            require(status == 200 and json.loads(body)["matches"], "source search missing match")

            status, headers, body = request(base, "/api/report", headers=authorized)
            require(status == 200 and "attachment" in header(headers, "Content-Disposition"),
                    "report download headers missing")
            report = json.loads(body)
            require(report["coverage"]["findings_total"] == 7, "report coverage mismatch")

            status, headers, body = request(base, "/api/sbom", headers=authorized)
            require(status == 200 and "attachment" in header(headers, "Content-Disposition")
                    and json.loads(body)["bomFormat"] == "CycloneDX", "SBOM download failed")

            status, _, _ = request(base, "/api/findings?limit=0", headers=authorized)
            require(status == 400, "invalid limit must be rejected")

            # Observability endpoints: unauthenticated liveness probe and a
            # token-gated read-only metrics snapshot.
            status, headers, body = request(base, "/healthz")
            require(status == 200 and header(headers, "Content-Type").startswith("application/json"),
                    f"/healthz must be an unauthenticated JSON probe: {status}")
            health = json.loads(body)
            require(health.get("status") == "ok" and health.get("product") == "TRIDENT" and health.get("version"),
                    f"/healthz payload: {health}")
            status, _, _ = request(base, "/api/metrics", headers=console)
            require(status == 401, "metrics without token must be rejected")
            status, headers, body = request(base, "/api/metrics", headers=authorized)
            require(status == 200 and header(headers, "Content-Type").startswith("application/json"),
                    f"metrics failed: {status}")
            metrics = json.loads(body)
            require(set(metrics) == {"product", "version", "uptime_seconds", "requests", "analysis"},
                    f"unexpected metrics fields: {sorted(metrics)}")
            require(metrics["requests"]["total"] >= 1 and metrics["requests"]["unauthorized"] >= 1,
                    f"metrics request counters: {metrics['requests']}")
            require(metrics["analysis"]["cached"] and metrics["analysis"]["cached_ok"]
                    and metrics["analysis"]["runs_total"] >= 1,
                    f"metrics analysis counters: {metrics['analysis']}")

            # Prometheus scrape endpoint: token-gated, bearer-friendly, plain
            # text 0.0.4. The JSON read above counted itself, so the scrape
            # total must be exactly json_total + 2 (this 401 probe + this scrape).
            status, _, _ = request(base, "/metrics")
            require(status == 401, "scrape without token must be rejected")
            status, headers, body = request(base, "/metrics", headers={**console, "Authorization": f"Bearer {TOKEN}"})
            require(status == 200 and header(headers, "Content-Type").startswith("text/plain; version=0.0.4"),
                    f"scrape failed: {status} {header(headers, 'Content-Type')}")
            scrape_text = body.decode("utf-8")
            for name in ("trident_console_build_info", "trident_console_uptime_seconds",
                         "trident_console_requests_total", "trident_console_requests_unauthorized_total",
                         "trident_console_requests_forbidden_total", "trident_console_analysis_runs_total",
                         "trident_console_analysis_cache_hits_total", "trident_console_analysis_failures_total",
                         "trident_console_analysis_cached", "trident_console_analysis_cached_ok",
                         "trident_console_analysis_last_duration_milliseconds"):
                require(f"# TYPE {name} " in scrape_text, f"scrape missing TYPE {name}")
            samples = dict(line.rsplit(" ", 1) for line in scrape_text.splitlines()
                           if line.startswith("trident_console_") and not line.startswith("#"))
            require(int(samples["trident_console_requests_total"]) == metrics["requests"]["total"] + 2,
                    f"scrape total drift: {samples.get('trident_console_requests_total')} vs {metrics['requests']['total']}")
            require(int(samples["trident_console_analysis_cached"]) == 1
                    and int(samples["trident_console_analysis_cached_ok"]) == 1,
                    f"scrape cache gauges: {samples}")
            require(TOKEN not in scrape_text, "scrape output must not contain the token")

            print("[01] console shell, token gate, session cookie and security headers: PASS")
            print("[02] overview, findings, endpoints, dependencies and file tools: PASS")

            # Extended read-only views: dependency tree and SARIF download come
            # from the same cached analysis; unconfigured optional sources answer
            # 409 with actionable guidance instead of failing silently.
            status, headers, body = request(base, "/api/tree", headers=authorized)
            tree_text = body.decode("utf-8")
            require(status == 200 and '"roots"' in tree_text and '"coverage"' in tree_text,
                    f"tree failed: {status}")
            status, _, body = request(base, "/api/sarif", headers=authorized)
            sarif_text = body.decode("utf-8")
            require(status == 200 and '"2.1.0"' in sarif_text and '"runs"' in sarif_text,
                    f"sarif download failed: {status}")
            for path in ("/api/reachability", "/api/runtime-report", "/api/agent/runs"):
                status, _, body = request(base, path, headers=authorized)
                require(status == 412, f"{path} without configuration must be 412: {status}")
            print("[02b] dependency tree, SARIF download and 412 guidance for unconfigured views: PASS")
            print("[03] runtime_status=not_run, traversal rejection and evidence report: PASS")
            print("[04] /healthz liveness probe and token-gated /api/metrics counters: PASS")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

        # ── Phase 2: multi-user token file, rotation, deterministic export and
        # JSONL access log. Same snapshot; still no database/model/Java.
        alice_token = "web-alice-token-0123456789"
        bob_token = "web-bob-token-0123456789"
        carol_token = "web-carol-token-0123456789"
        tokens_path = parent / "tokens.json"
        log_path = parent / "access.jsonl"

        def write_tokens(users):
            tokens_path.write_text(json.dumps(
                [{"id": user_id, "role": role, "token_hash": token_sha256(value)}
                 for user_id, role, value in users], indent=1), encoding="utf-8")
            future = time.time() + 2
            os.utime(tokens_path, (future, future))

        write_tokens([("alice", "reviewer", alice_token), ("bob", "auditor", bob_token)])
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        console_header = {"X-Trident-Request": "console"}
        server = subprocess.Popen(
            [str(binary), "web", "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
             "--advisories", str(ADVISORY), "--addr", f"127.0.0.1:{port}",
             "--tokens", str(tokens_path), "--access-log", str(log_path)],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        try:
            ready = False
            for _ in range(80):
                if server.poll() is not None:
                    break
                try:
                    status, _, _ = request(base, "/")
                    if status == 200:
                        ready = True
                        break
                except (urllib.error.URLError, ConnectionError):
                    pass
                time.sleep(0.1)
            require(ready, "multi-user console did not become ready: "
                    + (server.stderr.read() if server.poll() is not None else "timeout"))

            alice = {**console_header, "X-Trident-Token": alice_token}
            bob = {**console_header, "X-Trident-Token": bob_token}
            status, _, _ = request(base, "/api/overview", headers=alice)
            require(status == 200, f"alice overview failed: {status}")
            status, _, _ = request(base, "/api/health", headers=bob)
            require(status == 200, f"bob health failed: {status}")
            status, _, _ = request(base, "/api/overview", headers={**console_header, "X-Trident-Token": "charlie-token-0123456789"})
            require(status == 401, "unknown user token must be rejected")

            # Rotation: alice re-keyed, bob revoked, carol added; no restart.
            write_tokens([("alice", "reviewer", "web-alice-token-rotated-123456"),
                          ("carol", "reviewer", carol_token)])
            status, _, _ = request(base, "/api/overview", headers=alice)
            require(status == 401, "rotated-out alice token must be rejected")
            status, _, _ = request(base, "/api/overview", headers=bob)
            require(status == 401, "revoked bob token must be rejected")
            alice = {**console_header, "X-Trident-Token": "web-alice-token-rotated-123456"}
            status, _, _ = request(base, "/api/overview", headers=alice)
            require(status == 200, "rotated-in alice token must be accepted")
            carol = {**console_header, "X-Trident-Token": carol_token}
            status, _, _ = request(base, "/api/overview", headers=carol)
            require(status == 200, "carol token must be accepted")

            # Deterministic HTML export: byte-identical, no external URLs, no
            # wall-clock timestamps.
            status, headers, body = request(base, "/export/report", headers=alice)
            require(status == 200 and header(headers, "Content-Type") == "text/html; charset=utf-8",
                    f"export failed: {status} {header(headers, 'Content-Type')}")
            require("attachment" in header(headers, "Content-Disposition")
                    and ".html" in header(headers, "Content-Disposition"), "export disposition missing")
            status, _, body_again = request(base, "/export/report", headers=carol)
            require(body == body_again, "export must be byte-identical across users and requests")
            text = body.decode("utf-8")
            require(snapshot_hash[:12] in text, "export must pin the snapshot hash")
            require("sql_injection" in text, "export must contain finding details")
            for banned in ("http://", "https://", "<script", 'src="'):
                require(banned not in text, f"export must not contain external resource marker: {banned}")
            require(re.search(r"20\d{2}-\d{2}-\d{2}T", text) is None, "export must not contain ISO timestamps")

            # JSONL access audit: fixed fields, per-user ids, no token values.
            require(log_path.is_file(), "access log missing")
            lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            require(lines, "access log is empty")
            seen_ids = set()
            for line in lines:
                record = json.loads(line)
                require(set(record) == {"time", "token_id", "method", "path", "status"},
                        f"unexpected access record fields: {sorted(record)}")
                require("?" not in record["path"], "access record must not contain a query string")
                seen_ids.add(record["token_id"])
            require({"alice", "carol", ""} <= seen_ids, f"access log token ids incomplete: {sorted(seen_ids)}")
            log_text = log_path.read_text(encoding="utf-8")
            for secret in (alice_token, bob_token, carol_token, "web-alice-token-rotated-123456", TOKEN):
                require(secret not in log_text, "access log must never contain a token value")
            print("[05] multi-user token file isolation, rotation and revocation: PASS")
            print("[06] deterministic HTML export (byte-identical, no external URLs, no timestamps): PASS")
            print("[07] JSONL access audit log with per-user ids and no token values: PASS")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

        require(tree_hashes(snapshot) == snapshot_before, "snapshot changed during console verification")
        require(tree_hashes(FIXTURE) == fixture_before, "fixture changed during console verification")
        print("[08] snapshot and fixture are byte-identical; no database/model/Java execution: PASS")
        print("TRIDENT web console acceptance passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
