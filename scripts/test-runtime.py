"""Runtime HTTP verification acceptance.

Starts a loopback HTTP server, executes a session/redirect plan through the real
CLI, and checks bounded evidence redaction. No database, model or external
network is used.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send(self, status, body=b"", location=None, cookie=None):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            self._send(200, b"login page")
        elif path == "/admin":
            cookie = self.headers.get("Cookie", "")
            if "session=ok" not in cookie:
                self._send(302, location="/login")
            else:
                self._send(200, b"admin page")
        elif path == "/large":
            self._send(200, b"x" * (70 * 1024) + b"needle")
        else:
            self._send(404, b"missing")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        if path == "/dologin" and form.get("user") == ["admin"] and form.get("pass") == ["secret"]:
            self._send(302, location="/admin", cookie="session=ok; Path=/")
        else:
            self._send(403, b"denied")


@contextmanager
def loopback_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-runtime-")
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


def run_cli(binary, env, plan, approved, allow_loopback=True):
    args = [str(binary), "runtime", "http", "--plan", str(plan), "--approve-target", approved]
    if allow_loopback:
        args.append("--allow-loopback")
    return subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120)


def main():
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_MODEL_API_KEY",
                 "TRIDENT_TEST_DATABASE_URL", "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with loopback_server() as origin, temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        built = subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                               cwd=ROOT, env=env, capture_output=True, text=True,
                               encoding="utf-8", timeout=180)
        require(built.returncode == 0, built.stderr.strip() or "go build failed")
        plan = {
            "schema_version": 1,
            "name": "session-flow",
            "base_url": origin,
            "requests": [
                {"id": "login-page", "method": "GET", "path": "/login",
                 "expect": {"status": 200, "body_contains": "login page"}},
                {"id": "admin-unauth", "method": "GET", "path": "/admin",
                 "expect": {"status": 302, "location_prefix": "/login"}},
                {"id": "do-login", "method": "POST", "path": "/dologin", "session": "manager",
                 "form": {"user": "admin", "pass": "secret"},
                 "expect": {"status": 302, "location_prefix": "/admin"}},
                {"id": "admin-auth", "method": "GET", "path": "/admin", "session": "manager",
                 "expect": {"status": 200, "body_contains": "admin page"}},
            ],
        }
        plan_path = parent / "plan.json"
        plan_path.write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
        result = run_cli(binary, env, plan_path, origin)
        require(result.returncode == 0, result.stderr.strip() or "runtime verification failed")
        require("secret" not in result.stdout, "credentials leaked into runtime evidence")
        report = json.loads(result.stdout)
        require(report["status"] == "passed" and report["runtime_status"] == "observed",
                f"runtime status mismatch: {report}")
        require(report["coverage"]["requests"] == 4 and report["coverage"]["passed"] == 4,
                f"coverage mismatch: {report['coverage']}")
        by_id = {item["id"]: item for item in report["results"]}
        require(by_id["admin-unauth"]["observed_status"] == 302
                and by_id["admin-unauth"]["location"] == "/login",
                "redirect was followed or location lost")
        require(by_id["admin-auth"]["observed_status"] == 200, "session cookie was not reused")

        failed_plan = {
            "schema_version": 1, "name": "wrong-expectation", "base_url": origin,
            "requests": [{"id": "wrong", "method": "GET", "path": "/admin",
                          "expect": {"status": 200}}],
        }
        failed_path = parent / "failed.json"
        failed_path.write_text(json.dumps(failed_plan), encoding="utf-8")
        failed = run_cli(binary, env, failed_path, origin)
        require(failed.returncode != 0, "failing assertion returned success")
        failed_report = json.loads(failed.stdout)
        require(failed_report["status"] == "failed", "failing report status mismatch")

        unapproved = run_cli(binary, env, plan_path, "http://127.0.0.1:1")
        require(unapproved.returncode != 0, "unapproved origin was accepted")

        loopback = run_cli(binary, env, plan_path, origin, allow_loopback=False)
        require(loopback.returncode != 0, "loopback without explicit approval was accepted")

        print(json.dumps({
            "result": "passed", "origin": origin, "requests": report["coverage"]["requests"],
            "checks": ["runtime_observed", "session_cookie", "redirect_not_followed",
                       "credentials_redacted", "failing_assertion", "origin_allowlist",
                       "loopback_approval"],
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT runtime verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
