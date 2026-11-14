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

    def _send(self, status, body=b"", location=None, cookie=None, content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _session(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return value
        return ""

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            self._send(200, b"login page")
        elif path == "/csrf-login":
            self._send(200, b'<html><head><meta name="_csrf" content="token-csrf"></head>'
                            b'<body><form><input type="hidden" name="_csrf" value="token-csrf">'
                            b'</form></body></html>', content_type="text/html; charset=utf-8")
        elif path == "/admin":
            session = self._session()
            if not session:
                self._send(302, location="/login")
            elif session == "guest":
                self._send(403, b"denied")
            else:
                self._send(200, b"admin page")
        elif path == "/reports":
            if self._session() == "admin":
                self._send(200, b"reports page")
            else:
                self._send(403, b"denied")
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
        elif path == "/secure-login" and form.get("_csrf") == ["token-csrf"] \
                and form.get("user") in (["admin"], ["guest"]) \
                and form.get("pass") == ["secret-runtime"]:
            self._send(302, location="/reports", cookie=f"session={form['user'][0]}; Path=/")
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
                 "TRIDENT_TEST_DATABASE_URL", "TRIDENT_TEST_ADMIN_TOKEN",
                 "TRIDENT_TEST_PASS", "TRIDENT_MISSING_PASS"):
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

        env["TRIDENT_TEST_PASS"] = "secret-runtime"
        login_steps = lambda user: [
            {"id": "page", "method": "GET", "path": "/csrf-login",
             "expect": {"status": 200}},
            {"id": "submit", "method": "POST", "path": "/secure-login",
             "form": {"user": user, "pass": "${ENV:TRIDENT_TEST_PASS}"},
             "expect": {"status": 302, "location_prefix": "/reports"}},
        ]
        matrix_plan = {
            "schema_version": 1,
            "name": "role-matrix",
            "base_url": origin,
            "roles": [
                {"id": "admin", "session": "role-admin", "login": login_steps("admin"),
                 "csrf": {"selector": "meta[name=_csrf]", "field": "_csrf"}},
                {"id": "guest", "session": "role-guest", "login": login_steps("guest"),
                 "csrf": {"selector": "input[name=_csrf]", "field": "_csrf"}},
            ],
            "requests": [
                {"id": "admin-page", "method": "GET", "path": "/admin",
                 "expect": {"status": 302}},
                {"id": "reports", "method": "GET", "path": "/reports",
                 "expect": {"status": 403}},
            ],
            "matrix": [
                {"role": "admin", "request": "admin-page",
                 "expect": {"status": 200, "body_contains": "admin page"}},
                {"role": "admin", "request": "reports",
                 "expect": {"status": 200, "body_contains": "reports page"}},
                {"role": "guest", "request": "admin-page", "expect": {"status": 403}},
                {"role": "guest", "request": "reports", "expect": {"status": 403}},
            ],
        }
        matrix_path = parent / "matrix.json"
        matrix_path.write_text(json.dumps(matrix_plan, ensure_ascii=False), encoding="utf-8")
        matrix_run = run_cli(binary, env, matrix_path, origin)
        require(matrix_run.returncode == 0, matrix_run.stderr.strip() or "role matrix failed")
        for secret in ("secret-runtime", "token-csrf"):
            require(secret not in matrix_run.stdout, "credentials or CSRF token leaked into evidence")
        matrix_report = json.loads(matrix_run.stdout)
        require(matrix_report["status"] == "passed"
                and matrix_report["runtime_status"] == "observed",
                f"matrix status mismatch: {matrix_report['status']}")
        require(matrix_report["coverage"]["requests"] == 10
                and matrix_report["coverage"]["passed"] == 10,
                f"matrix coverage mismatch: {matrix_report['coverage']}")
        for role in ("admin", "guest"):
            entry = matrix_report["coverage"]["roles"][role]
            require(entry["requests"] == 4 and entry["passed"] == 4
                    and entry["login_status"] == "complete",
                    f"role coverage mismatch for {role}: {entry}")
        cells = {item["id"]: item for item in matrix_report["results"]}
        require(cells["role:admin:submit"].get("csrf") == "token_injected",
                f"csrf injection not reported: {cells['role:admin:submit']}")
        require(cells["matrix:admin:reports"]["observed_status"] == 200
                and cells["matrix:guest:reports"]["observed_status"] == 403
                and cells["matrix:guest:admin-page"]["observed_status"] == 403,
                "role matrix responses do not match the declared roles")

        missing_csrf = {
            "schema_version": 1, "name": "csrf-missing", "base_url": origin,
            "roles": [{"id": "broken", "login": login_steps("admin"),
                       "csrf": {"selector": "input[name=absent]", "field": "_csrf"}}],
            "requests": [{"id": "admin-page", "method": "GET", "path": "/admin",
                          "expect": {"status": 302}}],
            "matrix": [{"role": "broken", "request": "admin-page",
                        "expect": {"status": 200}}],
        }
        missing_path = parent / "csrf-missing.json"
        missing_path.write_text(json.dumps(missing_csrf), encoding="utf-8")
        missing = run_cli(binary, env, missing_path, origin)
        require(missing.returncode != 0, "missing CSRF token did not fail verification")
        missing_report = json.loads(missing.stdout)
        require(missing_report["status"] == "inconclusive"
                and missing_report["coverage"]["roles"]["broken"]["login_status"] == "incomplete",
                f"missing CSRF report mismatch: {missing_report['status']}")
        missing_cells = {item["id"]: item for item in missing_report["results"]}
        require(missing_cells["role:broken:submit"].get("error") == "csrf_token_not_found"
                and missing_cells["matrix:broken:admin-page"].get("error") == "role_login_incomplete",
                "missing CSRF error codes mismatch")

        unresolved_env = json.loads(json.dumps(missing_csrf))
        unresolved_env["name"] = "unresolved-env"
        unresolved_env["roles"][0]["login"][1]["form"]["pass"] = "${ENV:TRIDENT_MISSING_PASS}"
        unresolved_env["roles"][0]["csrf"] = {"selector": "meta[name=_csrf]", "field": "_csrf"}
        unresolved_path = parent / "unresolved-env.json"
        unresolved_path.write_text(json.dumps(unresolved_env), encoding="utf-8")
        unresolved = run_cli(binary, env, unresolved_path, origin)
        require(unresolved.returncode != 0, "unresolved credential placeholder was accepted")
        unresolved_report = json.loads(unresolved.stdout)
        unresolved_cells = {item["id"]: item for item in unresolved_report["results"]}
        require(unresolved_cells["role:broken:submit"].get("error") == "credential_placeholder_unresolved",
                "unresolved credential placeholder was not reported")

        unsafe_matrix = json.loads(json.dumps(matrix_plan))
        unsafe_matrix["roles"][1]["session"] = "role-admin"
        unsafe_path = parent / "unsafe-matrix.json"
        unsafe_path.write_text(json.dumps(unsafe_matrix), encoding="utf-8")
        unsafe = run_cli(binary, env, unsafe_path, origin)
        require(unsafe.returncode != 0, "roles sharing a session were accepted")

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
                       "loopback_approval", "role_matrix", "csrf_token_injection",
                       "csrf_missing_inconclusive", "credential_placeholder_required",
                       "role_session_isolation"],
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT runtime verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
