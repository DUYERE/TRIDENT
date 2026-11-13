#!/usr/bin/env python
"""[01] Real Go CLI / PostgreSQL E2E against a local scripted protocol server, NOT a real LLM.

Run: python scripts/test-agent.py
Writes migrations and synthetic Agent Runs ONLY to trident_test at 127.0.0.1:55432.
Requires the existing .env password and secrets/test-admin.json; never bootstraps,
resets data, executes Maven/Java, downloads Go modules, or contacts a real model.
"""
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "fixtures" / "java-maven"
SOURCE_PATH = "jdbc-app/src/main/java/example/synthetic/DynamicCustomerLookup.java"
MODEL = "local-protocol-test"
FAKE_KEY = "local-scripted-protocol-test-not-a-provider-secret"
HASH = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    """[02] Fail with fixed diagnostics, never subprocess output or secret values."""
    if not condition:
        raise RuntimeError(message)


def tree_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def canonical_hash(value):
    """[03] Match Go encoding/json canonical map ordering and HTML escaping."""
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    for char, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                          (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(char, escaped)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def isolated_environment():
    """[04] Read local credentials internally; ignore every inherited database/model destination."""
    values = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8-sig").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            values[name.strip()] = value.strip()
    password = values.get("TRIDENT_POSTGRES_PASSWORD", "")
    require(password and password != "replace-with-a-random-local-password",
            "Configure the existing dedicated test database password")
    admin = json.loads((ROOT / "secrets" / "test-admin.json").read_text(encoding="utf-8-sig"))
    token = admin.get("token")
    require(isinstance(token, str) and token, "Existing test admin token required; no bootstrap performed")
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("TRIDENT_", "OPENAI_", "ANTHROPIC_", "AZURE_", "PG"))
           and k.upper() not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")}
    dsn = ("postgres://trident_test:" + quote(password, safe="")
           + "@127.0.0.1:55432/trident_test?sslmode=disable&connect_timeout=5")
    env.update(TRIDENT_DATABASE_URL=dsn, TRIDENT_TOKEN=token,
               TRIDENT_MIGRATION_ACTOR="local-agent-protocol-test",
               TRIDENT_LOCAL_FAKE_KEY=FAKE_KEY, GOPROXY="off", GOSUMDB="off",
               GOTOOLCHAIN="local", GOENV="off", GOFLAGS="", GOWORK="off",
               GOTELEMETRY="off", GONOPROXY="none", GONOSUMDB="*", GOVCS="*:off",
               GOCACHEPROG="", CGO_ENABLED="0", NO_PROXY="127.0.0.1")
    return env, (password, token, dsn, quote(password, safe=""))


def check_no_secrets(text, secrets):
    require(not any(secret and secret in text for secret in secrets),
            "Credential unexpectedly appeared in CLI output or model request; output suppressed")


@contextmanager
def temporary_work():
    """[05] Retry TemporaryDirectory cleanup after Windows releases the Go executable."""
    work = tempfile.TemporaryDirectory(prefix="trident-agent-")
    try:
        yield Path(work.name)
    finally:
        for attempt in range(40):
            try:
                work.cleanup()
                break
            except OSError:
                if attempt == 39:
                    raise RuntimeError("Temporary CLI directory cleanup failed after retries") from None
                time.sleep(0.25)


class ProtocolServer(ThreadingHTTPServer):
    """[06] Bounded, single-run deterministic Chat Completions protocol, no outbound I/O."""
    daemon_threads = True
    block_on_close = True

    def __init__(self, snapshot_hash, source_hash, secrets, corrupt=False):
        super().__init__(("127.0.0.1", 0), ProtocolHandler)
        self.snapshot_hash = snapshot_hash
        self.source_hash = source_hash
        self.secrets = secrets
        self.corrupt = corrupt
        self.requests = 0
        self.errors = []
        self.lock = threading.Lock()
        self.tool_results = {}
        self.final = None

    def completion(self, request):
        require(request.get("model") == MODEL, "Unexpected model selection")
        require(not request.get("stream", False), "Streaming was not authorized")
        require(request.get("max_completion_tokens") == 2048 and "max_tokens" not in request,
                "Explicit output token profile not respected")
        names = [entry.get("function", {}).get("name") for entry in request.get("tools", [])]
        require(set(names) == {"inspect_project", "list_files", "read_source", "search_source",
                               "inspect_dependencies", "match_advisories", "query_endpoints",
                               "trace_dataflow", "list_findings"}
                and len(names) == 9, "Read-only tool allowlist changed")
        messages = request.get("messages")
        require(isinstance(messages, list) and messages, "Missing model history")
        tools = [entry for entry in messages if entry.get("role") == "tool"]
        round_index = self.requests
        require(round_index < 3 and len(tools) == round_index, "Unexpected model round/history")
        for index, entry in enumerate(tools):
            expected_id = ("local_inspect", "local_read")[index]
            require(entry.get("tool_call_id") == expected_id, "Tool result/call ID mismatch")
            result = json.loads(entry["content"])
            require(result.get("snapshot_hash") == self.snapshot_hash, "Tool snapshot hash mismatch")
            if index == 0:
                require(any(item["path"] == "pom.xml" for item in result["build_files"]),
                        "Maven build-file clue missing")
            else:
                require(result.get("verification") == "content_sha256"
                        and result.get("path") == SOURCE_PATH
                        and result.get("sha256") == self.source_hash
                        and result.get("limits", {}).get("limit") == 200,
                        "Verified read_source metadata mismatch")
                lines = result.get("lines", [])
                require(lines and not result.get("binary") and result.get("utf8")
                        and not any(line.get("truncated") for line in lines),
                        "Expected complete synthetic source evidence")
                require(any("Class.forName" in line["text"] for line in lines),
                        "Synthetic reflection source not returned")
            if expected_id in self.tool_results:
                require(self.tool_results[expected_id] == result, "Historical tool result changed")
            self.tool_results[expected_id] = result
        if round_index == 0:
            message = self.tool_call("local_inspect", "inspect_project", {})
        elif round_index == 1:
            message = self.tool_call("local_read", "read_source",
                                     {"path": SOURCE_PATH, "start_line": 1, "limit": 200})
        else:
            # [07] Cite only hashes/line numbers actually received from read_source.
            read = self.tool_results["local_read"]
            line = next(row["number"] for row in read["lines"] if "Class.forName" in row["text"])
            evidence = {"snapshot_hash": read["snapshot_hash"], "path": read["path"],
                        "sha256": read["sha256"], "start_line": line, "end_line": line}
            if self.corrupt:
                evidence["sha256"] = "0" * 64
            self.final = {
                "summary": "Local scripted protocol test; not a real LLM security assessment.",
                "hypotheses": [{"statement": "Configured reflection requires external handler review; "
                                "this does not establish an exploitable vulnerability.",
                                "evidence": [evidence]}],
                "limitations": ["Only one synthetic source file was read.",
                                "No Java/Maven execution, real model, or external network verification."]}
            message = {"role": "assistant", "content": json.dumps(self.final, separators=(",", ":"))}
        self.requests += 1
        return {"id": "local-protocol-" + str(self.requests), "object": "chat.completion",
                "created": 1, "model": MODEL,
                "choices": [{"index": 0, "message": message,
                             "finish_reason": "stop" if round_index == 2 else "tool_calls"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200}}

    @staticmethod
    def tool_call(call_id, name, arguments):
        return {"role": "assistant", "content": None, "tool_calls": [
            {"id": call_id, "type": "function", "function": {
                "name": name, "arguments": json.dumps(arguments, separators=(",", ":"))}}]}


class ProtocolHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass  # [08] Never log request headers, body, credential, or source content.

    def do_POST(self):
        self.connection.settimeout(10)
        try:
            require(self.client_address[0] == "127.0.0.1" and self.path == "/v1/chat/completions",
                    "Unexpected HTTP peer/path")
            require(self.headers.get("Host") == "127.0.0.1:" + str(self.server.server_port),
                    "Unexpected HTTP host")
            require(self.headers.get("Authorization") == "Bearer " + FAKE_KEY,
                    "Explicit synthetic API key not used")
            require(self.headers.get_content_type() == "application/json"
                    and not self.headers.get("Transfer-Encoding"), "Unexpected HTTP encoding")
            length = int(self.headers.get("Content-Length", "0"))
            require(0 < length <= 2 << 20, "Invalid HTTP request size")
            body = self.rfile.read(length).decode("utf-8")
            check_no_secrets(body, self.server.secrets)
            with self.server.lock:
                response = self.server.completion(json.loads(body))
            status = 200
        except Exception:
            # Store no exception details: third-party parsing errors may contain input.
            self.server.errors.append("Local scripted protocol request validation failed")
            response, status = {"error": {"message": "local protocol validation failed"}}, 400
        data = json.dumps(response, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True


@contextmanager
def protocol_server(snapshot_hash, source_hash, secrets, corrupt=False):
    server = ProtocolServer(snapshot_hash, source_hash, secrets, corrupt)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        require(not thread.is_alive(), "Local protocol server failed to stop")


def validate_steps(invoke, run, snapshot_hash):
    """[09] Validate this newly created Run's canonical payload/config hashes and step pages."""
    require(HASH.fullmatch(run["config_hash"])
            and canonical_hash(run["config"]) == run["config_hash"], "Run config hash mismatch")
    require(run["snapshot_hash"] == snapshot_hash, "Persisted Run snapshot mismatch")
    steps, after = [], 0
    while True:
        page = invoke("agent", "steps", "--id", str(run["id"]), "--after", str(after), "--limit", "3")
        require(isinstance(page, list) and len(page) <= 3, "Invalid steps page")
        if not page:
            break
        for step in page:
            require(step["run_id"] == run["id"] and step["seq"] == after + 1,
                    "Missing, duplicate, or out-of-order persisted step")
            require(HASH.fullmatch(step["digest"]) and HASH.fullmatch(step["payload_hash"])
                    and canonical_hash(step["payload"]) == step["payload_hash"],
                    "Step canonical payload hash mismatch")
            steps.append(step)
            after = step["seq"]
        require(after <= run["last_seq"], "Step pagination exceeds Run sequence")
    require(after == run["last_seq"] and steps and steps[0]["kind"] == "run.created",
            "Incomplete persisted lifecycle")
    require(sum(step["kind"] == "model.prepared" for step in steps) == 3
            and sum(step["kind"] == "model.completed" for step in steps) == 3
            and sum(step["kind"] == "tool.completed" for step in steps) == 2,
            "Persisted model/tool attempt counts mismatch")
    return steps


def main():
    if len(sys.argv) != 1:
        if sys.argv[1:] == ["--help"]:
            print(__doc__)
            return
        raise RuntimeError("Usage: python scripts/test-agent.py [--help]")
    before = tree_hashes(SOURCE)
    require(SOURCE_PATH in before and before, "Missing synthetic Java/Maven fixture")
    env, secrets = isolated_environment()
    reports = []
    with temporary_work() as work:
        binary = work / ("trident.exe" if os.name == "nt" else "trident")
        built = subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                               cwd=ROOT, env=env, capture_output=True, timeout=180)
        require(built.returncode == 0, "Offline Go build failed; verify installed toolchain and cached modules")

        def command(*arguments, expected=0):
            result = subprocess.run([str(binary), *arguments], cwd=ROOT, env=env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=120)
            check_no_secrets(result.stdout + result.stderr, secrets)
            require(result.returncode == expected,
                    "CLI " + " ".join(arguments[:2]) + " unexpected exit status " + str(result.returncode))
            return result

        def invoke(*arguments):
            return json.loads(command(*arguments).stdout)

        # [10] Explicit migrations only; authentication uses the existing admin token.
        command("migrate")
        snapshot = work / "snapshot"
        imported = invoke("project", "import", "--source", str(SOURCE), "--snapshot", str(snapshot))
        snapshot_hash = imported["snapshot_hash"]
        require(HASH.fullmatch(snapshot_hash), "Invalid trusted import snapshot hash")
        require(any(entry["path"] == SOURCE_PATH and entry["sha256"] == before[SOURCE_PATH]
                    for entry in imported["manifest"]["entries"]), "Imported source content hash mismatch")
        snapshot_before = tree_hashes(snapshot)
        # The manifest hash covers exact bytes, NOT sorted-key reserialization.
        require(snapshot_before.get(".trident-manifest.json") == snapshot_hash,
                "Import snapshot hash differs from raw manifest bytes")
        for corrupt in (False, True):
            scenario = "corrupt_evidence" if corrupt else "happy"
            with protocol_server(snapshot_hash, before[SOURCE_PATH], secrets, corrupt) as server:
                endpoint = "http://127.0.0.1:" + str(server.server_port) + "/v1"
                result = command("agent", "run", "--key", "local-protocol-" + uuid.uuid4().hex,
                                 "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
                                 "--goal", "Synthetic local scripted protocol test only; inspect_project then "
                                 "read the configured DynamicCustomerLookup source. Do not execute code.",
                                 "--approve-egress", "--allow-loopback-http", "--endpoint", endpoint,
                                 "--model", MODEL, "--api-key-env", "TRIDENT_LOCAL_FAKE_KEY",
                                 "--max-output-tokens", "2048", "--model-timeout-seconds", "15",
                                 "--max-model-calls", "3", "--max-tool-calls", "2",
                                 "--max-tokens", "131072", expected=1 if corrupt else 0)
                require(not server.errors and server.requests == 3,
                        "Local scripted protocol did not complete exactly three requests")
                run = json.loads(result.stdout)
                status = invoke("agent", "status", "--id", str(run["id"]))
                require(status == run, "agent run output differs from persisted status")
                require(run["state"] == ("failed" if corrupt else "completed")
                        and run["model_calls"] == 3 and run["tool_calls"] == 2,
                        "Unexpected Run state or call counts")
                require(run["tokens_used"] == 600 and run["tokens_reserved"] == 0,
                        "Synthetic reported token accounting mismatch")
                require(run["config"]["endpoint"] == endpoint
                        and run["config"]["model"] == MODEL
                        and run["config"]["allow_loopback_http"] is True
                        and run["config"]["egress_allowed"] is True,
                        "Run destination/approval differs from local server")
                steps = validate_steps(invoke, run, snapshot_hash)
                require(steps[-1]["kind"] == ("run.failed" if corrupt else "run.completed"),
                        "Unexpected terminal persisted step")
                if not corrupt:
                    final = steps[-1]["payload"]
                    require(final.get("summary") == server.final["summary"]
                            and final.get("limitations") == server.final["limitations"] + [
                                "Static source evidence supports unverified hypotheses only; "
                                "no vulnerability exploitation or completeness was confirmed."]
                            and len(final["hypotheses"]) == 1
                            and final["hypotheses"][0]["statement"] == "[UNVERIFIED INFERENCE / 未验证推断] "
                            + server.final["hypotheses"][0]["statement"]
                            and final["hypotheses"][0]["evidence"] == server.final["hypotheses"][0]["evidence"],
                            "Persisted normalized result/evidence differs from actual tool-derived response")
                else:
                    require(not any(step["kind"] == "run.completed" for step in steps),
                            "Corrupt evidence was accepted as a successful final result")
                reports.append({"scenario": scenario, "run_id": run["id"], "cli_exit": result.returncode,
                                "state": run["state"], "model_requests": server.requests,
                                "tool_calls": run["tool_calls"], "persisted_steps": len(steps)})
        require(tree_hashes(SOURCE) == before, "Original synthetic source changed")
        require(tree_hashes(snapshot) == snapshot_before, "Read-only agent changed its snapshot")
    print(json.dumps({"result": "passed", "driver": "real_go_cli_local_scripted_protocol",
                      "real_llm": False, "external_model_requests": False,
                      "database": "trident_test@127.0.0.1:55432/trident_test",
                      "migrations_cli_exit": 0, "bootstrap_or_reset": False,
                      "snapshot_hash": snapshot_hash, "scenarios": reports,
                      "checks": ["authenticated_existing_admin", "inspect_project", "read_source_limit_200",
                                 "actual_tool_result_evidence", "status", "paginated_steps",
                                 "config_and_payload_hashes", "corrupt_evidence_rejected",
                                 "source_unchanged", "snapshot_unchanged", "loopback_only_endpoint"],
                      "maven_executed": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        # [11] RuntimeError messages are fixed text and never contain subprocess output.
        print("TRIDENT local scripted agent verification failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        # Parsing/network exceptions can embed credential-bearing input: suppress details.
        print("TRIDENT local scripted agent verification failed; no credential/output dump. "
              "Check cached Go modules, dedicated test PostgreSQL, existing admin secret, "
              "and current CLI/protocol schema.", file=sys.stderr)
        sys.exit(1)
