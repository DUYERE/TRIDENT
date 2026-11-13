#!/usr/bin/env python
"""[01] Real CLI acceptance for AI patch proposal plus isolated validation.

A loopback Chat Completions server returns a fixed diff, so this is NOT a real
LLM test. It proves the command, strict proposal parsing, exact-context patch
validation, snapshot immutability, process Maven verification and (when the
pinned image is present) Docker sandbox verification.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-patch"
SAFE_PATCH = (FIXTURE / "safe.patch").read_text(encoding="utf-8")
IMAGE = ("maven:3.9.9-eclipse-temurin-17@sha256:"
         "f58d59b6273e785ac0a4477f6e9b5ba1d7731c75b906c0f7b34076f1851318cc")
FAKE_KEY = "local-scripted-patch-test-not-a-provider-secret"
MODEL = "local-patch-test"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-patch-ai-")
    try:
        yield Path(work)
    finally:
        for attempt in range(40):
            try:
                shutil.rmtree(work)
                break
            except FileNotFoundError:
                break
            except OSError:
                if attempt == 39:
                    print(f"WARNING: temporary directory retained: {work}", file=sys.stderr)
                else:
                    time.sleep(0.25)


class ProposalServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), ProposalHandler)
        self.errors = []


class ProposalHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        try:
            require(self.client_address[0] == "127.0.0.1"
                    and self.path == "/v1/chat/completions", "unexpected peer/path")
            require(self.headers.get("Authorization") == "Bearer " + FAKE_KEY,
                    "explicit synthetic key not used")
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            require(body.get("model") == MODEL, "unexpected model")
            require("tools" not in body, "unexpected tools")
            messages = body.get("messages")
            require(isinstance(messages, list) and len(messages) == 2
                    and messages[0]["role"] == "system" and messages[1]["role"] == "user",
                    "unexpected messages")
            prompt = messages[1]["content"]
            require("SELECT * FROM users" in prompt and "Vulnerable.java" in prompt,
                    "source context missing")
            content = json.dumps({"patch": SAFE_PATCH,
                                  "rationale": "Replace concatenation with a placeholder."},
                                 separators=(",", ":"))
            response = {"id": "local-patch", "object": "chat.completion", "created": 1,
                        "model": MODEL,
                        "choices": [{"index": 0,
                                     "message": {"role": "assistant", "content": content,
                                                 "reasoning_content": "local deterministic proposal"},
                                     "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}
            data = json.dumps(response, separators=(",", ":")).encode("utf-8")
            status = 200
        except Exception:
            response = {"error": {"message": "local proposal validation failed"}}
            data = json.dumps(response).encode("utf-8")
            status = 400
            self.server.errors.append("request validation failed")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def docker_available():
    try:
        result = subprocess.run(["docker", "image", "inspect", IMAGE],
                                capture_output=True, timeout=30)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before, "missing java-patch fixture")
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_MODEL_API_KEY",
                 "OPENAI_API_KEY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        env.pop(name, None)
    env["TRIDENT_LOCAL_FAKE_KEY"] = FAKE_KEY
    env["NO_PROXY"] = "127.0.0.1"
    server = ProposalServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with temporary_work() as work:
            binary = work / ("trident.exe" if os.name == "nt" else "trident")
            subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                           cwd=ROOT, env=env, check=True, timeout=180)
            snapshot = work / "snapshot"
            imported = json.loads(subprocess.run(
                [str(binary), "project", "import", "--source", str(FIXTURE),
                 "--snapshot", str(snapshot)],
                cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
                check=True, timeout=120).stdout)
            snapshot_hash = imported["snapshot_hash"]
            snapshot_before = tree_hashes(snapshot)
            patch = work / "ai.patch"
            common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]
            proposal = subprocess.run(
                [str(binary), "patch", "propose", *common,
                 "--path", "src/main/java/demo/Vulnerable.java",
                 "--goal", "Replace string concatenation with a parameter placeholder.",
                 "--out", str(patch),
                 "--endpoint", f"http://127.0.0.1:{server.server_port}/v1",
                 "--model", MODEL, "--api-key-env", "TRIDENT_LOCAL_FAKE_KEY",
                 "--allow-loopback-http", "--approve-egress",
                 "--max-output-tokens", "2048", "--timeout-seconds", "60"],
                cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
                timeout=180)
            require(proposal.returncode == 0, proposal.stderr.strip() or "proposal failed")
            report = json.loads(proposal.stdout)
            require(report["snapshot_hash"] == snapshot_hash and report["patch_bytes"] > 0
                    and report["egress_approved"] is True and report["runtime_status"] == "not_run",
                    "proposal report mismatch")
            require(patch.is_file() and "name=?" in patch.read_text(encoding="utf-8"),
                    "proposed patch content mismatch")
            require(not server.errors, "loopback proposal server rejected a request")

            process_ws = work / "ws-process"
            process = subprocess.run(
                [str(binary), "patch", "verify", *common,
                 "--workspace", str(process_ws), "--patch", str(patch),
                 "--profile", "maven", "--main-class", "demo.Main",
                 "--approve-execution"],
                cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
                timeout=300)
            require(process.returncode == 0, process.stderr.strip() or "process verify failed")
            process_report = json.loads(process.stdout)
            require(process_report["status"] == "validation_passed"
                    and process_report["original_snapshot_intact"] is True,
                    "process validation mismatch")

            docker_report = None
            m2 = Path.home() / ".m2"
            if docker_available() and m2.is_dir():
                docker_ws = work / "ws-docker"
                docker = subprocess.run(
                    [str(binary), "patch", "verify", *common,
                     "--workspace", str(docker_ws), "--patch", str(patch),
                     "--profile", "maven", "--main-class", "demo.Main",
                     "--approve-execution", "--sandbox", "docker",
                     "--sandbox-image", IMAGE, "--sandbox-network", "none",
                     "--sandbox-maven-repo", str(m2)],
                    cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
                    timeout=600)
                require(docker.returncode == 0, docker.stderr.strip() or "docker verify failed")
                docker_report = json.loads(docker.stdout)
                require(docker_report["status"] == "validation_passed"
                        and docker_report["validation"]["sandbox"] == "docker"
                        and docker_report["original_snapshot_intact"] is True,
                        "docker validation mismatch")
                require(all("--network none" in step["command"]
                            and "--cap-drop ALL" in step["command"]
                            for step in docker_report["validation"]["commands"]),
                        "docker isolation args missing")

            require(tree_hashes(snapshot) == snapshot_before, "snapshot changed")
            require(tree_hashes(FIXTURE) == fixture_before, "fixture changed")
            print(json.dumps({"result": "passed", "snapshot_hash": snapshot_hash,
                              "patch_sha256": report["patch_sha256"],
                              "process_status": process_report["status"],
                              "docker_status": (docker_report or {}).get("status"),
                              "docker_skipped": docker_report is None,
                              "checks": ["real_cli", "loopback_not_real_llm",
                                         "strict_proposal_json", "exact_context_patch",
                                         "output_outside_snapshot", "process_maven_validation",
                                         "docker_sandbox_validation", "network_none",
                                         "cap_drop_all", "snapshot_unchanged"]},
                             ensure_ascii=False))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT AI patch acceptance failed: {exc}", file=sys.stderr)
        sys.exit(1)
