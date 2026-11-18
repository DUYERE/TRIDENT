#!/usr/bin/env python
"""[code-audit] 多语言代码审计真实 CLI / Web 验收。

只读取受信任快照，不编译、不执行被审计源码，不访问网络、不调用模型。
覆盖：7 种语言前端、source→sink 证据链、负例、规则外置、格式导出、
确定性、失败关闭、Web 只读接口与快照/样本字节不变。
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
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
FIXTURE = ROOT / "tests" / "fixtures" / "polyglot-audit"
CUSTOM_RULES = FIXTURE / "rules" / "custom-rules.json"
TOKEN = "trident-demo-0123456789abcdef"

# (rule_id, relative file, sink line) — 每一条都是 fixture 中的显式正例。
EXPECTED = [
    ("csharp.sql.command", "src/dotnet/UserController.cs", 16),
    ("csharp.command.process", "src/dotnet/UserController.cs", 25),
    ("csharp.deserialization.formatter", "src/dotnet/UserController.cs", 45),
    ("csharp.sql.command", "src/dotnet/UserController.cs", 58),
    ("go.sql.query", "src/go/main.go", 13),
    ("go.ssrf.http", "src/go/main.go", 14),
    ("go.command.exec", "src/go/main.go", 19),
    ("go.template.parse", "src/go/main.go", 31),
    ("go.redirect.http", "src/go/main.go", 46),
    ("java.sql.statement", "src/java/SearchController.java", 17),
    ("java.command.runtime", "src/java/SearchController.java", 22),
    ("java.deserialization.readobject", "src/java/SearchController.java", 37),
    ("java.redirect.response", "src/java/SearchController.java", 46),
    ("js.sql.query", "src/js/server.js", 7),
    ("js.command.exec", "src/js/server.js", 13),
    ("js.xss.response", "src/js/server.js", 23),
    ("js.code_exec.eval", "src/js/server.js", 28),
    ("js.sql.query", "src/js/server.js", 37),
    ("php.sql.query", "src/php/search.php", 5),
    ("php.command.exec", "src/php/search.php", 9),
    ("php.xss.output", "src/php/search.php", 10),
    ("php.code_exec.eval", "src/php/search.php", 31),
    ("php.deserialization.unserialize", "src/php/search.php", 32),
    ("php.sql.query", "src/php/search.php", 36),
    ("php.sql.query", "src/php/search.php", 40),
    ("php.sql.query", "src/php/search.php", 48),
    ("php.redirect.header", "src/php/search.php", 51),
    ("php.xpath.query", "src/php/search.php", 52),
    ("python.sql.execute", "src/python/app.py", 12),
    ("python.command.subprocess", "src/python/app.py", 19),
    ("python.xss.response", "src/python/app.py", 41),
    ("python.code_exec.eval", "src/python/app.py", 47),
    ("python.deserialization.pickle", "src/python/app.py", 48),
    ("python.sql.execute", "src/python/app.py", 57),
    ("js.xss.response", "src/ts/handler.ts", 3),
    ("js.xss.response", "src/ts/handler.ts", 13),
]

# 显式负例：参数绑定 / 类型转换 / 显式转义 / 注释与字符串诱饵所在行；
# v2 增加：非插值字符串（PHP 单引号、Python 普通与 r 前缀、JS 无插值模板）、
# 净化包装器（wrapper 体内 sink 只接收 intval 参数）。
NEGATIVE_LINES = {
    "src/php/search.php": [17, 21, 24, 25, 27, 55, 57, 59],
    "src/dotnet/UserController.cs": [35, 36, 52, 53],
    "src/python/app.py": [27, 36, 51, 52, 53, 60, 61, 62, 63],
    "src/js/server.js": [19, 31, 32, 33, 40],
    "src/java/SearchController.java": [29, 30, 40, 41, 42],
    "src/go/main.go": [25, 40, 41, 42],
    "src/ts/handler.ts": [9],
}


def tree_hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-code-audit-")
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


def http_request(base, path, headers=None, method="GET", body=None):
    request_headers = dict(headers or {})
    data = None
    if body is not None:
        data = body.encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    call = urllib.request.Request(base + path, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(call, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before and CUSTOM_RULES.is_file(), "多语言 fixture 或自定义规则文件缺失")
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                       cwd=ROOT, env=env, check=True, timeout=180)

        def invoke(*args, failure=False):
            result = subprocess.run([str(binary), *args], cwd=ROOT, env=env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=180)
            if failure:
                require(result.returncode != 0 and not result.stdout.strip(),
                        f"应失败关闭但成功或输出了 JSON: {args!r} / {result.stdout[:200]}")
                return None
            require(result.returncode == 0, result.stderr.strip() or f"CLI failed: {args!r}")
            return json.loads(result.stdout)

        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(FIXTURE), "--snapshot", str(snapshot))
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        report = invoke("audit", "code", *common)
        require(report["analysis_kind"] == "multi_language_code_audit_v2", "analysis_kind 不匹配")
        require(report["ruleset_version"].startswith("trident-core-rules-"), "规则集版本缺失")
        require(report["coverage"]["runtime_status"] == "not_run", "运行时状态被提升")
        require(report["schema_version"] == 1 and report["partial"] is False, "报告身份/覆盖异常")

        languages = {item["language"]: item for item in report["languages"]}
        require(set(languages) == {"php", "csharp", "python", "javascript", "typescript", "java", "go"},
                f"语言前端不完整: {sorted(languages)}")
        scanned = [name for name, item in languages.items() if item["status"] == "scanned"]
        require(len(scanned) == 7, f"应有 7 种语言被扫描，实际 {scanned}")
        require(all(languages[name]["rules_active"] > 0 for name in scanned), "存在无规则的语言前端")
        require(all(not entry["file"].endswith("README.txt") for entry in report["files"]),
                "不支持扩展名被误扫描")

        observed = {(item["rule_id"], item["file"], item["sink"]["line"]) for item in report["findings"]}
        for expected in EXPECTED:
            require(expected in observed, f"漏报正例: {expected}")
        print(f"[01] 7 种语言前端、{len(EXPECTED)} 条正例证据链: PASS")

        for item in report["findings"]:
            require(item["runtime_status"] == "not_run", "单条 finding 的运行时状态被提升")
            require(item["status"] == "static_confirmed", f"非预期状态: {item['id']}")
            require(item["source"] and item["sink"] and item["flow"] and item["evidence"],
                    f"证据链不完整: {item['id']}")
            require(len(item["sha256"]) == 64, "文件哈希缺失")
            require(all(step["sha256"] == item["sha256"] and step["line"] > 0 for step in item["flow"]),
                    f"证据步骤未绑定快照哈希: {item['id']}")
            require(item["flow"][0]["kind"] == "source" and item["flow"][-1]["kind"] == "sink",
                    f"流顺序异常: {item['id']}")
            require(item["limitations"] and item["cwe"].startswith("CWE-"), "缺少限制或 CWE")
        for file, lines in NEGATIVE_LINES.items():
            for line in lines:
                require(not any(item["file"] == file and item["sink"]["line"] == line
                                for item in report["findings"]),
                        f"负例被误报: {file}:{line}")
        print("[02] 证据完整性、注释/字符串诱饵与负例零误报: PASS")

        categories = {item["category"] for item in report["findings"]}
        require({"sql", "command", "code_exec", "deserialization", "xss", "ssrf", "template"} <= categories,
                f"漏洞类别覆盖不足: {categories}")
        route_languages = {route["language"] for route in report["routes"]}
        require({"php", "csharp", "python", "javascript", "java", "go"} <= route_languages,
                f"声明入口覆盖不足: {route_languages}")
        require(all(route["sha256"] and route["line"] > 0 for route in report["routes"]), "入口证据缺失")
        print(f"[03] 多类别规则与 {len(report['routes'])} 条声明入口: PASS")

        repeat = subprocess.run([str(binary), "audit", "code", *common], cwd=ROOT, env=env,
                                capture_output=True, timeout=180)
        first = subprocess.run([str(binary), "audit", "code", *common], cwd=ROOT, env=env,
                               capture_output=True, timeout=180)
        require(first.returncode == repeat.returncode == 0 and first.stdout == repeat.stdout,
                "输出不确定（两次字节不一致）")
        print("[04] 同输入字节级确定性: PASS")

        php_only = invoke("audit", "code", *common, "--language", "php")
        require({item["language"] for item in php_only["findings"]} == {"php"}, "语言过滤未生效")
        require(php_only["languages"][0]["status"] in ("scanned", "skipped_by_filter"), "语言状态异常")
        invoke("audit", "code", *common, "--language", "cobol", failure=True)
        print("[05] 语言过滤与不支持语言失败关闭: PASS")

        custom = invoke("audit", "code", *common, "--rules", str(CUSTOM_RULES))
        require(any(item["rule_id"] == "caller.php.debug_log" for item in custom["findings"]),
                "调用者规则未生效")
        require(custom["ruleset_version"] != report["ruleset_version"], "规则变更未改变规则集版本")
        invalid = {
            "unknown_field.json": '{"schema_version":1,"rules":[{"id":"x","bogus":1}]}',
            "bad_language.json": '{"schema_version":1,"rules":[{"id":"x","languages":["cobol"],"category":"sql","cwe":"CWE-89","severity":"high","confidence":"high","title":"t","message":"m","sources":[{"kind":"access","names":["x"]}],"sinks":[{"kind":"call","names":["y"]}]}]}',
            "wrong_schema.json": '{"schema_version":99,"rules":[]}',
        }
        for name, body in invalid.items():
            path = parent / name
            path.write_text(body, encoding="utf-8")
            invoke("audit", "code", *common, "--rules", str(path), failure=True)
        print("[06] 调用者规则加载与非法规则失败关闭: PASS")

        unified = invoke("audit", "code", *common, "--format", "findings")
        require(unified["analysis_kind"] == "multi_language_code_audit_v2" and
                len(unified["findings"]) == len(report["findings"]), "统一证据模型转换异常")
        require(all(item["id"].startswith("code:") and item["runtime_status"] == "not_run"
                    for item in unified["findings"]), "统一模型状态异常")
        sarif = invoke("audit", "code", *common, "--format", "sarif")
        require(sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1, "SARIF 版本异常")
        require(len(sarif["runs"][0]["results"]) == len(report["findings"]) and
                sarif["runs"][0]["tool"]["driver"]["rules"], "SARIF 结果/规则缺失")
        require(sarif["runs"][0]["properties"]["runtime_status"] == "not_run", "SARIF 运行时状态异常")
        print("[07] 统一证据模型与 SARIF 2.1.0 导出: PASS")

        baseline = invoke("audit", "findings", *common)
        merged = invoke("audit", "findings", *common, "--include-code-audit")
        require(all(not item["id"].startswith("code:") for item in baseline["findings"]),
                "默认 findings 输出被新引擎污染")
        require(sum(1 for item in merged["findings"] if item["id"].startswith("code:")) == len(report["findings"]),
                "显式合并未包含全部多语言发现")
        print("[08] 默认 findings 兼容与显式合并: PASS")

        invoke("audit", "code", "--snapshot", str(snapshot), "--snapshot-hash", "0" * 64, failure=True)
        print("[09] 错误快照哈希失败关闭: PASS")

        port = free_port()
        base = f"http://127.0.0.1:{port}"
        server = subprocess.Popen(
            [str(binary), "web", "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash,
             "--addr", f"127.0.0.1:{port}", "--token", TOKEN],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        try:
            ready = False
            for _ in range(80):
                if server.poll() is not None:
                    break
                try:
                    status, _ = http_request(base, "/")
                    if status == 200:
                        ready = True
                        break
                except (urllib.error.URLError, ConnectionError):
                    pass
                time.sleep(0.1)
            require(ready, "Web 控制台未就绪")
            headers = {"X-Trident-Request": "console", "X-Trident-Token": TOKEN}
            # 首屏概览不得触发多语言分析：大项目上它曾让导入成功反馈卡住 30+ 秒。
            started = time.time()
            status, body = http_request(base, "/api/overview", headers=headers)
            require(status == 200 and time.time() - started < 10, "首次概览触发了耗时分析")
            early = json.loads(body)
            require(early["code"]["available"] is False and
                    "analysis_pending" in early["code"]["reason"],
                    "多语言分析未在首次 /api/code-audit 前保持惰性")
            status, body = http_request(base, "/api/code-audit", headers=headers)
            require(status == 200, f"/api/code-audit 返回 {status}")
            view = json.loads(body)
            require(view["available"] is True and view["total"] == len(report["findings"]),
                    "Web 代码审计接口发现数不一致")
            require(len(view["languages"]) == 7 and view["runtime_status"] == "not_run", "Web 语言/状态异常")
            status, body = http_request(base, "/api/code-audit?language=php", headers=headers)
            require(status == 200 and all(item["language"] == "php" for item in json.loads(body)["items"]),
                    "Web 语言筛选失效")
            status, body = http_request(base, "/api/overview", headers=headers)
            require(status == 200 and json.loads(body)["code"]["findings"] == len(report["findings"]),
                    "概览未暴露多语言审计摘要")
            status, body = http_request(base, "/api/agent/threads", headers=headers)
            thread_error = json.loads(body) if status == 412 else {}
            thread_hint = thread_error.get("error", "")
            require(status == 412 and thread_error.get("code") == "agent_database_missing"
                    and "设置" in thread_hint and "无需重启" in thread_hint
                    and "--agent-dsn" not in thread_hint,
                    "未配置 Agent 库时应指向设置页且无需重启，而不是空白页或要求重启")
            # 发现主页必须合并多语言规则发现，否则非 Java 项目读起来就是"零发现"。
            status, body = http_request(base, "/api/findings?limit=100", headers=headers)
            require(status == 200, f"/api/findings 返回 {status}")
            listing = json.loads(body)
            code_items = [item for item in listing["items"] if item["id"].startswith("code:")]
            require(len(code_items) == len(report["findings"]) and listing["total"] >= len(code_items),
                    f"/api/findings 未合并多语言发现: total={listing['total']} code={len(code_items)}")
            detail_id = urllib.parse.quote(code_items[0]["id"], safe="")
            status, body = http_request(base, "/api/finding?id=" + detail_id, headers=headers)
            require(status == 200 and json.loads(body)["runtime_status"] == "not_run",
                    "多语言发现详情不可读")
            print("[10] Web 只读接口、惰性分析、筛选与会话库提示: PASS")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)

        require(tree_hashes(FIXTURE) == fixture_before, "fixture 字节被修改")
        require(tree_hashes(snapshot) == snapshot_before, "快照字节被修改")
        print("[11] 样本与快照字节不变（无网络 / 无模型 / 无源码执行）: PASS")
        print("TRIDENT multi-language code audit acceptance passed.")


if __name__ == "__main__":
    main()
