"""Bounded authorization-control inventory acceptance.

Runs the real CLI against the synthetic Java authz fixture. It checks that MVC
interceptors, servlet filters, Spring Security XML/Java config and method
annotations are recognized, while endpoints without a control remain
`inconclusive` findings. No Java, database, model or network is used.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "java-authz"
CHAIN_FIXTURE = ROOT / "tests" / "fixtures" / "java-authz-chain"


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-authz-")
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


def main():
    before = tree_hashes(FIXTURE)
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_MODEL_API_KEY",
                 "TRIDENT_TEST_DATABASE_URL", "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        built = subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                               cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=180)
        require(built.returncode == 0, built.stderr.strip() or "go build failed")
        snapshot = parent / "snapshot"
        imported = subprocess.run([str(binary), "project", "import", "--source", str(FIXTURE),
                                   "--snapshot", str(snapshot)], cwd=ROOT, env=env,
                                  capture_output=True, text=True, encoding="utf-8", timeout=180)
        require(imported.returncode == 0, imported.stderr.strip() or "import failed")
        snapshot_hash = json.loads(imported.stdout)["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        result = subprocess.run([str(binary), "audit", "authz",
                                 "--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash],
                                cwd=ROOT, env=env, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=180)
        require(result.returncode == 0, result.stderr.strip() or "audit authz failed")
        report = json.loads(result.stdout)
        require(report["analysis_kind"] == "authorization_control_inventory", "analysis kind mismatch")
        require(report["runtime_status"] == "not_run" and report["coverage"]["runtime_status"] == "not_run",
                "runtime status was upgraded")
        kinds = {control["kind"] for control in report["controls"]}
        for kind in ("mvc_interceptor", "servlet_filter", "spring_security_java", "spring_security_xml"):
            require(kind in kinds, f"missing control kind: {kind}")
        decisions = {endpoint["path"]: endpoint["decision"] for endpoint in report["endpoints"]}
        expected = {
            "/secure/admin": "protected",
            "/secure/login": "public",
            "/public/hello": "unprotected",
            "/api/admin": "protected",
            "/api/open": "public",
            "/api/private/data": "protected",
            "/filtered/data": "protected",
            "/xmlfilter/data": "protected",
            "/xmlsecure/data": "protected",
            "/manual/check": "unknown",
            "/open/hello": "unprotected",
        }
        for path, decision in expected.items():
            require(decisions.get(path) == decision,
                    f"{path}: {decisions.get(path)!r} != {decision!r}")
        coverage = report["coverage"]
        require(coverage["protected"] == 6 and coverage["public"] == 2
                and coverage["unprotected"] == 2 and coverage["unknown"] == 1,
                f"coverage mismatch: {coverage}")
        findings = report["findings"]
        require(len(findings) == 2, f"findings: {findings}")
        require(all(finding["status"] == "inconclusive" and finding["cwe"] == "CWE-306"
                    and finding["runtime_status"] == "not_run" for finding in findings),
                "finding status mismatch")
        require({finding["path"] for finding in findings} == {"/open/hello", "/public/hello"},
                "unexpected finding paths")
        require(report["partial"] is False, "fixture unexpectedly partial")
        require(tree_hashes(snapshot) == snapshot_before, "analysis changed the snapshot")
        require(tree_hashes(FIXTURE) == before, "fixture changed")
        chain_before = tree_hashes(CHAIN_FIXTURE)
        chain_snapshot = parent / "chain-snapshot"
        imported_chain = subprocess.run([str(binary), "project", "import", "--source", str(CHAIN_FIXTURE),
                                         "--snapshot", str(chain_snapshot)], cwd=ROOT, env=env,
                                        capture_output=True, text=True, encoding="utf-8", timeout=180)
        require(imported_chain.returncode == 0, imported_chain.stderr.strip() or "chain import failed")
        chain_hash = json.loads(imported_chain.stdout)["snapshot_hash"]
        chain_snapshot_before = tree_hashes(chain_snapshot)
        chain_result = subprocess.run([str(binary), "audit", "authz",
                                       "--snapshot", str(chain_snapshot), "--snapshot-hash", chain_hash],
                                      cwd=ROOT, env=env, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=180)
        require(chain_result.returncode == 0, chain_result.stderr.strip() or "chain audit authz failed")
        chain_report = json.loads(chain_result.stdout)
        require(chain_report["tool_version"].find("authz-chain-v2") >= 0, "chain tool version mismatch")
        chains = chain_report["chains"]
        require(len(chains) == 2, f"chains: {chains}")
        require(chains[0]["order"] == 1 and chains[0]["order_source"] == "annotation"
                and chains[0]["security_matchers"] == ["/chain/api/**"] and len(chains[0]["rules"]) == 3,
                f"ordered chain mismatch: {chains[0]}")
        require(len(chains[0].get("custom_filters", [])) == 1
                and "AuditFilter" in chains[0]["custom_filters"][0],
                f"custom filter metadata mismatch: {chains[0]}")
        require(chains[1]["order_source"] == "default" and not chains[1].get("security_matchers")
                and len(chains[1]["rules"]) == 1, f"default chain mismatch: {chains[1]}")
        chain_decisions = {endpoint["path"]: endpoint for endpoint in chain_report["endpoints"]}
        expected_chain = {
            "/chain/api/hello": "protected",
            "/chain/api/public/info": "public",
            "/chain/api/admin/panel": "protected",
            "/chain/web/open": "public",
            "/chain/web/members": "protected",
            "/chain/web/feature": "protected",
            "/chain/web/denied": "protected",
            "/chain/web/unknown": "unknown",
            "/ctx/hello": "public",
        }
        for path, decision in expected_chain.items():
            require(chain_decisions.get(path, {}).get("decision") == decision,
                    f"{path}: {chain_decisions.get(path, {}).get('decision')!r} != {decision!r}")
        require(chain_decisions["/chain/api/hello"]["chain"] == chains[0]["id"]
                and chain_decisions["/chain/web/open"]["chain"] == chains[1]["id"],
                "filter chain attribution mismatch")
        require(chain_decisions["/chain/api/admin/panel"]["roles"] == ["ROLE_ADMIN"]
                and chain_decisions["/chain/web/feature"]["roles"] == ["ROLE_ADMIN"],
                "role normalization mismatch")
        require(chain_decisions["/ctx/hello"]["external_path"] == "/app/ctx/hello",
                "context path prefix mismatch")
        chain_coverage = chain_report["coverage"]
        require(chain_coverage["chains"] == 2 and chain_coverage["method_security"] == "enabled"
                and chain_coverage["context_path"] == "/app"
                and chain_coverage["context_path_source"] == "src/main/resources/application.properties",
                f"chain coverage mismatch: {chain_coverage}")
        require(chain_coverage["protected"] == 5 and chain_coverage["public"] == 3
                and chain_coverage["unknown"] == 1 and chain_coverage["unprotected"] == 0,
                f"chain decision counts: {chain_coverage}")
        limitations = chain_report["limitations"]
        for limitation in ("filter_chain_order_bounded", "filter_chain_rule_order_bounded",
                           "spel_subset_only", "context_path_unknown"):
            require(any(item.startswith(limitation) for item in limitations),
                    f"missing limitation: {limitation}")
        require(chain_report["findings"] == [], f"unexpected findings: {chain_report['findings']}")
        require(chain_report["partial"] is False, "chain fixture unexpectedly partial")
        require(chain_report["runtime_status"] == "not_run", "chain runtime status was upgraded")
        require(tree_hashes(chain_snapshot) == chain_snapshot_before, "analysis changed the chain snapshot")
        require(tree_hashes(CHAIN_FIXTURE) == chain_before, "chain fixture changed")
        print(json.dumps({
            "result": "passed", "snapshot_hash": snapshot_hash, "chain_snapshot_hash": chain_hash,
            "controls": len(report["controls"]), "protected": coverage["protected"],
            "public": coverage["public"], "unprotected": coverage["unprotected"],
            "unknown": coverage["unknown"], "chains": len(chains),
            "checks": ["mvc_interceptor", "servlet_filter", "spring_security_java",
                       "spring_security_xml", "method_annotations", "manual_unknown",
                       "inconclusive_findings", "runtime_not_run", "snapshot_unchanged",
                       "fixture_unchanged", "ordered_filter_chains", "security_matcher_scope",
                       "first_matching_rule", "method_annotation_priority", "spel_subset",
                       "context_path_prefix", "chain_limitations"],
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"TRIDENT authz verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
