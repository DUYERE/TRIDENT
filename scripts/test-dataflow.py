#!/usr/bin/env python
"""[01] 构建并驱动真实 CLI 验证 JDBC Source/Sink 静态证据；不编译/执行 Java。"""
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
FIXTURE = ROOT / "tests" / "fixtures" / "java-maven"
FORMAT_FIXTURE = ROOT / "tests" / "fixtures" / "java-builder-format"
RETURN_FIXTURE = ROOT / "tests" / "fixtures" / "java-return-flow"
DISPATCH_FIXTURE = ROOT / "tests" / "fixtures" / "java-dispatch-field"
OVERLOAD_FIXTURE = ROOT / "tests" / "fixtures" / "java-overload-parent"
ADVANCED_FIXTURE = ROOT / "tests" / "fixtures" / "java-lambda-generic-varargs"
INJECTION_FIXTURE = ROOT / "tests" / "fixtures" / "java-injection-sinks"
EXTRA_FIXTURE = ROOT / "tests" / "fixtures" / "java-extra-sinks"
COLLECTION_FIXTURE = ROOT / "tests" / "fixtures" / "java-collections"


def tree_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def temporary_work():
    work = tempfile.mkdtemp(prefix="trident-dataflow-")
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


def finding(report, path):
    for entry in report["findings"]:
        if entry["endpoint"]["path"] == path:
            return entry
    raise RuntimeError(f"missing finding {path}")


def findings_for(report, path):
    return [entry for entry in report["findings"] if entry["endpoint"]["path"] == path]


def finding_cwe(report, path, cwe):
    for entry in report["findings"]:
        if entry["endpoint"]["path"] == path and entry["cwe"] == cwe:
            return entry
    return None


def flow_kinds_of(entry):
    return {step["kind"] for step in entry["flow"]}


def main():
    fixture_before = tree_hashes(FIXTURE)
    require(fixture_before, "Missing synthetic Java fixture")
    env = os.environ.copy()
    for name in ("TRIDENT_DATABASE_URL", "TRIDENT_TOKEN", "TRIDENT_TEST_DATABASE_URL",
                 "TRIDENT_TEST_ADMIN_TOKEN"):
        env.pop(name, None)
    with temporary_work() as work:
        parent = Path(work)
        binary = parent / ("trident.exe" if os.name == "nt" else "trident")
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/trident"],
                       cwd=ROOT, env=env, check=True, timeout=180)

        def invoke(*args, failure=False, retries=0):
            # [02] Windows may briefly deny the strict snapshot sharing mode while
            # a freshly written file is scanned; retry only that transient.
            for attempt in range(retries + 1):
                result = subprocess.run([str(binary), *args], cwd=ROOT, env=env,
                                        capture_output=True, text=True, encoding="utf-8", timeout=120)
                if not failure and result.returncode != 0 and attempt < retries \
                        and "share access flags are incompatible" in result.stderr:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                break
            if failure:
                require(result.returncode != 0 and not result.stdout.strip(),
                        "Expected failure without success JSON: " + repr(args))
                return None
            require(result.returncode == 0, result.stderr.strip() or "CLI failed")
            return json.loads(result.stdout)

        snapshot = parent / "snapshot"
        imported = invoke("project", "import", "--source", str(FIXTURE), "--snapshot", str(snapshot), retries=3)
        snapshot_hash = imported["snapshot_hash"]
        snapshot_before = tree_hashes(snapshot)
        common = ["--snapshot", str(snapshot), "--snapshot-hash", snapshot_hash]

        report = invoke("audit", "dataflow", *common, retries=3)
        require(report["schema_version"] == 1
                and report["analysis_kind"] == "source_sink_multi_category_v1"
                and report["snapshot_hash"] == snapshot_hash,
                "Unexpected dataflow report identity")
        require(report["partial"] is False
                and report["coverage"]["endpoints_analyzed"] == 3
                and len(report["findings"]) == 3,
                "Finding/endpoint coverage mismatch")
        require(report["coverage"]["findings_confirmed"] == 1
                and report["coverage"]["findings_refuted"] == 1
                and report["coverage"]["findings_inconclusive"] == 1,
                "Finding status counts mismatch")
        require(report["coverage"]["java_ast"] == "not_available"
                and report["coverage"]["taint_analysis"] == "bounded_lexical_multi_category"
                and report["coverage"]["runtime_status"] == "not_run",
                "Dataflow coverage overclaimed analysis")

        unsafe = finding(report, "/synthetic/customers/unsafe")
        require(unsafe["status"] == "static_confirmed"
                and unsafe["severity"] == "high"
                and unsafe["cwe"] == "CWE-89"
                and unsafe["runtime_status"] == "not_run",
                "Unsafe finding status mismatch")
        require(unsafe["sink"]["api"] == "statement.executeQuery"
                and unsafe["sink"]["line"] == 28
                and unsafe["sink"]["file"].endswith("CustomerRepository.java"),
                "Unsafe sink mismatch")
        require(unsafe["sources"][0]["parameter"] == "name"
                and unsafe["sources"][0]["binding_name"] == "name",
                "Unsafe source mismatch")
        flow_kinds = {step["kind"] for step in unsafe["flow"]}
        require({"call", "concat", "sink"} <= flow_kinds, "Unsafe flow incomplete")
        anchors = {item.get("anchor") for item in unsafe["evidence"]}
        require({"fixture:unsafe-http-source", "fixture:sql-concatenation"} <= anchors,
                "Unsafe evidence anchors missing")

        parameterized = finding(report, "/synthetic/customers/parameterized")
        require(parameterized["status"] == "refuted"
                and parameterized["severity"] == "none"
                and "sink" not in parameterized
                and parameterized["protection"]["api"] == "statement.setString"
                and parameterized["protection"]["line"] == 39,
                "Parameterized negative control mismatch")

        dynamic = finding(report, "/synthetic/customers/dynamic")
        require(dynamic["status"] == "inconclusive"
                and dynamic["boundary"]["kind"] == "dynamic_invocation",
                "Dynamic finding mismatch")

        # [03] Builder/String.format coverage is a separate fixture so the
        # original endpoint/finding counts stay stable.
        format_before = tree_hashes(FORMAT_FIXTURE)
        require(format_before, "Missing builder/format fixture")
        format_snapshot = parent / "format-snapshot"
        format_imported = invoke("project", "import", "--source", str(FORMAT_FIXTURE),
                                 "--snapshot", str(format_snapshot), retries=3)
        format_hash = format_imported["snapshot_hash"]
        format_common = ["--snapshot", str(format_snapshot), "--snapshot-hash", format_hash]
        format_snapshot_before = tree_hashes(format_snapshot)
        format_report = invoke("audit", "dataflow", *format_common, retries=3)
        require(format_report["partial"] is False
                and format_report["coverage"]["endpoints_analyzed"] == 8
                and len(format_report["findings"]) == 9,
                "Builder/format finding coverage mismatch")
        require(format_report["coverage"]["findings_confirmed"] == 4
                and format_report["coverage"]["findings_inconclusive"] == 5
                and format_report["coverage"]["findings_refuted"] == 0,
                "Builder/format status counts mismatch")

        builder = finding(format_report, "/synthetic/format/builder")
        require(builder["status"] == "static_confirmed"
                and builder["sink"]["api"] == "statement.executeQuery"
                and {"builder_append", "sink"} <= flow_kinds_of(builder),
                "StringBuilder append sink mismatch")
        require("fixture:builder-append" in {item.get("anchor") for item in builder["evidence"]},
                "StringBuilder evidence anchor missing")

        buffer = finding(format_report, "/synthetic/format/buffer")
        require(buffer["status"] == "static_confirmed"
                and {"builder_append", "builder_to_string", "sink"} <= flow_kinds_of(buffer),
                "StringBuffer toString flow mismatch")

        constant_builder = finding(format_report, "/synthetic/format/builder-constant")
        require(constant_builder["status"] == "inconclusive" and "sink" not in constant_builder,
                "Constant builder negative control mismatch")

        formatted = finding(format_report, "/synthetic/format/format")
        require(formatted["status"] == "static_confirmed"
                and {"string_format", "sink"} <= flow_kinds_of(formatted),
                "String.format assignment mismatch")

        format_sink = finding(format_report, "/synthetic/format/format-sink")
        require(format_sink["status"] == "static_confirmed"
                and format_sink["sink"]["api"] == "statement.executeQuery",
                "String.format sink mismatch")

        constant_format = finding(format_report, "/synthetic/format/format-constant")
        require(constant_format["status"] == "inconclusive" and "sink" not in constant_format,
                "String.format ignored argument negative control mismatch")

        dynamic_format = findings_for(format_report, "/synthetic/format/format-dynamic")
        require(len(dynamic_format) == 2
                and all(entry["status"] == "inconclusive"
                        and entry["boundary"]["kind"] == "string_format_dynamic"
                        for entry in dynamic_format),
                "Dynamic String.format boundary mismatch")

        builder_boundary = finding(format_report, "/synthetic/format/builder-boundary")
        require(builder_boundary["status"] == "inconclusive"
                and builder_boundary["boundary"]["kind"] == "unresolved_call",
                "Builder boundary mismatch")
        require(tree_hashes(format_snapshot) == format_snapshot_before,
                "Dataflow changed its builder/format snapshot")
        require(tree_hashes(FORMAT_FIXTURE) == format_before,
                "Original builder/format fixture was changed")

        # [04] Returned strings and builder mutation are also a separate fixture.
        return_before = tree_hashes(RETURN_FIXTURE)
        require(return_before, "Missing return-flow fixture")
        return_snapshot = parent / "return-snapshot"
        return_imported = invoke("project", "import", "--source", str(RETURN_FIXTURE),
                                 "--snapshot", str(return_snapshot), retries=3)
        return_hash = return_imported["snapshot_hash"]
        return_common = ["--snapshot", str(return_snapshot), "--snapshot-hash", return_hash]
        return_snapshot_before = tree_hashes(return_snapshot)
        return_report = invoke("audit", "dataflow", *return_common, retries=3)
        require(return_report["partial"] is False
                and return_report["coverage"]["endpoints_analyzed"] == 6
                and len(return_report["findings"]) == 7,
                "Return/builder-mutation coverage mismatch")
        require(return_report["coverage"]["findings_confirmed"] == 3
                and return_report["coverage"]["findings_inconclusive"] == 4
                and return_report["coverage"]["findings_refuted"] == 0,
                "Return/builder-mutation status counts mismatch")

        returned = finding(return_report, "/synthetic/return/sink")
        require(returned["status"] == "static_confirmed"
                and {"return", "sink"} <= flow_kinds_of(returned),
                "Tainted return assignment mismatch")
        require("fixture:return-concat" in {item.get("anchor") for item in returned["evidence"]},
                "Tainted return evidence anchor missing")

        return_direct = finding(return_report, "/synthetic/return/sink-direct")
        require(return_direct["status"] == "static_confirmed"
                and return_direct["sink"]["api"] == "statement.executeQuery",
                "Tainted return sink mismatch")

        return_constant = finding(return_report, "/synthetic/return/constant")
        require(return_constant["status"] == "inconclusive" and "sink" not in return_constant,
                "Clean return negative control mismatch")

        return_dynamic = findings_for(return_report, "/synthetic/return/dynamic")
        require(len(return_dynamic) == 2
                and all(entry["status"] == "inconclusive"
                        and entry["boundary"]["kind"] == "string_format_dynamic"
                        for entry in return_dynamic),
                "Dynamic format through return boundary mismatch")

        mutation = finding(return_report, "/synthetic/return/builder")
        require(mutation["status"] == "static_confirmed"
                and {"builder_mutated", "sink"} <= flow_kinds_of(mutation),
                "Builder mutation through helper mismatch")
        require("fixture:builder-mutation" in {item.get("anchor") for item in mutation["evidence"]},
                "Builder mutation evidence anchor missing")

        mutation_constant = finding(return_report, "/synthetic/return/builder-constant")
        require(mutation_constant["status"] == "inconclusive" and "sink" not in mutation_constant,
                "Builder mutation negative control mismatch")
        require(tree_hashes(return_snapshot) == return_snapshot_before,
                "Dataflow changed its return-flow snapshot")
        require(tree_hashes(RETURN_FIXTURE) == return_before,
                "Original return-flow fixture was changed")

        # [05] Interface/inheritance dispatch and field taint are a separate fixture.
        dispatch_before = tree_hashes(DISPATCH_FIXTURE)
        require(dispatch_before, "Missing dispatch/field fixture")
        dispatch_snapshot = parent / "dispatch-snapshot"
        dispatch_imported = invoke("project", "import", "--source", str(DISPATCH_FIXTURE),
                                   "--snapshot", str(dispatch_snapshot), retries=3)
        dispatch_hash = dispatch_imported["snapshot_hash"]
        dispatch_common = ["--snapshot", str(dispatch_snapshot), "--snapshot-hash", dispatch_hash]
        dispatch_snapshot_before = tree_hashes(dispatch_snapshot)
        dispatch_report = invoke("audit", "dataflow", *dispatch_common, retries=3)
        require(dispatch_report["partial"] is False
                and dispatch_report["coverage"]["endpoints_analyzed"] == 8
                and len(dispatch_report["findings"]) == 8,
                "Dispatch/field coverage mismatch")
        require(dispatch_report["coverage"]["findings_confirmed"] == 6
                and dispatch_report["coverage"]["findings_inconclusive"] == 2
                and dispatch_report["coverage"]["findings_refuted"] == 0,
                "Dispatch/field status counts mismatch")

        iface = finding(dispatch_report, "/synthetic/dispatch/iface")
        require(iface["status"] == "static_confirmed"
                and iface["sink"]["api"] == "statement.executeQuery",
                "Interface dispatch sink mismatch")
        require("fixture:interface-dispatch" in {item.get("anchor") for item in iface["evidence"]},
                "Interface dispatch evidence anchor missing")

        ambiguous = finding(dispatch_report, "/synthetic/dispatch/iface-ambiguous")
        require(ambiguous["status"] == "inconclusive"
                and ambiguous["boundary"]["kind"] == "ambiguous_dispatch",
                "Ambiguous dispatch boundary mismatch")

        inherited = finding(dispatch_report, "/synthetic/dispatch/extends")
        require(inherited["status"] == "static_confirmed"
                and "fixture:inherited-method" in {item.get("anchor") for item in inherited["evidence"]},
                "Inherited method mismatch")

        override = finding(dispatch_report, "/synthetic/dispatch/override")
        require(override["status"] == "static_confirmed" and override["sink"]["api"] == "statement.executeQuery",
                "Override method mismatch")

        field = finding(dispatch_report, "/synthetic/dispatch/field")
        require(field["status"] == "static_confirmed"
                and "field_write" in flow_kinds_of(field),
                "Field taint mismatch")
        require("fixture:field-write" in {item.get("anchor") for item in field["evidence"]},
                "Field write evidence anchor missing")

        field_copy = finding(dispatch_report, "/synthetic/dispatch/field-copy")
        require(field_copy["status"] == "static_confirmed"
                and "field_read" in flow_kinds_of(field_copy),
                "Field copy mismatch")

        field_constant = finding(dispatch_report, "/synthetic/dispatch/field-constant")
        require(field_constant["status"] == "inconclusive" and "sink" not in field_constant,
                "Constant field negative control mismatch")

        inherited_field = finding(dispatch_report, "/synthetic/dispatch/field-inherited")
        require(inherited_field["status"] == "static_confirmed"
                and "field_write" in flow_kinds_of(inherited_field),
                "Inherited field taint mismatch")
        require("fixture:inherited-field-write" in {item.get("anchor") for item in inherited_field["evidence"]},
                "Inherited field evidence anchor missing")
        require(tree_hashes(dispatch_snapshot) == dispatch_snapshot_before,
                "Dataflow changed its dispatch/field snapshot")
        require(tree_hashes(DISPATCH_FIXTURE) == dispatch_before,
                "Original dispatch/field fixture was changed")

        # [06] Overload selection and out-of-snapshot parents use a separate fixture.
        overload_before = tree_hashes(OVERLOAD_FIXTURE)
        require(overload_before, "Missing overload/parent fixture")
        overload_snapshot = parent / "overload-snapshot"
        overload_imported = invoke("project", "import", "--source", str(OVERLOAD_FIXTURE),
                                   "--snapshot", str(overload_snapshot), retries=3)
        overload_hash = overload_imported["snapshot_hash"]
        overload_common = ["--snapshot", str(overload_snapshot), "--snapshot-hash", overload_hash]
        overload_snapshot_before = tree_hashes(overload_snapshot)
        overload_report = invoke("audit", "dataflow", *overload_common, retries=3)
        require(overload_report["partial"] is False
                and overload_report["coverage"]["endpoints_analyzed"] == 5
                and len(overload_report["findings"]) == 5,
                "Overload/parent coverage mismatch")
        require(overload_report["coverage"]["findings_confirmed"] == 3
                and overload_report["coverage"]["findings_inconclusive"] == 2
                and overload_report["coverage"]["findings_refuted"] == 0,
                "Overload/parent status counts mismatch")

        overload_string = finding(overload_report, "/synthetic/overload/string")
        require(overload_string["status"] == "static_confirmed"
                and overload_string["sink"]["api"] == "statement.executeQuery",
                "String overload sink mismatch")
        require("fixture:overload-string" in {item.get("anchor") for item in overload_string["evidence"]},
                "String overload evidence anchor missing")

        overload_int = finding(overload_report, "/synthetic/overload/int")
        require(overload_int["status"] == "static_confirmed"
                and overload_int["sink"]["api"] == "statement.executeQuery",
                "Integer overload sink mismatch")

        overload_object = finding(overload_report, "/synthetic/overload/object")
        require(overload_object["status"] == "inconclusive"
                and overload_object["boundary"]["kind"] == "ambiguous_overload",
                "Ambiguous overload boundary mismatch")

        unresolved_parent = finding(overload_report, "/synthetic/overload/parent")
        require(unresolved_parent["status"] == "inconclusive"
                and unresolved_parent["boundary"]["kind"] == "unresolved_parent",
                "Unresolved parent boundary mismatch")

        local_parent = finding(overload_report, "/synthetic/overload/local-parent")
        require(local_parent["status"] == "static_confirmed"
                and "fixture:local-parent" in {item.get("anchor") for item in local_parent["evidence"]},
                "Local parent mismatch")
        require(tree_hashes(overload_snapshot) == overload_snapshot_before,
                "Dataflow changed its overload/parent snapshot")
        require(tree_hashes(OVERLOAD_FIXTURE) == overload_before,
                "Original overload/parent fixture was changed")

        # [07] Lambda, generic and varargs overloads use a separate fixture.
        advanced_before = tree_hashes(ADVANCED_FIXTURE)
        require(advanced_before, "Missing lambda/generic/varargs fixture")
        advanced_snapshot = parent / "advanced-snapshot"
        advanced_imported = invoke("project", "import", "--source", str(ADVANCED_FIXTURE),
                                   "--snapshot", str(advanced_snapshot), retries=3)
        advanced_hash = advanced_imported["snapshot_hash"]
        advanced_common = ["--snapshot", str(advanced_snapshot), "--snapshot-hash", advanced_hash]
        advanced_snapshot_before = tree_hashes(advanced_snapshot)
        advanced_report = invoke("audit", "dataflow", *advanced_common, retries=3)
        require(advanced_report["partial"] is False
                and advanced_report["coverage"]["endpoints_analyzed"] == 6
                and len(advanced_report["findings"]) == 6,
                "Lambda/generic/varargs coverage mismatch")
        require(advanced_report["coverage"]["findings_confirmed"] == 4
                and advanced_report["coverage"]["findings_inconclusive"] == 2
                and advanced_report["coverage"]["findings_refuted"] == 0,
                "Lambda/generic/varargs status counts mismatch")

        lambda_finding = finding(advanced_report, "/synthetic/advanced/lambda")
        require(lambda_finding["status"] == "static_confirmed"
                and lambda_finding["sink"]["api"] == "statement.executeQuery",
                "Lambda overload sink mismatch")
        require("fixture:lambda-overload" in {item.get("anchor") for item in lambda_finding["evidence"]},
                "Lambda overload evidence anchor missing")

        lambda_boundary = finding(advanced_report, "/synthetic/advanced/lambda-ambiguous")
        require(lambda_boundary["status"] == "inconclusive"
                and lambda_boundary["boundary"]["kind"] == "ambiguous_overload",
                "Ambiguous lambda boundary mismatch")

        varargs_finding = finding(advanced_report, "/synthetic/advanced/varargs")
        require(varargs_finding["status"] == "static_confirmed"
                and "fixture:varargs-overload" in {item.get("anchor") for item in varargs_finding["evidence"]},
                "Varargs overload mismatch")

        varargs_boundary = finding(advanced_report, "/synthetic/advanced/varargs-ambiguous")
        require(varargs_boundary["status"] == "inconclusive"
                and varargs_boundary["boundary"]["kind"] == "ambiguous_overload",
                "Ambiguous varargs boundary mismatch")

        generic_finding = finding(advanced_report, "/synthetic/advanced/generic")
        require(generic_finding["status"] == "static_confirmed"
                and generic_finding["sink"]["api"] == "statement.executeQuery",
                "Generic overload mismatch")
        require("fixture:generic-identity" in {item.get("anchor") for item in generic_finding["evidence"]},
                "Generic identity evidence anchor missing")

        generic_direct = finding(advanced_report, "/synthetic/advanced/generic-direct")
        require(generic_direct["status"] == "static_confirmed"
                and generic_direct["sink"]["api"] == "statement.executeQuery",
                "Generic identity assignment mismatch")
        require(tree_hashes(advanced_snapshot) == advanced_snapshot_before,
                "Dataflow changed its lambda/generic/varargs snapshot")
        require(tree_hashes(ADVANCED_FIXTURE) == advanced_before,
                "Original lambda/generic/varargs fixture was changed")

        # [08] Non-SQL injection sinks use a separate fixture. SQL findings remain
        # one per parameter; other categories appear only when observed.
        injection_before = tree_hashes(INJECTION_FIXTURE)
        require(injection_before, "Missing injection-sink fixture")
        injection_snapshot = parent / "injection-snapshot"
        injection_imported = invoke("project", "import", "--source", str(INJECTION_FIXTURE),
                                    "--snapshot", str(injection_snapshot), retries=3)
        injection_hash = injection_imported["snapshot_hash"]
        injection_common = ["--snapshot", str(injection_snapshot), "--snapshot-hash", injection_hash]
        injection_snapshot_before = tree_hashes(injection_snapshot)
        injection_report = invoke("audit", "dataflow", *injection_common, retries=3)
        require(injection_report["partial"] is False
                and injection_report["coverage"]["endpoints_analyzed"] == 12
                and len(injection_report["findings"]) == 21,
                "Injection-sink coverage mismatch")
        require(injection_report["coverage"]["findings_confirmed"] == 8
                and injection_report["coverage"]["findings_inconclusive"] == 13
                and injection_report["coverage"]["findings_refuted"] == 0,
                "Injection-sink status counts mismatch")

        command = finding_cwe(injection_report, "/synthetic/inject/command", "CWE-78")
        require(command is not None and command["status"] == "static_confirmed"
                and command["sink"]["api"] == "Runtime.getRuntime().exec"
                and {"call", "command_sink"} <= flow_kinds_of(command),
                "Runtime.exec command sink mismatch")
        require("fixture:command-exec" in {item.get("anchor") for item in command["evidence"]},
                "Command evidence anchor missing")

        command_builder = finding_cwe(injection_report, "/synthetic/inject/command-builder", "CWE-78")
        require(command_builder is not None and command_builder["status"] == "static_confirmed"
                and command_builder["sink"]["api"] == "builder.start"
                and "command_append" in flow_kinds_of(command_builder),
                "ProcessBuilder command sink mismatch")

        command_constant = finding_cwe(injection_report, "/synthetic/inject/command-constant", "CWE-78")
        require(command_constant is None, "Constant command must not be reported")

        command_dynamic = finding_cwe(injection_report, "/synthetic/inject/command-dynamic", "CWE-78")
        require(command_dynamic is not None and command_dynamic["status"] == "inconclusive"
                and "sink" not in command_dynamic
                and command_dynamic["boundary"]["kind"] == "unresolved_sink",
                "Dynamic command boundary mismatch")

        ssrf = finding_cwe(injection_report, "/synthetic/inject/ssrf", "CWE-918")
        require(ssrf is not None and ssrf["status"] == "static_confirmed"
                and ssrf["sink"]["api"] == "URL.openConnection"
                and "constructor" in flow_kinds_of(ssrf),
                "URL.openConnection SSRF mismatch")

        ssrf_rest = finding_cwe(injection_report, "/synthetic/inject/ssrf-rest", "CWE-918")
        require(ssrf_rest is not None and ssrf_rest["status"] == "static_confirmed"
                and ssrf_rest["sink"]["api"] == "RestTemplate.getForObject",
                "RestTemplate SSRF mismatch")

        ssrf_constant = finding_cwe(injection_report, "/synthetic/inject/ssrf-constant", "CWE-918")
        require(ssrf_constant is None, "Constant URL must not be reported as SSRF")

        path = finding_cwe(injection_report, "/synthetic/inject/path", "CWE-22")
        require(path is not None and path["status"] == "static_confirmed"
                and path["sink"]["api"] == "new FileInputStream"
                and "path_sink" in flow_kinds_of(path),
                "FileInputStream path traversal mismatch")
        require("fixture:path-stream" in {item.get("anchor") for item in path["evidence"]},
                "Path evidence anchor missing")

        path_files = finding_cwe(injection_report, "/synthetic/inject/path-files", "CWE-22")
        require(path_files is not None and path_files["status"] == "static_confirmed"
                and path_files["sink"]["api"] == "Files.readAllBytes",
                "Files.readAllBytes path traversal mismatch")

        path_constant = finding_cwe(injection_report, "/synthetic/inject/path-constant", "CWE-22")
        require(path_constant is None, "Constant path must not be reported")

        template = finding_cwe(injection_report, "/synthetic/inject/template", "CWE-1336")
        require(template is not None and template["status"] == "static_confirmed"
                and template["sink"]["api"] == "SpelExpressionParser.parseExpression",
                "Spel template injection mismatch")
        require("fixture:template-spel" in {item.get("anchor") for item in template["evidence"]},
                "Template evidence anchor missing")

        template_engine = finding_cwe(injection_report, "/synthetic/inject/template-engine", "CWE-1336")
        require(template_engine is not None and template_engine["status"] == "static_confirmed"
                and template_engine["sink"]["api"] == "SpringTemplateEngine.process",
                "Template engine injection mismatch")

        sql_findings = [entry for entry in injection_report["findings"] if entry["cwe"] == "CWE-89"]
        require(len(sql_findings) == 12
                and all(entry["status"] == "inconclusive" for entry in sql_findings),
                "SQL findings must stay one per parameter and inconclusive")
        require(tree_hashes(injection_snapshot) == injection_snapshot_before,
                "Dataflow changed its injection-sink snapshot")
        require(tree_hashes(INJECTION_FIXTURE) == injection_before,
                "Original injection-sink fixture was changed")

        # [09] XSS, deserialization, XXE and LDAP sinks use a separate fixture.
        extra_before = tree_hashes(EXTRA_FIXTURE)
        require(extra_before, "Missing extra-sink fixture")
        extra_snapshot = parent / "extra-snapshot"
        extra_imported = invoke("project", "import", "--source", str(EXTRA_FIXTURE),
                                "--snapshot", str(extra_snapshot), retries=3)
        extra_hash = extra_imported["snapshot_hash"]
        extra_common = ["--snapshot", str(extra_snapshot), "--snapshot-hash", extra_hash]
        extra_snapshot_before = tree_hashes(extra_snapshot)
        extra_report = invoke("audit", "dataflow", *extra_common, retries=3)
        require(extra_report["partial"] is False
                and extra_report["coverage"]["endpoints_analyzed"] == 14
                and len(extra_report["findings"]) == 24,
                "Extra-sink coverage mismatch")
        require(extra_report["coverage"]["findings_confirmed"] == 8
                and extra_report["coverage"]["findings_inconclusive"] == 16
                and extra_report["coverage"]["findings_refuted"] == 0,
                "Extra-sink status counts mismatch")

        xss_chain = finding_cwe(extra_report, "/synthetic/extra/xss-chain", "CWE-79")
        require(xss_chain is not None and xss_chain["status"] == "static_confirmed"
                and xss_chain["sink"]["api"] == "getWriter().write"
                and "xss_sink" in flow_kinds_of(xss_chain),
                "Inline response writer XSS mismatch")
        require("fixture:xss-chain" in {item.get("anchor") for item in xss_chain["evidence"]},
                "XSS chain evidence anchor missing")

        xss_writer = finding_cwe(extra_report, "/synthetic/extra/xss-writer", "CWE-79")
        require(xss_writer is not None and xss_writer["status"] == "static_confirmed"
                and xss_writer["sink"]["api"] == "PrintWriter.print",
                "PrintWriter XSS mismatch")

        xss_dynamic = finding_cwe(extra_report, "/synthetic/extra/xss-dynamic", "CWE-79")
        require(xss_dynamic is not None and xss_dynamic["status"] == "inconclusive"
                and "sink" not in xss_dynamic
                and xss_dynamic["boundary"]["kind"] == "unresolved_sink",
                "Dynamic XSS boundary mismatch")

        xss_constant = finding_cwe(extra_report, "/synthetic/extra/xss-constant", "CWE-79")
        require(xss_constant is None, "Constant response writer must not be reported")

        deserialization = finding_cwe(extra_report, "/synthetic/extra/deserialization", "CWE-502")
        require(deserialization is not None and deserialization["status"] == "static_confirmed"
                and deserialization["sink"]["api"] == "new ObjectInputStream"
                and "deserialization_sink" in flow_kinds_of(deserialization),
                "ObjectInputStream deserialization mismatch")
        require("fixture:deserialization" in {item.get("anchor") for item in deserialization["evidence"]},
                "Deserialization evidence anchor missing")

        xml_decoder = finding_cwe(extra_report, "/synthetic/extra/xml-decoder", "CWE-502")
        require(xml_decoder is not None and xml_decoder["status"] == "static_confirmed"
                and xml_decoder["sink"]["api"] == "new XMLDecoder",
                "XMLDecoder deserialization mismatch")

        deserialization_constant = finding_cwe(
            extra_report, "/synthetic/extra/deserialization-constant", "CWE-502")
        require(deserialization_constant is None, "Constant deserialization must not be reported")

        xxe_dom = finding_cwe(extra_report, "/synthetic/extra/xxe-dom", "CWE-611")
        require(xxe_dom is not None and xxe_dom["status"] == "static_confirmed"
                and xxe_dom["sink"]["api"] == "DocumentBuilder.parse"
                and "xxe_sink" in flow_kinds_of(xxe_dom),
                "DocumentBuilder XXE mismatch")
        require("fixture:xxe-dom" in {item.get("anchor") for item in xxe_dom["evidence"]},
                "XXE DOM evidence anchor missing")

        xxe_sax = finding_cwe(extra_report, "/synthetic/extra/xxe-sax", "CWE-611")
        require(xxe_sax is not None and xxe_sax["status"] == "static_confirmed"
                and xxe_sax["sink"]["api"] == "SAXParser.parse",
                "SAXParser XXE mismatch")

        xxe_dynamic = finding_cwe(extra_report, "/synthetic/extra/xxe-dynamic", "CWE-611")
        require(xxe_dynamic is not None and xxe_dynamic["status"] == "inconclusive"
                and "sink" not in xxe_dynamic
                and xxe_dynamic["boundary"]["kind"] == "unresolved_sink",
                "Dynamic XXE boundary mismatch")

        xxe_constant = finding_cwe(extra_report, "/synthetic/extra/xxe-constant", "CWE-611")
        require(xxe_constant is None, "Constant XML source must not be reported")

        ldap_search = finding_cwe(extra_report, "/synthetic/extra/ldap-search", "CWE-90")
        require(ldap_search is not None and ldap_search["status"] == "static_confirmed"
                and ldap_search["sink"]["api"] == "InitialDirContext.search"
                and "ldap_sink" in flow_kinds_of(ldap_search),
                "DirContext LDAP search mismatch")
        require("fixture:ldap-search" in {item.get("anchor") for item in ldap_search["evidence"]},
                "LDAP search evidence anchor missing")

        ldap_lookup = finding_cwe(extra_report, "/synthetic/extra/ldap-lookup", "CWE-90")
        require(ldap_lookup is not None and ldap_lookup["status"] == "static_confirmed"
                and ldap_lookup["sink"]["api"] == "LdapTemplate.lookup",
                "LdapTemplate lookup mismatch")

        ldap_constant = finding_cwe(extra_report, "/synthetic/extra/ldap-constant", "CWE-90")
        require(ldap_constant is None, "Constant LDAP query must not be reported")

        extra_sql = [entry for entry in extra_report["findings"] if entry["cwe"] == "CWE-89"]
        require(len(extra_sql) == 14
                and all(entry["status"] == "inconclusive" for entry in extra_sql),
                "Extra-sink SQL findings must stay one per parameter and inconclusive")
        require(tree_hashes(extra_snapshot) == extra_snapshot_before,
                "Dataflow changed its extra-sink snapshot")
        require(tree_hashes(EXTRA_FIXTURE) == extra_before,
                "Original extra-sink fixture was changed")

        # [10] Container taint propagation uses a separate fixture so the
        # earlier endpoint/finding counts stay stable.
        collection_before = tree_hashes(COLLECTION_FIXTURE)
        require(collection_before, "Missing collection fixture")
        collection_snapshot = parent / "collection-snapshot"
        collection_imported = invoke("project", "import", "--source", str(COLLECTION_FIXTURE),
                                     "--snapshot", str(collection_snapshot), retries=3)
        collection_hash = collection_imported["snapshot_hash"]
        collection_common = ["--snapshot", str(collection_snapshot), "--snapshot-hash", collection_hash]
        collection_snapshot_before = tree_hashes(collection_snapshot)
        collection_report = invoke("audit", "dataflow", *collection_common, retries=3)
        require(collection_report["partial"] is False
                and collection_report["coverage"]["endpoints_analyzed"] == 8
                and len(collection_report["findings"]) == 10,
                "Collection coverage mismatch")
        require(collection_report["coverage"]["findings_confirmed"] == 4
                and collection_report["coverage"]["findings_inconclusive"] == 6
                and collection_report["coverage"]["findings_refuted"] == 0,
                "Collection status counts mismatch")

        sql_list = finding_cwe(collection_report, "/synthetic/collection/sql-list", "CWE-89")
        require(sql_list is not None and sql_list["status"] == "static_confirmed"
                and {"collection_add", "collection_read", "sink"} <= flow_kinds_of(sql_list),
                "List collection sink mismatch")
        require("fixture:collection-sql-list" in {item.get("anchor") for item in sql_list["evidence"]},
                "List collection evidence anchor missing")

        sql_map = finding_cwe(collection_report, "/synthetic/collection/sql-map", "CWE-89")
        require(sql_map is not None and sql_map["status"] == "static_confirmed"
                and {"collection_add", "collection_read"} <= flow_kinds_of(sql_map),
                "Map collection sink mismatch")

        sql_constant = finding_cwe(collection_report, "/synthetic/collection/sql-constant", "CWE-89")
        require(sql_constant is not None and sql_constant["status"] == "inconclusive"
                and "sink" not in sql_constant,
                "Constant collection negative control mismatch")

        collection_command = finding_cwe(collection_report, "/synthetic/collection/command-list", "CWE-78")
        require(collection_command is not None and collection_command["status"] == "static_confirmed"
                and collection_command["sink"]["api"] == "Runtime.getRuntime().exec"
                and {"collection_add", "collection_read", "command_sink"} <= flow_kinds_of(collection_command),
                "Collection command sink mismatch")
        require("fixture:collection-command-list" in {item.get("anchor") for item in collection_command["evidence"]},
                "Collection command evidence anchor missing")

        collection_command_constant = finding_cwe(
            collection_report, "/synthetic/collection/command-constant", "CWE-78")
        require(collection_command_constant is None, "Constant collection command must not be reported")

        collection_xss = finding_cwe(collection_report, "/synthetic/collection/xss-list", "CWE-79")
        require(collection_xss is not None and collection_xss["status"] == "static_confirmed"
                and collection_xss["sink"]["api"] == "PrintWriter.write"
                and {"collection_read", "xss_sink"} <= flow_kinds_of(collection_xss),
                "Collection XSS mismatch")

        collection_dynamic = finding_cwe(collection_report, "/synthetic/collection/dynamic", "CWE-89")
        require(collection_dynamic is not None and collection_dynamic["status"] == "inconclusive"
                and "collection_dynamic" in collection_dynamic["limitations"],
                "Dynamic collection limitation mismatch")

        collection_unknown = finding_cwe(
            collection_report, "/synthetic/collection/unknown-receiver", "CWE-89")
        require(collection_unknown is not None and collection_unknown["status"] == "inconclusive"
                and collection_unknown["boundary"]["kind"] == "unresolved_call",
                "Unknown collection receiver boundary mismatch")
        require(tree_hashes(collection_snapshot) == collection_snapshot_before,
                "Dataflow changed its collection snapshot")
        require(tree_hashes(COLLECTION_FIXTURE) == collection_before,
                "Original collection fixture was changed")

        invoke("audit", "dataflow", "--snapshot", str(snapshot), failure=True)
        invoke("audit", "dataflow", *common[:-1], "0" * 64, failure=True)
        require(tree_hashes(snapshot) == snapshot_before, "Dataflow changed its read-only snapshot")
        tampered = snapshot / "jdbc-app" / "src" / "main" / "java" / "example" / "synthetic" / "CustomerRepository.java"
        tampered.write_bytes(tampered.read_bytes() + b"\n// tampered\n")
        invoke("audit", "dataflow", *common, failure=True)
        require(tree_hashes(FIXTURE) == fixture_before, "Original synthetic fixture was changed")

        print(json.dumps({"result": "passed", "snapshot_hash": snapshot_hash,
                          "findings": len(report["findings"]),
                          "confirmed": report["coverage"]["findings_confirmed"],
                          "refuted": report["coverage"]["findings_refuted"],
                          "inconclusive": report["coverage"]["findings_inconclusive"],
                          "builder_format_findings": len(format_report["findings"]),
                          "builder_format_confirmed": format_report["coverage"]["findings_confirmed"],
                          "builder_format_inconclusive": format_report["coverage"]["findings_inconclusive"],
                          "return_flow_findings": len(return_report["findings"]),
                          "return_flow_confirmed": return_report["coverage"]["findings_confirmed"],
                          "return_flow_inconclusive": return_report["coverage"]["findings_inconclusive"],
                          "dispatch_field_findings": len(dispatch_report["findings"]),
                          "dispatch_field_confirmed": dispatch_report["coverage"]["findings_confirmed"],
                          "dispatch_field_inconclusive": dispatch_report["coverage"]["findings_inconclusive"],
                          "overload_parent_findings": len(overload_report["findings"]),
                          "overload_parent_confirmed": overload_report["coverage"]["findings_confirmed"],
                          "overload_parent_inconclusive": overload_report["coverage"]["findings_inconclusive"],
                          "advanced_findings": len(advanced_report["findings"]),
                          "advanced_confirmed": advanced_report["coverage"]["findings_confirmed"],
                          "advanced_inconclusive": advanced_report["coverage"]["findings_inconclusive"],
                          "injection_findings": len(injection_report["findings"]),
                          "injection_confirmed": injection_report["coverage"]["findings_confirmed"],
                          "injection_inconclusive": injection_report["coverage"]["findings_inconclusive"],
                          "extra_findings": len(extra_report["findings"]),
                          "extra_confirmed": extra_report["coverage"]["findings_confirmed"],
                          "extra_inconclusive": extra_report["coverage"]["findings_inconclusive"],
                          "collection_findings": len(collection_report["findings"]),
                          "collection_confirmed": collection_report["coverage"]["findings_confirmed"],
                          "collection_inconclusive": collection_report["coverage"]["findings_inconclusive"],
                          "checks": ["real_cli", "no_database", "no_java_execution",
                                     "cross_method_taint", "string_concat_sink",
                                     "prepared_statement_negative", "dynamic_boundary",
                                     "fixture_anchors", "trusted_hash_required",
                                     "snapshot_unchanged", "content_tampering_rejected",
                                     "string_builder_append", "string_buffer_to_string",
                                     "string_format_literal", "string_format_ignored_argument",
                                     "dynamic_format_boundary", "builder_boundary",
                                     "tainted_return_value", "tainted_return_sink",
                                     "clean_return_negative", "dynamic_format_return_boundary",
                                     "builder_parameter_mutation", "builder_mutation_negative",
                                     "interface_dispatch", "ambiguous_dispatch_boundary",
                                     "inherited_method", "override_method", "field_taint",
                                     "field_copy", "field_constant_negative", "inherited_field_taint",
                                     "overload_string", "overload_int", "ambiguous_overload_boundary",
                                     "unresolved_parent_boundary", "local_parent_override",
                                     "lambda_overload", "ambiguous_lambda_boundary",
                                     "varargs_overload", "ambiguous_varargs_boundary",
                                     "generic_identity", "generic_nested_return",
                                     "command_exec_sink", "process_builder_command",
                                     "constant_command_negative", "dynamic_command_boundary",
                                     "url_open_connection_ssrf", "rest_template_ssrf",
                                     "constant_url_negative", "file_input_stream_path",
                                     "files_read_path", "constant_path_negative",
                                     "spel_parse_expression", "template_engine_process",
                                     "response_writer_xss", "print_writer_xss",
                                     "constant_xss_negative", "dynamic_xss_boundary",
                                     "object_input_stream_deserialization", "xml_decoder_deserialization",
                                     "constant_deserialization_negative",
                                     "document_builder_xxe", "sax_parser_xxe",
                                     "constant_xxe_negative", "dynamic_xxe_boundary",
                                     "ldap_search_sink", "ldap_template_lookup",
                                     "constant_ldap_negative",
                                     "list_collection_taint", "map_collection_taint",
                                     "constant_collection_negative",
                                     "collection_command_sink", "constant_collection_command_negative",
                                     "collection_xss_sink", "collection_dynamic_boundary",
                                     "unknown_collection_receiver_boundary"],
                          "java_executed": False, "model_called": False}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"TRIDENT dataflow verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
