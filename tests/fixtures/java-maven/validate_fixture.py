#!/usr/bin/env python3
"""[01] Read-only fixture integrity checks; never build, import or execute Java samples."""

import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


# [02] Resolve only fixture-local files and reject symlinks; no network/subprocess/import hooks.
ROOT = Path(__file__).resolve().parent
NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def local_file(relative):
    path = ROOT / relative
    require(not Path(relative).is_absolute(), "absolute fixture reference: " + relative)
    require(".." not in Path(relative).parts, "parent traversal reference: " + relative)
    require(not path.is_symlink(), "symlink fixture reference: " + relative)
    require(ROOT in path.resolve().parents, "reference escapes fixture: " + relative)
    require(path.is_file(), "missing fixture file: " + relative)
    return path


def read_json(relative):
    return json.loads(local_file(relative).read_text(encoding="utf-8"))


def text(node, query):
    value = node.find(query, NS)
    require(value is not None and value.text is not None, "missing POM element: " + query)
    return value.text.strip()


def marker(reference):
    source = local_file(reference["path"]).read_text(encoding="utf-8")
    require(source.count(reference["anchor"]) == 1, "missing/nonunique anchor: " + reference["anchor"])


def main():
    # [03] XML/JSON parsing and narrowly scoped inheritance assertions are not Maven resolution.
    expected = read_json("expected.json")
    advisory = read_json(expected["advisory_fixture"])
    require(expected["synthetic_data_only"] is True, "synthetic data flag missing")
    require(expected["schema_version"] == "1.0.0", "unsupported fixture schema")
    require(advisory["advisory_id"] == "CVE-2022-42889", "unexpected advisory")
    parent = ET.parse(local_file("pom.xml")).getroot()
    require(text(parent, "m:packaging") == "pom", "parent must use pom packaging")
    modules = [item.text for item in parent.findall("m:modules/m:module", NS)]
    require(modules == expected["project"]["modules"], "module inventory differs")
    parent_properties = {item.tag.split("}")[-1]: item.text for item in parent.find("m:properties", NS)}
    managed = parent.find("m:dependencyManagement/m:dependencies", NS)
    text_dependencies = [dep for dep in managed if text(dep, "m:artifactId") == "commons-text"]
    require(len(text_dependencies) == 1, "expected one managed Commons Text declaration")
    require(text(text_dependencies[0], "m:version") == "${commons-text.version}", "management must use property")
    require(parent.find("m:dependencies", NS) is None, "management must not become a parent dependency")
    versions = []
    for assertion in expected["dependency_assertions"]:
        module = ET.parse(local_file(assertion["declaration_pom"])).getroot()
        require(text(module, "m:parent/m:relativePath") == "../pom.xml", "local parent path differs")
        for key in ("groupId", "artifactId", "version"):
            require(text(module, "m:parent/m:" + key) == text(parent, "m:" + key), "parent coordinates differ")
        properties = dict(parent_properties)
        child_properties = module.find("m:properties", NS)
        if child_properties is not None:
            properties.update({item.tag.split("}")[-1]: item.text for item in child_properties})
        dependencies = module.findall("m:dependencies/m:dependency", NS)
        matches = [dep for dep in dependencies if text(dep, "m:artifactId") == "commons-text"]
        require(len(matches) == 1, "missing/duplicate module dependency")
        require(text(matches[0], "m:groupId") == "org.apache.commons", "wrong Commons coordinate")
        require(matches[0].find("m:version", NS) is None, "child must inherit managed version")
        require(properties[assertion["property"]] == assertion["expected_version"], "wrong inherited/overridden version")
        versions.append(assertion["expected_version"])
        case = next(item for item in advisory["version_cases"] if item["version"] == assertion["expected_version"])
        require(case["version_matched"] == assertion["version_matched"], "version-match assertion differs")
        require(case["supply_chain_status"] == assertion["supply_chain_status"], "advisory status differs")
        require(assertion["rce_confirmed"] is False and assertion["all_cves_safe"] is False, "overstated dependency claim")
        marker({"path": assertion["component_callsite"], "anchor": assertion["component_callsite_anchor"]})
    require(versions == ["1.9", "1.10.0"], "wrong candidate/control versions")

    # [04] Verify source evidence anchors, without pretending a text search is AST/taint analysis.
    for assertion in expected["source_assertions"]:
        marker(assertion["source"])
        marker(assertion.get("sink", assertion.get("boundary")))
        require(assertion["runtime_status"] == "not_run", "runtime result was invented")
    repository = local_file("jdbc-app/src/main/java/example/synthetic/CustomerRepository.java").read_text(encoding="utf-8")
    require("SELECT id, name FROM synthetic_customers" in repository, "missing uppercase SELECT search material")
    require('statement.setString(1, name)' in repository, "missing bound-value control")
    require('statement.executeQuery(sql)' in repository, "missing concatenation sink")
    require('statement.executeQuery()' in repository, "missing parameterized execution")

    # [05] Inventory frozen future test methods/tags by text only; never load or execute a test.
    validation = expected["future_validation"]
    found = set()
    test_hashes = {}
    suite = hashlib.sha256()
    for relative in validation["test_files"]:
        data = local_file(relative).read_bytes()
        source = data.decode("utf-8")
        package = re.search(r"package\s+([\w.]+);", source).group(1)
        class_name = re.search(r"class\s+(\w+)", source).group(1)
        methods = re.findall(r'@Test\s+@Tag\("(business|security)"\)\s+void\s+(\w+)\s*\(', source)
        require(len(methods) == len(re.findall(r"@Test\b", source)), "unaccounted test annotations")
        require("@Disabled" not in source, "required tests must not be disabled")
        found.update((package + "." + class_name, method, tag) for tag, method in methods)
        test_hashes[relative] = hashlib.sha256(data).hexdigest()
        suite.update(relative.encode("utf-8") + b"\0" + data + b"\0")
    declared = {(item["class"], item["method"], item["tag"]) for item in validation["cases"]}
    require(found == declared, "declared and actual test method inventories differ")
    require(len(found) == validation["required_test_count"] == 9, "required test count differs")
    baseline_failures = [case for case in validation["cases"] if case["baseline"] == "fail_assertion_due_to_extra_rows"]
    require(len(baseline_failures) == 2, "baseline must retain two security assertion failures")
    for phase in ("baseline", "patched"):
        totals = validation["expected_totals"][phase]
        failures = sum(case[phase] != "pass" for case in validation["cases"])
        require(totals == {"executed": 9, "passed": 9 - failures, "failed": failures, "errors": 0, "skipped": 0}, "inconsistent planned totals")
    for root in expected["project"]["source_roots"] + expected["project"]["test_roots"]:
        require((ROOT / root).is_dir(), "missing source/test root: " + root)
    require(expected["execution"]["maven"] == "not_run", "unexpected Maven execution claim")
    require(expected["execution"]["java_tests"] == "not_run", "unexpected Java execution claim")

    # [06] Emit reproducible evidence, not artifacts; no file writes and no generated bytecode.
    print(json.dumps({
        "status": "pass",
        "scope": "fixture_structure_only_not_java_behavior",
        "modules": modules,
        "commons_text_versions": versions,
        "source_assertions": len(expected["source_assertions"]),
        "future_test_methods": len(found),
        "test_file_sha256": test_hashes,
        "test_suite_sha256": suite.hexdigest(),
        "maven_executed": False,
        "java_executed": False,
    }, indent=2))


# [07] A failed integrity check exits nonzero; no failure can be reported as an acceptance pass.
if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, StopIteration, ET.ParseError) as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}), file=sys.stderr)
        sys.exit(1)
