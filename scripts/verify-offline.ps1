# TRIDENT offline verification. Run from the repository root.
# Requires Go, Python 3.12+ and the Python `jsonschema` package.
$ErrorActionPreference = "Stop"

go test -count=1 ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go vet ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$scripts = @(
    "test-project.py",
    "test-sca.py",
    "test-artifact-hash.py",
    "test-intel.py",
    "test-reachability.py",
    "test-java-ast.py",
    "test-audit.py",
    "test-authz.py",
    "test-dataflow.py",
    "test-findings.py",
    "test-sbom.py",
    "test-web.py",
    "test-runtime.py"
)
foreach ($name in $scripts) {
    python (Join-Path "scripts" $name)
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
Write-Output "TRIDENT offline verification passed."
