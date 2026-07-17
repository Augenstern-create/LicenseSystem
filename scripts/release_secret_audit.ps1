param(
    [switch]$AuditOnly
)

$ErrorActionPreference = 'Stop'
$tracked = @(& git ls-files)
if ($LASTEXITCODE -ne 0) {
    throw '无法读取 Git 跟踪文件清单'
}
$working = @(& rg --files --hidden -g '!target/**' -g '!fuzz/target/**' -g '!.git/**')
if ($LASTEXITCODE -ne 0) {
    throw '无法读取工作区文件清单'
}
$candidates = @($tracked + $working | Sort-Object -Unique)
$privatePemPattern = '-----BEGIN ' + '(RSA |EC |OPENSSH )?PRIVATE KEY-----'

$blocking = [System.Collections.Generic.List[string]]::new()
$testFixtures = [System.Collections.Generic.List[string]]::new()

foreach ($path in $candidates) {
    $normalized = $path.Replace('\', '/')
    if ($normalized -match '(?i)(^|/)([^/]*(private|secret)[^/]*\.(der|pem|key|pk8))$') {
        $blocking.Add("tracked private-key-like path: $normalized")
    }
    if ($normalized -eq 'tests/vectors/ed25519-v1.json') {
        $content = Get-Content -Raw -LiteralPath $path
        if ($content -match 'private_key_seed_hex') {
            $testFixtures.Add('public deterministic test seed: tests/vectors/ed25519-v1.json')
        }
    }
    if ($normalized -match '(?i)\.(rs|toml|json|md|ps1|py|txt)$') {
        $content = Get-Content -Raw -LiteralPath $path
        if ($content -match $privatePemPattern) {
            $blocking.Add("embedded PEM private key marker: $normalized")
        }
    }
}

Write-Output "tracked_files=$($tracked.Count)"
Write-Output "candidate_files=$($candidates.Count)"
foreach ($fixture in $testFixtures) {
    Write-Output "TEST_FIXTURE: $fixture"
}
foreach ($finding in $blocking) {
    Write-Output "BLOCKER: $finding"
}
Write-Output "blocking_findings=$($blocking.Count)"

if ($blocking.Count -gt 0 -and -not $AuditOnly) {
    Write-Output 'RELEASE_BLOCKED: 仓库仍跟踪私钥或疑似私钥材料。'
    exit 2
}
