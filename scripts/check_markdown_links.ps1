param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$files = @(
    Get-Item -LiteralPath (Join-Path $root 'README.md')
    Get-ChildItem -LiteralPath (Join-Path $root 'docs') -Recurse -File -Filter '*.md'
    Get-ChildItem -LiteralPath (Join-Path $root 'release') -Recurse -File -Filter '*.md'
) | Sort-Object -Property FullName -Unique

$failures = [System.Collections.Generic.List[string]]::new()
$checked = 0

function Get-MarkdownAnchors {
    param([string]$Path)

    $anchors = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -notmatch '^\s{0,3}#{1,6}\s+(?<heading>.+?)\s*#*\s*$') {
            continue
        }
        $heading = $Matches.heading.ToLowerInvariant()
        $heading = $heading -replace '[`*_~]', ''
        $heading = $heading -replace '[^\p{L}\p{N}\s-]', ''
        $heading = ($heading -replace '\s+', '-').Trim('-')
        [void]$anchors.Add($heading)
    }
    return $anchors
}

foreach ($file in $files) {
    $content = Get-Content -Raw -LiteralPath $file.FullName
    $matches = [regex]::Matches($content, '!?\[[^\]]*\]\((?<target>[^)\r\n]+)\)')
    foreach ($match in $matches) {
        $target = $match.Groups['target'].Value.Trim()
        if ($target.StartsWith('<') -and $target.EndsWith('>')) {
            $target = $target.Substring(1, $target.Length - 2)
        }
        if ($target -match '^(?i:https?|mailto):') {
            continue
        }
        $checked++
        $parts = $target.Split('#', 2)
        $pathPart = [uri]::UnescapeDataString($parts[0])
        $anchor = if ($parts.Count -eq 2) { [uri]::UnescapeDataString($parts[1]) } else { '' }
        $resolved = if ([string]::IsNullOrEmpty($pathPart)) {
            $file.FullName
        } else {
            [System.IO.Path]::GetFullPath((Join-Path $file.DirectoryName $pathPart))
        }
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            $relativeFile = [System.IO.Path]::GetRelativePath($root, $file.FullName)
            $failures.Add("$relativeFile -> missing: $target")
            continue
        }
        if (-not [string]::IsNullOrEmpty($anchor) -and
            [System.IO.Path]::GetExtension($resolved) -ieq '.md') {
            $anchors = Get-MarkdownAnchors -Path $resolved
            if (-not $anchors.Contains($anchor)) {
                $relativeFile = [System.IO.Path]::GetRelativePath($root, $file.FullName)
                $failures.Add("$relativeFile -> missing anchor: $target")
            }
        }
    }
}

Write-Output "markdown_files=$($files.Count)"
Write-Output "local_links_checked=$checked"
Write-Output "link_failures=$($failures.Count)"
foreach ($failure in $failures) {
    Write-Output "BROKEN_LINK: $failure"
}

if ($failures.Count -gt 0) {
    exit 1
}
