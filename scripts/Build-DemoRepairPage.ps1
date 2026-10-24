# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
<#
.SYNOPSIS
    Renders a static Repair-Console_sample.html from demo-findings.json for the docs screenshots.
    No admin needed. The page's Apply/Simulate buttons point at a fake token so they do nothing
    when loaded as a file: this is a picture, not a working session.
#>
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $root 'samples' }
. (Join-Path $root 'scanner\lib\Core.ps1')
. (Join-Path $root 'scanner\lib\Report.ps1')
. (Join-Path $root 'scanner\lib\RepairPage.ps1')
$findings = Get-Content -LiteralPath (Join-Path $OutDir 'demo-findings.json') -Raw | ConvertFrom-Json

$items = New-Object System.Collections.Generic.List[object]
foreach ($f in @($findings.Findings)) {
    $acts = @($f.Actions | Where-Object { $_ })
    if ($acts.Count -eq 0) { continue }
    $steps = @()
    foreach ($a in $acts) {
        $h = @{}
        foreach ($p in $a.PSObject.Properties) { $h[$p.Name] = $p.Value }
        $steps += , $h
    }
    $items.Add([pscustomobject]@{ Id = ('r' + $items.Count); Severity = $f.Severity; Category = $f.Category; Title = $f.Title; Detail = $f.Detail; Why = $f.Why; Fix = $f.Fix; Evidence = @($f.Evidence); Steps = $steps })
}

$html = Get-RepairPageHtml -Token 'DEMO-TOKEN-NOT-WIRED' -Items $items -Meta $findings.Meta -ScanAge ([timespan]::FromMinutes(2)) -Store (Join-Path $env:TEMP 'pchs-demo') -SessionId 'DEMO'
$out = Join-Path $OutDir 'Repair-Console_sample.html'
# Make sure the live-poll JS cannot talk to anything from a file:// page
$html = $html -replace "api\('/api/", "console.log('demo-only: ', '/api/" -replace 'fetch\(', 'void('
[IO.File]::WriteAllText($out, $html, [Text.UTF8Encoding]::new($false))
Write-Host "wrote $out"
