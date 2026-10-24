# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Run after editing any scanner file: Defender's AMSI must not flag the scripts on the target PC.
# Copies each script with an early 'return' (after the param block, if any) so AMSI scans the full text but nothing executes.
param([string]$Root = (Join-Path (Split-Path $PSScriptRoot -Parent) 'scanner'), [string[]]$Only)
$work = Join-Path $env:TEMP 'pchs-amsi-work'
New-Item -ItemType Directory -Path $work -Force | Out-Null
foreach ($f in Get-ChildItem $Root -Recurse -Filter *.ps1) {
    if ($Only -and $Only -notcontains $f.Name) { continue }
    $txt = [IO.File]::ReadAllText($f.FullName)
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($txt, [ref]$tokens, [ref]$errs)
    if ($ast.ParamBlock) {
        $end = $ast.ParamBlock.Extent.EndOffset
        $txt = $txt.Substring(0, $end) + "`nreturn`n" + $txt.Substring($end)
    } else { $txt = "return`n" + $txt }
    $copy = Join-Path $work $f.Name
    [IO.File]::WriteAllText($copy, $txt)
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $copy 2>&1 | Out-String
    $status = if ($out -match 'malicious content') { 'BLOCKED' } elseif ($out.Trim()) { 'ERR: ' + ($out.Trim() -split "`n")[0] } else { 'ok' }
    '{0,-28} {1}' -f $f.Name, $status
}
Remove-Item $work -Recurse -Force
