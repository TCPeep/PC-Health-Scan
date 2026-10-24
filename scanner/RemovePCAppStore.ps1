<#
.SYNOPSIS
    Removes PC App Store (Fast Corporation LTD) completely, straight from the console window - no web page needed.
    For PCs where its full-screen "create your account" page makes a browser unusable. Started by RUN-REPAIRS.cmd
    (options 3 = show what would be removed, 4 = remove). Uses the same guarded engine and undo journal as the
    Repair Console, so every step can be undone later from RUN-REPAIRS.cmd > Undo & restore.
.NOTES
    PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
    Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
#>
[CmdletBinding()]
param([switch]$DryRun)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$libDir = Join-Path $PSScriptRoot 'lib'
. (Join-Path $libDir 'Core.ps1')
. (Join-Path $libDir 'Repair.ps1')

if (-not $DryRun -and -not (Test-IsAdmin)) { Write-Host '  Administrator rights are needed. Start it from RUN-REPAIRS.cmd.' -ForegroundColor Yellow; exit 1 }

$reports = Join-Path (Split-Path $PSScriptRoot -Parent) 'Reports'
New-Item -ItemType Directory -Path $reports -Force | Out-Null
$logFile = Join-Path $reports ("PCAppStore-removal_{0}_{1}.txt" -f $env:COMPUTERNAME, (Get-Date).ToString('yyyy-MM-dd_HHmm'))
try { $ctx = New-RepairSession -DryRun:$DryRun } catch { Write-Host "  Could not prepare $(Get-RepairBase): $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
$ctx.Job = 'pcas-' + (Get-Date).ToString('HHmmss'); $ctx.Item = 'Remove PC App Store completely'
$ctx.JobState = [hashtable]::Synchronized(@{ Changes = 0 })

$log = {
    param($m)
    $line = (Get-Date).ToString('HH:mm:ss') + '  ' + $m
    $color = if ($m -match 'FAILED|REFUSED|STILL|could not|NOT FINISHED') { 'Red' } elseif ($m -match '^\s*\[SIMULATE\]') { 'DarkGray' } elseif ($m -match '^== |^####') { 'Cyan' } elseif ($m -match 'nothing .*left|nothing found|checked again') { 'Green' } else { 'Gray' }
    Write-Host ('  ' + $line) -ForegroundColor $color
    try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch {}
}

Write-Host ''
Write-Host '  ==========================================================' -ForegroundColor Cyan
Write-Host $(if ($DryRun) { '    PC APP STORE - what would be removed (nothing is changed)' } else { '    PC APP STORE - complete removal' }) -ForegroundColor Cyan
Write-Host '  ==========================================================' -ForegroundColor Cyan
& $log ("#### " + $(if ($DryRun) { 'SIMULATE' } else { 'APPLY' }) + ': Remove PC App Store completely')
$r = Invoke-RepairAction -Action (New-RepairAction -Kind RemovePCAppStore -Label 'Remove PC App Store completely' -Risk caution) -Log $log -Ctx $ctx -DryRun:$DryRun
if (-not $DryRun -and $r.Ok) {
    # stop it coming back: Defender's potentially-unwanted-app blocking (undoable)
    $null = Invoke-RepairAction -Action (New-RepairAction -Kind MpPreference -Label 'Turn on Defender blocking of potentially unwanted apps' -Params @{ Setting = 'PUAProtection'; Value = 'Enabled' }) -Log $log -Ctx $ctx
}
& $log ("#### finished: " + $(if ($r.Ok) { 'OK' } else { 'not everything could be done - see the red lines above' }))
Write-Host ''
Write-Host "  Log saved to: $logFile" -ForegroundColor DarkCyan
if (-not $DryRun) {
    Write-Host '  Every change can be undone: RUN-REPAIRS.cmd > option 1 > "Undo & restore".' -ForegroundColor DarkCyan
    Write-Host '  Next: restart the PC, run START-SCAN.cmd again, then a Microsoft Defender full scan.' -ForegroundColor White
}
