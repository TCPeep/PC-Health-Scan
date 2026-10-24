<#
.SYNOPSIS
    PC Health Scan - an in-depth, read-only health and security audit of a Windows 10/11 PC.
    Produces a self-contained HTML report (plus findings.json and a log) in the Reports folder.

.PARAMETER Mode
    Quick, Standard (default) or Deep. START-SCAN.cmd shows a menu and passes this in.
    Deep additionally updates Defender definitions, runs a Defender quick scan and verifies system files (sfc /verifyonly).

.PARAMETER Days
    Look-back window for event logs, new files, installs and the timeline. Default 30.
.NOTES
    PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
    Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Standard', 'Deep')][string]$Mode = 'Standard',
    [ValidateRange(1, 365)][int]$Days = 30,
    [string]$OutputDir,
    [switch]$NoOpen,
    [string[]]$Skip
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$script:Version = '1.0.0'
$script:ScannerRoot = $PSScriptRoot
$script:Days = $Days
$script:Cutoff = (Get-Date).AddDays(-$Days)

. (Join-Path $PSScriptRoot 'lib\Core.ps1')
. (Join-Path $PSScriptRoot 'lib\Report.ps1')
foreach ($m in (Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'modules') -Filter '*.ps1' | Sort-Object Name)) { . $m.FullName }

if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    Write-Host '  NOTE: running in 32-bit PowerShell; some registry areas may be hidden. Use START-SCAN.cmd.' -ForegroundColor Yellow
}
Write-Host ''
Write-Host "  PC Health & Security Scan v$($script:Version) - $Mode scan (read-only)" -ForegroundColor Cyan
Write-Host '  by TCPeep - github.com/TCPeep/PC-Health-Scan' -ForegroundColor DarkGray
Write-Host ''
$script:Mode = $Mode

$script:IsAdmin = Test-IsAdmin
if (-not $script:IsAdmin) {
    Write-Host '    NOTE: not running as administrator. Defender exclusions, drive wear, security logs,' -ForegroundColor Yellow
    Write-Host '          other users'' files and system-file checks will be skipped. Use START-SCAN.cmd for a full scan.' -ForegroundColor Yellow
    Write-Host ''
}

# Output folder
$start = Get-Date
$stamp = $start.ToString('yyyy-MM-dd_HHmm')
$base = if ($OutputDir) { $OutputDir } else { Join-Path (Split-Path $PSScriptRoot -Parent) 'Reports' }
$script:OutDir = Join-Path $base "$($env:COMPUTERNAME)_$stamp"
try { New-Item -ItemType Directory -Path $script:OutDir -Force -ErrorAction Stop | Out-Null }
catch {
    $script:OutDir = Join-Path "$env:PUBLIC\Documents\PC-Health-Scan" "$($env:COMPUTERNAME)_$stamp"
    New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
}
try { Start-Transcript -LiteralPath (Join-Path $script:OutDir 'scan-log.txt') -ErrorAction Stop | Out-Null; $transcript = $true } catch { $transcript = $false }

$script:Profiles = @(Get-UserProfiles)
$script:Hives = @(Get-UserHives)
$script:Shared.PupHits = @()
Import-TrustList (Join-Path (Split-Path $PSScriptRoot -Parent) 'trusted.txt')

Register-Section 'system' 'System overview' 'What this PC is, which Windows it runs, and whether that version still gets security updates.'
Register-Section 'security' 'Windows security settings' 'The built-in protections: UAC, firewall, SmartScreen, Secure Boot, encryption, remote access and more.'
Register-Section 'antivirus' 'Antivirus & threat history' 'Which antivirus is protecting the PC, how it is configured, and everything it has caught.'
Register-Section 'updates' 'Windows Update' 'When Windows last patched itself, failures, and anything blocking updates.'
Register-Section 'accounts' 'Accounts & sign-in' 'Who can sign in to this PC and with what rights.'
Register-Section 'processes' 'Running programs' 'Everything running at scan time that is not a signed Microsoft component, plus CPU and memory use.'
Register-Section 'persistence' 'Startup programs, tasks & services' 'Every way a program can make itself start automatically. This is where adware and malware hide.'
Register-Section 'browsers' 'Browsers' 'Extensions, hijacked search/home pages, forced policies, notification spam and tampered shortcuts.'
Register-Section 'software' 'Installed software & remote access' 'Installed programs, known adware, outdated software and remote-control tools.'
Register-Section 'sweep' 'Malware & adware file sweep' 'Leftover adware folders, recently dropped programs and scripts, downloads and their source websites.'
Register-Section 'network' 'Network' 'Connections, DNS, proxy, hosts file, firewall exceptions and trusted certificates.'
Register-Section 'hardware' 'Hardware & drives' 'Drive health and wear, free space, memory, graphics, battery and device problems.'
Register-Section 'stability' 'Crashes, errors & event logs' 'Blue screens, power losses, hardware errors, crashing programs, security events and suspicious activity.'
Register-Section 'performance' 'Performance & disk space' 'What slows the PC down and how much space can be freed.'
Register-Section 'integrity' 'System integrity' 'Health of Windows itself.'
Register-Section 'timeline' 'Timeline' 'Installs, new services, tasks, downloads, detections and crashes in date order - useful for working out when and how something got in.'

$modules = @(
    @{ Fn = 'Invoke-SystemScan'; Label = 'System overview' },
    @{ Fn = 'Invoke-AccountsScan'; Label = 'Accounts & sign-in' },
    @{ Fn = 'Invoke-SecuritySettingsScan'; Label = 'Windows security settings' },
    @{ Fn = 'Invoke-AntivirusScan'; Label = 'Antivirus & threat history' },
    @{ Fn = 'Invoke-UpdatesScan'; Label = 'Windows Update' },
    @{ Fn = 'Invoke-ProcessesScan'; Label = 'Running programs' },
    @{ Fn = 'Invoke-AutostartScan'; Label = 'Startup programs, tasks, services, drivers' },
    @{ Fn = 'Invoke-BrowsersScan'; Label = 'Browsers' },
    @{ Fn = 'Invoke-SoftwareScan'; Label = 'Installed software' },
    @{ Fn = 'Invoke-MalwareSweepScan'; Label = 'Malware & adware file sweep' },
    @{ Fn = 'Invoke-NetworkScan'; Label = 'Network' },
    @{ Fn = 'Invoke-HardwareScan'; Label = 'Hardware & drives' },
    @{ Fn = 'Invoke-EventsScan'; Label = 'Event logs & stability' },
    @{ Fn = 'Invoke-PerformanceScan'; Label = 'Performance & disk space' },
    @{ Fn = 'Invoke-IntegrityScan'; Label = 'System integrity + pending updates' }
)

$errLog = New-Object System.Collections.Generic.List[string]
$i = 0
foreach ($m in $modules) {
    $i++
    $short = $m.Fn -replace '^Invoke-', '' -replace 'Scan$', ''
    if ($Skip -contains $short) { continue }
    Write-Host ('  [{0,2}/{1}] {2}' -f $i, $modules.Count, $m.Label) -ForegroundColor White
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $result = 'OK'
    $Error.Clear()
    try { & $m.Fn }
    catch {
        $where = ''
        if ($_.InvocationInfo -and $_.InvocationInfo.ScriptName) { $where = " ($(Split-Path $_.InvocationInfo.ScriptName -Leaf):$($_.InvocationInfo.ScriptLineNumber))" }
        $result = "FAILED: $($_.Exception.Message)$where"
        Write-Host "     ! $result" -ForegroundColor DarkYellow
        Add-Finding -Severity Info -Category 'Scanner' -Title "Part of the scan failed: $($m.Label)" -Detail $result -Section $null
    }
    $sw.Stop()
    if ($Error.Count -gt 0) {
        foreach ($e in @($Error | Select-Object -First 25)) {
            $loc = ''
            if ($e.InvocationInfo -and $e.InvocationInfo.ScriptName) { $loc = "$(Split-Path $e.InvocationInfo.ScriptName -Leaf):$($e.InvocationInfo.ScriptLineNumber)" }
            $errLog.Add("[$($m.Label)] $loc $($e.Exception.Message)")
        }
    }
    $script:ModuleLog.Add([pscustomobject]@{ Module = $m.Label; Seconds = $sw.Elapsed.TotalSeconds; Result = $result })
}

# timeline
$tl = @($script:Timeline | Sort-Object Time -Descending | Select-Object -First 800)
Add-Table -Section 'timeline' -Title "What happened in the last $Days days" -Rows $tl -Columns @('Time', 'Type', 'Event', 'Severity') `
    -Note 'Tip: find the first adware/malware event and look at what was downloaded or installed just before it - that is usually how it got in.'

if ($script:TrustHits.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Scanner' -Section 'persistence' -Title "$($script:TrustHits.Count) program(s) were not flagged because they are in trusted.txt" `
        -Evidence @($script:TrustHits.Values | Sort-Object) `
        -Why 'You (or whoever ran the Repair Console) marked these as known and legitimate.' `
        -Fix "To flag them again, delete their lines from $($script:TrustList.File)."
}

if (-not $script:IsAdmin) {
    Add-Finding -Severity Info -Category 'Scanner' -Section 'system' -Title 'Scan ran without administrator rights' `
        -Detail 'Defender exclusions and threat history, drive wear/temperature, the Security event log, WMI persistence, other users'' folders and system-file checks were partly or fully skipped.' `
        -Fix 'Re-run with START-SCAN.cmd and accept the administrator prompt for a complete picture.'
}

# report
$elapsed = (Get-Date) - $start
$meta = [pscustomobject]@{
    Computer = $env:COMPUTERNAME; OSLine = $script:Shared.OSLine; User = "$env:USERDOMAIN\$env:USERNAME"; Started = $start
    Duration = ('{0}m {1:00}s' -f [int][Math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds); Mode = $Mode; Admin = $script:IsAdmin; Days = $Days; Version = $script:Version
}
$reportPath = Join-Path $script:OutDir "PC-Health-Report_$($env:COMPUTERNAME)_$stamp.html"
Write-Host ''
Write-Host '  Writing report...' -ForegroundColor White
try { New-HtmlReport -Path $reportPath -Meta $meta } catch { Write-Host "  ! Report failed: $($_.Exception.Message) line $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red }

try {
    $jsonSections = @()   # (not $sections: PowerShell names are case-insensitive and that IS $script:Sections)
    foreach ($sec in $script:Sections) {
        $tables = @()
        foreach ($b in $sec.Blocks) {
            if ($b.Kind -eq 'note') { continue }
            $rows = @()
            foreach ($r in $b.Rows) {
                $o = [ordered]@{}
                foreach ($c in $b.Columns) { $o[[string]$c] = $r.$c }
                $rows += , $o
            }
            $tables += , [ordered]@{ Title = $b.Title; Rows = $rows }
        }
        $jsonSections += , [ordered]@{ Id = $sec.Id; Title = $sec.Title; Tables = $tables }
    }
    $data = [ordered]@{
        Meta     = $meta
        Findings = @($script:Findings | Sort-Object Rank -Descending | Select-Object Id, Severity, Category, Title, Detail, Why, Fix, Evidence, Section, Actions)
        Passed   = $script:Passes.ToArray()   # not @(): some PS 5.1 builds throw "Argument types do not match" on @(List[object])
        Timeline = @($tl | Select-Object Time, Type, Event, Severity)
        Sections = $jsonSections
    }
    (ConvertTo-PlainData $data) | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath (Join-Path $script:OutDir 'findings.json') -Encoding UTF8
} catch { $errLog.Add("[json] $($_.Exception.Message)") }
# expected noise (missing keys, protected folders) is dropped so real scanner bugs stand out
$errLog = @($errLog | Where-Object { $_ -notmatch 'Cannot find path|does not exist|Could not find a part of the path|Access to the path|Access denied|registry access is not allowed|alternate data stream|No events were found|not an event provider|No matching MSFT_' })
if ($errLog.Count -gt 0) { $errLog | Set-Content -LiteralPath (Join-Path $script:OutDir 'scanner-errors.txt') -Encoding UTF8 }

# console summary
$cnt = @{}
foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $cnt[$s] = @($script:Findings | Where-Object { $_.Severity -eq $s }).Count }
$secScore = Get-ScoreInfo $script:SecurityCategories
$heaScore = Get-ScoreInfo $script:HealthCategories
Write-Host ''
Write-Host '  ==========================================================' -ForegroundColor Cyan
Write-Host ('    Finished in {0}' -f $meta.Duration) -ForegroundColor Cyan
Write-Host ('    Security grade: {0} ({1}/100)    Health grade: {2} ({3}/100)' -f $secScore.Grade, $secScore.Score, $heaScore.Grade, $heaScore.Score) -ForegroundColor Cyan
Write-Host ('    Critical: {0}   High: {1}   Medium: {2}   Low: {3}' -f $cnt['Critical'], $cnt['High'], $cnt['Medium'], $cnt['Low']) -ForegroundColor $(if ($cnt['Critical'] -gt 0) { 'Magenta' } elseif ($cnt['High'] -gt 0) { 'Red' } elseif ($cnt['Medium'] -gt 0) { 'Yellow' } else { 'Green' })
Write-Host '  ==========================================================' -ForegroundColor Cyan
Write-Host "    Report: $reportPath" -ForegroundColor White
Write-Host ''
if ($transcript) { try { Stop-Transcript | Out-Null } catch {} }

if (-not $NoOpen -and (Test-Path -LiteralPath $reportPath)) {
    # explorer.exe opens it in the signed-in user's normal (non-elevated) browser
    Start-Process -FilePath "$env:SystemRoot\explorer.exe" -ArgumentList "`"$reportPath`""
}
