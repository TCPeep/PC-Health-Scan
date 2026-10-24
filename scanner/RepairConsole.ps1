<#
.SYNOPSIS
    PC Health Scan - Repair Console. Reads findings.json from a scan, serves a local web page (127.0.0.1 only)
    with Simulate / Apply / Undo buttons and a live log for every repairable issue.

    Jobs run one at a time (a queue), so two heavy repairs (e.g. DISM) never collide. Every change is written to an
    undo journal in %ProgramData%\PCHealthScan before it happens, and can be reversed from the page later - even
    from a new console session.

.PARAMETER FindingsPath
    Path to a findings.json. Default: the newest one under ..\Reports.
.PARAMETER DryRun
    Force Simulate mode for everything (nothing is changed), useful for testing.
.NOTES
    PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
    Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
#>
[CmdletBinding()]
param(
    [string]$FindingsPath,
    [switch]$DryRun,
    [switch]$NoOpen,
    [int]$Port = 0
)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$libDir = Join-Path $PSScriptRoot 'lib'
$toolRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $libDir 'Core.ps1')
. (Join-Path $libDir 'Repair.ps1')

if (-not (Test-IsAdmin)) {
    if (-not $DryRun) {
        Write-Host '  The Repair Console needs administrator rights. Start it with RUN-REPAIRS.cmd.' -ForegroundColor Yellow
        exit 1
    }
    Write-Host '  Not administrator: running in forced SIMULATE mode (nothing can be changed).' -ForegroundColor Yellow
}

# ---- locate findings
if (-not $FindingsPath) {
    $FindingsPath = Get-ChildItem -LiteralPath (Join-Path $toolRoot 'Reports') -Filter 'findings.json' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $FindingsPath -or -not (Test-Path -LiteralPath $FindingsPath)) {
    Write-Host '  No findings.json found. Run START-SCAN.cmd first.' -ForegroundColor Yellow
    exit 1
}
$reportDir = Split-Path $FindingsPath -Parent
$data = Get-Content -LiteralPath $FindingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$scanAge = (Get-Date) - (Get-Item -LiteralPath $FindingsPath).LastWriteTime
$logFile = Join-Path $reportDir 'repair-log.txt'

# ---- session (protected store, journal) + earlier quarantines without a journal
try { $ctx = New-RepairSession -DryRun:$DryRun }
catch { Write-Host "  Could not prepare $(Get-RepairBase): $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
$legacy = 0
if (-not $DryRun) {
    foreach ($r in @((Join-Path $toolRoot 'Reports'), (Split-Path $reportDir -Parent)) | Select-Object -Unique) { $legacy += Import-LegacyQuarantine -Ctx $ctx -ReportsRoot $r }
}

# findings with repair steps, as plain hashtables
$items = New-Object System.Collections.Generic.List[object]
foreach ($f in @($data.Findings)) {
    $acts = @($f.Actions | Where-Object { $_ })
    if ($acts.Count -eq 0) { continue }
    $steps = @()
    foreach ($a in $acts) {
        $h = @{}
        foreach ($p in $a.PSObject.Properties) { $h[$p.Name] = $p.Value }
        $h['Risk'] = Get-EnforcedRisk $h
        if ([string]$h['Kind'] -eq 'Run' -and [string]$h['Command'] -eq 'reboot-to-firmware') { $h['Off'] = $true }   # never pre-ticked
        $steps += , $h
    }
    $items.Add([pscustomobject]@{ Id = ('r' + $items.Count); Severity = $f.Severity; Category = $f.Category; Title = $f.Title; Detail = $f.Detail; Why = $f.Why; Fix = $f.Fix; Evidence = @($f.Evidence); Steps = $steps })
}

# ---- jobs: queued, then run one at a time in their own runspace (so the page keeps getting log updates)
$jobs = [hashtable]::Synchronized(@{})
$queue = New-Object System.Collections.Generic.List[string]
$jobWorker = {
    param($LibDir, $Kind, $Steps, $Records, $LogList, $State, $DryRun, $Ctx, $LogFile, $Title, $JobId)
    $ErrorActionPreference = 'SilentlyContinue'
    . (Join-Path $LibDir 'Core.ps1')
    . (Join-Path $LibDir 'Repair.ps1')
    $State.Status = 'running'
    $log = {
        param($m)
        $line = (Get-Date).ToString('HH:mm:ss') + '  ' + $m
        [void]$LogList.Add($line)
        try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch {}
    }
    $jc = @{}
    foreach ($k in @($Ctx.Keys)) { $jc[$k] = $Ctx[$k] }
    $jc.Job = $JobId; $jc.Item = $Title; $jc.JobState = $State
    $allOk = $true; $reboot = $false; $changed = $false
    try {
        if ($Kind -eq 'undo') {
            & $log ("#### " + $(if ($DryRun) { 'SIMULATE ' } else { '' }) + "UNDO: $Title")
            foreach ($r in $Records) {
                $res = Invoke-UndoRecord -Record $r -Log $log -Ctx $jc -DryRun:$DryRun
                if (-not $res.Ok) { $allOk = $false }
                & $log ("   -> " + $(if ($res.Ok) { 'restored' } else { 'NOT restored' }))
            }
        } else {
            & $log ("#### " + $(if ($DryRun) { 'SIMULATE' } else { 'APPLY' }) + ": $Title")
            foreach ($s in $Steps) {
                $r = Invoke-RepairAction -Action $s -Log $log -Ctx $jc -DryRun:$DryRun
                if (-not $r.Ok) { $allOk = $false }
                if ($r.Reboot) { $reboot = $true }
                if ($r.Changed) { $changed = $true }
                & $log ("   -> " + $(if ($r.Ok) { 'done' } else { 'FAILED' }))
            }
        }
    } catch {
        $allOk = $false
        & $log "   !! unexpected error: $($_.Exception.Message)"
    }
    & $log ("#### finished: " + $(if ($allOk) { 'all steps OK' } else { 'some steps failed - see above' }) + $(if ($reboot) { ' (restart needed)' } else { '' }))
    $State.Ok = $allOk; $State.Reboot = $reboot; $State.Changed = $changed; $State.Done = $true; $State.Status = 'done'
}

function Add-Job {
    param([string]$Kind, [string]$Title, [string]$ItemId, $Steps, $Records, [bool]$Simulate)
    $jid = [guid]::NewGuid().ToString('N').Substring(0, 10)
    $logList = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $state = [hashtable]::Synchronized(@{ Status = 'queued'; Done = $false; Ok = $null; Reboot = $false; Changed = $false; Changes = 0 })
    $jobs[$jid] = @{ Kind = $Kind; Title = $Title; Item = $ItemId; Log = $logList; State = $state; Steps = $Steps; Records = $Records; Simulate = [bool]($Simulate -or $DryRun); PS = $null; RS = $null; Handle = $null; Queued = (Get-Date) }
    $queue.Add($jid)
    Update-Queue
    $jid
}

function Update-Queue {
    $running = $null
    foreach ($k in @($jobs.Keys)) {
        $j = $jobs[$k]
        if ($j.State.Status -eq 'running' -or ($j.PS -and -not $j.State.Done)) {
            if ($j.Handle -and $j.Handle.IsCompleted -and -not $j.State.Done) {
                # worker died without reporting back
                $err = ''; try { $err = ($j.PS.Streams.Error | Select-Object -First 1 | Out-String).Trim() } catch {}
                [void]$j.Log.Add((Get-Date).ToString('HH:mm:ss') + "  #### the repair stopped unexpectedly. $err")
                $j.State.Ok = $false; $j.State.Done = $true; $j.State.Status = 'done'
            } else { $running = $k }
        }
        if ($j.State.Done -and $j.PS) { try { $j.PS.EndInvoke($j.Handle) | Out-Null; $j.PS.Dispose(); $j.RS.Dispose() } catch {}; $j.PS = $null }
    }
    if ($running -or $queue.Count -eq 0) { return }
    $jid = $queue[0]; $queue.RemoveAt(0)
    $j = $jobs[$jid]
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState = 'MTA'; $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript($jobWorker).AddArgument($libDir).AddArgument($j.Kind).AddArgument($j.Steps).AddArgument($j.Records).AddArgument($j.Log).AddArgument($j.State).AddArgument($j.Simulate).AddArgument($ctx).AddArgument($logFile).AddArgument($j.Title).AddArgument($jid)
    $j.State.Status = 'running'
    $j.Handle = $ps.BeginInvoke(); $j.PS = $ps; $j.RS = $rs
    Write-Host ("  [{0}] {1} {2}: {3}" -f (Get-Date).ToString('HH:mm:ss'), $(if ($j.Kind -eq 'undo') { 'UNDO' } else { '' }), $(if ($j.Simulate) { 'SIMULATE' } else { 'APPLY' }), $j.Title) -ForegroundColor $(if ($j.Simulate) { 'DarkGray' } else { 'Yellow' })
}

function Get-QueuePosition { param([string]$Jid) $i = $queue.IndexOf($Jid); if ($i -ge 0) { $i + 1 } else { 0 } }

function Get-UndoList {
    $recs = @(Get-UndoJournal $ctx.Journal)
    foreach ($r in $recs) {
        $u = $r.undo
        [pscustomobject]@{
            id = [string]$r.id; time = [string]$r.time; session = [string]$r.session; job = [string]$r.job; item = [string]$r.item; desc = [string]$r.desc
            undoable = ([string]$u.Kind -ne 'None'); reason = [string]$u.Reason; undone = [bool]$r.Undone; legacy = [bool]$r.legacy; current = ([string]$r.session -eq $ctx.SessionId)
        }
    }
}

# ---- tiny HTTP helpers
function Send-Json { param($Ctx, $Obj, [int]$Code = 200)
    $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Obj -Depth 8 -Compress))
    $Ctx.Response.StatusCode = $Code; $Ctx.Response.ContentType = 'application/json; charset=utf-8'
    $Ctx.Response.Headers['Cache-Control'] = 'no-store'
    $Ctx.Response.ContentLength64 = $bytes.Length; $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length); $Ctx.Response.Close()
}
function Send-Html { param($Ctx, [string]$Html)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Html)
    $Ctx.Response.ContentType = 'text/html; charset=utf-8'; $Ctx.Response.Headers['Cache-Control'] = 'no-store'
    $Ctx.Response.ContentLength64 = $bytes.Length; $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length); $Ctx.Response.Close()
}

# ---- listener (127.0.0.1 only, random port, per-session token, custom header + origin check)
$token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
if ($Port -le 0) { $Port = Get-Random -Minimum 42000 -Maximum 59000 }
$listener = New-Object System.Net.HttpListener
$prefix = "http://127.0.0.1:$Port/"
$listener.Prefixes.Add($prefix)
try { $listener.Start() } catch { Write-Host "  Could not open $prefix : $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
$origin = "http://127.0.0.1:$Port"

. (Join-Path $libDir 'RepairPage.ps1')
$pageHtml = Get-RepairPageHtml -Token $token -Items $items -Meta $data.Meta -ScanAge $scanAge -ForcedDryRun:$DryRun -Store $ctx.SessionDir -SessionId $ctx.SessionId

Add-Content -LiteralPath $logFile -Value ("`r`n===== Repair Console started " + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + " by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME" + $(if ($DryRun) { ' (forced SIMULATE)' }) + " - session $($ctx.SessionId)") -Encoding UTF8

Write-Host ''
Write-Host '  ==========================================================' -ForegroundColor Cyan
Write-Host '    PC HEALTH SCAN - REPAIR CONSOLE' -ForegroundColor Cyan
Write-Host "    $($items.Count) repairable issue(s) from $FindingsPath" -ForegroundColor Cyan
Write-Host "    Undo journal + quarantine: $(if ($DryRun) { '(simulate only - nothing written)' } else { $ctx.Base })" -ForegroundColor DarkCyan
if ($legacy -gt 0) { Write-Host "    Imported $legacy item(s) quarantined by an earlier version - they can be restored from the page." -ForegroundColor DarkCyan }
Write-Host "    Page: $origin/?t=$token" -ForegroundColor DarkCyan
Write-Host '    Keep this window open while you work. Close it (or click Finish on the page) when done.' -ForegroundColor DarkCyan
Write-Host '  ==========================================================' -ForegroundColor Cyan
if (-not $NoOpen) { Start-Process -FilePath "$env:SystemRoot\explorer.exe" -ArgumentList "`"$origin/?t=$token`"" }

$running = $true
$lastHit = Get-Date
while ($running) {
    $ar = $listener.BeginGetContext($null, $null)
    while (-not $ar.AsyncWaitHandle.WaitOne(500)) {
        Update-Queue
        if (((Get-Date) - $lastHit).TotalMinutes -gt 240) { Write-Host '  No activity for 4 hours - shutting down.'; $running = $false; break }
    }
    if (-not $running) { break }
    $hc = $null
    try { $hc = $listener.EndGetContext($ar) } catch { continue }
    $lastHit = Get-Date
    try {
        $req = $hc.Request
        $path = $req.Url.AbsolutePath
        $q = $req.QueryString
        $org = $req.Headers['Origin']
        if ($org -and $org -ne $origin) { Send-Json $hc @{ error = 'bad origin' } 403; continue }
        if ($path -eq '/') {
            if ($q['t'] -ne $token) { Send-Html $hc '<p>Not authorised. Use the link printed in the Repair Console window.</p>'; continue }
            Send-Html $hc $pageHtml; continue
        }
        if ($q['t'] -ne $token -or $req.Headers['X-Repair'] -ne '1') { Send-Json $hc @{ error = 'not authorised' } 403; continue }
        $isPost = $req.HttpMethod -eq 'POST'
        switch ($path) {
            '/api/run' {
                if (-not $isPost) { Send-Json $hc @{ error = 'POST only' } 405; break }
                $item = $items | Where-Object { $_.Id -eq $q['id'] } | Select-Object -First 1
                if (-not $item) { Send-Json $hc @{ error = 'unknown item' } 404; break }
                $idx = @(); foreach ($s in ([string]$q['steps'] -split ',')) { if ($s -match '^\d+$') { $idx += [int]$s } }
                $steps = @(); foreach ($i in $idx) { if ($i -ge 0 -and $i -lt $item.Steps.Count) { $steps += , $item.Steps[$i] } }
                if ($steps.Count -eq 0) { Send-Json $hc @{ error = 'no steps selected' } 400; break }
                $jid = Add-Job -Kind 'fix' -Title $item.Title -ItemId $item.Id -Steps $steps -Records @() -Simulate ($q['mode'] -ne 'apply')
                Send-Json $hc @{ job = $jid; position = (Get-QueuePosition $jid) }
            }
            '/api/log' {
                $j = $jobs[[string]$q['job']]
                if (-not $j) { Send-Json $hc @{ error = 'unknown job' } 404; break }
                Update-Queue
                $since = 0; if ($q['since'] -match '^\d+$') { $since = [int]$q['since'] }
                $lines = @(); $snap = @($j.Log.ToArray())
                if ($snap.Count -gt $since) { $lines = @($snap[$since..($snap.Count - 1)]) }
                $st = $j.State
                Send-Json $hc @{ lines = $lines; next = $snap.Count; status = [string]$st.Status; position = (Get-QueuePosition ([string]$q['job'])); done = [bool]$st.Done; ok = $st.Ok; reboot = [bool]$st.Reboot; changed = [bool]$st.Changed; changes = [int]$st.Changes }
            }
            '/api/undo/list' {
                Send-Json $hc @{ records = @(Get-UndoList); session = $ctx.SessionId; store = $(if ($DryRun) { '' } else { $ctx.Base }) }
            }
            '/api/undo' {
                if (-not $isPost) { Send-Json $hc @{ error = 'POST only' } 405; break }
                $all = @(Get-UndoJournal $ctx.Journal | Where-Object { -not $_.Undone -and [string]$_.undo.Kind -ne 'None' })
                $sel = @()
                $title = ''
                if ($q['rec']) { $sel = @($all | Where-Object { $_.id -eq $q['rec'] }); $title = "1 change" }
                elseif ($q['job']) { $sel = @($all | Where-Object { $_.job -eq $q['job'] }); $title = "the fix '$($jobs[[string]$q['job']].Title)'" }
                elseif ($q['scope'] -eq 'session') { $sel = @($all | Where-Object { $_.session -eq $ctx.SessionId }); $title = 'everything from this session' }
                if ($sel.Count -eq 0) { Send-Json $hc @{ error = 'nothing to undo' } 400; break }
                [array]::Reverse($sel)   # journal is chronological; undo newest first (timestamps alone are only to the second)
                $jid = Add-Job -Kind 'undo' -Title "$title ($($sel.Count) change(s))" -ItemId ([string]$q['item']) -Steps @() -Records $sel -Simulate ($q['mode'] -eq 'simulate')
                Send-Json $hc @{ job = $jid; count = $sel.Count; position = (Get-QueuePosition $jid) }
            }
            '/api/open' {
                if (-not $isPost) { Send-Json $hc @{ error = 'POST only' } 405; break }
                if ($q['what'] -eq 'rstrui') { Start-Process -FilePath "$env:SystemRoot\System32\rstrui.exe" -ErrorAction SilentlyContinue; Send-Json $hc @{ ok = $true } }
                else { Send-Json $hc @{ error = 'unknown' } 400 }
            }
            '/api/finish' {
                $busy = @($jobs.Values | Where-Object { -not $_.State.Done })
                if ($busy.Count -gt 0 -and $q['force'] -ne '1') { Send-Json $hc @{ busy = $true; title = $busy[0].Title }; break }
                Write-Host '  Finish requested from the page.'
                Send-Json $hc @{ ok = $true }
                $running = $false
            }
            default { Send-Json $hc @{ error = 'not found' } 404 }
        }
    } catch {
        try { Send-Json $hc @{ error = $_.Exception.Message } 500 } catch {}
    }
}
$listener.Stop(); $listener.Close()
$stillBusy = @($jobs.Values | Where-Object { -not $_.State.Done })
if ($stillBusy.Count -gt 0) { Write-Host "  Note: '$($stillBusy[0].Title)' was still running. Programs it started (e.g. DISM) keep running in the background until they finish." -ForegroundColor Yellow }
Add-Content -LiteralPath $logFile -Value ("===== Repair Console closed " + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) -Encoding UTF8
Write-Host "  Repair log: $logFile"
if (-not $DryRun) { Write-Host "  Undo journal, backups and quarantine: $($ctx.Base)  (open RUN-REPAIRS.cmd again to undo anything)" }
