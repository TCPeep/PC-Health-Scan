# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# PC Health Scan - repair engine (ASCII-only source)
# Executes repair actions recorded in findings.json. Only the Kinds listed in Invoke-RepairAction exist;
# a JSON file cannot make this tool run anything else. Every action supports -DryRun (Simulate mode).
#
# UNDO: before each change, a record describing how to reverse it is appended to an undo journal.
# The journal, quarantined files and backups live in %ProgramData%\PCHealthScan (administrators-only,
# deliberately outside OneDrive so quarantined adware is never synced to the cloud).
#
# $Ctx (built by New-RepairSession, copied per job) carries: Base, SessionId, SessionDir, Quarantine, Backups,
# Journal, TrustFile, State (synchronized, shared by all jobs), Job, Item, JobState.

function Invoke-RepairLog { param($Log, [string]$Text) if ($Log) { & $Log $Text } }

function New-RepairResult {
    param([bool]$Ok, [bool]$Changed = $false, [bool]$Reboot = $false, [string]$Message = '')
    [pscustomobject]@{ Ok = $Ok; Changed = $Changed; Reboot = $Reboot; Message = $Message }
}

# ---------------------------------------------------------------- store / session

# ($script:RepairTestStore is only ever set by the dev test harness, in-process)
function Get-RepairBase { if ($script:RepairTestStore) { return $script:RepairTestStore } Join-Path $env:ProgramData 'PCHealthScan' }

function Initialize-RepairStore {
    $base = Get-RepairBase
    New-Item -ItemType Directory -Path $base -Force -ErrorAction Stop | Out-Null
    # administrators + SYSTEM only: the journal drives admin-level undo actions, so standard users must not be able to edit it
    $null = & "$env:SystemRoot\System32\icacls.exe" $base /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /Q 2>&1
    $base
}

function New-RepairSession {
    param([switch]$DryRun)
    $stamp = (Get-Date).ToString('yyyy-MM-dd_HHmmss')
    $ctx = [hashtable]::Synchronized(@{})
    $ctx.SessionId = "$($env:COMPUTERNAME)_$stamp"
    $ctx.State = [hashtable]::Synchronized(@{ RestorePointDone = $false })
    $ctx.TrustFile = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'trusted.txt'
    if ($DryRun) {
        # simulate-only: nothing is written to the protected store
        $ctx.Base = Join-Path $env:TEMP 'pchs-simulate'
        $ctx.Journal = Join-Path (Get-RepairBase) 'undo-journal.jsonl'   # read-only use (listing)
    } else {
        $ctx.Base = Initialize-RepairStore
        $ctx.Journal = Join-Path $ctx.Base 'undo-journal.jsonl'
    }
    $ctx.SessionDir = Join-Path (Join-Path $ctx.Base 'Sessions') $ctx.SessionId
    $ctx.Quarantine = Join-Path $ctx.SessionDir 'Quarantine'
    $ctx.Backups = Join-Path $ctx.SessionDir 'Backups'
    $ctx
}

function Test-InsideStore {
    param([string]$Path)
    if (-not $Path) { return $false }
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $false }
    $full.StartsWith((Get-RepairBase).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function New-BackupPath {
    param($Ctx, [string]$Name)
    New-Item -ItemType Directory -Path $Ctx.Backups -Force | Out-Null
    $safe = ($Name -replace '[\\/:*?"<>|\s]', '_')
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
    Join-Path $Ctx.Backups ("{0}_{1}" -f (Get-Date).ToString('HHmmss_fff'), $safe)
}

# ---------------------------------------------------------------- undo journal

function Add-UndoRecord {
    param($Ctx, [string]$Desc, [hashtable]$Undo)
    $rec = [ordered]@{
        type = 'change'; id = ([guid]::NewGuid().ToString('N').Substring(0, 12)); time = (Get-Date).ToString('s')
        session = $Ctx.SessionId; job = $Ctx.Job; item = $Ctx.Item; desc = $Desc; undo = $Undo
    }
    $line = ConvertTo-Json -InputObject $rec -Depth 6 -Compress
    for ($i = 0; $i -lt 5; $i++) {
        try { [IO.File]::AppendAllText($Ctx.Journal, $line + "`r`n", (New-Object Text.UTF8Encoding($false))); break } catch { Start-Sleep -Milliseconds 150 }
    }
    if ($Ctx.JobState) { $Ctx.JobState.Changes = [int]$Ctx.JobState.Changes + 1 }
}

function Add-UndoneMark {
    param($Ctx, [string]$Id, [bool]$Ok, [string]$Note)
    $rec = [ordered]@{ type = 'undone'; id = $Id; time = (Get-Date).ToString('s'); ok = $Ok; note = $Note; session = $Ctx.SessionId }
    try { [IO.File]::AppendAllText($Ctx.Journal, (ConvertTo-Json -InputObject $rec -Compress) + "`r`n", (New-Object Text.UTF8Encoding($false))) } catch {}
}

# Emits the change records one by one (callers wrap in @() and can pipe straight into Where-Object).
function Get-UndoJournal {
    param([string]$Journal)
    $changes = New-Object System.Collections.Generic.List[object]
    $done = @{}
    if (-not $Journal -or -not [IO.File]::Exists($Journal)) { return }
    $lines = @()
    try { $lines = [IO.File]::ReadAllLines($Journal) } catch { return }
    foreach ($l in $lines) {
        if (-not $l.Trim()) { continue }
        try { $o = ConvertFrom-Json $l } catch { continue }
        if ($o.type -eq 'change') { $changes.Add($o) }
        elseif ($o.type -eq 'undone' -and $o.ok) { $done[[string]$o.id] = $o.time }
    }
    foreach ($c in $changes) {
        $c | Add-Member -NotePropertyName Undone -NotePropertyValue $done.ContainsKey([string]$c.id) -Force -PassThru |
            Add-Member -NotePropertyName UndoneAt -NotePropertyValue $done[[string]$c.id] -Force -PassThru
    }
}

# Earlier versions quarantined into Reports\...\Quarantine_*\MANIFEST.txt without a journal.
# Turn those entries into journal records so they get Restore buttons too.
function Import-LegacyQuarantine {
    param($Ctx, [string]$ReportsRoot)
    if (-not $ReportsRoot -or -not (Test-Path -LiteralPath $ReportsRoot)) { return 0 }
    $known = @{}
    foreach ($r in (Get-UndoJournal $Ctx.Journal)) { $known[[string]$r.id] = $true }
    $n = 0
    foreach ($m in (Get-ChildItem -LiteralPath $ReportsRoot -Filter 'MANIFEST.txt' -Recurse -ErrorAction SilentlyContinue)) {
        if ($m.Directory.Name -notlike 'Quarantine_*') { continue }
        foreach ($line in [IO.File]::ReadAllLines($m.FullName)) {
            $p = $line -split "`t"
            if ($p.Count -lt 3) { continue }
            $from = $p[1]; $to = $p[2]
            if (-not (Test-Path -LiteralPath $from)) { continue }
            $sha = [Security.Cryptography.SHA1]::Create()
            $id = 'L' + ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($from.ToLowerInvariant()))) -replace '-', '').Substring(0, 11).ToLowerInvariant()
            if ($known.ContainsKey($id)) { continue }
            $rec = [ordered]@{
                type = 'change'; id = $id; time = $p[0]; session = 'earlier (before undo support)'; job = ''; item = 'Quarantined by an earlier Repair Console'
                desc = "Moved $to to quarantine"; legacy = $true; undo = [ordered]@{ Kind = 'MoveBack'; From = $from; To = $to; Legacy = $true }
            }
            [IO.File]::AppendAllText($Ctx.Journal, (ConvertTo-Json -InputObject $rec -Depth 6 -Compress) + "`r`n", (New-Object Text.UTF8Encoding($false)))
            $known[$id] = $true
            $n++
        }
    }
    $n
}

# ---------------------------------------------------------------- snapshots

function ConvertTo-RegExePath { param([string]$Path) ($Path -replace '^(?i)Registry::', '') }

function Get-RegSnapshot {
    param([string]$Path, [string]$Name)
    $snap = [ordered]@{ Kind = 'RegValue'; Path = $Path; Name = $Name; Existed = $false; ValueKind = ''; Data = '' }
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if (@($k.GetValueNames()) -contains $Name) {
            $vk = $k.GetValueKind($Name)
            $v = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $snap.Existed = $true; $snap.ValueKind = [string]$vk
            switch ([string]$vk) {
                'Binary' { $snap.Data = [Convert]::ToBase64String([byte[]]$v) }
                'MultiString' { $snap.Data = @($v | ForEach-Object { [string]$_ }) }
                default { $snap.Data = [string]$v }
            }
        }
    } catch {}
    $snap
}

function Export-RegKeyBackup {
    param($Ctx, [string]$Path, $Log)
    $file = (New-BackupPath $Ctx ('reg_' + (Split-Path (ConvertTo-RegExePath $Path) -Leaf))) + '.reg'
    $r = Invoke-External -File "$env:SystemRoot\System32\reg.exe" -Arguments ("export `"{0}`" `"{1}`" /y" -f (ConvertTo-RegExePath $Path), $file) -TimeoutSec 60
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "could not back up $Path before changing it: $($r.Output.Trim())" }
    Invoke-RepairLog $Log "  backed up $(ConvertTo-RegExePath $Path)"
    $file
}

function Backup-FileForUndo {
    param($Ctx, [string]$Path, [string]$Desc, $Log)
    $b = New-BackupPath $Ctx (Split-Path $Path -Leaf)
    Copy-Item -LiteralPath $Path -Destination $b -Force -ErrorAction Stop
    Add-UndoRecord $Ctx $Desc ([ordered]@{ Kind = 'FileRestore'; Backup = $b; Target = $Path })
    $b
}

function Get-ServiceSnapshot {
    param([string]$Service)
    $k = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$Service"
    $s = Get-CimInstance Win32_Service -Filter "Name='$($Service -replace "'", "''")'" -ErrorAction SilentlyContinue
    [ordered]@{ Kind = 'ServiceConfig'; Service = $Service; Start = [int](Get-RegValue $k 'Start'); Delayed = [int](Get-RegValue $k 'DelayedAutostart'); WasRunning = [bool]($s -and $s.State -eq 'Running') }
}

# ---------------------------------------------------------------- helpers

function New-RestorePointOnce {
    param($Ctx, $Log, [switch]$DryRun)
    if ($Ctx.State.RestorePointDone) { return }
    if ($DryRun) {
        if ($Ctx.JobState -and -not $Ctx.JobState.RpNoted) { $Ctx.JobState.RpNoted = $true; Invoke-RepairLog $Log '  [SIMULATE] one System Restore point would be created before the first real change of this session' }
        return
    }
    $Ctx.State.RestorePointDone = $true
    try {
        $recent = Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object { [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime) } | Sort-Object -Descending | Select-Object -First 1
        if ($recent -and ((Get-Date) - $recent).TotalMinutes -lt 30) {
            Invoke-RepairLog $Log "  a System Restore point already exists from $($recent.ToString('HH:mm')) - not creating another"
            return
        }
    } catch {}
    Invoke-RepairLog $Log 'Creating ONE System Restore point for this session (extra safety net besides the Undo buttons)...'
    try {
        $k = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $old = Get-RegValue $k 'SystemRestorePointCreationFrequency'
        Set-ItemProperty -LiteralPath $k -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -ErrorAction SilentlyContinue
        try {
            Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description 'PC Health Scan repair' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
            Invoke-RepairLog $Log '  restore point created'
        } finally {
            if ($null -eq $old) { Remove-ItemProperty -LiteralPath $k -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue }
            else { Set-ItemProperty -LiteralPath $k -Name 'SystemRestorePointCreationFrequency' -Value $old -ErrorAction SilentlyContinue }
        }
    } catch {
        Invoke-RepairLog $Log "  could not create a restore point: $($_.Exception.Message) (continuing - every change still has its own Undo)"
    }
}

# ---------------------------------------------------------------- safety guards
# These run BEFORE anything is changed. A target that fails them is refused outright - nothing is ended, moved or edited.

$script:RepairToolRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

function Test-ProtectedPath {
    # Folders that must never be moved, or have their programs ended, wholesale. $true = protected (refuse).
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    try { $l = [IO.Path]::GetFullPath($Path).TrimEnd('\').ToLowerInvariant() } catch { return $true }
    if ($l.Length -le 3) { return $true }   # a drive root
    if ($l -match '^[a-z]:\\(windows|program files|program files \(x86\)|programdata|users|recovery|boot|system volume information|\$recycle\.bin)$') { return $true }
    if ($l -match '^[a-z]:\\windows\\' -and $l -notmatch '^[a-z]:\\windows\\temp\\.') { return $true }
    if ($l -match '^[a-z]:\\programdata\\(microsoft|packages|package cache|pchealthscan)(\\|$)') { return $true }
    if ($l -match '^[a-z]:\\program files( \(x86\))?\\(windows defender|windowsapps|common files|microsoft[^\\]*|internet explorer|windows [^\\]+)(\\|$)') { return $true }
    if ($l -match '^[a-z]:\\users\\[^\\]+$') { return $true }
    if ($l -match '^[a-z]:\\users\\[^\\]+\\(appdata|appdata\\local|appdata\\roaming|appdata\\locallow|appdata\\local\\programs|appdata\\local\\temp|appdata\\local\\microsoft|appdata\\roaming\\microsoft|appdata\\local\\packages|desktop|documents|downloads|pictures|music|videos|favorites|links|saved games|contacts|searches|onedrive[^\\]*|onedrive[^\\]*\\(desktop|documents|pictures))$') { return $true }
    # this tool, anything inside it, and any folder that contains it
    if ($script:RepairToolRoot) {
        $t = $script:RepairToolRoot.TrimEnd('\').ToLowerInvariant()
        if ($t -eq $l -or $t.StartsWith($l + '\') -or $l.StartsWith($t + '\')) { return $true }
    }
    $false
}

# Never ended, whatever the target: Windows itself, browsers (the console page may be open in one),
# terminals/editors, and remote-access tools (ending them would cut the session the technician is using).
$script:NeverEndNames = @('system', 'registry', 'idle', 'csrss', 'wininit', 'winlogon', 'lsass', 'lsaiso', 'services', 'smss', 'svchost', 'explorer', 'dwm',
    'sihost', 'fontdrvhost', 'ctfmon', 'conhost', 'runtimebroker', 'taskhostw', 'dllhost', 'wmiprvse', 'spoolsv', 'audiodg', 'searchhost', 'searchindexer',
    'startmenuexperiencehost', 'shellexperiencehost', 'textinputhost', 'memory compression', 'msmpeng', 'nissrv', 'mpdefendercoreservice', 'securityhealthservice', 'securityhealthsystray',
    'powershell', 'pwsh', 'cmd', 'windowsterminal', 'openconsole', 'wt', 'code', 'devenv', 'notepad',
    'msedge', 'msedgewebview2', 'chrome', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore',
    'anydesk', 'teamviewer', 'teamviewer_service', 'rustdesk', 'remoting_host', 'quickassist', 'mstsc', 'rdpclip')
$script:MaxEndProcesses = 8
$script:MaxEndPrograms = 4

# The console never trusts the risk label stored in findings.json (it is an ordinary editable file, and older scans
# labelled some deletions 'safe'). Anything that removes, deletes, ends, uninstalls, restarts or cannot be undone is
# treated as 'caution', so "Apply all safe steps" can only ever change settings - all of which have an Undo.
$script:SafeKinds = @('RegSetValue', 'RegDeleteValue', 'MpPreference', 'FirewallOn', 'ServiceEnable', 'DefenderPolicyReset', 'Trust')
$script:SafeRunCommands = @('flushdns', 'wu-scan', 'defender-update', 'defender-quickscan', 'smartscreen-on', 'power-balanced', 'guest-off', 'restore-point', 'bitlocker-resume')
function Get-EnforcedRisk {
    param([hashtable]$Action)
    $k = [string]$Action['Kind']
    if ($k -eq 'Open') { return 'guided' }
    $r = [string]$Action['Risk']
    if ($r -notin 'safe', 'caution') { $r = 'caution' }
    if ($Action['Reboot'] -eq $true -or [string]$Action['Reboot'] -eq 'True') { return 'caution' }
    if ($k -eq 'Run') { if ($script:SafeRunCommands -notcontains [string]$Action['Command']) { return 'caution' } }
    elseif ($script:SafeKinds -notcontains $k) { return 'caution' }
    $r
}

# Windows' own services (Microsoft-signed binary in the Windows folder) and anything security-related are never
# stopped, disabled or deleted by this tool, whatever findings.json says.
$script:NeverTouchServices = @('windefend', 'wdnissvc', 'sense', 'mpssvc', 'bfe', 'wscsvc', 'securityhealthservice', 'eventlog', 'rpcss', 'dcomlaunch', 'lsm',
    'wuauserv', 'usosvc', 'waasmedicsvc', 'bits', 'cryptsvc', 'trustedinstaller', 'winmgmt', 'schedule', 'samss', 'netlogon', 'dhcp', 'dnscache', 'nsi', 'lanmanworkstation',
    'anydesk', 'teamviewer', 'rustdesk', 'termservice', 'appinfo', 'profsvc', 'plugplay', 'power', 'audiosrv', 'themes', 'gpsvc')
function Test-ProtectedService {
    param([string]$Service, $Log)
    if ($script:NeverTouchServices -contains $Service.ToLowerInvariant()) { Invoke-RepairLog $Log "  REFUSED: '$Service' is a core Windows/security/remote-access service and is never changed by this tool"; return $true }
    $k = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$Service"
    $img = [string](Get-RegValue $k 'ImagePath')
    $dll = [string](Get-RegValue "$k\Parameters" 'ServiceDll')
    foreach ($cmd in @($img, $dll)) {
        if (-not $cmd) { continue }
        $t = (Resolve-LaunchTarget $cmd).Target
        if ($dll -and $cmd -eq $img) { continue }   # svchost host itself is judged by its ServiceDll
        if ($t -match '^(?i)[a-z]:\\windows\\' -and (Get-FileSig $t).IsMicrosoft) {
            Invoke-RepairLog $Log "  REFUSED: '$Service' runs a Microsoft-signed Windows file ($t) - Windows services are never changed by this tool"
            return $true
        }
    }
    $false
}

function Get-OwnProcessChain {
    $all = @{}
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $all[[int]$p.ProcessId] = $p }
    $ids = @{}
    $cur = $PID
    for ($i = 0; $i -lt 25 -and $cur -and $all.ContainsKey($cur) -and -not $ids.ContainsKey($cur); $i++) { $ids[$cur] = $true; $cur = [int]$all[$cur].ParentProcessId }
    $ids
}

# The ONLY function in the tool that ends processes.
# Returns $true when it is fine to carry on (nothing was running there, or it was all ended),
# $false when it refused or something could not be ended - callers must then leave the target alone.
function Stop-TargetProcesses {
    # -MaxProcesses is only raised by the dedicated PC App Store routine, for one exact, verified program file
    # (its NW.js runtime runs several copies of itself). Every other guard still applies.
    param([string]$Path, $Log, [switch]$DryRun, [int]$MaxProcesses = $script:MaxEndProcesses)
    if (-not $Path) { return $true }
    if (Test-ProtectedPath $Path) { Invoke-RepairLog $Log "  REFUSED: will not end programs running from a system, profile or tool folder ($Path)"; return $false }
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\').ToLowerInvariant() } catch { return $false }
    $isDir = $false
    try { $isDir = [IO.Directory]::Exists($Path) } catch {}
    $hits = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $ep = [string]$_.ExecutablePath
            $ep -and $(if ($isDir) { $ep.ToLowerInvariant().StartsWith($full + '\') } else { $ep.ToLowerInvariant() -eq $full })
        })
    if ($hits.Count -eq 0) { return $true }
    $own = Get-OwnProcessChain
    $blocked = @($hits | Where-Object {
            $own.ContainsKey([int]$_.ProcessId) -or
            ($script:NeverEndNames -contains ([IO.Path]::GetFileNameWithoutExtension([string]$_.Name)).ToLowerInvariant()) -or
            ([string]$_.ExecutablePath -match '^(?i)[a-z]:\\windows\\')
        })
    if ($blocked.Count -gt 0) {
        Invoke-RepairLog $Log ("  REFUSED: {0} is a Windows, browser, terminal, remote-access or this-tool process and is never ended automatically. Close it yourself if it really is unwanted, then try again." -f (($blocked | ForEach-Object { "$($_.Name) (PID $($_.ProcessId))" }) -join ', '))
        return $false
    }
    $names = @($hits | ForEach-Object { [string]$_.Name } | Select-Object -Unique)
    if ($hits.Count -gt $MaxProcesses -or $names.Count -gt $script:MaxEndPrograms) {
        Invoke-RepairLog $Log "  REFUSED: this would end $($hits.Count) processes from $($names.Count) programs ($(($names | Select-Object -First 8) -join ', ')). That is more than one unwanted app ever needs - close them yourself if you are sure, then try again."
        return $false
    }
    $ok = $true
    foreach ($h in $hits) {
        if ($DryRun) { Invoke-RepairLog $Log "  [SIMULATE] would end $($h.Name) (PID $($h.ProcessId)) running from $($h.ExecutablePath)"; continue }
        if ($script:RepairNoKill) { Invoke-RepairLog $Log "  [TEST MODE] would end $($h.Name) (PID $($h.ProcessId))"; continue }
        try { Stop-Process -Id $h.ProcessId -Force -ErrorAction Stop; Invoke-RepairLog $Log "  ended $($h.Name) (PID $($h.ProcessId)) running from $($h.ExecutablePath)" }
        catch { Invoke-RepairLog $Log "  could not end $($h.Name): $($_.Exception.Message)"; $ok = $false }
    }
    if (-not $DryRun -and -not $script:RepairNoKill) { Start-Sleep -Milliseconds 800 }
    $ok
}

function Move-ToQuarantine {
    param($Ctx, [string]$Path, $Log, [switch]$DryRun)
    if (-not $Path) { return $true }
    if (-not (Test-Path -LiteralPath $Path)) { Invoke-RepairLog $Log "  already gone: $Path"; return $true }
    if (Test-ProtectedPath $Path) { Invoke-RepairLog $Log "  REFUSED: will not move a system, profile or tool folder: $Path"; return $false }
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $sz = Get-DirSize -Path $Path -MaxSeconds 10
        if ($sz.Files -gt 5000 -or $sz.Bytes -gt 2GB -or ($sz.Partial -and $sz.Files -gt 2000)) {
            Invoke-RepairLog $Log "  REFUSED: $Path holds $(Format-Bytes $sz.Bytes) in $($sz.Files)+ files - too big to be a single unwanted program. Remove it by hand if you are sure."
            return $false
        }
    }
    $safe = ($Path -replace '^([A-Za-z]):\\', '$1_' -replace '[\\/:*?"<>|]', '_')
    if ($safe.Length -gt 150) { $safe = $safe.Substring(0, 110) + '_' + ([Math]::Abs($Path.ToLowerInvariant().GetHashCode())) }
    $dest = Join-Path $Ctx.Quarantine $safe
    if ($DryRun) { Invoke-RepairLog $Log "  [SIMULATE] would move $Path -> quarantine (restorable)"; return $true }
    try {
        New-Item -ItemType Directory -Path $Ctx.Quarantine -Force | Out-Null
        if (Test-Path -LiteralPath $dest) { $dest += '_' + (Get-Date).ToString('HHmmssfff') }
        # Move-Item cannot move folders across drives; copy+delete in that case
        if ([IO.Path]::GetPathRoot($Path) -ieq [IO.Path]::GetPathRoot($dest)) {
            Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
        } else {
            Copy-Item -LiteralPath $Path -Destination $dest -Recurse -Force -ErrorAction Stop
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
        Add-UndoRecord $Ctx "Moved $Path to quarantine" ([ordered]@{ Kind = 'MoveBack'; From = $dest; To = $Path })
        Invoke-RepairLog $Log "  quarantined: $Path"
        return $true
    } catch {
        Invoke-RepairLog $Log "  could not move $Path : $($_.Exception.Message)"
        return $false
    }
}

function Find-UninstallKeys {
    # Apps-list entries whose uninstaller/install folder is the given command or lives under the given folder
    param([string]$Command, [string]$Folder)
    $roots = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in @(Get-UserHives)) { $roots += "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    $f = if ($Folder) { $Folder.TrimEnd('\').ToLowerInvariant() + '\' } else { $null }
    foreach ($r in $roots) {
        foreach ($k in (Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
            $us = [string]$k.GetValue('UninstallString'); $il = [string]$k.GetValue('InstallLocation')
            $match = $false
            if ($Command -and $us -and $us.Trim() -ieq $Command.Trim()) { $match = $true }
            if ($f) {
                $exe = (Resolve-LaunchTarget $us).Host
                if ($exe -and $exe.ToLowerInvariant().StartsWith($f)) { $match = $true }
                if ($il -and ($il.TrimEnd('\').ToLowerInvariant() + '\') -eq $f) { $match = $true }
            }
            if ($match) { [pscustomobject]@{ Key = "Registry::$($k.Name)"; Name = [string]$k.GetValue('DisplayName') } }
        }
    }
}

function Remove-UninstallEntry {
    param($Ctx, [string]$Key, [string]$Name, $Log, [switch]$DryRun)
    if (-not (Test-RegKey $Key)) { return }
    Invoke-RepairLog $Log "  remove the leftover Apps-list entry for '$Name' ($(ConvertTo-RegExePath $Key))"
    if ($DryRun) { Invoke-RepairLog $Log '  [SIMULATE] would back it up and delete it'; return }
    $bak = Export-RegKeyBackup $Ctx $Key $Log
    Remove-Item -LiteralPath $Key -Recurse -Force -ErrorAction Stop
    Add-UndoRecord $Ctx "Removed the Apps-list entry for '$Name'" ([ordered]@{ Kind = 'RegImport'; File = $bak })
}

function Get-FreeSpace { try { (New-Object IO.DriveInfo($env:SystemDrive)).AvailableFreeSpace } catch { 0 } }

# Runs a program and streams its output into the log as it arrives (DISM/SFC progress included).
function Invoke-StreamedProcess {
    param([string]$File, [string]$Arguments, [int]$TimeoutSec, $Log)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $File; $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $stream = $p.StandardOutput.BaseStream
    $buf = New-Object byte[] 4096
    $dec = $null; $pending = ''; $all = New-Object Text.StringBuilder
    $lastPct = -100.0; $lastLog = Get-Date; $sw = [Diagnostics.Stopwatch]::StartNew(); $timedOut = $false
    $emit = {
        param($seg)
        $t = $seg.Trim()
        if (-not $t) { return }
        [void]$all.AppendLine($t)
        if ($t -match '(\d{1,3}(?:\.\d+)?)\s*%') {
            $pct = [double]$Matches[1]
            if ([Math]::Abs($pct - $lastPct) -ge 5 -or $pct -ge 100 -or ((Get-Date) - $script:streamLastPctLog).TotalSeconds -ge 30) {
                Set-Variable -Name lastPct -Value $pct -Scope 1
                $script:streamLastPctLog = Get-Date
                $rest = ($t -replace '\[[=\s]*\d{1,3}(?:\.\d+)?%[=\s]*\]', '').Trim()
                & $Log ("    progress {0:0.#}%{1}" -f $pct, $(if ($rest -and $rest -notmatch '^\d') { "  $rest" } else { '' }))
                Set-Variable -Name lastLog -Value (Get-Date) -Scope 1
            }
        } else {
            & $Log "    $t"
            Set-Variable -Name lastLog -Value (Get-Date) -Scope 1
        }
    }
    $script:streamLastPctLog = Get-Date
    $readTask = $null
    while ($true) {
        if (-not $readTask) { $readTask = $stream.ReadAsync($buf, 0, $buf.Length) }
        $ready = $false
        try { $ready = $readTask.Wait(1000) } catch { break }
        if ($ready) {
            $n = $readTask.Result; $readTask = $null
            if ($n -le 0) { break }
            if (-not $dec) {
                $zeros = 0; for ($i = 1; $i -lt $n; $i += 2) { if ($buf[$i] -eq 0) { $zeros++ } }
                $enc = if ($zeros -gt ($n / 4)) { [Text.Encoding]::Unicode } else { [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage) }
                $dec = $enc.GetDecoder()
            }
            $chars = New-Object char[] ($n + 4)
            $c = $dec.GetChars($buf, 0, $n, $chars, 0)
            $pending += (New-Object string($chars, 0, $c)) -replace "`0", ''
            $parts = $pending -split "[`r`n]"
            for ($i = 0; $i -lt $parts.Count - 1; $i++) { & $emit $parts[$i] }
            $pending = $parts[$parts.Count - 1]
        } else {
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) { $timedOut = $true; try { $p.Kill() } catch {}; break }
            if (((Get-Date) - $lastLog).TotalSeconds -ge 60) {
                & $Log ("    ... still working ({0:0} min)" -f $sw.Elapsed.TotalMinutes)
                $lastLog = Get-Date
            }
        }
    }
    if ($pending) { & $emit $pending }
    [void]$p.WaitForExit(10000)
    $errText = ''
    try { if ($errTask.Wait(3000)) { $errText = $errTask.Result } } catch {}
    foreach ($l in @($errText -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 10)) { & $Log "    ! $($l.Trim())" }
    $code = $null; try { $code = $p.ExitCode } catch {}
    [pscustomobject]@{ ExitCode = $code; Output = $all.ToString(); TimedOut = $timedOut }
}

function Invoke-RepairProcess {
    param([string]$File, [string]$Arguments, [int]$TimeoutSec, $Log, [switch]$DryRun)
    Invoke-RepairLog $Log "  run: $File $Arguments"
    if ($DryRun) { Invoke-RepairLog $Log '  [SIMULATE] not executed'; return [pscustomobject]@{ ExitCode = 0; Output = ''; TimedOut = $false } }
    $r = Invoke-StreamedProcess -File $File -Arguments $Arguments -TimeoutSec $TimeoutSec -Log $Log
    if ($r.TimedOut) { Invoke-RepairLog $Log "  stopped after the $TimeoutSec s time limit" }
    Invoke-RepairLog $Log "  exit code $($r.ExitCode)"
    $r
}

function Get-ActionParam { param($Action, [string]$Name) if ($Action.ContainsKey($Name)) { return $Action[$Name] } $null }

function Remove-JsonKeyPath {
    # removes $Leaf from the dictionary found at dotted $Path; returns $true if something was removed
    param($Obj, [string]$Path, [string]$Leaf)
    $d = Get-JVal $Obj $Path
    if ($d -is [System.Collections.IDictionary] -and $d.ContainsKey($Leaf)) { [void]$d.Remove($Leaf); return $true }
    $false
}

# ---------------------------------------------------------------- fixed command list ('Run' kind)

function Get-RunSpec {
    param([string]$What)
    $win = $env:SystemRoot
    $ps = "$win\System32\WindowsPowerShell\v1.0\powershell.exe"
    switch ($What) {
        'dism-restorehealth' { @("$win\System32\dism.exe", '/Online /Cleanup-Image /RestoreHealth /English', 3600, 'DISM only restores original Microsoft files; nothing to undo.') }
        'sfc-scannow' { @("$win\System32\sfc.exe", '/scannow', 3600, 'SFC only restores original Microsoft files; nothing to undo.') }
        'flushdns' { @("$win\System32\ipconfig.exe", '/flushdns', 30, '') }
        'winsock-reset' { @("$win\System32\netsh.exe", 'winsock reset', 60, 'Network stack reset; use the System Restore point if needed.') }
        'wu-reset' { @("$win\System32\cmd.exe", "/d /c net stop wuauserv >nul 2>&1 & net stop bits >nul 2>&1 & net stop cryptsvc >nul 2>&1 & (if exist `"$win\SoftwareDistribution.old`" rd /s /q `"$win\SoftwareDistribution.old`") & ren `"$win\SoftwareDistribution`" SoftwareDistribution.old & (if exist `"$win\System32\catroot2.old`" rd /s /q `"$win\System32\catroot2.old`") & ren `"$win\System32\catroot2`" catroot2.old & net start cryptsvc & net start bits & net start wuauserv & exit /b 0", 300, 'The old folders were renamed to SoftwareDistribution.old / catroot2.old (Windows rebuilds them; safe to delete later).') }
        'wu-scan' { @("$win\System32\UsoClient.exe", 'StartInteractiveScan', 60, '') }
        'defender-update' { @("$env:ProgramFiles\Windows Defender\MpCmdRun.exe", '-SignatureUpdate', 900, '') }
        'defender-quickscan' { @("$env:ProgramFiles\Windows Defender\MpCmdRun.exe", '-Scan -ScanType 1', 3600, '') }
        'defender-fullscan' { @("$env:ProgramFiles\Windows Defender\MpCmdRun.exe", '-Scan -ScanType 2', 14400, '') }
        'chkdsk-scan' { @("$win\System32\chkdsk.exe", "$env:SystemDrive /scan", 3600, '') }
        'chkdsk-fix-on-boot' { @("$win\System32\cmd.exe", "/d /c echo y| chkdsk $env:SystemDrive /f", 60, 'Cancel before restarting with: chkntfs /x C:') }
        'bcd-normal' { @("$win\System32\cmd.exe", '/d /c bcdedit /set testsigning off & bcdedit /set nointegritychecks off & bcdedit /debug off', 60, 'Use the System Restore point to bring the old boot options back.') }
        # empties the temp folders; files in use simply stay (errors are silenced, freed space is reported instead)
        'cleanmgr-auto' { @("$win\System32\cmd.exe", "/d /c (for /d %i in (`"%TEMP%\*`") do @rd /s /q `"%i`" >nul 2>&1) & del /f /q `"%TEMP%\*.*`" >nul 2>&1 & (for /d %i in (`"$win\Temp\*`") do @rd /s /q `"%i`" >nul 2>&1) & del /f /q `"$win\Temp\*.*`" >nul 2>&1 & (for /d %i in (`"$win\SoftwareDistribution\Download\*`") do @rd /s /q `"%i`" >nul 2>&1) & del /f /q `"$win\SoftwareDistribution\Download\*.*`" >nul 2>&1 & exit /b 0", 600, 'Temporary files cannot be restored (they are not needed).') }
        'empty-recyclebin' { @($ps, '-NoProfile -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue; exit 0"', 600, 'An emptied Recycle Bin cannot be restored.') }
        'hibernate-off' { @("$win\System32\powercfg.exe", '/h off', 30, '') }
        'restore-point' { @($ps, "-NoProfile -Command `"Enable-ComputerRestore -Drive $env:SystemDrive; Checkpoint-Computer -Description 'Before cleanup' -RestorePointType MODIFY_SETTINGS`"", 300, '') }
        'smartscreen-on' { @("$win\System32\reg.exe", 'add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Warn /f', 30, '') }
        'power-balanced' { @("$win\System32\powercfg.exe", '/setactive SCHEME_BALANCED', 30, 'Pick the old plan again in Control Panel > Power Options.') }
        'guest-off' { @("$win\System32\net.exe", 'user guest /active:no', 30, '') }
        'builtin-admin-off' { @("$win\System32\net.exe", 'user administrator /active:no', 30, '') }
        'bitlocker-resume' { @("$win\System32\manage-bde.exe", "-protectors -enable $env:SystemDrive", 60, '') }
        'reboot-to-firmware' { @("$win\System32\shutdown.exe", '/r /fw /t 15 /c "PC Health Scan: restarting into the BIOS/UEFI setup"', 30, 'Cancel within 15 seconds with: shutdown /a') }
        # undo-only helpers
        'guest-on' { @("$win\System32\net.exe", 'user guest /active:yes', 30, '') }
        'builtin-admin-on' { @("$win\System32\net.exe", 'user administrator /active:yes', 30, '') }
        'hibernate-on' { @("$win\System32\powercfg.exe", '/h on', 30, '') }
        default { $null }
    }
}

# ---------------------------------------------------------------- repair actions

function Invoke-RepairAction {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Action,
        [Parameter(Mandatory = $true)][scriptblock]$Log,
        [Parameter(Mandatory = $true)]$Ctx,
        [switch]$DryRun)
    $kind = [string]$Action['Kind']
    $label = [string]$Action['Label']
    $reboot = ($Action['Reboot'] -eq $true -or [string]$Action['Reboot'] -eq 'True')
    & $Log "== $label"
    if ([string]$Action['Risk'] -ne 'guided' -and $kind -notin 'Open', 'Trust') { New-RestorePointOnce -Ctx $Ctx -Log $Log -DryRun:$DryRun }
    $P = { param($n) Get-ActionParam $Action $n }
    $sim = { param($what) & $Log "  [SIMULATE] $what" }
    try {
        switch ($kind) {

            'RegDeleteValue' {
                $path = & $P 'Path'; $name = & $P 'Name'
                $snap = Get-RegSnapshot $path $name
                if (-not $snap.Existed) { & $Log "  value already absent: $(ConvertTo-RegExePath $path)\$name"; return New-RepairResult $true }
                & $Log "  delete registry value $(ConvertTo-RegExePath $path)\$name  (was: $(Limit-Text (@($snap.Data) -join ' | ') 200))"
                if ($DryRun) { & $sim 'not deleted'; return New-RepairResult $true }
                Remove-ItemProperty -LiteralPath $path -Name $name -Force -ErrorAction Stop
                Add-UndoRecord $Ctx "Deleted registry value $(ConvertTo-RegExePath $path)\$name" $snap
                return New-RepairResult $true $true $reboot
            }
            'RegDeleteKey' {
                $path = & $P 'Path'
                if (-not (Test-RegKey $path)) { & $Log "  key already absent: $(ConvertTo-RegExePath $path)"; return New-RepairResult $true }
                $vals = @(Get-RegValues $path)
                & $Log "  delete registry key $(ConvertTo-RegExePath $path) ($($vals.Count) value(s))"
                foreach ($v in $vals | Select-Object -First 15) { & $Log "    $($v.Name) = $(Limit-Text ([string]$v.Value) 120)" }
                if ($DryRun) { & $sim 'would back the key up to a .reg file, then delete it'; return New-RepairResult $true }
                $bak = Export-RegKeyBackup $Ctx $path $Log
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                Add-UndoRecord $Ctx "Deleted registry key $(ConvertTo-RegExePath $path)" ([ordered]@{ Kind = 'RegImport'; File = $bak })
                return New-RepairResult $true $true $reboot
            }
            'RegSetValue' {
                $path = & $P 'Path'; $name = & $P 'Name'; $type = & $P 'Type'; $value = & $P 'Value'
                if (-not $type) { $type = 'DWord' }
                $snap = Get-RegSnapshot $path $name
                & $Log "  set $(ConvertTo-RegExePath $path)\$name = $value ($type)  (was: $(if (-not $snap.Existed) { '<absent>' } else { @($snap.Data) -join ' | ' }))"
                if ($DryRun) { & $sim 'not changed'; return New-RepairResult $true }
                if (-not (Test-RegKey $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
                $typed = if ($type -eq 'DWord') { [int]$value } elseif ($type -eq 'QWord') { [long]$value } else { [string]$value }
                Set-ItemProperty -LiteralPath $path -Name $name -Value $typed -Type $type -Force -ErrorAction Stop
                Add-UndoRecord $Ctx "Set $(ConvertTo-RegExePath $path)\$name to $value" $snap
                return New-RepairResult $true $true $reboot
            }
            'TaskDelete' {
                $tn = & $P 'Task'; $tp = & $P 'TaskPath'
                $t = Get-ScheduledTask -TaskName $tn -TaskPath $tp -ErrorAction SilentlyContinue
                if (-not $t) { & $Log "  task already gone: $tp$tn"; return New-RepairResult $true }
                foreach ($a in @($t.Actions)) { if ($a.Execute) { & $Log "  task runs: $($a.Execute) $($a.Arguments)" } }
                & $Log "  back up, disable and delete scheduled task $tp$tn"
                if ($DryRun) { & $sim 'not deleted'; return New-RepairResult $true }
                $xmlFile = (New-BackupPath $Ctx "task_$tn") + '.xml'
                [IO.File]::WriteAllText($xmlFile, (Export-ScheduledTask -TaskName $tn -TaskPath $tp -ErrorAction Stop))
                Disable-ScheduledTask -TaskName $tn -TaskPath $tp -ErrorAction SilentlyContinue | Out-Null
                Unregister-ScheduledTask -TaskName $tn -TaskPath $tp -Confirm:$false -ErrorAction Stop
                Add-UndoRecord $Ctx "Deleted scheduled task $tp$tn" ([ordered]@{ Kind = 'TaskRegister'; Task = $tn; TaskPath = $tp; XmlFile = $xmlFile })
                return New-RepairResult $true $true
            }
            'TaskDisable' {
                $tn = & $P 'Task'; $tp = & $P 'TaskPath'
                & $Log "  disable scheduled task $tp$tn"
                if ($DryRun) { & $sim 'not disabled'; return New-RepairResult $true }
                Disable-ScheduledTask -TaskName $tn -TaskPath $tp -ErrorAction Stop | Out-Null
                Add-UndoRecord $Ctx "Disabled scheduled task $tp$tn" ([ordered]@{ Kind = 'TaskEnable'; Task = $tn; TaskPath = $tp })
                return New-RepairResult $true $true
            }
            'ServiceStopDisable' {
                $svc = & $P 'Service'
                $s = Get-CimInstance Win32_Service -Filter "Name='$($svc -replace "'", "''")'" -ErrorAction SilentlyContinue
                if (-not $s) { & $Log "  service not found: $svc"; return New-RepairResult $true }
                if (Test-ProtectedService $svc $Log) { return New-RepairResult $false }
                & $Log "  service '$svc' ($($s.DisplayName)) is $($s.State), start type $($s.StartMode); command: $($s.PathName)"
                & $Log '  stop it and set start type to Disabled'
                if ($DryRun) { & $sim 'not changed'; return New-RepairResult $true }
                $snap = Get-ServiceSnapshot $svc
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                $r = Invoke-External -File "$env:SystemRoot\System32\sc.exe" -Arguments "config `"$svc`" start= disabled" -TimeoutSec 30
                if ($r.ExitCode -ne 0) { throw "sc.exe config failed: $($r.Output.Trim())" }
                Add-UndoRecord $Ctx "Stopped and disabled service $svc" $snap
                return New-RepairResult $true $true
            }
            'ServiceDelete' {
                $svc = & $P 'Service'
                $s = Get-CimInstance Win32_Service -Filter "Name='$($svc -replace "'", "''")'" -ErrorAction SilentlyContinue
                if (-not $s) { & $Log "  service already gone: $svc"; return New-RepairResult $true }
                if (Test-ProtectedService $svc $Log) { return New-RepairResult $false }
                & $Log "  service '$svc' ($($s.DisplayName)); command: $($s.PathName)"
                & $Log '  back up its registration, stop it and delete it (the program file is handled separately)'
                if ($DryRun) { & $sim 'not deleted'; return New-RepairResult $true }
                $bak = Export-RegKeyBackup $Ctx "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$svc" $Log
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                $r = Invoke-External -File "$env:SystemRoot\System32\sc.exe" -Arguments "delete `"$svc`"" -TimeoutSec 30
                if ($r.ExitCode -ne 0) { throw "sc.exe delete failed: $($r.Output.Trim())" }
                Add-UndoRecord $Ctx "Deleted service $svc (comes back after a restart once undone)" ([ordered]@{ Kind = 'RegImport'; File = $bak })
                return New-RepairResult $true $true
            }
            'ServiceEnable' {
                $svc = & $P 'Service'; $mode = & $P 'StartMode'; if (-not $mode) { $mode = 'auto' }
                & $Log "  set service '$svc' start type to $mode and start it"
                if ($DryRun) { & $sim 'not changed'; return New-RepairResult $true }
                $snap = Get-ServiceSnapshot $svc
                $r = Invoke-External -File "$env:SystemRoot\System32\sc.exe" -Arguments "config `"$svc`" start= $mode" -TimeoutSec 30
                if ($r.ExitCode -ne 0) { throw "sc.exe config failed: $($r.Output.Trim())" }
                Start-Service -Name $svc -ErrorAction SilentlyContinue
                Add-UndoRecord $Ctx "Re-enabled service $svc" $snap
                return New-RepairResult $true $true
            }
            'StopProcess' {
                $ok = $true
                foreach ($t in @(& $P 'Targets')) { if (-not (Stop-TargetProcesses -Path $t -Log $Log -DryRun:$DryRun)) { $ok = $false } }
                return New-RepairResult $ok $false
            }
            'Quarantine' {
                $ok = $true
                foreach ($t in @(& $P 'Targets')) {
                    if (-not $t) { continue }
                    # safety check FIRST - before any program is ended
                    if (Test-ProtectedPath $t) { & $Log "  REFUSED: $t is a system, profile or tool folder - nothing was ended or moved"; $ok = $false; continue }
                    if (-not (Test-Path -LiteralPath $t)) { & $Log "  already gone: $t"; continue }
                    $wasDir = Test-Path -LiteralPath $t -PathType Container
                    if (-not (Stop-TargetProcesses -Path $t -Log $Log -DryRun:$DryRun)) { & $Log "  left $t where it is"; $ok = $false; continue }
                    if (-not (Move-ToQuarantine -Ctx $Ctx -Path $t -Log $Log -DryRun:$DryRun)) { $ok = $false; continue }
                    # a removed program folder often leaves its Apps-list entry behind; clean that up too (backed up)
                    if ($wasDir) { foreach ($u in @(Find-UninstallKeys -Folder $t)) { Remove-UninstallEntry -Ctx $Ctx -Key $u.Key -Name $u.Name -Log $Log -DryRun:$DryRun } }
                }
                if ($ok) { & $Log "  quarantine: $($Ctx.Quarantine) (use Undo to put anything back)" }
                return New-RepairResult $ok $true
            }
            'Uninstall' {
                $cmd = [string](& $P 'Command'); $name = [string](& $P 'Name'); $key = [string](& $P 'Key')
                if (-not $key -or -not (Test-RegKey $key)) { $key = @(Find-UninstallKeys -Command $cmd | Select-Object -First 1 -ExpandProperty Key) | Select-Object -First 1 }
                $lt = Resolve-LaunchTarget $cmd
                if (-not $cmd -or ($lt.Host -and -not (Test-Path -LiteralPath $lt.Host))) {
                    & $Log "  the uninstaller is already gone ($($lt.Host)) - the program files were removed earlier; only its entry in the Apps list is left"
                    if (-not $key -or -not (Test-RegKey $key)) { & $Log '  no Apps-list entry left either - nothing to do'; return New-RepairResult $true }
                    Remove-UninstallEntry -Ctx $Ctx -Key $key -Name $name -Log $Log -DryRun:$DryRun
                    return New-RepairResult $true $true
                }
                $silent = $cmd
                if ($cmd -match '(?i)msiexec' -and $cmd -match '\{[0-9A-F-]{36}\}') { $silent = "msiexec.exe /x $($Matches[0]) /qn /norestart" }
                elseif ($cmd -notmatch '(?i)\s/(S|silent|quiet|verysilent|qn)\b') { $silent = "$cmd /S" }   # NSIS/most adware installers
                & $Log "  uninstall $name (tries silently first)"
                $r = Invoke-RepairProcess -File "$env:SystemRoot\System32\cmd.exe" -Arguments "/d /c $silent" -TimeoutSec 600 -Log $Log -DryRun:$DryRun
                if ($DryRun) { return New-RepairResult $true }
                if ($r.ExitCode -notin 0, 1605, 1614, 3010, 1641) {
                    & $Log "  silent uninstall returned $($r.ExitCode); opening the normal uninstaller for you to click through"
                    if ($cmd -ne $silent) { Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/d /c $cmd" -ErrorAction SilentlyContinue }
                    return New-RepairResult $false $true
                }
                Start-Sleep -Seconds 2
                if ($key -and (Test-RegKey $key) -and -not (Test-Path -LiteralPath $lt.Host)) { Remove-UninstallEntry -Ctx $Ctx -Key $key -Name $name -Log $Log }
                Add-UndoRecord $Ctx "Uninstalled $name" ([ordered]@{ Kind = 'None'; Reason = 'An uninstall cannot be reversed automatically - reinstall the program, or use the System Restore point.' })
                return New-RepairResult $true $true ($r.ExitCode -in 3010, 1641)
            }
            'HostsRemove' {
                $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
                $names = @(& $P 'Hostnames' | ForEach-Object { $_.ToLowerInvariant() })
                $lines = [IO.File]::ReadAllLines($hosts)
                $keep = New-Object System.Collections.Generic.List[string]
                $removed = 0
                foreach ($l in $lines) {
                    $t = ($l -replace '#.*$', '').Trim()
                    $drop = $false
                    if ($t) {
                        $parts = @($t -split '\s+')
                        if ($parts.Count -ge 2) { foreach ($n in $parts[1..($parts.Count - 1)]) { if ($names -contains $n.ToLowerInvariant()) { $drop = $true } } }
                    }
                    if ($drop) { $removed++; & $Log "  remove line: $l" } else { $keep.Add($l) }
                }
                if ($removed -eq 0) { & $Log '  nothing to remove'; return New-RepairResult $true }
                if ($DryRun) { & $sim 'hosts file not changed'; return New-RepairResult $true }
                $null = Backup-FileForUndo $Ctx $hosts "Removed $removed line(s) from the hosts file" $Log
                [IO.File]::WriteAllLines($hosts, $keep.ToArray())
                & $Log "  hosts file rewritten ($removed line(s) removed)"
                Invoke-RepairProcess -File "$env:SystemRoot\System32\ipconfig.exe" -Arguments '/flushdns' -TimeoutSec 30 -Log $Log | Out-Null
                return New-RepairResult $true $true
            }
            'ProxyReset' {
                foreach ($h in @(Get-UserHives)) {
                    $k = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                    $en = Get-RegValue $k 'ProxyEnable'; $pac = Get-RegValue $k 'AutoConfigURL'
                    if ($en -ne 1 -and -not $pac) { continue }
                    & $Log "  user $($h.User): ProxyEnable=$en ProxyServer=$(Get-RegValue $k 'ProxyServer') AutoConfigURL=$pac -> direct connection"
                    if ($DryRun) { continue }
                    foreach ($n in 'ProxyEnable', 'ProxyServer', 'AutoConfigURL') { Add-UndoRecord $Ctx "Proxy setting $n for $($h.User)" (Get-RegSnapshot $k $n) }
                    Set-ItemProperty -LiteralPath $k -Name 'ProxyEnable' -Value 0 -Type DWord -ErrorAction SilentlyContinue
                    Remove-ItemProperty -LiteralPath $k -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -LiteralPath $k -Name 'ProxyServer' -ErrorAction SilentlyContinue
                }
                $wh = Invoke-External -File "$env:SystemRoot\System32\netsh.exe" -Arguments 'winhttp show proxy' -TimeoutSec 20
                if ($wh.Output -match '(?im)Proxy Server\(s\)\s*:\s*(\S.*)$') {
                    $srv = $Matches[1].Trim(); $byp = ''
                    if ($wh.Output -match '(?im)Bypass List\s*:\s*(\S.*)$') { $byp = $Matches[1].Trim() }
                    & $Log "  WinHTTP proxy $srv -> direct"
                    if (-not $DryRun) { Add-UndoRecord $Ctx "Reset WinHTTP proxy $srv" ([ordered]@{ Kind = 'WinHttpProxy'; Server = $srv; Bypass = $byp }) }
                    Invoke-RepairProcess -File "$env:SystemRoot\System32\netsh.exe" -Arguments 'winhttp reset proxy' -TimeoutSec 30 -Log $Log -DryRun:$DryRun | Out-Null
                }
                return New-RepairResult $true $true
            }
            'DnsAuto' {
                foreach ($idx in @(& $P 'InterfaceIndex')) {
                    $ad = Get-NetAdapter -InterfaceIndex ([int]$idx) -ErrorAction SilentlyContinue
                    $servers = @()
                    foreach ($stack in 'Tcpip', 'Tcpip6') {
                        $ns = [string](Get-RegValue "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$stack\Parameters\Interfaces\$($ad.InterfaceGuid)" 'NameServer')
                        if ($ns.Trim()) { $servers += @($ns -split '[,\s]+' | Where-Object { $_ }) }
                    }
                    if ($servers.Count -eq 0) { & $Log "  adapter $($ad.Name): already automatic - nothing to change"; continue }
                    & $Log "  adapter $($ad.Name): DNS $($servers -join ', ') -> automatic (DHCP)"
                    if ($DryRun) { continue }
                    Set-DnsClientServerAddress -InterfaceIndex ([int]$idx) -ResetServerAddresses -ErrorAction Stop
                    Add-UndoRecord $Ctx "Set DNS on $($ad.Name) back to automatic (was $($servers -join ', '))" ([ordered]@{ Kind = 'DnsServers'; InterfaceIndex = [int]$idx; Servers = @($servers) })
                }
                Invoke-RepairProcess -File "$env:SystemRoot\System32\ipconfig.exe" -Arguments '/flushdns' -TimeoutSec 30 -Log $Log -DryRun:$DryRun | Out-Null
                return New-RepairResult $true $true
            }
            'MpPreference' {
                $setting = & $P 'Setting'; $value = & $P 'Value'
                $old = $null; try { $old = (Get-MpPreference -ErrorAction Stop).$setting } catch {}
                & $Log "  Set-MpPreference -$setting $value  (was: $old)"
                if ($DryRun) { & $sim 'not changed'; return New-RepairResult $true }
                $splat = @{ $setting = $value; ErrorAction = 'Stop' }
                Set-MpPreference @splat
                if ($null -ne $old) { Add-UndoRecord $Ctx "Defender: $setting = $value" ([ordered]@{ Kind = 'MpSet'; Setting = $setting; Value = [string]$old }) }
                return New-RepairResult $true $true
            }
            'MpRemoveExclusion' {
                $type = & $P 'Type'; $value = & $P 'Value'
                & $Log "  remove Defender exclusion ($type): $value"
                if ($DryRun) { & $sim 'not removed'; return New-RepairResult $true }
                $splat = @{ ('Exclusion' + $type) = $value; ErrorAction = 'Stop' }
                Remove-MpPreference @splat
                Add-UndoRecord $Ctx "Removed Defender exclusion $value" ([ordered]@{ Kind = 'MpAddExclusion'; Type = $type; Value = $value })
                return New-RepairResult $true $true
            }
            'DefenderPolicyReset' {
                $base = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
                $hits = @()
                foreach ($pair in @(@($base, 'DisableAntiSpyware'), @($base, 'DisableAntiVirus'), @("$base\Real-Time Protection", 'DisableRealtimeMonitoring'),
                        @("$base\Real-Time Protection", 'DisableBehaviorMonitoring'), @("$base\Real-Time Protection", 'DisableOnAccessProtection'),
                        @("$base\Real-Time Protection", 'DisableIOAVProtection'), @("$base\Real-Time Protection", 'DisableScanOnRealtimeEnable'), @("$base\Spynet", 'SpynetReporting'))) {
                    if ($null -ne (Get-RegValue $pair[0] $pair[1])) { $hits += , $pair }
                }
                $svc = Get-CimInstance Win32_Service -Filter "Name='WinDefend'" -ErrorAction SilentlyContinue
                $svcOff = $svc -and $svc.StartMode -eq 'Disabled'
                if ($hits.Count -eq 0 -and -not $svcOff) { & $Log '  nothing to change'; return New-RepairResult $true }
                foreach ($h in $hits) { & $Log "  delete policy $(ConvertTo-RegExePath $h[0])\$($h[1])" }
                if ($svcOff) { & $Log '  WinDefend service is Disabled -> Automatic' }
                if ($DryRun) { & $sim 'not changed'; return New-RepairResult $true }
                foreach ($h in $hits) {
                    $snap = Get-RegSnapshot $h[0] $h[1]
                    Remove-ItemProperty -LiteralPath $h[0] -Name $h[1] -Force -ErrorAction Stop
                    Add-UndoRecord $Ctx "Deleted Defender policy $($h[1])" $snap
                }
                if ($svcOff) {
                    $snap = Get-ServiceSnapshot 'WinDefend'
                    Invoke-External -File "$env:SystemRoot\System32\sc.exe" -Arguments 'config WinDefend start= auto' -TimeoutSec 30 | Out-Null
                    Start-Service WinDefend -ErrorAction SilentlyContinue
                    Add-UndoRecord $Ctx 'Re-enabled the WinDefend service' $snap
                }
                return New-RepairResult $true $true $true
            }
            'FirewallOn' {
                $before = [ordered]@{ Kind = 'FirewallProfiles' }
                foreach ($fp in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { $before[[string]$fp.Name] = ([string]$fp.Enabled -eq 'True') }
                & $Log "  Set-NetFirewallProfile -All -Enabled True  (was: $((@($before.Keys | Where-Object { $_ -ne 'Kind' }) | ForEach-Object { "$_=$($before[$_])" }) -join ', '))"
                if ($DryRun) { & $sim 'not changed'; return New-RepairResult $true }
                Set-NetFirewallProfile -All -Enabled True -ErrorAction Stop
                Add-UndoRecord $Ctx 'Turned Windows Firewall on for all profiles' $before
                return New-RepairResult $true $true
            }
            'FirewallRuleRemove' {
                # Only rules for the flagged program(s). Several programs often share a rule name (e.g. "javaw.exe"),
                # so matching on the name alone would also remove rules for legitimate copies.
                $progs = @(& $P 'Programs' | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).ToLowerInvariant() })
                $fw = New-Object -ComObject HNetCfg.FwPolicy2
                foreach ($n in @(& $P 'Rules')) {
                    $matched = @($fw.Rules | Where-Object { $_.Name -eq $n })
                    if ($matched.Count -eq 0) { & $Log "  rule '$n' already gone"; continue }
                    $mine = @($matched | Where-Object {
                            $app = [Environment]::ExpandEnvironmentVariables([string]$_.ApplicationName).ToLowerInvariant()
                            if ($progs.Count) { $progs -contains $app } else { $app -and (Test-UserWritableZone (Get-PathZone $app)) -and -not (Get-FileSig $app).Trusted }
                        })
                    if ($matched.Count -gt $mine.Count) { & $Log "  keeping $($matched.Count - $mine.Count) other rule(s) named '$n' that belong to other programs" }
                    if ($mine.Count -eq 0) { continue }
                    $apps = @($mine | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_.ApplicationName).ToLowerInvariant() } | Select-Object -Unique)
                    & $Log "  remove $($mine.Count) firewall rule(s) '$n' for $($apps -join ', ')"
                    if ($DryRun) { continue }
                    foreach ($r in $mine) {
                        $props = [ordered]@{ Kind = 'FirewallRule' }
                        foreach ($pn in 'Name', 'Description', 'ApplicationName', 'serviceName', 'Protocol', 'LocalPorts', 'RemotePorts', 'LocalAddresses', 'RemoteAddresses', 'Direction', 'Enabled', 'Grouping', 'Profiles', 'EdgeTraversal', 'Action', 'InterfaceTypes') {
                            try { $props[$pn] = [string]$r.$pn } catch {}
                        }
                        Add-UndoRecord $Ctx "Removed firewall rule '$n' ($($r.ApplicationName))" $props
                    }
                    foreach ($nr in @(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) {
                        $prog = [string](($nr | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program)
                        if ($apps -contains [Environment]::ExpandEnvironmentVariables($prog).ToLowerInvariant()) { $nr | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
                    }
                }
                return New-RepairResult $true $true
            }
            'WindowsFeatureDisable' {
                $f = & $P 'Feature'
                & $Log "  Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart"
                if ($DryRun) { & $sim 'not changed'; return New-RepairResult $true }
                Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null
                Add-UndoRecord $Ctx "Removed Windows feature $f" ([ordered]@{ Kind = 'FeatureEnable'; Feature = $f })
                return New-RepairResult $true $true $true
            }
            'Run' {
                $what = & $P 'Command'
                $spec = Get-RunSpec $what
                if (-not $spec -or $what -in 'guest-on', 'builtin-admin-on', 'hibernate-on') { & $Log "  unknown command '$what' - refused"; return New-RepairResult $false }
                $snap = $null
                if ($what -eq 'smartscreen-on') { $snap = Get-RegSnapshot 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' }
                $free0 = Get-FreeSpace
                $r = Invoke-RepairProcess -File $spec[0] -Arguments $spec[1] -TimeoutSec $spec[2] -Log $Log -DryRun:$DryRun
                if ($DryRun) { return New-RepairResult $true }
                $freed = (Get-FreeSpace) - $free0
                if ([Math]::Abs($freed) -ge 50MB) { & $Log ("  free space on {0} changed by {1}{2}" -f $env:SystemDrive, $(if ($freed -gt 0) { '+' } else { '-' }), (Format-Bytes ([Math]::Abs($freed)))) }
                $ok = ($r.ExitCode -in 0, 3010) -or ($what -eq 'sfc-scannow' -and $r.Output -match '(?i)successfully repaired|did not find any integrity violations')
                if ($what -eq 'sfc-scannow' -and $r.Output -match '(?i)unable to fix') { & $Log '  SFC could not fix everything - run DISM RestoreHealth first, restart, then SFC again'; $ok = $false }
                if ($ok) {
                    $undo = switch ($what) {
                        'smartscreen-on' { $snap }
                        'guest-off' { [ordered]@{ Kind = 'RunFixed'; Command = 'guest-on' } }
                        'builtin-admin-off' { [ordered]@{ Kind = 'RunFixed'; Command = 'builtin-admin-on' } }
                        'hibernate-off' { [ordered]@{ Kind = 'RunFixed'; Command = 'hibernate-on' } }
                        default { if ($spec[3]) { [ordered]@{ Kind = 'None'; Reason = $spec[3] } } else { $null } }
                    }
                    if ($undo) { Add-UndoRecord $Ctx $label $undo }
                }
                return New-RepairResult $ok $true ($reboot -or $r.ExitCode -eq 3010)
            }
            'Open' {
                $uri = & $P 'Uri'
                if ($DryRun) { & $sim "would open $uri for you to finish by hand" }
                else { & $Log "  opening $uri for you to finish by hand"; Start-Process -FilePath "$env:SystemRoot\explorer.exe" -ArgumentList $uri -ErrorAction SilentlyContinue }
                $note = & $P 'Note'
                if ($note) { & $Log "  $note" }
                return New-RepairResult $true
            }
            'Trust' {
                $path = & $P 'Path'
                if (-not $path) { & $Log '  no program path recorded'; return New-RepairResult $false }
                $line = "path $path"
                $existing = @(); if ([IO.File]::Exists($Ctx.TrustFile)) { $existing = [IO.File]::ReadAllLines($Ctx.TrustFile) }
                if ($existing | Where-Object { ($_ -replace '#.*$', '').Trim() -ieq $line }) { & $Log "  already trusted: $path"; return New-RepairResult $true }
                & $Log "  add to $($Ctx.TrustFile): $line"
                if ($DryRun) { & $sim 'trusted.txt not changed'; return New-RepairResult $true }
                $full = "$line    # added $((Get-Date).ToString('yyyy-MM-dd')) by the Repair Console on $env:COMPUTERNAME"
                [IO.File]::AppendAllText($Ctx.TrustFile, "`r`n$full", (New-Object Text.UTF8Encoding($false)))
                Add-UndoRecord $Ctx "Trusted $path" ([ordered]@{ Kind = 'TrustRemove'; File = $Ctx.TrustFile; Line = $line })
                & $Log '  the next scan will list it under "Informational notes" instead of flagging it'
                return New-RepairResult $true $true
            }
            'BrowserReset' {
                $profDir = [string](& $P 'ProfileDir'); $extId = [string](& $P 'ExtensionId'); $pn = [string](& $P 'Process'); $extDir = [string](& $P 'ExtDir')
                if ($extId -notmatch '^[a-p]{32}$') { & $Log '  invalid extension id - refused'; return New-RepairResult $false }
                # The browser is NEVER closed for you (this page may be open in it, along with unsaved work).
                # While it is open its settings files are left alone - it would overwrite them when it exits.
                $browserOpen = $false
                if ($pn -and $pn -match '^[A-Za-z0-9_-]+$') { $browserOpen = @(Get-Process -Name $pn -ErrorAction SilentlyContinue).Count -gt 0 }
                if ($browserOpen) { & $Log "  $pn is open - its extension files can be quarantined now, but its settings will only be cleaned once every $pn window is closed" }
                # where the extension's files really are: the profile's Extensions\<id> folder, or (for "unpacked"/sideloaded
                # extensions, typical of hijackers) a folder elsewhere, e.g. AppData\Local\<random>\<random>
                $dirs = @()
                $std = Join-Path (Join-Path $profDir 'Extensions') $extId
                if (Test-Path -LiteralPath $std) { $dirs += $std }
                $prefPaths = @()
                foreach ($pf in 'Preferences', 'Secure Preferences') {
                    $o = Read-JsonFile (Join-Path $profDir $pf)
                    $pp = [string](Get-JVal $o "extensions.settings.$extId.path")
                    if ($pp) { $prefPaths += $(if ([IO.Path]::IsPathRooted($pp)) { $pp } else { Join-Path (Join-Path $profDir 'Extensions') $pp }) }
                }
                foreach ($cand in @($extDir) + $prefPaths) {
                    if (-not $cand -or -not (Test-Path -LiteralPath $cand)) { continue }
                    if ($cand.ToLowerInvariant().StartsWith($std.ToLowerInvariant())) { continue }   # already covered
                    if (-not [IO.File]::Exists((Join-Path $cand 'manifest.json'))) { & $Log "  skipped $cand (no manifest.json - not an extension folder)"; continue }
                    if ($dirs -notcontains $cand) { $dirs += $cand }
                }
                if ($dirs.Count -eq 0) { & $Log '  no extension files found on disk (only its settings entry remains)' }
                $ok = $true
                foreach ($d in $dirs) {
                    $parent = Split-Path $d -Parent
                    if (-not (Move-ToQuarantine -Ctx $Ctx -Path $d -Log $Log -DryRun:$DryRun)) { $ok = $false; continue }
                    # hijackers use a throw-away parent folder (e.g. AppData\Local\599aa); remove it if now empty
                    if (-not $DryRun -and (Test-Path -LiteralPath $parent) -and -not (Test-ProtectedPath $parent) -and $parent -notmatch '(?i)\\Extensions$' -and @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                        Remove-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
                        & $Log "  removed the now-empty folder $parent"
                    }
                }
                $pendingPrefs = $false
                foreach ($pf in 'Preferences', 'Secure Preferences') {
                    $pp = Join-Path $profDir $pf
                    if (-not (Test-Path -LiteralPath $pp)) { continue }
                    $txt = [IO.File]::ReadAllText($pp)
                    if ($txt -notmatch [regex]::Escape($extId)) { continue }
                    if ($browserOpen) { $pendingPrefs = $true; continue }
                    & $Log "  remove '$extId' from $pf"
                    if ($DryRun) { continue }
                    $null = Backup-FileForUndo $Ctx $pp "Edited $pf of $(Split-Path $profDir -Leaf) (removed extension $extId)" $Log
                    $o = ConvertFrom-JsonFast $txt
                    $n = 0
                    if (Remove-JsonKeyPath $o 'extensions.settings' $extId) { $n++ }
                    if (Remove-JsonKeyPath $o 'protection.macs.extensions.settings' $extId) { $n++ }
                    if (Remove-JsonKeyPath $o 'protection.macs.extensions.settings_encrypted_hash' $extId) { $n++ }
                    $extObj = Get-JVal $o 'extensions'
                    foreach ($leaf in 'pinned_extensions', 'toolbar') {
                        # read the list straight from its parent: a one-item list would otherwise come back as a plain string
                        if ($extObj -is [System.Collections.IDictionary] -and $extObj.ContainsKey($leaf)) {
                            $lst = @($extObj[$leaf])
                            if ($lst -contains $extId) { $extObj[$leaf] = [object[]]@($lst | Where-Object { $_ -ne $extId }); $n++ }
                        }
                    }
                    [IO.File]::WriteAllText($pp, $script:JsSer.Serialize($o))
                    & $Log "    $n entr$(if ($n -eq 1) { 'y' } else { 'ies' }) removed"
                }
                if ($pendingPrefs) {
                    & $Log "  NOT FINISHED: close every $pn window (save your work first), then press Apply again to remove the extension from the browser's settings"
                    return New-RepairResult $false $true
                }
                & $Log '  next time the browser opens it may say some settings were reset - that is expected after removing a hijacker'
                return New-RepairResult $ok $true
            }
            'RemovePCAppStore' {
                # re-discovers everything live (never trusts paths stored in findings.json), then removes it step by step
                return Invoke-PCAppStoreRemoval -Ctx $Ctx -Log $Log -DryRun:$DryRun
            }
            'WmiRemove' {
                $name = & $P 'Consumer'
                & $Log "  remove WMI event consumer '$name' and its filter bindings"
                $bind = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { [string]$_.Consumer -match [regex]::Escape($name) })
                $filters = @()
                foreach ($b in $bind) { if ([string]$b.Filter -match 'Name="([^"]+)"') { $filters += $Matches[1] } }
                foreach ($f in $filters) { & $Log "    bound filter: $f" }
                if ($DryRun) { & $sim 'not removed'; return New-RepairResult $true }
                $consumer = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $name }
                $bak = (New-BackupPath $Ctx "wmi_$name") + '.txt'
                (@($consumer) + @($bind) | Format-List * | Out-String) | Set-Content -LiteralPath $bak -Encoding UTF8
                $bind | Remove-CimInstance -ErrorAction SilentlyContinue
                $consumer | Remove-CimInstance -ErrorAction Stop
                foreach ($f in $filters) { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $f } | Remove-CimInstance -ErrorAction SilentlyContinue }
                Add-UndoRecord $Ctx "Removed WMI subscription $name" ([ordered]@{ Kind = 'None'; Reason = "WMI subscriptions are not recreated automatically (they are almost always malware). Details were saved to $bak; the System Restore point also brings it back." })
                return New-RepairResult $true $true
            }
            'CertRemove' {
                $store = & $P 'Store'; $thumb = & $P 'Thumbprint'
                if ($store -notin 'LocalMachine', 'CurrentUser' -or $thumb -notmatch '^[0-9A-Fa-f]{40}$') { & $Log '  invalid store/thumbprint - refused'; return New-RepairResult $false }
                $path = "Cert:\$store\Root\$thumb"
                $c = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                if (-not $c) { & $Log "  certificate not found in $store\Root: $thumb"; return New-RepairResult $true }
                & $Log "  remove trusted root certificate: $($c.Subject) [$thumb]"
                if ($DryRun) { & $sim 'not removed'; return New-RepairResult $true }
                $file = (New-BackupPath $Ctx "cert_$thumb") + '.cer'
                Export-Certificate -Cert $c -FilePath $file -Force -ErrorAction Stop | Out-Null
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                Add-UndoRecord $Ctx "Removed root certificate $($c.Subject)" ([ordered]@{ Kind = 'CertImport'; File = $file; Store = $store })
                return New-RepairResult $true $true
            }
            default { & $Log "  unknown action kind '$kind' - refused"; return New-RepairResult $false }
        }
    } catch {
        & $Log "  FAILED: $($_.Exception.Message)"
        return New-RepairResult $false
    }
}

# ---------------------------------------------------------------- undo

function ConvertTo-HashtableShallow {
    param($Obj)
    $h = @{}
    if ($Obj -is [System.Collections.IDictionary]) { foreach ($k in $Obj.Keys) { $h[[string]$k] = $Obj[$k] } }
    elseif ($Obj) { foreach ($p in $Obj.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $h
}

function Invoke-UndoRecord {
    param([Parameter(Mandatory = $true)]$Record, [Parameter(Mandatory = $true)][scriptblock]$Log, [Parameter(Mandatory = $true)]$Ctx, [switch]$DryRun)
    $u = ConvertTo-HashtableShallow $Record.undo
    & $Log "== UNDO: $($Record.desc)"
    if ($Record.Undone) { & $Log '  already undone'; return New-RepairResult $true }
    $sim = { param($what) & $Log "  [SIMULATE] $what" }
    try {
        switch ([string]$u.Kind) {
            'None' { & $Log "  cannot be undone automatically: $($u.Reason)"; return New-RepairResult $false }
            'RegValue' {
                $path = [string]$u.Path; $name = [string]$u.Name
                if (-not [bool]$u.Existed) {
                    & $Log "  remove $(ConvertTo-RegExePath $path)\$name (it did not exist before)"
                    if (-not $DryRun) { Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue }
                } else {
                    $vk = [string]$u.ValueKind
                    $data = switch ($vk) {
                        'Binary' { [Convert]::FromBase64String([string]$u.Data) }
                        'DWord' { [int]$u.Data }
                        'QWord' { [long]$u.Data }
                        'MultiString' { [string[]]@($u.Data) }
                        default { [string]$u.Data }
                    }
                    & $Log "  restore $(ConvertTo-RegExePath $path)\$name = $(Limit-Text (@($u.Data) -join ' | ') 200) ($vk)"
                    if (-not $DryRun) {
                        if (-not (Test-RegKey $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
                        New-ItemProperty -LiteralPath $path -Name $name -PropertyType $vk -Value $data -Force -ErrorAction Stop | Out-Null
                    }
                }
            }
            'RegImport' {
                $f = [string]$u.File
                if (-not (Test-InsideStore $f) -or -not (Test-Path -LiteralPath $f)) { & $Log "  backup file missing or outside the protected store: $f"; return New-RepairResult $false }
                if ($DryRun) { & $sim "would import $f" } else {
                    $r = Invoke-External -File "$env:SystemRoot\System32\reg.exe" -Arguments "import `"$f`"" -TimeoutSec 60
                    if ($r.ExitCode -ne 0) { throw "reg import failed: $($r.Output.Trim())" }
                    & $Log "  registry restored from backup"
                }
            }
            'TaskRegister' {
                $f = [string]$u.XmlFile
                if (-not (Test-InsideStore $f) -or -not (Test-Path -LiteralPath $f)) { & $Log "  task backup missing: $f"; return New-RepairResult $false }
                & $Log "  re-create scheduled task $($u.TaskPath)$($u.Task)"
                if (-not $DryRun) { Register-ScheduledTask -Xml ([IO.File]::ReadAllText($f)) -TaskName $u.Task -TaskPath $u.TaskPath -Force -ErrorAction Stop | Out-Null }
            }
            'TaskEnable' {
                & $Log "  enable scheduled task $($u.TaskPath)$($u.Task)"
                if (-not $DryRun) { Enable-ScheduledTask -TaskName $u.Task -TaskPath $u.TaskPath -ErrorAction Stop | Out-Null }
            }
            'ServiceConfig' {
                $mode = switch ([int]$u.Start) { 0 { 'boot' } 1 { 'system' } 2 { if ([int]$u.Delayed -eq 1) { 'delayed-auto' } else { 'auto' } } 3 { 'demand' } 4 { 'disabled' } default { 'demand' } }
                & $Log "  service $($u.Service): start type back to $mode$(if ([bool]$u.WasRunning) { ', and start it' })"
                if (-not $DryRun) {
                    $r = Invoke-External -File "$env:SystemRoot\System32\sc.exe" -Arguments "config `"$($u.Service)`" start= $mode" -TimeoutSec 30
                    if ($r.ExitCode -ne 0) { throw "sc.exe config failed: $($r.Output.Trim())" }
                    if ([bool]$u.WasRunning) { Start-Service -Name $u.Service -ErrorAction SilentlyContinue }
                    elseif ($mode -eq 'disabled') { Stop-Service -Name $u.Service -Force -ErrorAction SilentlyContinue }
                }
            }
            'MoveBack' {
                $from = [string]$u.From; $to = [string]$u.To
                if (-not (Test-Path -LiteralPath $from)) { & $Log "  no longer in quarantine: $from (an antivirus may have removed it)"; return New-RepairResult $false }
                if (Test-Path -LiteralPath $to) { & $Log "  something already exists at $to - not overwriting it"; return New-RepairResult $false }
                if ([bool]$u.Legacy -and $to -notmatch '^(?i)[a-z]:\\users\\[^\\]+\\') { & $Log "  refused: older quarantine entries can only be restored into a user folder ($to)"; return New-RepairResult $false }
                if ($to -match '^(?i)[a-z]:\\windows\\') { & $Log "  refused: will not write into the Windows folder ($to)"; return New-RepairResult $false }
                & $Log "  move back: $to"
                if (-not $DryRun) {
                    $parent = Split-Path $to -Parent
                    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
                    if ([IO.Path]::GetPathRoot($from) -ieq [IO.Path]::GetPathRoot($to)) { Move-Item -LiteralPath $from -Destination $to -ErrorAction Stop }
                    else { Copy-Item -LiteralPath $from -Destination $to -Recurse -ErrorAction Stop; Remove-Item -LiteralPath $from -Recurse -Force -ErrorAction SilentlyContinue }
                }
            }
            'FileRestore' {
                $b = [string]$u.Backup; $t = [string]$u.Target
                $allowed = ($t -ieq "$env:SystemRoot\System32\drivers\etc\hosts") -or ($t -match '(?i)\\(User Data\\[^\\]+|Opera Software\\[^\\]+(\\[^\\]+)?)\\(Secure )?Preferences$')
                if (-not $allowed) { & $Log "  refused: unexpected restore target $t"; return New-RepairResult $false }
                if (-not (Test-InsideStore $b) -or -not (Test-Path -LiteralPath $b)) { & $Log "  backup missing: $b"; return New-RepairResult $false }
                & $Log "  restore $t from backup"
                if ($t -match 'Preferences$') { & $Log '  (close the browser first, or it may overwrite the restored file when it exits)' }
                if (-not $DryRun) { Copy-Item -LiteralPath $b -Destination $t -Force -ErrorAction Stop }
            }
            'DnsServers' {
                $srv = @($u.Servers | Where-Object { $_ })
                & $Log "  adapter $($u.InterfaceIndex): DNS back to $($srv -join ', ')"
                if (-not $DryRun) { Set-DnsClientServerAddress -InterfaceIndex ([int]$u.InterfaceIndex) -ServerAddresses $srv -ErrorAction Stop }
            }
            'WinHttpProxy' {
                $a = "winhttp set proxy proxy-server=`"$($u.Server)`"" + $(if ($u.Bypass) { " bypass-list=`"$($u.Bypass)`"" } else { '' })
                if ($DryRun) { & $sim "netsh $a" } else { $null = Invoke-RepairProcess -File "$env:SystemRoot\System32\netsh.exe" -Arguments $a -TimeoutSec 30 -Log $Log }
            }
            'MpSet' {
                & $Log "  Set-MpPreference -$($u.Setting) $($u.Value)"
                if (-not $DryRun) { $splat = @{ ([string]$u.Setting) = [string]$u.Value; ErrorAction = 'Stop' }; Set-MpPreference @splat }
            }
            'MpAddExclusion' {
                & $Log "  add Defender exclusion back ($($u.Type)): $($u.Value)"
                if (-not $DryRun) { $splat = @{ ('Exclusion' + [string]$u.Type) = [string]$u.Value; ErrorAction = 'Stop' }; Add-MpPreference @splat }
            }
            'FirewallProfiles' {
                foreach ($n in 'Domain', 'Private', 'Public') {
                    if ($u.ContainsKey($n)) {
                        & $Log "  firewall $n profile -> $(if ([bool]$u[$n]) { 'on' } else { 'off' })"
                        if (-not $DryRun) { Set-NetFirewallProfile -Name $n -Enabled $(if ([bool]$u[$n]) { 'True' } else { 'False' }) -ErrorAction Stop }
                    }
                }
            }
            'FirewallRule' {
                & $Log "  re-create firewall rule '$($u.Name)' for $($u.ApplicationName)"
                if (-not $DryRun) {
                    $r = New-Object -ComObject HNetCfg.FWRule
                    $r.Name = [string]$u.Name
                    foreach ($pn in 'Description', 'ApplicationName', 'serviceName', 'Grouping') { if ([string]$u[$pn]) { try { $r.$pn = [string]$u[$pn] } catch {} } }
                    foreach ($pn in 'Protocol', 'Direction', 'Action', 'Profiles') { if ([string]$u[$pn]) { try { $r.$pn = [int]$u[$pn] } catch {} } }
                    if ([int]$u['Protocol'] -in 6, 17) { foreach ($pn in 'LocalPorts', 'RemotePorts') { if ([string]$u[$pn] -and [string]$u[$pn] -ne '*') { try { $r.$pn = [string]$u[$pn] } catch {} } } }
                    foreach ($pn in 'LocalAddresses', 'RemoteAddresses', 'InterfaceTypes') { if ([string]$u[$pn] -and [string]$u[$pn] -ne '*') { try { $r.$pn = [string]$u[$pn] } catch {} } }
                    try { $r.EdgeTraversal = ([string]$u['EdgeTraversal'] -eq 'True') } catch {}
                    $r.Enabled = ([string]$u['Enabled'] -ne 'False')
                    (New-Object -ComObject HNetCfg.FwPolicy2).Rules.Add($r)
                }
            }
            'FeatureEnable' {
                & $Log "  Enable-WindowsOptionalFeature -Online -FeatureName $($u.Feature) -NoRestart"
                if (-not $DryRun) { Enable-WindowsOptionalFeature -Online -FeatureName $u.Feature -NoRestart -All -ErrorAction Stop | Out-Null }
            }
            'CertImport' {
                $f = [string]$u.File
                if (-not (Test-InsideStore $f) -or -not (Test-Path -LiteralPath $f)) { & $Log "  certificate backup missing: $f"; return New-RepairResult $false }
                & $Log "  import certificate back into $($u.Store)\Root"
                if (-not $DryRun) { Import-Certificate -FilePath $f -CertStoreLocation "Cert:\$($u.Store)\Root" -ErrorAction Stop | Out-Null }
            }
            'TrustRemove' {
                $f = [string]$u.File; $line = [string]$u.Line
                if (-not [IO.File]::Exists($f)) { & $Log '  trusted.txt not found'; return New-RepairResult $true }
                & $Log "  remove '$line' from trusted.txt"
                if (-not $DryRun) {
                    $keep = @([IO.File]::ReadAllLines($f) | Where-Object { ($_ -replace '#.*$', '').Trim() -ine $line })
                    [IO.File]::WriteAllLines($f, $keep)
                }
            }
            'RunFixed' {
                $spec = Get-RunSpec ([string]$u.Command)
                if (-not $spec -or [string]$u.Command -notin 'guest-on', 'builtin-admin-on', 'hibernate-on') { & $Log '  unknown undo command - refused'; return New-RepairResult $false }
                $r = Invoke-RepairProcess -File $spec[0] -Arguments $spec[1] -TimeoutSec $spec[2] -Log $Log -DryRun:$DryRun
                if (-not $DryRun -and $r.ExitCode -ne 0) { return New-RepairResult $false }
            }
            default { & $Log "  unknown undo kind '$($u.Kind)'"; return New-RepairResult $false }
        }
        if (-not $DryRun) { Add-UndoneMark -Ctx $Ctx -Id ([string]$Record.id) -Ok $true -Note '' }
        return New-RepairResult $true $true
    } catch {
        & $Log "  FAILED: $($_.Exception.Message)"
        return New-RepairResult $false
    }
}
