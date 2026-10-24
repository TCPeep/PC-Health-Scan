# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# PC App Store (Fast Corporation LTD) - dedicated detection and complete removal. ASCII-only source.
#
# Built ONLY from written research (the vendor's own uninstall article, Microsoft Q&A threads including an FRST
# fixlist from a volunteer moderator, BleepingComputer forum logs, a 2026 hands-on write-up, sandbox report
# summaries). It has never been run against the real program and must never be tested with it: the real
# installer is extremely hard to remove. dev\repair-selftest.ps1 tests it with harmless fake stand-ins.
#
# What is known to keep it alive (versions differ, so all are handled):
#   - HKCU Run values  PCAppStore ("...\PCAppStore\PCAppStore.exe" /src=autostart), PcAppStoreUpdater (AutoUpdater.exe /i),
#     Watchdog (Watchdog.exe); older builds: PCAPP (PcAppStore.exe /init default). Newer builds may put Watchdog in HKLM\...\WOW6432Node\...\Run.
#   - Watchdog.exe restarts / holds the app when PCAppStore.exe is ended -> end Watchdog first and repeat.
#   - Older builds: scheduled task "PCAppStoreAutoUpdater" (every 18 h). Some builds: PcAppStoreSRV.exe (service, name unknown).
#   - Folder %USERPROFILE%\PCAppStore (nwjs\, UserData\, PCAppStore.exe, Watchdog.exe, AutoUpdater.exe, PcAppStoreSRV.exe, Uninstaller.exe)
#   - HKCU\Software\PCAppStore, HKLM\SOFTWARE\WOW6432Node\PCAppStore, Apps-list key ...\Uninstall\PCAppStore, "PC App Store.lnk".
#
# Matching rule: an item belongs to PC App Store only if it IS, lives in, or points into a folder named exactly
# "PCAppStore", or is a key named exactly PCAppStore / an Apps-list entry published by Fast Corporation.
# Generic names on their own (Watchdog.exe, AutoUpdater.exe, nwjs) are never enough.

$script:PcasRx = '(?i)\\PCAppStore\\'
# Program names unique to this product (file.net / removal guides list PCAppStoreSvc.exe and AppStoreDeskTool.exe too).
# These count even outside a PCAppStore folder; generic names (Watchdog.exe, AutoUpdater.exe, nw.exe) never do.
$script:PcasNameRx = '(?i)\\(PCAppStore|PcAppStoreSRV|PCAppStoreSvc|AppStoreDeskTool|NW_store)\.exe\b'
$script:PcasExeOrder = @('watchdog.exe', 'autoupdater.exe', 'pcappstoresrv.exe', 'pcappstoresvc.exe', 'appstoredesktool.exe', 'pcappstore.exe', 'nw_store.exe', 'nw.exe')

function Test-PcasPath {
    param([string]$Text)
    if (-not $Text) { return $false }
    $byFolder = $Text -match $script:PcasRx
    $byName = $Text -match $script:PcasNameRx -and $Text -notmatch '(?i)[a-z]:\\windows\\(?!temp\\)'
    if (-not ($byFolder -or $byName)) { return $false }
    # never anything inside this tool or its quarantine/backup store
    $l = $Text.ToLowerInvariant()
    foreach ($ex in @((Join-Path $env:ProgramData 'PCHealthScan'), $script:ScannerRoot, $script:RepairToolRoot)) {
        if ($ex -and $l.Contains($ex.TrimEnd('\').ToLowerInvariant() + '\')) { return $false }
    }
    $true
}

function Test-PCAppStoreFolder {
    param([string]$Path)
    if (-not $Path -or (Split-Path $Path -Leaf) -ine 'PCAppStore') { return $false }
    try { if (-not [IO.Directory]::Exists($Path)) { return $false } } catch { return $false }
    foreach ($f in 'PCAppStore.exe', 'Watchdog.exe', 'AutoUpdater.exe', 'PcAppStoreSRV.exe', 'PCAppStoreSvc.exe', 'AppStoreDeskTool.exe', 'Uninstaller.exe', 'NW_store.exe') { if ([IO.File]::Exists((Join-Path $Path $f))) { return $true } }
    foreach ($d in 'nwjs', 'UserData') { if ([IO.Directory]::Exists((Join-Path $Path $d))) { return $true } }
    $entries = @(); try { $entries = @([IO.Directory]::GetFileSystemEntries($Path)) } catch {}
    if ($entries.Count -eq 0) { return $true }   # empty leftover
    foreach ($f in (Get-FilesSafe -Root $Path -MaxDepth 3 -Extensions @('.exe') -MaxFiles 25 -MaxSeconds 5)) {
        if ((Get-FileSig $f.FullName).Signer -match '(?i)^fast corporation') { return $true }
    }
    $false
}

# Where to look. Defaults = every user profile on this PC + the real HKLM. The self-test passes fake profiles and
# fake registry roots instead (and -SkipSystemWide, so it never looks at real tasks, services, processes or firewall).
function Get-PcasContext {
    param($Profiles, [string]$MachineRoot = 'Registry::HKEY_LOCAL_MACHINE', [string[]]$MachineFolders, [switch]$SkipSystemWide)
    if (-not $Profiles) {
        $hives = @{}
        foreach ($h in @(Get-UserHives)) { $hives[$h.Sid] = $h.Root }
        $Profiles = foreach ($p in @(Get-UserProfiles)) { [pscustomobject]@{ Sid = $p.Sid; User = $p.User; Path = $p.Path; Hive = $hives[$p.Sid] } }
    }
    if ($null -eq $MachineFolders) { $MachineFolders = @("${env:ProgramFiles(x86)}\PCAppStore", "$env:ProgramFiles\PCAppStore", "$env:ProgramData\PCAppStore") }
    [pscustomobject]@{ Profiles = @($Profiles); MachineRoot = $MachineRoot; MachineFolders = @($MachineFolders | Where-Object { $_ }); SkipSystemWide = [bool]$SkipSystemWide }
}

# Read-only. Returns @{ Items = every PC App Store artifact found; Notes = things that could not be checked }.
function Find-PCAppStore {
    param($Context)
    if (-not $Context) { $Context = Get-PcasContext }
    $items = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $add = {
        param($Type, $Owner, $Path, $Name, $Detail)
        $k = "$Type|$Path|$Name".ToLowerInvariant()
        if ($seen.ContainsKey($k)) { return }
        $seen[$k] = $true
        $items.Add([pscustomobject]@{ Type = $Type; Owner = $Owner; Path = $Path; Name = $Name; Detail = $Detail })
    }
    $findRun = {
        param($Root, $Sub, $Approved, $Owner)
        foreach ($v in (Get-RegValues "$Root\$Sub")) {
            if (-not (Test-PcasPath ([string]$v.Value))) { continue }
            & $add 'RunValue' $Owner "$Root\$Sub" $v.Name ([string]$v.Value)
            if ($Approved) {
                $ak = "$Root\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Approved"
                if (@((Get-RegValues $ak) | Where-Object { $_.Name -eq $v.Name }).Count) { & $add 'StartupApproved' $Owner $ak $v.Name 'Task Manager startup-list entry' }
            }
        }
    }
    $findUninstall = {
        param($Root, $Owner)
        foreach ($sub in 'Software\Microsoft\Windows\CurrentVersion\Uninstall', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
            foreach ($k in @(Get-ChildItem -LiteralPath "$Root\$sub" -ErrorAction SilentlyContinue)) {
                $dn = [string]$k.GetValue('DisplayName'); $pub = [string]$k.GetValue('Publisher')
                $us = [string]$k.GetValue('UninstallString'); $il = [string]$k.GetValue('InstallLocation')
                if ($k.PSChildName -ieq 'PCAppStore' -or ($dn -match '^(?i)PC App Store' -and $pub -match '(?i)fast corporation') -or (Test-PcasPath $us) -or (Test-PcasPath ($il.TrimEnd('\') + '\'))) {
                    & $add 'AppsListEntry' $Owner "Registry::$($k.Name)" $(if ($dn) { $dn } else { $k.PSChildName }) "$pub $us".Trim()
                }
            }
        }
    }
    $findLinks = {
        param($Dirs, $Owner)
        foreach ($d in $Dirs) {
            foreach ($f in (Get-FilesSafe -Root $d -MaxDepth 2 -Extensions @('.lnk') -MaxFiles 3000 -MaxSeconds 10)) {
                $si = Get-ShortcutInfo $f.FullName
                $t = if ($si) { [string]$si.Target } else { '' }
                $exists = $false; if ($t) { try { $exists = [IO.File]::Exists($t) } catch {} }
                if ((Test-PcasPath $t) -or ($f.Name -ieq 'PC App Store.lnk' -and -not $exists)) { & $add 'Shortcut' $Owner $f.FullName '' $t }
            }
        }
    }
    $folder = {
        param($Path, $Owner)
        if (Test-PCAppStoreFolder $Path) { $sz = Get-DirSize -Path $Path -MaxSeconds 5; & $add 'Folder' $Owner $Path '' "$(Format-Bytes $sz.Bytes), $($sz.Files) file(s)" }
    }

    # ---- per user account
    foreach ($p in $Context.Profiles) {
        $owner = Get-ShortUser $p.User
        foreach ($rel in 'PCAppStore', 'AppData\Local\PCAppStore', 'AppData\Roaming\PCAppStore', 'AppData\Local\Programs\PCAppStore') { & $folder (Join-Path $p.Path $rel) $owner }
        if ($p.Hive) {
            & $findRun $p.Hive 'Software\Microsoft\Windows\CurrentVersion\Run' 'Run' $owner
            & $findRun $p.Hive 'Software\Microsoft\Windows\CurrentVersion\RunOnce' $null $owner
            if (Test-RegKey "$($p.Hive)\Software\PCAppStore") { & $add 'RegKey' $owner "$($p.Hive)\Software\PCAppStore" 'PCAppStore' 'its settings key' }
            & $findUninstall $p.Hive $owner
        } elseif ($p.Sid) {
            $notes.Add("The registry of '$owner' could not be checked because that account is not signed in right now. If PC App Store was used on that account, sign in to it and run the scan again.")
        }
        $dirs = @((Join-Path $p.Path 'Desktop'), (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'), (Join-Path $p.Path 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'))
        try { foreach ($od in [IO.Directory]::GetDirectories($p.Path, 'OneDrive*')) { $dirs += (Join-Path $od 'Desktop') } } catch {}
        & $findLinks $dirs $owner
    }

    # ---- machine-wide registry and folders
    $m = $Context.MachineRoot
    & $findRun $m 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Run' 'all users'
    & $findRun $m 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' $null 'all users'
    & $findRun $m 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' 'Run32' 'all users'
    & $findRun $m 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' $null 'all users'
    foreach ($k in "$m\SOFTWARE\PCAppStore", "$m\SOFTWARE\WOW6432Node\PCAppStore") { if (Test-RegKey $k) { & $add 'RegKey' 'all users' $k 'PCAppStore' 'its settings key' } }
    & $findUninstall $m 'all users'
    foreach ($f in $Context.MachineFolders) { & $folder $f 'all users' }

    # ---- tasks, services, running programs, firewall, all-users shortcuts (skipped by the self-test)
    if (-not $Context.SkipSystemWide) {
        & $findLinks @("$env:PUBLIC\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs") 'all users'
        foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            $acts = (@($t.Actions) | Where-Object { $_ } | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
            if ($t.TaskName -match '^(?i)PCAppStore' -or (Test-PcasPath $acts)) { & $add 'Task' 'all users' $t.TaskPath $t.TaskName $acts }
        }
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            if (Test-PcasPath ([string]$s.PathName)) { & $add 'Service' 'all users' ([string]$s.PathName) $s.Name "$($s.DisplayName) ($($s.State))" }
        }
        foreach ($pr in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
            if (Test-PcasPath ([string]$pr.ExecutablePath)) { & $add 'Process' '' ([string]$pr.ExecutablePath) $pr.Name "PID $($pr.ProcessId)" }
        }
        try {
            foreach ($r in (New-Object -ComObject HNetCfg.FwPolicy2).Rules) {
                $app = [Environment]::ExpandEnvironmentVariables([string]$r.ApplicationName)
                if (Test-PcasPath $app) { & $add 'FirewallRule' 'all users' $app $r.Name '' }
            }
        } catch {}
    }

    # program files with its unique names that live OUTSIDE a PCAppStore folder (seen via a startup entry, task,
    # service or running process) are quarantined one by one
    $folders = @($items | Where-Object { $_.Type -eq 'Folder' } | ForEach-Object { $_.Path.TrimEnd('\').ToLowerInvariant() + '\' })
    foreach ($x in @($items | Where-Object { $_.Type -in 'RunValue', 'Task', 'Service', 'Process' })) {
        $src = if ($x.Type -in 'RunValue', 'Task') { $x.Detail } else { $x.Path }
        $t = (Resolve-LaunchTarget $src).Target
        if (-not $t -or $t -notmatch $script:PcasNameRx -or $t -match $script:PcasRx) { continue }
        $exists = $false; try { $exists = [IO.File]::Exists($t) } catch {}
        if (-not $exists) { continue }
        $inside = $false; foreach ($f in $folders) { if ($t.ToLowerInvariant().StartsWith($f)) { $inside = $true } }
        if (-not $inside) { & $add 'File' $x.Owner $t '' 'PC App Store program outside its usual folder' }
    }
    [pscustomobject]@{ Items = $items.ToArray(); Notes = $notes.ToArray() }
}

# Ends PC App Store's own programs: exact, verified file paths only, Watchdog first, repeated because Watchdog
# restarts the app. Returns $true when none of them are running any more.
function Stop-PCAppStoreProcesses {
    param($Log, [switch]$DryRun, $Context)
    if ($Context -and $Context.SkipSystemWide) { return $true }
    for ($pass = 1; $pass -le 4; $pass++) {
        $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { Test-PcasPath ([string]$_.ExecutablePath) })
        if ($procs.Count -eq 0) { if ($pass -gt 1) { & $Log '  no PC App Store programs running any more' }; return $true }
        $exes = @($procs | ForEach-Object { [string]$_.ExecutablePath } | Select-Object -Unique | Sort-Object {
                $i = [array]::IndexOf($script:PcasExeOrder, ([IO.Path]::GetFileName($_)).ToLowerInvariant()); if ($i -lt 0) { 99 } else { $i } })
        & $Log "  pass ${pass}: $($procs.Count) PC App Store process(es) running - ending them, Watchdog first"
        foreach ($e in $exes) { $null = Stop-TargetProcesses -Path $e -Log $Log -DryRun:$DryRun -MaxProcesses 40 }
        if ($DryRun -or $script:RepairNoKill) { return $true }
        Start-Sleep -Seconds 1
    }
    $left = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { Test-PcasPath ([string]$_.ExecutablePath) })
    foreach ($l in $left) { & $Log "  still running: $($l.Name) (PID $($l.ProcessId))" }
    $left.Count -eq 0
}

# The complete removal, in the order the vetted fixlist uses. Every change goes through the normal repair
# actions, so each one is guarded, logged and individually undoable.
function Invoke-PCAppStoreRemoval {
    param($Ctx, [scriptblock]$Log, [switch]$DryRun, $Context)
    if (-not $Context) { $Context = Get-PcasContext }
    $sub = { param($A) (Invoke-RepairAction -Action $A -Log $Log -Ctx $Ctx -DryRun:$DryRun).Ok }
    & $Log '  looking for every PC App Store item on this PC (all user accounts)...'
    $found = Find-PCAppStore -Context $Context
    foreach ($n in $found.Notes) { & $Log "  NOTE: $n" }
    $it = @($found.Items)
    if ($it.Count -eq 0) { & $Log '  nothing found - PC App Store is not on this PC (or was already fully removed)'; return New-RepairResult $true }
    foreach ($g in ($it | Group-Object Type)) { & $Log ("  found: {0} x {1}" -f $g.Count, $g.Name) }
    $ok = $true

    # 1. everything that starts it - so nothing can bring it back while it is being removed
    foreach ($x in @($it | Where-Object { $_.Type -in 'RunValue', 'StartupApproved' })) {
        if (-not (& $sub (New-RepairAction -Kind RegDeleteValue -Label "Remove its startup entry '$($x.Name)' ($($x.Owner))" -Risk caution -Params @{ Path = $x.Path; Name = $x.Name }))) { $ok = $false }
    }
    foreach ($x in @($it | Where-Object { $_.Type -eq 'Task' })) {
        if (-not (& $sub (New-RepairAction -Kind TaskDelete -Label "Remove its scheduled task $($x.Path)$($x.Name)" -Risk caution -Params @{ Task = $x.Name; TaskPath = $x.Path }))) { $ok = $false }
    }
    foreach ($x in @($it | Where-Object { $_.Type -eq 'Service' })) {
        if (-not (& $sub (New-RepairAction -Kind ServiceDelete -Label "Remove its service '$($x.Name)'" -Risk caution -Params @{ Service = $x.Name }))) { $ok = $false }
    }

    # 2. end its programs (Watchdog first, repeated)
    $stopped = Stop-PCAppStoreProcesses -Log $Log -DryRun:$DryRun -Context $Context
    if (-not $stopped) {
        & $Log '  Some PC App Store programs are still running, so its folders were left where they are. Its startup entries are already gone:'
        & $Log '  restart the PC, then press Apply on this fix again.'
        $ok = $false
    }

    # 3. folders and shortcuts -> quarantine (restorable)
    if ($stopped) {
        foreach ($x in @($it | Where-Object { $_.Type -eq 'Folder' })) {
            if (-not (& $sub (New-RepairAction -Kind Quarantine -Label "Quarantine its folder $($x.Path)" -Risk caution -Params @{ Targets = @($x.Path) }))) { $ok = $false }
        }
        foreach ($x in @($it | Where-Object { $_.Type -eq 'File' })) {
            if (-not (& $sub (New-RepairAction -Kind Quarantine -Label "Quarantine its program file $($x.Path)" -Risk caution -Params @{ Targets = @($x.Path) }))) { $ok = $false }
        }
    }
    foreach ($x in @($it | Where-Object { $_.Type -eq 'Shortcut' })) {
        if (-not (& $sub (New-RepairAction -Kind Quarantine -Label "Quarantine the shortcut $(Split-Path $x.Path -Leaf)" -Risk caution -Params @{ Targets = @($x.Path) }))) { $ok = $false }
    }

    # 4. registry: Apps-list entries and its settings keys (each backed up first)
    foreach ($x in @($it | Where-Object { $_.Type -in 'AppsListEntry', 'RegKey' })) {
        if (-not (& $sub (New-RepairAction -Kind RegDeleteKey -Label "Remove $(if ($x.Type -eq 'AppsListEntry') { "its Apps-list entry '$($x.Name)'" } else { 'its registry key' }) ($($x.Owner))" -Risk caution -Params @{ Path = $x.Path }))) { $ok = $false }
    }

    # 5. firewall exceptions for its programs
    $fw = @($it | Where-Object { $_.Type -eq 'FirewallRule' })
    if ($fw.Count) {
        if (-not (& $sub (New-RepairAction -Kind FirewallRuleRemove -Label 'Remove its firewall exceptions' -Risk caution -Params @{ Rules = @($fw | ForEach-Object { $_.Name } | Select-Object -Unique); Programs = @($fw | ForEach-Object { $_.Path.ToLowerInvariant() } | Select-Object -Unique) }))) { $ok = $false }
    }

    # 6. check the result
    if (-not $DryRun) {
        $left = @((Find-PCAppStore -Context $Context).Items)
        if ($left.Count) {
            & $Log "  STILL PRESENT ($($left.Count)):"
            foreach ($l in $left) { & $Log "    $($l.Type): $($l.Path) $($l.Name)" }
            $ok = $false
        } else { & $Log '  checked again: nothing from PC App Store is left on this PC' }
    }
    & $Log '  next: restart the PC, run START-SCAN.cmd again, and run a Microsoft Defender full scan.'
    & $Log '  note: removing the program does NOT cancel anything that was paid for through it - check the card/bank statement.'
    New-RepairResult $ok $true
}
