# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Persistence: everything that makes a program start automatically

$script:VulnDrivers = @('winring0x64.sys', 'winring0.sys', 'rtcore64.sys', 'rtcore32.sys', 'gdrv.sys', 'dbutil_2_3.sys', 'asrdrv101.sys', 'asrdrv102.sys',
    'asrdrv103.sys', 'asrdrv104.sys', 'asrdrv106.sys', 'atszio64.sys', 'glckio2.sys', 'enetechio64.sys', 'msio64.sys', 'iqvw64e.sys', 'cpuz141.sys',
    'mhyprot2.sys', 'kprocesshacker.sys', 'speedfan.sys', 'physmem.sys', 'ntiolib_x64.sys', 'eneio64.sys', 'zamguard64.sys', 'truesight.sys', 'aswarpot.sys')

function Get-StartupApproved {
    param([string]$Root, [string]$Sub)
    $h = @{}
    foreach ($v in (Get-RegValues "$Root\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Sub")) {
        $b = $v.Value
        if ($b -is [byte[]] -and $b.Length -gt 0) { $h[$v.Name.ToLowerInvariant()] = (($b[0] -band 1) -eq 0) }
    }
    $h
}

function New-AutoRow {
    param([string]$Type, [string]$Location, [string]$Name, [string]$Command, [string]$State = 'Enabled', [string]$Fix, [switch]$Quiet, [string]$Extra,
        [object[]]$Remove)   # repair action(s) that remove this entry; the target file is quarantined too when it looks bad
    $risk = Measure-ExecRisk -Command $Command -Name $Name -Quiet:$Quiet
    $sev = $risk.Severity
    if ($State -like 'Disabled*' -and $sev -in 'Low', 'Medium') { $sev = 'Low' }
    $acts = @($Remove | Where-Object { $_ })
    if ($acts.Count -gt 0 -and $risk.Exists -and $risk.Target -and (Test-UserWritableZone $risk.Zone) -and ($risk.Pup -or -not $risk.Trusted)) {
        $acts += New-RepairAction -Kind Quarantine -Label "Quarantine the program it starts: $($risk.Target)" -Risk caution -Params @{ Targets = @($risk.Target) }
    }
    # merely unsigned (not known adware, no malicious command line): could be a small legit app - nothing pre-ticked
    $knownBad = $risk.Pup -or ($Command -match $script:StrongCmdRx) -or $risk.SigStatus -eq 'HashMismatch'
    if ($acts.Count -gt 0 -and $risk.Exists -and -not $knownBad -and -not $risk.Trusted) {
        $acts = New-UnknownProgramActions -Path $risk.Target -Name $Name -RemoveActions $acts
    }
    [pscustomobject]@{
        Type = $Type; Name = $Name; State = $State; Concerns = $risk.Reasons; Signer = (Get-SigLabel $risk); Target = $risk.Target
        Command = (Limit-Text $Command 400); Location = $Location; Details = $Extra
        _Flag = (ConvertTo-FlagClass $sev); _Sev = $sev; _Risk = $risk; _Fix = $Fix; _Actions = $acts
    }
}

function Submit-PersistenceFindings {
    param([object[]]$Rows, [string]$What)
    $low = @(); $lowActs = @()
    foreach ($r in $Rows) {
        $sev = $r._Sev
        if (-not $sev -or $sev -eq 'Info') { continue }
        if ($sev -eq 'Low') {
            $low += "$($r.Name) -> $($r.Target) [$($r.Concerns)]"
            # only offer one-click removal for entries whose target no longer exists (pure leftovers)
            if (-not $r._Risk.Exists -and $r._Actions) { $lowActs += @($r._Actions | Where-Object { $_.Kind -ne 'Quarantine' }) }
            continue
        }
        $pup = $r._Risk.Pup
        $hash = if ($r._Risk.Exists) { Get-Sha256 $r._Risk.Target } else { '' }
        Add-Finding -Severity $sev -Category $(if ($pup) { 'Malware & PUPs' } else { 'Persistence' }) -Section 'persistence' `
            -Title "$What auto-starts something suspicious: $($r.Name)" -Detail $r.Concerns `
            -Evidence @("Location: $($r.Location)", "Command: $($r.Command)", "File: $($r.Target)", "Signer: $($r.Signer)", $(if ($hash) { "SHA256: $hash" }), $(if ($r.Details) { $r.Details })) `
            -Why $(if ($pup) { $pup.Info } else { 'Malware and adware make sure they restart with Windows. Unsigned programs auto-starting from user folders, or hidden/encoded commands, are the classic signs.' }) `
            -Fix $r._Fix -Actions $r._Actions
    }
    if ($low.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Persistence' -Section 'persistence' -Title "$What items to review: $($low.Count) leftover or unsigned" `
            -Evidence $low -Why 'Leftover entries point at files that no longer exist (often from removed adware). Unsigned entries are not necessarily bad but deserve a look.' `
            -Fix 'Review each one. Sysinternals Autoruns (free, from Microsoft) is the easiest way to delete leftovers safely.' `
            -Actions $lowActs
    }
}

function Invoke-AutostartScan {
    $S = 'persistence'
    $machine = 'Registry::HKEY_LOCAL_MACHINE'
    $hives = @($script:Hives)

    # ---------------- Run keys
    $runRows = @()
    $specs = @(
        @{ Root = $machine; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Approved = 'Run'; Label = 'HKLM\...\Run' },
        @{ Root = $machine; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Approved = $null; Label = 'HKLM\...\RunOnce' },
        @{ Root = $machine; Path = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'Run32'; Label = 'HKLM\WOW6432Node\...\Run' },
        @{ Root = $machine; Path = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Approved = $null; Label = 'HKLM\WOW6432Node\...\RunOnce' },
        @{ Root = $machine; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Approved = $null; Label = 'HKLM\...\Policies\Explorer\Run' }
    )
    foreach ($h in $hives) {
        $u = Get-ShortUser $h.User
        $specs += @{ Root = $h.Root; Path = 'Software\Microsoft\Windows\CurrentVersion\Run'; Approved = 'Run'; Label = "HKCU\...\Run ($u)" }
        $specs += @{ Root = $h.Root; Path = 'Software\Microsoft\Windows\CurrentVersion\RunOnce'; Approved = $null; Label = "HKCU\...\RunOnce ($u)" }
        $specs += @{ Root = $h.Root; Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Approved = $null; Label = "HKCU\...\Policies\Explorer\Run ($u)" }
    }
    foreach ($sp in $specs) {
        $appr = if ($sp.Approved) { Get-StartupApproved $sp.Root $sp.Approved } else { @{} }
        foreach ($v in (Get-RegValues "$($sp.Root)\$($sp.Path)")) {
            if (-not $v.Name -and -not $v.Value) { continue }
            $state = 'Enabled'
            if ($appr.ContainsKey($v.Name.ToLowerInvariant()) -and -not $appr[$v.Name.ToLowerInvariant()]) { $state = 'Disabled (Task Manager)' }
            $fix = "Task Manager > Startup apps > Disable it, uninstall the program it belongs to, then delete the value '$($v.Name)' from $($sp.Label) (regedit) or with Sysinternals Autoruns."
            $runRows += New-AutoRow -Type 'Registry Run' -Location $sp.Label -Name $v.Name -Command ([string]$v.Value) -State $state -Fix $fix `
                -Remove @((New-RepairAction -Kind RegDeleteValue -Label "Remove startup entry '$($v.Name)' from $($sp.Label)" -Risk caution -Params @{ Path = "$($sp.Root)\$($sp.Path)"; Name = $v.Name }))
        }
    }

    # ---------------- Startup folders
    $folderSpecs = @(@{ Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"; Label = 'All-users Startup folder'; Root = $machine })
    foreach ($p in $script:Profiles) {
        $hv = $hives | Where-Object { $_.Sid -eq $p.Sid } | Select-Object -First 1
        $folderSpecs += @{ Path = (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'); Label = "Startup folder ($(Get-ShortUser $p.User))"; Root = $(if ($hv) { $hv.Root } else { $null }) }
    }
    foreach ($fs in $folderSpecs) {
        $appr = if ($fs.Root) { Get-StartupApproved $fs.Root 'StartupFolder' } else { @{} }
        $files = @()
        try { $files = @([IO.Directory]::GetFiles($fs.Path)) } catch {}
        foreach ($f in $files) {
            $leaf = [IO.Path]::GetFileName($f)
            if ($leaf -ieq 'desktop.ini') { continue }
            $cmd = '"' + $f + '"'
            if ($leaf -match '\.lnk$') {
                $si = Get-ShortcutInfo $f
                if ($si -and $si.Target) { $cmd = ('"' + $si.Target + '" ' + $si.Args).Trim() }
            }
            $state = 'Enabled'
            if ($appr.ContainsKey($leaf.ToLowerInvariant()) -and -not $appr[$leaf.ToLowerInvariant()]) { $state = 'Disabled (Task Manager)' }
            $runRows += New-AutoRow -Type 'Startup folder' -Location $fs.Path -Name $leaf -Command $cmd -State $state -Fix "Delete '$leaf' from $($fs.Path) and uninstall the program it belongs to." `
                -Remove @((New-RepairAction -Kind Quarantine -Label "Remove '$leaf' from the Startup folder" -Risk caution -Params @{ Targets = @($f) }))
        }
    }
    $script:Shared.StartupCount = @($runRows | Where-Object { $_.State -eq 'Enabled' -and $_.Type -in 'Registry Run', 'Startup folder' }).Count
    Add-Table -Section $S -Title 'Startup programs (Run keys and Startup folders)' -Rows $runRows -Columns @('Name', 'State', 'Concerns', 'Signer', 'Target', 'Command', 'Location')
    Submit-PersistenceFindings -Rows $runRows -What 'Startup entry'
    foreach ($r in $runRows) { if ($r._Risk.Pup) { $script:Shared.PupHits += , $r._Risk.Pup.Name } }

    # ---------------- Advanced hijack points
    $adv = @()
    $wl = "$machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $shell = [string](Get-RegValue $wl 'Shell')
    if ($shell -and $shell.Trim().TrimEnd(',') -notmatch '^(?i)explorer(\.exe)?$') {
        $adv += [pscustomobject]@{ Point = 'Winlogon Shell'; Location = $wl; Value = $shell; Concern = 'Should be just explorer.exe'; _Flag = 'high' }
        Add-Finding -Severity High -Category 'Persistence' -Section $S -Title 'Windows logon shell has been changed' -Detail "Shell = $shell" `
            -Why 'Malware replaces or appends to the shell value so it runs every time anyone signs in.' -Fix "Set HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell back to explorer.exe (as admin), after identifying and removing the extra program." `
            -Actions @((New-RepairAction -Kind RegSetValue -Label 'Set the logon shell back to explorer.exe' -Risk caution -Params @{ Path = $wl; Name = 'Shell'; Type = 'String'; Value = 'explorer.exe' }))
    }
    $ui = [string](Get-RegValue $wl 'Userinit')
    if ($ui -and $ui.Trim().TrimEnd(',') -notmatch '^(?i)(c:\\windows\\system32\\)?userinit(\.exe)?$') {
        $adv += [pscustomobject]@{ Point = 'Winlogon Userinit'; Location = $wl; Value = $ui; Concern = 'Should be C:\Windows\system32\userinit.exe,'; _Flag = 'high' }
        Add-Finding -Severity High -Category 'Persistence' -Section $S -Title 'Winlogon Userinit has extra programs' -Detail "Userinit = $ui" `
            -Fix 'Set it back to C:\Windows\system32\userinit.exe, (with the trailing comma) after removing the extra program.' `
            -Actions @((New-RepairAction -Kind RegSetValue -Label 'Set Userinit back to the Windows default' -Risk caution -Params @{ Path = $wl; Name = 'Userinit'; Type = 'String'; Value = "$env:SystemRoot\system32\userinit.exe," }))
    }
    foreach ($h in $hives) {
        $u = Get-ShortUser $h.User
        $uShell = Get-RegValue "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell'
        if ($uShell) {
            $adv += [pscustomobject]@{ Point = "Per-user Winlogon Shell ($u)"; Location = "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value = $uShell; Concern = 'Per-user shell override'; _Flag = 'high' }
            Add-Finding -Severity High -Category 'Persistence' -Section $S -Title "Per-user logon shell override for $u" -Detail "Shell = $uShell" -Fix 'Delete the Shell value under HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon for that user.' `
                -Actions @((New-RepairAction -Kind RegDeleteValue -Label "Remove the per-user Shell override for $u" -Risk caution -Params @{ Path = "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = 'Shell' }))
        }
        foreach ($n in 'Load', 'Run') {
            $val = [string](Get-RegValue "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Windows" $n)
            if ($val.Trim()) {
                $adv += [pscustomobject]@{ Point = "Legacy Windows\$n ($u)"; Location = 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows'; Value = $val; Concern = 'Old autostart point rarely used by legit software'; _Flag = 'high' }
                Add-Finding -Severity High -Category 'Persistence' -Section $S -Title "Legacy '$n' autostart value is set for $u" -Detail $val -Fix "Delete the $n value under HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows." `
                    -Actions @((New-RepairAction -Kind RegDeleteValue -Label "Delete the legacy '$n' value for $u" -Risk caution -Params @{ Path = "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Windows"; Name = $n }))
            }
        }
        $car = Get-RegValue "$($h.Root)\Software\Microsoft\Command Processor" 'AutoRun'
        if ($car) { $adv += [pscustomobject]@{ Point = "cmd.exe AutoRun ($u)"; Location = 'HKCU\Software\Microsoft\Command Processor'; Value = $car; Concern = 'Runs every time cmd.exe starts'; _Flag = 'medium'; _Path = "$($h.Root)\Software\Microsoft\Command Processor" } }
    }
    $carM = Get-RegValue "$machine\SOFTWARE\Microsoft\Command Processor" 'AutoRun'
    if ($carM) { $adv += [pscustomobject]@{ Point = 'cmd.exe AutoRun (machine)'; Location = 'HKLM\SOFTWARE\Microsoft\Command Processor'; Value = $carM; Concern = 'Runs every time cmd.exe starts'; _Flag = 'medium'; _Path = "$machine\SOFTWARE\Microsoft\Command Processor" } }
    foreach ($row in @($adv | Where-Object { $_.Point -like 'cmd.exe AutoRun*' })) {
        Add-Finding -Severity Medium -Category 'Persistence' -Section $S -Title 'Command Prompt AutoRun is set' -Detail "$($row.Value)" -Fix "Delete the AutoRun value under $($row.Location) unless you set it yourself." `
            -Actions @((New-RepairAction -Kind RegDeleteValue -Label "Delete the cmd.exe AutoRun value ($($row.Location))" -Risk caution -Params @{ Path = $row._Path; Name = 'AutoRun' }))
    }

    foreach ($k in @("$machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "$machine\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows")) {
        $dlls = [string](Get-RegValue $k 'AppInit_DLLs')
        $load = Get-RegValue $k 'LoadAppInit_DLLs'
        if ($dlls.Trim()) {
            $active = ($load -eq 1)
            $adv += [pscustomobject]@{ Point = 'AppInit_DLLs'; Location = $k; Value = $dlls; Concern = $(if ($active) { 'Loaded into every GUI program' } else { 'Present but loading disabled' }); _Flag = $(if ($active) { 'high' } else { 'low' }) }
            if ($active) {
                Add-Finding -Severity High -Category 'Persistence' -Section $S -Title 'AppInit_DLLs injects a DLL into every program' -Detail $dlls `
                    -Why 'This old mechanism is mostly used by adware and malware to inject into browsers.' -Fix "Clear AppInit_DLLs and set LoadAppInit_DLLs to 0 under $k (as admin), then remove the DLL." `
                    -Actions @((New-RepairAction -Kind RegSetValue -Label 'Stop loading AppInit DLLs' -Risk caution -Params @{ Path = $k; Name = 'LoadAppInit_DLLs'; Value = 0 }),
                        (New-RepairAction -Kind RegSetValue -Label 'Clear the AppInit_DLLs list' -Risk caution -Params @{ Path = $k; Name = 'AppInit_DLLs'; Type = 'String'; Value = '' }))
            }
        }
    }

    foreach ($ifeoRoot in @("$machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "$machine\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")) {
        foreach ($sk in (Get-ChildItem -LiteralPath $ifeoRoot -ErrorAction SilentlyContinue)) {
            $dbg = $sk.GetValue('Debugger')
            if (-not $dbg) { continue }
            $lt = Resolve-LaunchTarget ([string]$dbg)
            $sig = Get-FileSig $lt.Target
            $benign = $sig.IsMicrosoft -and $lt.Target -match '(?i)procexp|vsjitdebugger|systemsettings'
            $adv += [pscustomobject]@{ Point = "IFEO debugger for $($sk.PSChildName)"; Location = $sk.Name; Value = $dbg; Concern = $(if ($benign) { 'Microsoft tool (e.g. Process Explorer replacing Task Manager)' } else { 'Hijacks a program: launching it runs this instead' }); _Flag = $(if ($benign) { 'low' } else { 'high' }) }
            if (-not $benign) {
                Add-Finding -Severity High -Category 'Persistence' -Section $S -Title "Program launch is hijacked: $($sk.PSChildName)" -Detail "Debugger = $dbg" `
                    -Why 'Image File Execution Options "Debugger" makes Windows run a different program whenever the named one is started. Malware uses it to block antivirus tools or to run itself.' `
                    -Fix "Delete the Debugger value under $($sk.Name) (as admin)." `
                    -Actions @((New-RepairAction -Kind RegDeleteValue -Label "Remove the Debugger hijack for $($sk.PSChildName)" -Risk caution -Params @{ Path = "Registry::$($sk.Name)"; Name = 'Debugger' }))
            }
        }
    }
    foreach ($sk in (Get-ChildItem -LiteralPath "$machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" -ErrorAction SilentlyContinue)) {
        $mon = $sk.GetValue('MonitorProcess')
        if ($mon) {
            $adv += [pscustomobject]@{ Point = "SilentProcessExit for $($sk.PSChildName)"; Location = $sk.Name; Value = $mon; Concern = 'Runs a program whenever this one exits'; _Flag = 'high' }
            Add-Finding -Severity High -Category 'Persistence' -Section $S -Title "Hidden launch trigger on $($sk.PSChildName) exit" -Detail "MonitorProcess = $mon" -Fix "Delete the key $($sk.Name) (as admin)." `
                -Actions @((New-RepairAction -Kind RegDeleteKey -Label "Delete the SilentProcessExit key for $($sk.PSChildName)" -Risk caution -Params @{ Path = "Registry::$($sk.Name)" }))
        }
    }

    $lsa = "$machine\SYSTEM\CurrentControlSet\Control\Lsa"
    $okPkgs = @('msv1_0', 'scecli', 'rassfm', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'msoidssp', 'wsauth', '""', '')
    foreach ($n in 'Authentication Packages', 'Notification Packages', 'Security Packages') {
        foreach ($pkg in @(Get-RegValue $lsa $n)) {
            $pk = ([string]$pkg).Trim()
            if ($okPkgs -contains $pk.ToLowerInvariant()) { continue }
            $dll = "$env:SystemRoot\System32\$pk.dll"
            $sig = Get-FileSig $dll
            if ($sig.IsMicrosoft) { continue }
            $adv += [pscustomobject]@{ Point = "LSA $n"; Location = $lsa; Value = $pk; Concern = "Non-Microsoft package loaded into LSASS ($($sig.Status) $($sig.Signer))"; _Flag = 'high' }
            Add-Finding -Severity High -Category 'Persistence' -Section $S -Title "Unknown DLL loaded into the Windows login process (LSA $n)" -Detail "$pk ($($sig.Status) $($sig.Signer))" `
                -Why 'DLLs registered here see every password typed at login. Password stealers use this.' -Fix "Unless it belongs to known security software, remove '$pk' from $n under $lsa (as admin) and investigate."
        }
    }

    foreach ($sk in (Get-ChildItem -LiteralPath "$machine\SOFTWARE\Microsoft\Active Setup\Installed Components" -ErrorAction SilentlyContinue)) {
        $stub = $sk.GetValue('StubPath')
        if (-not $stub) { continue }
        $r = New-AutoRow -Type 'Active Setup' -Location $sk.Name -Name ([string]$sk.GetValue('')) -Command ([string]$stub) -Quiet -Fix "Delete the key $($sk.Name) (as admin) after uninstalling its program." `
            -Remove @((New-RepairAction -Kind RegDeleteKey -Label "Delete Active Setup entry $($sk.PSChildName)" -Risk caution -Params @{ Path = "Registry::$($sk.Name)" }))
        if ($r._Risk.IsMicrosoft) { continue }
        if ($r._Sev -and $r._Sev -ne 'Low') { $runRows += $r; Submit-PersistenceFindings -Rows @($r) -What 'Active Setup' }
        $adv += [pscustomobject]@{ Point = 'Active Setup'; Location = $sk.PSChildName; Value = $stub; Concern = $r.Concerns; _Flag = $r._Flag }
    }
    foreach ($sk in (Get-ChildItem -LiteralPath "$machine\SYSTEM\CurrentControlSet\Control\Print\Monitors" -ErrorAction SilentlyContinue)) {
        $drv = $sk.GetValue('Driver')
        if (-not $drv) { continue }
        $path = if ($drv -match '\\') { $drv } else { "$env:SystemRoot\System32\$drv" }
        $sig = Get-FileSig $path
        if ($sig.IsMicrosoft -or $sig.Trusted) { continue }
        $adv += [pscustomobject]@{ Point = 'Print monitor'; Location = $sk.Name; Value = $drv; Concern = "Unsigned DLL loaded by the print spooler ($($sig.Status))"; _Flag = 'medium' }
        Add-Finding -Severity Medium -Category 'Persistence' -Section $S -Title "Unsigned print monitor DLL: $drv" -Fix 'Check which printer software installed it; remove if unknown.'
    }
    Add-Table -Section $S -Title 'Advanced hijack points (Winlogon, IFEO, AppInit, LSA, Active Setup, print monitors)' -Rows $adv -Empty 'Nothing unusual. Good.'
    if (@($adv | Where-Object { $_._Flag -eq 'high' }).Count -eq 0) { Add-Pass 'Persistence' 'No Winlogon / IFEO / AppInit / LSA hijacks' }

    # ---------------- Scheduled tasks
    $taskRows = @()
    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { Add-Note -Section $S -Text "Could not list scheduled tasks: $($_.Exception.Message)" -Tone warn }
    foreach ($t in $tasks) {
        $isMs = $t.TaskPath -like '\Microsoft\*'
        $full = $t.TaskPath + $t.TaskName
        foreach ($a in @($t.Actions)) {
            if (-not $a) { continue }
            $cls = $a.CimClass.CimClassName
            $cmd = $null
            if ($cls -eq 'MSFT_TaskExecAction') {
                $exe = ([string]$a.Execute).Trim()
                $arg = [string]$a.Arguments
                if (-not $exe) { continue }
                $cmd = if ($exe.StartsWith('"')) { "$exe $arg" } else { "`"$exe`" $arg" }
            } elseif ($cls -eq 'MSFT_TaskComHandlerAction') {
                if ($isMs) { continue }
                $dll = Get-RegValue "Registry::HKEY_CLASSES_ROOT\CLSID\$($a.ClassId)\InprocServer32" ''
                if (-not $dll) { continue }
                $cmd = '"' + [Environment]::ExpandEnvironmentVariables([string]$dll) + '"'
            } else { continue }
            $hiddenTask = $false
            try { $hiddenTask = [bool]$t.Settings.Hidden } catch {}
            $trig = @($t.Triggers | Where-Object { $_ } | ForEach-Object {
                    $n = ($_.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', '')
                    if (-not $n) { $n = 'Event' }
                    if ($_.Repetition -and $_.Repetition.Interval) { $n += " (repeat $($_.Repetition.Interval))" }
                    $n }) -join ', '
            $fix = "Open Task Scheduler (taskschd.msc), find '$full', Disable then Delete it - or as admin: schtasks /Delete /TN `"$full`" /F. Then uninstall the program it belongs to."
            $row = New-AutoRow -Type 'Scheduled task' -Location $t.TaskPath -Name $t.TaskName -Command $cmd -State ([string]$t.State) -Fix $fix -Quiet:$isMs `
                -Extra "Author: $($t.Author); Runs as: $($t.Principal.UserId) $($t.Principal.RunLevel); Triggers: $trig$(if ($hiddenTask) { '; HIDDEN' })" `
                -Remove @((New-RepairAction -Kind TaskDelete -Label "Delete scheduled task $full" -Risk caution -Params @{ Task = $t.TaskName; TaskPath = $t.TaskPath }))
            if ($isMs) {
                if ($row._Risk.IsMicrosoft) { continue }
                if (-not $row._Sev -or $row._Sev -eq 'Low') { continue }
                $row.Concerns = 'Non-Microsoft program hiding in the \Microsoft\ task folder; ' + $row.Concerns
                $row._Sev = Get-MaxSeverity @($row._Sev, 'High'); $row._Flag = ConvertTo-FlagClass $row._Sev
            } elseif ($hiddenTask -and -not $row._Risk.Trusted) {
                $row.Concerns = (@($row.Concerns, 'Hidden task') | Where-Object { $_ }) -join '; '
                $row._Sev = Get-MaxSeverity @($row._Sev, 'Medium'); $row._Flag = ConvertTo-FlagClass $row._Sev
            }
            $reg = $null
            if ($t.Date) { $tmp = [datetime]::MinValue; if ([datetime]::TryParse([string]$t.Date, [ref]$tmp)) { $reg = $tmp } }
            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch {}
            $row | Add-Member -NotePropertyName Created -NotePropertyValue $reg
            $row | Add-Member -NotePropertyName 'Last run' -NotePropertyValue $(if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { $info.LastRunTime } else { $null })
            $row | Add-Member -NotePropertyName Triggers -NotePropertyValue $trig
            $taskRows += $row
            if ($reg) { Add-TimelineEvent $reg 'Scheduled task created' "$full -> $($row.Target)" $(if ($row._Sev) { $row._Sev } else { 'Info' }) }
            if ($row._Risk.Pup) { $script:Shared.PupHits += , $row._Risk.Pup.Name }
        }
    }
    Add-Table -Section $S -Title 'Scheduled tasks (non-Microsoft, plus anything suspicious)' -Rows $taskRows `
        -Columns @('Name', 'State', 'Concerns', 'Signer', 'Target', 'Command', 'Triggers', 'Created', 'Last run', 'Location', 'Details') `
        -Note "Normal Microsoft tasks are hidden. $($tasks.Count) tasks exist in total."
    Submit-PersistenceFindings -Rows $taskRows -What 'Scheduled task'

    # ---------------- Services
    $svcRows = @()
    $critSvc = @{ 'wscsvc' = 'Security Center'; 'mpssvc' = 'Windows Firewall'; 'BFE' = 'Base Filtering Engine (firewall)'; 'SecurityHealthService' = 'Windows Security'; 'EventLog' = 'Windows Event Log'; 'WdNisSvc' = 'Defender network inspection'; 'Sense' = 'Defender for Endpoint' }
    foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        if ($critSvc.ContainsKey($svc.Name) -and $svc.StartMode -eq 'Disabled' -and $svc.Name -notin 'Sense', 'WdNisSvc') {
            Add-Finding -Severity High -Category 'Security Settings' -Section $S -Title "Security service disabled: $($critSvc[$svc.Name])" -Detail "Service '$($svc.Name)' start type is Disabled." `
                -Why 'Malware and aggressive "tweak" tools switch off security services.' -Fix "As admin: sc.exe config $($svc.Name) start= auto, then restart. If it will not stay on, something keeps disabling it - check the persistence findings." `
                -Actions @((New-RepairAction -Kind ServiceEnable -Label "Re-enable and start '$($critSvc[$svc.Name])'" -Params @{ Service = $svc.Name; StartMode = 'auto' }))
        }
        $cmd = [string]$svc.PathName
        if (-not $cmd) { continue }
        $lt = Resolve-LaunchTarget $cmd
        $evalCmd = $cmd
        if ($lt.Host -match '(?i)\\svchost\.exe$') {
            $dll = Get-RegValue "$machine\SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters" 'ServiceDll'
            if (-not $dll) { $dll = Get-RegValue "$machine\SYSTEM\CurrentControlSet\Services\$($svc.Name)" 'ServiceDll' }
            if ($dll) { $evalCmd = '"' + [Environment]::ExpandEnvironmentVariables([string]$dll) + '"' }
        }
        $fix = "As admin: sc.exe stop `"$($svc.Name)`" then sc.exe config `"$($svc.Name)`" start= disabled. Uninstall the program that owns it; if it is malware with no uninstaller: sc.exe delete `"$($svc.Name)`"."
        $row = New-AutoRow -Type 'Service' -Location "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name "$($svc.DisplayName) ($($svc.Name))" -Command $evalCmd -State "$($svc.StartMode) / $($svc.State)" -Fix $fix -Quiet `
            -Extra "Runs as: $($svc.StartName)" `
            -Remove @((New-RepairAction -Kind ServiceStopDisable -Label "Stop and disable service '$($svc.Name)'" -Risk caution -Params @{ Service = $svc.Name }))
        if ($row._Risk.IsMicrosoft -and -not $row._Sev) { continue }
        if ($cmd -match $script:StrongCmdRx) { $row._Sev = Get-MaxSeverity @($row._Sev, 'High'); $row.Concerns = (@($row.Concerns, 'Suspicious service command') | Where-Object { $_ }) -join '; ' }
        if ($svc.StartMode -ne 'Auto' -and $row._Sev -eq 'Low') { $row._Sev = $null }
        if (-not $cmd.StartsWith('"') -and $cmd -match '^(?i)[a-z]:\\[^"]*\s[^"]*\.exe' -and $cmd -notmatch '^(?i)[a-z]:\\windows\\') {
            $row.Concerns = (@($row.Concerns, 'Unquoted path with spaces (privilege-escalation weakness)') | Where-Object { $_ }) -join '; '
            $row._Sev = Get-MaxSeverity @($row._Sev, 'Low')
        }
        $row._Flag = ConvertTo-FlagClass $row._Sev
        $svcRows += $row
        if ($row._Risk.Pup) { $script:Shared.PupHits += , $row._Risk.Pup.Name }
    }
    Add-Table -Section $S -Title 'Services (non-Microsoft, plus anything suspicious)' -Rows $svcRows -Columns @('Name', 'State', 'Concerns', 'Signer', 'Target', 'Command', 'Details')
    Submit-PersistenceFindings -Rows $svcRows -What 'Service'

    # ---------------- Kernel drivers (running)
    $drvRows = @()
    foreach ($d in @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -ErrorAction SilentlyContinue)) {
        if (-not $d.PathName) { continue }
        $lt = Resolve-LaunchTarget ([string]$d.PathName)
        $sig = Get-FileSig $lt.Target
        if ($sig.IsMicrosoft) { continue }
        $leaf = ''
        try { $leaf = [IO.Path]::GetFileName($lt.Target).ToLowerInvariant() } catch {}
        $zone = Get-PathZone $lt.Target
        $sev = $null; $why = @()
        if (Test-UserWritableZone $zone) { $sev = 'High'; $why += "Driver loaded from $zone" }
        if ($sig.Exists -and -not $sig.Trusted -and -not $sig.Skipped) { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += "Signature: $($sig.Status)" }
        if ($script:VulnDrivers -contains $leaf) { $sev = Get-MaxSeverity @($sev, 'Low'); $why += 'Known-vulnerable driver (abused by malware/cheats)' }
        $pup = Find-Pup @($d.Name, $d.DisplayName, $lt.Target, $sig.Signer)
        if ($pup) { $sev = Get-MaxSeverity @($sev, $pup.Severity); $why += "Known PUP: $($pup.Name)" }
        $drvRows += [pscustomobject]@{ Driver = $d.DisplayName; Name = $d.Name; File = $lt.Target; Signer = $(if ($sig.Trusted) { $sig.Signer } else { "$($sig.Signer) [$($sig.Status)]" }); Concerns = ($why -join '; '); _Flag = (ConvertTo-FlagClass $sev); _Sev = $sev }
        if ($sev -in 'High', 'Medium') {
            Add-Finding -Severity $sev -Category 'Persistence' -Section $S -Title "Suspicious kernel driver: $($d.Name)" -Detail ($why -join '; ') -Evidence @("File: $($lt.Target)", "Signer: $($sig.Signer) [$($sig.Status)]", "SHA256: $(Get-Sha256 $lt.Target)") `
                -Why 'Drivers run with full control of Windows. Rootkits and cheat tools load drivers like this.' -Fix 'Identify the software that installed it (check the vendor/signer). Uninstall it; if unknown, run Microsoft Defender Offline scan.'
        }
    }
    $vul = @($drvRows | Where-Object { $_.Concerns -match 'Known-vulnerable' })
    if ($vul.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Drivers' -Section $S -Title 'A known-vulnerable driver is loaded' -Evidence @($vul | ForEach-Object { "$($_.Name): $($_.File)" }) `
            -Why 'These drivers (usually from RGB, fan-control or overclocking utilities) have security holes that malware can abuse to get kernel access. They also block Memory integrity.' `
            -Fix 'Update or uninstall the utility that installed it (e.g. old MSI Afterburner, RGB/fan tools, hardware monitors).'
    }
    Add-Table -Section $S -Title 'Third-party kernel drivers (running)' -Rows $drvRows -Columns @('Driver', 'Name', 'Concerns', 'Signer', 'File')

    # ---------------- WMI event subscriptions
    try {
        $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
        $filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
        $wmiRows = @()
        foreach ($c in $consumers) {
            $cls = $c.CimClass.CimClassName
            if ($c.Name -in 'SCM Event Log Consumer', 'BVTConsumer' -and $cls -eq 'NTEventLogEventConsumer') { continue }
            $payload = switch ($cls) {
                'CommandLineEventConsumer' { "$($c.ExecutablePath) $($c.CommandLineTemplate)" }
                'ActiveScriptEventConsumer' { if ($c.ScriptFileName) { $c.ScriptFileName } else { Limit-Text $c.ScriptText 300 } }
                default { $cls }
            }
            $bad = $cls -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer'
            $wmiRows += [pscustomobject]@{ Consumer = $c.Name; Type = $cls; Runs = $payload; _Flag = $(if ($bad) { 'high' } else { '' }) }
            if ($bad) {
                Add-Finding -Severity High -Category 'Persistence' -Section $S -Title "WMI event subscription runs code: $($c.Name)" -Detail $payload `
                    -Why 'Fileless malware and miners hide here because it does not show up in Task Manager or normal startup lists.' `
                    -Fix "As admin in PowerShell: Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Where-Object Name -eq '$($c.Name)' | Remove-CimInstance ; then remove the matching __EventFilter and __FilterToConsumerBinding." `
                    -Actions @((New-RepairAction -Kind WmiRemove -Label "Remove WMI subscription '$($c.Name)' and its filter(s)" -Risk caution -Params @{ Consumer = $c.Name }))
            }
        }
        foreach ($f in $filters) {
            if ($f.Name -in 'SCM Event Log Filter', 'BVTFilter') { continue }
            $wmiRows += [pscustomobject]@{ Consumer = "(filter) $($f.Name)"; Type = '__EventFilter'; Runs = $f.Query; _Flag = '' }
        }
        Add-Table -Section $S -Title 'WMI event subscriptions' -Rows $wmiRows -Empty 'None (only the Windows defaults). Good.'
        if (@($wmiRows | Where-Object { $_._Flag -eq 'high' }).Count -eq 0) { Add-Pass 'Persistence' 'No WMI persistence' }
    } catch {
        Add-Note -Section $S -Text 'WMI subscriptions could not be checked (administrator rights needed).' -Tone warn
    }

    if (@($runRows + $taskRows + $svcRows | Where-Object { $_._Sev -in 'Critical', 'High', 'Medium' }).Count -eq 0) {
        Add-Pass 'Persistence' 'No suspicious startup programs, tasks or services' "$($runRows.Count) startup entries, $($taskRows.Count) third-party tasks, $($svcRows.Count) third-party services checked"
    }
}
