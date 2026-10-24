# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Windows Update: history, failures, services, policies, pause state, pending reboot, pending updates (background search)

function Get-PendingRebootReasons {
    $r = @()
    if (Test-RegKey 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $r += 'Windows component servicing' }
    if (Test-RegKey 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $r += 'Windows Update' }
    $cn = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
    $cnPending = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
    if ($cn -and $cnPending -and $cn -ne $cnPending) { $r += 'Computer rename' }
    $r
}

function Start-PendingUpdateSearch {
    try {
        $script:WUJob = Start-Job -ScriptBlock {
            $s = New-Object -ComObject Microsoft.Update.Session
            $s.ClientApplicationID = 'PC Health Scan'
            $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
            $out = @()
            for ($i = 0; $i -lt $r.Updates.Count; $i++) {
                $u = $r.Updates.Item($i)
                $kb = @(); for ($k = 0; $k -lt $u.KBArticleIDs.Count; $k++) { $kb += 'KB' + $u.KBArticleIDs.Item($k) }
                $out += [pscustomobject]@{ Title = $u.Title; KB = ($kb -join ', '); Severity = [string]$u.MsrcSeverity; Downloaded = [bool]$u.IsDownloaded; SizeMB = [int]($u.MaxDownloadSize / 1MB) }
            }
            $out
        }
        $script:WUJobStarted = Get-Date
    } catch { $script:WUJob = $null }
}

function Complete-PendingUpdateSearch {
    param([int]$TimeoutSec = 120)
    $S = 'updates'
    if (-not $script:WUJob) { return }
    $remaining = [Math]::Max(5, $TimeoutSec - [int]((Get-Date) - $script:WUJobStarted).TotalSeconds)
    Write-Status "Waiting up to $remaining s for the Windows Update search..."
    $done = Wait-Job $script:WUJob -Timeout $remaining
    if (-not $done) {
        Add-Note -Section $S -Text 'The online check for missing updates did not finish in time (slow connection or Windows Update service problem).' -Tone warn
        Remove-Job $script:WUJob -Force -ErrorAction SilentlyContinue
        return
    }
    $pending = @()
    $err = $null
    try { $pending = @(Receive-Job $script:WUJob -ErrorAction Stop | Select-Object Title, KB, Severity, Downloaded, SizeMB) } catch { $err = $_.Exception.Message }
    Remove-Job $script:WUJob -Force -ErrorAction SilentlyContinue
    if ($err) { Add-Note -Section $S -Text "Online update check failed: $err" -Tone warn; return }
    foreach ($p in $pending) {
        $flag = if ($p.Severity -eq 'Critical') { 'high' } elseif ($p.Severity -eq 'Important') { 'medium' } else { '' }
        $p | Add-Member -NotePropertyName _Flag -NotePropertyValue $flag
    }
    Add-Table -Section $S -Title 'Updates available but not installed' -Rows $pending -Empty 'Windows Update reports nothing pending.'
    $sec = @($pending | Where-Object { $_.Severity -in 'Critical', 'Important' -or $_.Title -match 'Cumulative Update|Security' })
    if ($sec.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Updates' -Section $S -Title "$($sec.Count) security/cumulative update(s) waiting to install" `
            -Evidence @($sec | ForEach-Object { $_.Title }) -Fix 'Settings > Windows Update > Download & install, then restart.' `
            -Actions @((New-RepairAction -Kind Run -Label 'Tell Windows Update to scan and start downloading' -Params @{ Command = 'wu-scan' }),
                (New-RepairAction -Kind Open -Label 'Open Windows Update to install and restart' -Risk guided -Params @{ Uri = 'ms-settings:windowsupdate' }))
    } elseif ($pending.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Updates' -Section $S -Title "$($pending.Count) optional update(s) available" -Evidence @($pending | ForEach-Object { $_.Title })
    } else { Add-Pass 'Updates' 'No missing updates reported by Windows Update' }
}

function Invoke-UpdatesScan {
    $S = 'updates'
    Start-PendingUpdateSearch

    # --- history
    $hist = @()
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $searcher = $sess.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $coll = $searcher.QueryHistory(0, [Math]::Min($total, 400))
            for ($i = 0; $i -lt $coll.Count; $i++) {
                $h = $coll.Item($i)
                if (-not $h.Title) { continue }
                $res = switch ([int]$h.ResultCode) { 1 { 'In progress' } 2 { 'Succeeded' } 3 { 'Succeeded with errors' } 4 { 'FAILED' } 5 { 'Aborted' } default { 'Unknown' } }
                $hist += [pscustomobject]@{ Date = ([datetime]$h.Date).ToLocalTime(); Title = $h.Title; Result = $res; Code = ('0x{0:X8}' -f $h.HResult); Operation = $(if ($h.Operation -eq 2) { 'Uninstall' } else { 'Install' }) }
            }
        }
    } catch { Add-Note -Section $S -Text "Could not read Windows Update history: $($_.Exception.Message)" -Tone warn }

    $nonDef = @($hist | Where-Object { $_.Title -notmatch 'Security Intelligence|Defender Antivirus|antimalware|Malicious Software Removal' })
    $lastCU = $nonDef | Where-Object { $_.Result -like 'Succeeded*' -and $_.Title -match 'Cumulative Update' } | Sort-Object Date -Descending | Select-Object -First 1
    $lastAny = $nonDef | Where-Object { $_.Result -like 'Succeeded*' } | Sort-Object Date -Descending | Select-Object -First 1
    if (-not $lastAny) {
        try {
            $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
            if ($hf) { $lastAny = [pscustomobject]@{ Date = $hf.InstalledOn; Title = "$($hf.HotFixID) ($($hf.Description))" } }
        } catch {}
    }
    $ref = if ($lastCU) { $lastCU } else { $lastAny }
    if ($ref) {
        $age = [int]((Get-Date) - $ref.Date).TotalDays
        $what = if ($lastCU) { 'cumulative (security) update' } else { 'Windows update' }
        if ($age -gt 60) {
            Add-Finding -Severity High -Category 'Updates' -Section $S -Title "Last $what was installed $age days ago" `
                -Detail "$($ref.Title) on $($ref.Date.ToString('yyyy-MM-dd'))." `
                -Why 'Microsoft ships security fixes every month. This PC has missed at least two months of them.' `
                -Fix 'Settings > Windows Update > Check for updates. If it errors, run the Windows Update troubleshooter (Settings > System > Troubleshoot > Other troubleshooters).'
        } elseif ($age -gt 40) {
            Add-Finding -Severity Medium -Category 'Updates' -Section $S -Title "Last $what was installed $age days ago" -Detail "$($ref.Title)" -Fix 'Settings > Windows Update > Check for updates.'
        } else { Add-Pass 'Updates' 'Windows updates are recent' "Last $what $age day(s) ago" }
    } else {
        Add-Finding -Severity Medium -Category 'Updates' -Section $S -Title 'Could not determine when Windows was last updated' -Fix 'Open Settings > Windows Update and check the update history manually.'
    }

    $fails = @($nonDef | Where-Object { $_.Result -eq 'FAILED' -and $_.Date -ge $script:Cutoff })
    if ($fails.Count -gt 0) {
        $grp = @($fails | Group-Object Title | Sort-Object Count -Descending)
        $sev = if (@($grp | Where-Object { $_.Count -ge 3 }).Count -gt 0) { 'Medium' } else { 'Low' }
        Add-Finding -Severity $sev -Category 'Updates' -Section $S -Title "$($fails.Count) failed update install(s) in the last $($script:Days) days" `
            -Evidence @($grp | ForEach-Object { "$($_.Count)x $($_.Name) [$(($_.Group | Select-Object -First 1).Code)]" }) `
            -Why 'Repeated failures usually mean a corrupted update cache or component store.' `
            -Fix 'Run the Windows Update troubleshooter; if it keeps failing, run (as admin) DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow, and restart.' `
            -Actions @((New-RepairAction -Kind Run -Label 'Reset the Windows Update cache (SoftwareDistribution + catroot2)' -Risk caution -Params @{ Command = 'wu-reset' }),
                (New-RepairAction -Kind Run -Label 'Repair the Windows component store (DISM /RestoreHealth, 10-30 min)' -Params @{ Command = 'dism-restorehealth' }),
                (New-RepairAction -Kind Run -Label 'Scan for updates again' -Params @{ Command = 'wu-scan' }))
    }
    foreach ($h in ($hist | Where-Object { $_.Date -ge $script:Cutoff -and $_.Title -notmatch 'Security Intelligence' })) {
        Add-TimelineEvent $h.Date 'Windows Update' "$($h.Result): $($h.Title)" $(if ($h.Result -eq 'FAILED') { 'Low' } else { 'Info' })
    }
    $rowsH = @($hist | Sort-Object Date -Descending | Select-Object -First 80 | ForEach-Object {
            $_ | Add-Member -NotePropertyName _Flag -NotePropertyValue $(if ($_.Result -eq 'FAILED') { 'medium' } else { '' }) -PassThru })
    Add-Table -Section $S -Title 'Recent update history (latest 80)' -Rows $rowsH

    # --- services
    $srow = @()
    foreach ($n in @('wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'BITS', 'CryptSvc', 'TrustedInstaller')) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $bad = $svc.StartMode -eq 'Disabled'
        $srow += [pscustomobject]@{ Service = $svc.DisplayName; Name = $n; 'Start type' = $svc.StartMode; State = $svc.State; _Flag = $(if ($bad) { 'high' } else { '' }) }
        if ($bad) {
            Add-Finding -Severity $(if ($n -in 'wuauserv', 'UsoSvc', 'BITS') { 'High' } else { 'Medium' }) -Category 'Updates' -Section $S -Title "Windows Update service '$($svc.DisplayName)' is disabled" `
                -Why 'Something (a "debloater", update blocker, or malware) has switched off part of Windows Update, so security fixes cannot install.' `
                -Fix "Run as admin: sc.exe config $n start= demand (or reset with the Windows Update troubleshooter), then restart and check for updates." `
                -Actions @((New-RepairAction -Kind ServiceEnable -Label "Re-enable the '$($svc.DisplayName)' service" -Params @{ Service = $n; StartMode = $(if ($n -in 'wuauserv', 'BITS') { 'demand' } else { 'auto' }) }))
        }
    }
    Add-Table -Section $S -Title 'Update-related services' -Rows $srow

    # --- policies / pause
    $au = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $polRows = @()
    foreach ($v in (@(Get-RegValues $au) + @(Get-RegValues "$au\AU"))) { $polRows += [pscustomobject]@{ Policy = $v.Name; Value = [string]$v.Value } }
    Add-Table -Section $S -Title 'Windows Update policies' -Rows $polRows -Empty 'No update policies set (normal for a home PC).'
    if ((Get-RegValue "$au\AU" 'NoAutoUpdate') -eq 1) {
        Add-Finding -Severity Medium -Category 'Updates' -Section $S -Title 'Automatic updates are disabled by policy' -Fix 'Delete NoAutoUpdate under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU.' `
            -Actions @((New-RepairAction -Kind RegDeleteValue -Label 'Remove the NoAutoUpdate policy' -Params @{ Path = "$au\AU"; Name = 'NoAutoUpdate' }))
    }
    if ((Get-RegValue $au 'DisableWindowsUpdateAccess') -eq 1 -or (Get-RegValue $au 'SetDisableUXWUAccess') -eq 1) {
        Add-Finding -Severity High -Category 'Updates' -Section $S -Title 'Access to Windows Update is blocked by policy' -Fix 'Delete DisableWindowsUpdateAccess / SetDisableUXWUAccess under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate.' `
            -Actions @((New-RepairAction -Kind RegDeleteValue -Label 'Remove DisableWindowsUpdateAccess' -Params @{ Path = $au; Name = 'DisableWindowsUpdateAccess' }),
                (New-RepairAction -Kind RegDeleteValue -Label 'Remove SetDisableUXWUAccess' -Params @{ Path = $au; Name = 'SetDisableUXWUAccess' }))
    }
    $wsus = Get-RegValue $au 'WUServer'
    if ($wsus -and -not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Add-Finding -Severity Medium -Category 'Updates' -Section $S -Title 'Updates are redirected to a private update server' -Detail "WUServer = $wsus" `
            -Why 'Home PCs should get updates straight from Microsoft. A redirect means updates may never arrive.' -Fix 'Delete the WUServer/WUStatusServer values and UseWUServer under ...\WindowsUpdate\AU.' `
            -Actions @((New-RepairAction -Kind RegDeleteValue -Label 'Remove WUServer' -Risk caution -Params @{ Path = $au; Name = 'WUServer' }),
                (New-RepairAction -Kind RegDeleteValue -Label 'Remove WUStatusServer' -Risk caution -Params @{ Path = $au; Name = 'WUStatusServer' }),
                (New-RepairAction -Kind RegDeleteValue -Label 'Remove UseWUServer' -Risk caution -Params @{ Path = "$au\AU"; Name = 'UseWUServer' }),
                (New-RepairAction -Kind ServiceEnable -Label 'Restart Windows Update service' -Params @{ Service = 'wuauserv'; StartMode = 'demand' }))
    }
    $pause = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime'
    if ($pause) {
        try {
            $pd = [datetime]::Parse($pause, [Globalization.CultureInfo]::InvariantCulture)
            if ($pd -gt (Get-Date)) {
                $ux = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
                Add-Finding -Severity Medium -Category 'Updates' -Section $S -Title "Windows updates are paused until $($pd.ToString('yyyy-MM-dd'))" -Fix 'Settings > Windows Update > Resume updates.' `
                    -Actions @(@('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime', 'PauseUpdatesStartTime') | ForEach-Object { New-RepairAction -Kind RegDeleteValue -Label "Clear pause marker $_" -Params @{ Path = $ux; Name = $_ } }) + @((New-RepairAction -Kind Run -Label 'Scan for updates' -Params @{ Command = 'wu-scan' }))
            }
        } catch {}
    }

    # --- pending reboot
    $pr = @(Get-PendingRebootReasons)
    $script:Shared.PendingReboot = $pr
    if ($pr.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Updates' -Section $S -Title 'A restart is pending to finish installing updates' -Detail ($pr -join ', ') -Fix 'Restart the PC.'
    }
}
