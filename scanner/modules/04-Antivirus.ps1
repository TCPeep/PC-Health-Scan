# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Antivirus: Security Center products, Microsoft Defender health, policies, exclusions, threat history

$script:MpCategory = @{ 1 = 'Adware'; 2 = 'Spyware'; 3 = 'Password stealer'; 4 = 'Trojan downloader'; 5 = 'Worm'; 6 = 'Backdoor'; 7 = 'Remote access trojan';
    8 = 'Trojan'; 10 = 'Keylogger'; 12 = 'Monitoring software'; 13 = 'Browser modifier'; 18 = 'Security disabler'; 21 = 'Software bundler'; 23 = 'Settings modifier';
    24 = 'Toolbar'; 25 = 'Remote control software'; 27 = 'Potentially unwanted app'; 30 = 'Exploit'; 32 = 'Malware creation tool'; 33 = 'Remote control software';
    34 = 'Hack tool'; 37 = 'Trojan dropper'; 40 = 'Trojan proxy'; 42 = 'Virus'; 46 = 'Suspicious behavior'; 48 = 'Policy'; 49 = 'Unwanted software'; 50 = 'Ransomware' }
$script:MpStatus = @{ 0 = 'Unknown'; 1 = 'Detected'; 2 = 'Cleaned'; 3 = 'Quarantined'; 4 = 'Removed'; 5 = 'Allowed by user'; 6 = 'Blocked'; 102 = 'Quarantine FAILED';
    103 = 'Remove FAILED'; 104 = 'Allow failed'; 105 = 'Abandoned'; 107 = 'Block FAILED' }

function Invoke-AntivirusScan {
    $S = 'antivirus'

    # --- products registered with Windows Security Center
    $avRows = @(); $thirdOn = @(); $thirdBad = @()
    try {
        foreach ($a in (Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)) {
            $h = '{0:X6}' -f [int]$a.productState
            $on = $h.Substring(2, 2) -in '10', '11'
            $current = $h.Substring(4, 2) -eq '00'
            $isDef = $a.displayName -match 'Defender'
            $flag = ''
            if (-not $isDef) {
                if ($on -and $current) { $thirdOn += $a.displayName }
                else { $thirdBad += $a.displayName; $flag = 'high' }
            }
            $avRows += [pscustomobject]@{ Product = $a.displayName; 'Real-time protection' = $(if ($on) { 'On' } else { 'Off' }); Definitions = $(if ($current) { 'Up to date' } else { 'OUT OF DATE' }); Executable = $a.pathToSignedProductExe; _Flag = $flag }
        }
    } catch {}
    Add-Table -Section $S -Title 'Antivirus products registered with Windows Security' -Rows $avRows

    # --- Defender
    $mp = $null; $pref = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
    try { $pref = Get-MpPreference -ErrorAction Stop } catch {}
    $defActive = $false
    if ($mp) {
        $defActive = [bool]$mp.RealTimeProtectionEnabled -and ([string]$mp.AMRunningMode -in 'Normal', '')
        $kv = [ordered]@{
            'Running mode'                = [string]$mp.AMRunningMode
            'Real-time protection'        = [bool]$mp.RealTimeProtectionEnabled
            'Behavior monitoring'         = [bool]$mp.BehaviorMonitorEnabled
            'Download/attachment scanning' = [bool]$mp.IoavProtectionEnabled
            'Tamper protection'           = [bool]$mp.IsTamperProtected
            'Definitions last updated'    = $mp.AntivirusSignatureLastUpdated
            'Definitions age (days)'      = $mp.AntivirusSignatureAge
            'Last quick scan'             = $mp.QuickScanEndTime
            'Last full scan'              = $mp.FullScanEndTime
            'Engine / platform'           = "$($mp.AMEngineVersion) / $($mp.AMProductVersion)"
        }
        if ($mp.PSObject.Properties['SmartAppControlState']) { $kv['Smart App Control'] = [string]$mp.SmartAppControlState }
        if ($pref) {
            $kv['PUA (unwanted app) blocking'] = switch ([int]$pref.PUAProtection) { 1 { 'On' } 2 { 'Audit only' } default { 'OFF' } }
            $kv['Cloud protection'] = switch ([int]$pref.MAPSReporting) { 0 { 'OFF' } 1 { 'Basic' } 2 { 'Advanced' } default { [string]$pref.MAPSReporting } }
            $kv['Automatic sample submission'] = switch ([int]$pref.SubmitSamplesConsent) { 0 { 'Always prompt' } 1 { 'Send safe samples' } 2 { 'Never send' } 3 { 'Send all' } default { '' } }
            $kv['Network protection'] = switch ([int]$pref.EnableNetworkProtection) { 1 { 'On' } 2 { 'Audit' } default { 'Off' } }
            $kv['Controlled folder access (ransomware)'] = switch ([int]$pref.EnableControlledFolderAccess) { 1 { 'On' } 2 { 'Audit' } default { 'Off' } }
        }
        Add-KV -Section $S -Title 'Microsoft Defender status' -Data $kv
    } else {
        Add-Note -Section $S -Text 'Microsoft Defender status could not be read (Defender may be disabled or replaced by another antivirus).' -Tone warn
    }

    if (-not $defActive -and $thirdOn.Count -eq 0) {
        Add-Finding -Severity Critical -Category 'Antivirus' -Section $S -Title 'No antivirus is actively protecting this PC' `
            -Detail $(if ($thirdBad) { 'Registered but off/out of date: ' + ($thirdBad -join ', ') } else { 'Defender real-time protection is off and no other antivirus is active.' }) `
            -Why 'Nothing is scanning downloads or running programs.' `
            -Fix 'If a third-party antivirus trial has expired, uninstall it (Settings > Apps) so Microsoft Defender switches back on. Otherwise: Windows Security > Virus & threat protection > turn Real-time protection on.'
    } elseif ($thirdBad.Count -gt 0) {
        $sev = if ($defActive) { 'Medium' } else { 'High' }
        Add-Finding -Severity $sev -Category 'Antivirus' -Section $S -Title "Antivirus that is turned off or out of date: $($thirdBad -join ', ')" `
            -Why 'Expired antivirus trials (McAfee/Norton etc. that came with the PC) stop updating but can keep Microsoft Defender in the background. They also nag with scary pop-ups.' `
            -Fix 'Uninstall it from Settings > Apps (use the vendor removal tool if it fights back). Microsoft Defender takes over automatically.' `
            -Actions @((New-RepairAction -Kind Open -Label 'Open Installed apps to uninstall the expired antivirus' -Risk guided -Params @{ Uri = 'ms-settings:appsfeatures' }))
    } else {
        Add-Pass 'Antivirus' 'Antivirus protection is active' $(if ($thirdOn) { $thirdOn -join ', ' } else { 'Microsoft Defender' })
    }
    if ($thirdOn.Count -gt 1) {
        Add-Finding -Severity Low -Category 'Antivirus' -Section $S -Title 'More than one third-party antivirus is active' -Detail ($thirdOn -join ', ') `
            -Why 'Multiple real-time scanners slow the PC down and can conflict.' -Fix 'Keep one and uninstall the rest.'
    }

    if ($mp -and $defActive) {
        $age = [int]$mp.AntivirusSignatureAge
        if ($age -gt 30) {
            Add-Finding -Severity High -Category 'Antivirus' -Section $S -Title "Defender definitions are $age days old" `
                -Why 'Old definitions miss new threats.' -Fix 'Windows Security > Virus & threat protection > Protection updates > Check for updates. If it fails, Windows Update may be broken (see the Updates section).' `
                -Actions @((New-RepairAction -Kind Run -Label 'Update Defender definitions now' -Params @{ Command = 'defender-update' }))
        } elseif ($age -gt 7) {
            Add-Finding -Severity Medium -Category 'Antivirus' -Section $S -Title "Defender definitions are $age days old" -Fix 'Windows Security > Virus & threat protection > Protection updates > Check for updates.' `
                -Actions @((New-RepairAction -Kind Run -Label 'Update Defender definitions now' -Params @{ Command = 'defender-update' }))
        } else { Add-Pass 'Antivirus' 'Defender definitions are current' "$age day(s) old" }
        if (-not $mp.IsTamperProtected) {
            Add-Finding -Severity Medium -Category 'Antivirus' -Section $S -Title 'Defender Tamper Protection is off' `
                -Why 'Without it, malware (or a "debloat" script) can silently switch Defender off or add exclusions.' `
                -Fix 'Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On.' `
                -Actions @((New-RepairAction -Kind Open -Label 'Open Virus & threat protection settings (Tamper Protection can only be switched on there)' -Risk guided -Params @{ Uri = 'windowsdefender://threatsettings' }))
        } else { Add-Pass 'Antivirus' 'Tamper Protection is on' }
        if ($pref -and [int]$pref.PUAProtection -ne 1) {
            Add-Finding -Severity Medium -Category 'Antivirus' -Section $S -Title 'Potentially-unwanted-app (PUA) blocking is off' `
                -Why 'This is the setting that blocks adware like PC App Store, OneLaunch and bundled "optimizers" before they install.' `
                -Fix 'Windows Security > App & browser control > Reputation-based protection settings > Potentially unwanted app blocking: On (tick both Block apps and Block downloads). Or as admin: Set-MpPreference -PUAProtection Enabled' `
                -Actions @((New-RepairAction -Kind MpPreference -Label 'Turn on blocking of potentially unwanted apps (adware)' -Params @{ Setting = 'PUAProtection'; Value = 'Enabled' }))
        } elseif ($pref) { Add-Pass 'Antivirus' 'PUA (adware) blocking is on' }
        if ($pref -and [int]$pref.MAPSReporting -eq 0) {
            Add-Finding -Severity Medium -Category 'Antivirus' -Section $S -Title 'Defender cloud-delivered protection is off' `
                -Why 'Cloud protection catches brand-new threats within seconds.' -Fix 'Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection: On.' `
                -Actions @((New-RepairAction -Kind MpPreference -Label 'Turn cloud-delivered protection on' -Params @{ Setting = 'MAPSReporting'; Value = 'Advanced' }))
        }
        if ($mp.QuickScanAge -gt 30 -and $mp.QuickScanAge -lt 100000) {
            Add-Finding -Severity Low -Category 'Antivirus' -Section $S -Title "No Defender scan in $($mp.QuickScanAge) days" -Fix 'Run a Quick scan (or re-run this tool in Deep mode, which does it for you).' `
                -Actions @((New-RepairAction -Kind Run -Label 'Run a Defender quick scan (a few minutes)' -Params @{ Command = 'defender-quickscan' }))
        }
    }

    # --- Defender disabled by policy (classic malware / "debloater" trick)
    $dp = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
    $polHits = @()
    foreach ($pair in @(@($dp, 'DisableAntiSpyware'), @($dp, 'DisableAntiVirus'), @("$dp\Real-Time Protection", 'DisableRealtimeMonitoring'),
            @("$dp\Real-Time Protection", 'DisableBehaviorMonitoring'), @("$dp\Real-Time Protection", 'DisableOnAccessProtection'),
            @("$dp\Real-Time Protection", 'DisableIOAVProtection'), @("$dp\Real-Time Protection", 'DisableScanOnRealtimeEnable'), @("$dp\Spynet", 'SpynetReporting'))) {
        $v = Get-RegValue $pair[0] $pair[1]
        if ($null -eq $v) { continue }
        if (($pair[1] -eq 'SpynetReporting' -and $v -eq 0) -or ($pair[1] -ne 'SpynetReporting' -and $v -eq 1)) { $polHits += "$($pair[1]) = $v" }
    }
    $svc = Get-CimInstance Win32_Service -Filter "Name='WinDefend'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartMode -eq 'Disabled') { $polHits += 'WinDefend service is Disabled' }
    if ($polHits.Count -gt 0) {
        Add-Finding -Severity Critical -Category 'Antivirus' -Section $S -Title 'Microsoft Defender has been disabled through policy/registry' `
            -Evidence $polHits -Why 'Malware and piracy activators turn Defender off this way so they are not detected. On a home PC there is no good reason for these policies.' `
            -Fix 'Delete the listed values under HKLM\SOFTWARE\Policies\Microsoft\Windows Defender (or the whole key), restart, then run a Defender full scan.' `
            -Actions @((New-RepairAction -Kind DefenderPolicyReset -Label 'Remove the policies that disable Defender and re-enable its service' -Reboot),
                (New-RepairAction -Kind Run -Label 'Update definitions' -Params @{ Command = 'defender-update' }),
                (New-RepairAction -Kind Run -Label 'Run a Defender quick scan' -Params @{ Command = 'defender-quickscan' }))
    }

    # --- Exclusions (admin needed on modern Defender)
    $exRows = @()
    $needAdmin = $false
    if ($pref) {
        foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
            foreach ($e in @($pref.$kind)) {
                if (-not $e) { continue }
                if ([string]$e -match '^N/A') { $needAdmin = $true; continue }
                $exRows += [pscustomobject]@{ Type = $kind -replace 'Exclusion', ''; Value = [string]$e; Source = 'Defender settings' }
            }
        }
    }
    foreach ($kind in 'Paths', 'Processes', 'Extensions') {
        foreach ($v in (Get-RegValues "$dp\Exclusions\$kind")) { $exRows += [pscustomobject]@{ Type = $kind; Value = $v.Name; Source = 'Group Policy' } }
    }
    foreach ($r in $exRows) {
        $z = Get-PathZone $r.Value
        $risky = (Test-UserWritableZone $z) -or $r.Value -match '^[a-zA-Z]:\\?$' -or $r.Value -match '^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr|tmp)$' -or (Find-Pup @($r.Value))
        $r | Add-Member -NotePropertyName _Flag -NotePropertyValue $(if ($risky) { 'high' } else { 'medium' })
    }
    Add-Table -Section $S -Title 'Defender exclusions (files/folders Defender is told to ignore)' -Rows $exRows -Columns @('Type', 'Value', 'Source') `
        -Empty $(if ($needAdmin) { 'Not visible without administrator rights.' } else { 'No exclusions. Good.' })
    if ($exRows.Count -gt 0) {
        $sev = if (@($exRows | Where-Object { $_._Flag -eq 'high' }).Count -gt 0) { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Category 'Antivirus' -Section $S -Title "Defender has $($exRows.Count) exclusion(s)" `
            -Evidence @($exRows | ForEach-Object { "$($_.Type): $($_.Value)" }) `
            -Why 'Malware, cracks and activators add exclusions so Defender never scans them. Legit uses exist (game folders, dev tools), but every entry should be recognised.' `
            -Fix 'Windows Security > Virus & threat protection > Manage settings > Exclusions > remove anything not recognised. Then run a full scan.' `
            -Actions @(@($exRows | Where-Object { $_.Source -eq 'Defender settings' } | ForEach-Object { New-RepairAction -Kind MpRemoveExclusion -Label "Remove exclusion: $($_.Value)" -Risk caution -Params @{ Type = $_.Type; Value = $_.Value } }) +
                @($exRows | Where-Object { $_.Source -eq 'Group Policy' } | ForEach-Object { New-RepairAction -Kind RegDeleteValue -Label "Remove policy exclusion: $($_.Value)" -Risk caution -Params @{ Path = "$dp\Exclusions\$($_.Type)"; Name = $_.Value } }))
    } elseif (-not $needAdmin -and $pref) { Add-Pass 'Antivirus' 'No Defender exclusions' }

    # --- Threat history
    $threats = @{}
    try { foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $threats[[string]$t.ThreatID] = $t } } catch {}
    $det = @()
    try { $det = @(Get-MpThreatDetection -ErrorAction Stop) } catch {}
    $trows = @()
    $activeNames = @(); $ranNames = @(); $recentNames = @{}; $toolNames = @{}
    $malwareRx = 'Trojan|Backdoor|stealer|Worm|Virus|Ransom|Keylogger|Spyware|Exploit|Security disabler|Suspicious behavior|Monitoring'
    foreach ($d in $det) {
        $t = $threats[[string]$d.ThreatID]
        $name = if ($t) { $t.ThreatName } else { "ThreatID $($d.ThreatID)" }
        $cat = if ($t -and $script:MpCategory.ContainsKey([int]$t.CategoryID)) { $script:MpCategory[[int]$t.CategoryID] } elseif ($t) { "Category $($t.CategoryID)" } else { '' }
        $status = if ($script:MpStatus.ContainsKey([int]$d.ThreatStatusID)) { $script:MpStatus[[int]$d.ThreatStatusID] } else { [string]$d.ThreatStatusID }
        $failed = ([int]$d.ThreatStatusID -in 0, 1, 5, 102, 103, 105, 107) -or ($t -and $t.IsActive)
        $res = @($d.Resources | ForEach-Object { ([string]$_) -replace '^[a-z]+:_', '' })
        $isMal = ($cat -match $malwareRx) -or ($name -match '^(Trojan|Backdoor|Ransom|PWS|TrojanDownloader|TrojanDropper|Worm|Virus|Exploit|Behavior|Spyware):')
        $isTool = $name -match '^(HackTool|Hacktool|RemoteAccess|Tool|PUA|PUADlManager|PUAMiner|App):' -or $cat -match 'Hack tool|Remote control|unwanted|Adware|Bundler|Toolbar|Browser modifier|Policy'
        $flag = if ($failed) { 'critical' } elseif ($isMal) { 'high' } elseif ($isTool) { 'medium' } else { 'low' }
        $trows += [pscustomobject]@{ Detected = $d.InitialDetectionTime; Threat = $name; Type = $cat; Result = $status; 'Ran?' = $(if ($t) { [bool]$t.DidThreatExecute } else { '' }); Files = ($res -join ' | '); Process = $d.ProcessName; User = $d.DomainUser; _Flag = $flag }
        if ($failed) { $activeNames += "$name ($status)" }
        elseif ($t -and $t.DidThreatExecute -and $isMal) { $ranNames += $name }
        if ($name -match '^HackTool|GameHack|PUAMiner' -and $d.InitialDetectionTime -ge $script:Cutoff) { $toolNames[$name] = (@($res) | Select-Object -First 1) }
        if ($d.InitialDetectionTime -ge $script:Cutoff) { $recentNames[$name] = $cat }
        Add-TimelineEvent $d.InitialDetectionTime 'Defender detection' "$name ($cat) - $status" $(if ($failed) { 'Critical' } elseif ($flag -eq 'high') { 'High' } else { 'Low' })
    }
    $trows = @($trows | Sort-Object Detected -Descending)
    Add-Table -Section $S -Title 'Defender threat history' -Rows $trows -Note 'Everything Defender has detected that is still in its history (Windows keeps this for a limited time).' `
        -Empty $(if (-not $script:IsAdmin -and $det.Count -eq 0) { 'No history visible (administrator rights may be needed).' } else { 'No detections in history.' })
    if ($activeNames.Count -gt 0) {
        Add-Finding -Severity Critical -Category 'Malware & PUPs' -Section $S -Title 'Defender found threats it could NOT remove' -Evidence ($activeNames | Select-Object -Unique) `
            -Why 'These threats may still be on the PC and active.' `
            -Fix 'Windows Security > Virus & threat protection > Current threats > take action (Remove). Then run Microsoft Defender Offline scan (Scan options > Microsoft Defender Offline scan), which reboots and cleans from outside Windows.' `
            -Actions @((New-RepairAction -Kind Run -Label 'Update definitions' -Params @{ Command = 'defender-update' }),
                (New-RepairAction -Kind Run -Label 'Run a Defender FULL scan (can take 1-2 hours)' -Risk caution -Params @{ Command = 'defender-fullscan' }),
                (New-RepairAction -Kind Open -Label 'Open Protection history to confirm removal' -Risk guided -Params @{ Uri = 'windowsdefender://history' }))
    }
    if ($ranNames.Count -gt 0) {
        Add-Finding -Severity High -Category 'Malware & PUPs' -Section $S -Title 'Malware was detected after it had already run' -Evidence ($ranNames | Select-Object -Unique) `
            -Why 'Defender removed it, but it may have stolen saved passwords/cookies or dropped other files before that.' `
            -Fix 'Change important passwords (email first, from a different device), sign out of all sessions, turn on 2-factor authentication, and review the persistence and browser sections of this report.'
    }
    if ($toolNames.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Malware & PUPs' -Section $S -Title 'Hacking tools / game cheats were detected recently' -Evidence @($toolNames.Keys | ForEach-Object { "$_ - $($toolNames[$_])" }) `
            -Why 'Cheats, cracks and "executors" are one of the most common ways stealers and adware get onto gaming PCs, and people often switch antivirus off to run them.' `
            -Fix 'Confirm what each was. Delete cheat/crack tools and anything downloaded alongside them, then run a Defender full scan.'
    }
    if ($recentNames.Count -gt 0 -and $activeNames.Count -eq 0) {
        Add-Finding -Severity Info -Category 'Malware & PUPs' -Section $S -Title "Defender detected $($recentNames.Count) threat(s) in the last $($script:Days) days (handled)" `
            -Evidence @($recentNames.Keys | ForEach-Object { "$_ ($($recentNames[$_]))" }) -Why 'These were blocked/removed, but they show what has been reaching the PC.'
    }
}
