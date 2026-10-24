# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Event logs: stability (BSOD, shutdowns, crashes, WHEA, disk, GPU), security events, Defender tampering, PowerShell abuse, install history

$script:BugChecks = @{
    '0xA' = @('IRQL_NOT_LESS_OR_EQUAL', 'driver'); '0x1E' = @('KMODE_EXCEPTION_NOT_HANDLED', 'driver'); '0x3B' = @('SYSTEM_SERVICE_EXCEPTION', 'driver')
    '0x50' = @('PAGE_FAULT_IN_NONPAGED_AREA', 'memory'); '0x7E' = @('SYSTEM_THREAD_EXCEPTION_NOT_HANDLED', 'driver'); '0x7F' = @('UNEXPECTED_KERNEL_MODE_TRAP', 'hardware')
    '0x9F' = @('DRIVER_POWER_STATE_FAILURE', 'driver'); '0xD1' = @('DRIVER_IRQL_NOT_LESS_OR_EQUAL', 'driver'); '0xEF' = @('CRITICAL_PROCESS_DIED', 'system')
    '0x101' = @('CLOCK_WATCHDOG_TIMEOUT', 'cpu'); '0x116' = @('VIDEO_TDR_FAILURE', 'gpu'); '0x117' = @('VIDEO_TDR_TIMEOUT_DETECTED', 'gpu')
    '0x119' = @('VIDEO_SCHEDULER_INTERNAL_ERROR', 'gpu'); '0x124' = @('WHEA_UNCORRECTABLE_ERROR', 'hardware'); '0x133' = @('DPC_WATCHDOG_VIOLATION', 'driver')
    '0x139' = @('KERNEL_SECURITY_CHECK_FAILURE', 'driver'); '0x1A' = @('MEMORY_MANAGEMENT', 'memory'); '0xC2' = @('BAD_POOL_CALLER', 'driver')
    '0x19' = @('BAD_POOL_HEADER', 'memory'); '0x7A' = @('KERNEL_DATA_INPAGE_ERROR', 'disk'); '0x77' = @('KERNEL_STACK_INPAGE_ERROR', 'disk')
    '0xF4' = @('CRITICAL_OBJECT_TERMINATION', 'disk'); '0x154' = @('UNEXPECTED_STORE_EXCEPTION', 'disk'); '0x141' = @('VIDEO_ENGINE_TIMEOUT_DETECTED', 'gpu')
    '0xC5' = @('DRIVER_CORRUPTED_EXPOOL', 'driver'); '0xBE' = @('ATTEMPTED_WRITE_TO_READONLY_MEMORY', 'driver'); '0x109' = @('CRITICAL_STRUCTURE_CORRUPTION', 'memory')
    '0x12B' = @('FAULTY_HARDWARE_CORRUPTED_PAGE', 'memory'); '0x144' = @('BUGCODE_USB3_DRIVER', 'driver'); '0xFC' = @('ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY', 'driver')
    '0x4E' = @('PFN_LIST_CORRUPT', 'memory'); '0x24' = @('NTFS_FILE_SYSTEM', 'disk'); '0xED' = @('UNMOUNTABLE_BOOT_VOLUME', 'disk'); '0x7B' = @('INACCESSIBLE_BOOT_DEVICE', 'disk')
    '0x192' = @('KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL', 'driver'); '0x1D5' = @('DRIVER_PNP_WATCHDOG', 'driver'); '0x13A' = @('KERNEL_MODE_HEAP_CORRUPTION', 'driver')
}
$script:BugHints = @{
    driver = 'usually a faulty driver - update chipset, graphics, network and storage drivers, and remove old system utilities'
    memory = 'often faulty RAM or an unstable memory overclock - run Windows Memory Diagnostic (mdsched) or MemTest86'
    gpu = 'graphics driver/GPU problem - clean-install the latest GPU driver; if it continues check GPU temperatures and power'
    hardware = 'hardware error (CPU, RAM, motherboard or power supply) - remove overclocks, update BIOS, check temperatures and the PSU'
    cpu = 'CPU hang - remove overclocks/undervolts and update the BIOS'
    disk = 'storage problem - check the drive health above, run chkdsk, check SATA/NVMe cables and drivers'
    system = 'a core Windows process died - run sfc /scannow and DISM, and check the drive health'
}
$script:LiveKernel = @{ '141' = 'GPU hang (VIDEO_ENGINE_TIMEOUT)'; '117' = 'GPU driver timeout (TDR)'; '1a8' = 'GPU black screen'; '193' = 'Graphics kernel live dump'; '1b0' = 'GPU miniport failure';
    '190' = 'Win32k critical failure (display stack)'; 'a2000002' = 'Graphics/driver live dump (vendor)';
    '15f' = 'Connected-standby watchdog'; '144' = 'USB3 driver problem'; '1a1' = 'Win32k watchdog'; 'ab' = 'Session cleanup'; '1cc' = 'Kernel live dump' }

function Get-BugcheckInfo {
    param([string]$Message)
    $code = $null
    if ($Message -match '0x([0-9a-fA-F]{8})') { $code = '0x{0:X}' -f [Convert]::ToInt64($Matches[1], 16) }
    if (-not $code) { return [pscustomobject]@{ Code = '?'; Name = 'Unknown'; Kind = 'driver' } }
    if ($script:BugChecks.ContainsKey($code)) { return [pscustomobject]@{ Code = $code; Name = $script:BugChecks[$code][0]; Kind = $script:BugChecks[$code][1] } }
    [pscustomobject]@{ Code = $code; Name = 'see learn.microsoft.com bug check reference'; Kind = 'driver' }
}

function Invoke-EventsScan {
    $S = 'stability'
    $since = $script:Cutoff
    $lookbackDays = $script:Days

    # ---------------- blue screens
    $bs = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('Microsoft-Windows-WER-SystemErrorReporting', 'BugCheck'); Id = 1001; StartTime = $since } 200)
    $bsRows = @()
    foreach ($e in $bs) {
        $bi = Get-BugcheckInfo $e.Message
        $bsRows += [pscustomobject]@{ Time = $e.TimeCreated; Code = $bi.Code; Name = $bi.Name; 'Likely cause' = $script:BugHints[$bi.Kind]; _Flag = 'high'; _Kind = $bi.Kind }
        Add-TimelineEvent $e.TimeCreated 'Blue screen' "$($bi.Code) $($bi.Name)" 'High'
    }
    $bsRows = @($bsRows | Sort-Object Time -Descending | Group-Object { $_.Time.ToString('yyyyMMddHHmm') } | ForEach-Object { $_.Group[0] })
    Add-Table -Section $S -Title "Blue screens (last $lookbackDays days)" -Rows $bsRows -Columns @('Time', 'Code', 'Name', 'Likely cause') -Empty 'No blue screens. Good.'
    if ($bsRows.Count -gt 0) {
        $kinds = @($bsRows | Group-Object _Kind | Sort-Object Count -Descending)
        $sev = if ($bsRows.Count -ge 3) { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Category 'Stability' -Section $S -Title "$($bsRows.Count) blue screen crash(es) in the last $lookbackDays days" `
            -Evidence @($bsRows | ForEach-Object { "$($_.Time.ToString('yyyy-MM-dd HH:mm'))  $($_.Code) $($_.Name)" }) `
            -Why 'Repeated crashes point to a specific driver or hardware fault and risk file corruption.' `
            -Fix ("Most common pattern here: " + $script:BugHints[$kinds[0].Name] + '. Crash dumps are in C:\Windows\Minidump (WinDbg or BlueScreenView can name the driver).')
    } else { Add-Pass 'Stability' "No blue screens in the last $lookbackDays days" }

    # ---------------- unexpected shutdowns
    $kp = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since } 500)
    $kpOnly = @($kp | Where-Object { $t = $_.TimeCreated; -not ($bsRows | Where-Object { [Math]::Abs(($_.Time - $t).TotalMinutes) -lt 10 }) })
    $shRows = @($kpOnly | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Event = 'Rebooted without a clean shutdown (Kernel-Power 41)' } })
    foreach ($e in $kpOnly) { Add-TimelineEvent $e.TimeCreated 'Unexpected shutdown' 'Power loss, hard reset or freeze' 'Low' }
    Add-Table -Section $S -Title "Unexpected shutdowns (not caused by a blue screen)" -Rows $shRows -Empty 'None.'
    if ($kpOnly.Count -ge 3) {
        Add-Finding -Severity Medium -Category 'Stability' -Section $S -Title "$($kpOnly.Count) unexpected shutdowns/restarts in the last $lookbackDays days" `
            -Evidence @($kpOnly | Select-Object -First 15 | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }) `
            -Why 'The PC lost power or was forced off (holding the power button after a freeze). Causes: freezes, overheating, a weak power supply, or power cuts.' `
            -Fix 'Ask whether these were power cuts or forced shutdowns after a freeze. If freezes: check temperatures, GPU driver, and the drive health above.'
    }

    # ---------------- WHEA hardware errors
    $wh = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } 1000)
    if ($wh.Count -gt 0) {
        $whRows = @($wh | Group-Object Id | ForEach-Object {
                $id = [int]$_.Name
                $desc = switch ($id) { 1 { 'Hardware error' } 17 { 'Corrected PCIe error' } 18 { 'FATAL machine-check (CPU/RAM/board)' } 19 { 'Corrected machine-check' } 20 { 'Fatal hardware error' } 46 { 'Fatal PCIe error' } 47 { 'Corrected memory error' } default { 'WHEA event' } }
                [pscustomobject]@{ 'Event ID' = $id; Meaning = $desc; Count = $_.Count; Latest = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated; _Flag = $(if ($id -in 1, 18, 20, 46) { 'high' } elseif ($_.Count -gt 5) { 'medium' } else { 'low' }) } })
        Add-Table -Section $S -Title 'Hardware errors reported by the CPU/chipset (WHEA)' -Rows $whRows
        $fatal = @($whRows | Where-Object { $_.'Event ID' -in 1, 18, 20, 46 })
        $corr = @($whRows | Where-Object { $_.'Event ID' -in 19, 47 })
        $pcie = @($whRows | Where-Object { $_.'Event ID' -eq 17 })
        if ($fatal.Count) { Add-Finding -Severity High -Category 'Hardware' -Section $S -Title 'Fatal hardware errors were logged' -Evidence @($fatal | ForEach-Object { "ID $($_.'Event ID') $($_.Meaning): $($_.Count)x" }) -Why 'The CPU or chipset reported an error it could not correct.' -Fix 'Remove any overclock, update the BIOS, test RAM (MemTest86), check temperatures and the power supply.' }
        elseif ((($corr | Measure-Object Count -Sum).Sum) -gt 5) { Add-Finding -Severity Medium -Category 'Hardware' -Section $S -Title 'Repeated corrected CPU/memory errors' -Evidence @($corr | ForEach-Object { "ID $($_.'Event ID') $($_.Meaning): $($_.Count)x" }) -Fix 'Often an unstable overclock/XMP profile or failing RAM. Test RAM and try BIOS defaults.' }
        if ((($pcie | Measure-Object Count -Sum).Sum) -gt 50) { Add-Finding -Severity Low -Category 'Hardware' -Section $S -Title 'Many corrected PCIe errors' -Detail "$(($pcie | Measure-Object Count -Sum).Sum) in $lookbackDays days." -Fix 'Usually harmless link noise from a GPU/NVMe slot; reseating the card or updating the BIOS/chipset driver often stops it.' }
    } else { Add-Pass 'Hardware' 'No WHEA hardware errors' }

    # ---------------- disk / file system errors
    $de = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'storahci', 'stornvme', 'iaStorA', 'iaStorAC', 'iaStorAVC', 'iaStorVD'); Level = @(1, 2, 3); StartTime = $since } 1000)
    if ($de.Count -gt 0) {
        $deRows = @($de | Group-Object ProviderName, Id | ForEach-Object {
                $f = $_.Group[0]
                $sev = if ($f.ProviderName -eq 'disk' -and $f.Id -in 7, 11) { 'high' } elseif ($f.Id -in 51, 55, 98, 129, 153, 137, 140) { 'medium' } else { 'low' }
                [pscustomobject]@{ Source = $f.ProviderName; 'Event ID' = $f.Id; Count = $_.Count; Latest = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated; Example = (Limit-Text $f.Message 220); _Flag = $sev } })
        Add-Table -Section $S -Title 'Disk and file-system errors' -Rows $deRows
        $badBlocks = @($deRows | Where-Object { $_._Flag -eq 'high' })
        if ($badBlocks.Count) { Add-Finding -Severity High -Category 'Storage' -Section $S -Title 'The disk has reported bad blocks / controller errors' -Evidence @($badBlocks | ForEach-Object { "$($_.Source) $($_.'Event ID'): $($_.Count)x - $($_.Example)" }) -Why 'Bad blocks mean the drive is physically failing or a cable is bad.' -Fix 'Back up now. Check the drive with the vendor tool or CrystalDiskInfo; replace the drive/cable.' }
        elseif (@($deRows | Where-Object { $_._Flag -eq 'medium' }).Count) { Add-Finding -Severity Medium -Category 'Storage' -Section $S -Title 'Disk or file-system warnings were logged' -Evidence @($deRows | Where-Object { $_._Flag -eq 'medium' } | ForEach-Object { "$($_.Source) $($_.'Event ID'): $($_.Count)x" }) -Fix "Run as admin: chkdsk $env:SystemDrive /scan ; update storage/chipset drivers." }
    }

    # ---------------- GPU driver resets
    $gpu = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = @('Display', 'nvlddmkm', 'amdkmdag', 'amdwddmg', 'igfx', 'igfxn'); Level = @(1, 2, 3); StartTime = $since } 500)
    $lk = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; Id = 1001; StartTime = $since } 6000)
    $lkSeen = @{}
    $lkAgg = @{}
    $crashTypes = @{}
    foreach ($e in $lk) {
        $p = $e.Properties
        if ($p.Count -lt 6) { continue }
        $evName = [string]$p[2].Value
        if ($evName -eq 'LiveKernelEvent') {
            # WER writes several 1001 records per occurrence; count each code once per minute
            $code = ([string]$p[5].Value).ToLowerInvariant()
            $k = $code + '|' + $e.TimeCreated.ToString('yyyyMMddHHmm')
            if ($lkSeen.ContainsKey($k)) { continue }
            $lkSeen[$k] = $true
            if (-not $lkAgg.ContainsKey($code)) { $lkAgg[$code] = [pscustomobject]@{ Code = $code; Meaning = $(if ($script:LiveKernel.ContainsKey($code)) { $script:LiveKernel[$code] } else { 'Kernel live dump' }); Occurrences = 0; First = $e.TimeCreated; Latest = $e.TimeCreated } }
            $a = $lkAgg[$code]; $a.Occurrences++
            if ($e.TimeCreated -lt $a.First) { $a.First = $e.TimeCreated }
            if ($e.TimeCreated -gt $a.Latest) { $a.Latest = $e.TimeCreated }
        } elseif ($evName -match '^(APPCRASH|AppHangB1|BEX64|BEX|MoAppCrash|MoAppHang|AppHangXProcB1)$') {
            $app = [string]$p[5].Value
            $k = "$evName|$app"
            if (-not $crashTypes.ContainsKey($k)) { $crashTypes[$k] = 0 }
            $crashTypes[$k]++
        }
    }
    $gpuLk = @($lkAgg.Values | Where-Object { $_.Code -in '141', '117', '1a8', '1b0', '193' })
    $gpuCount = @($gpu | Where-Object { $_.Id -eq 4101 -or $_.ProviderName -ne 'Display' }).Count + (($gpuLk | Measure-Object Occurrences -Sum).Sum)
    if ($lkAgg.Count -gt 0) {
        Add-Table -Section $S -Title 'Live kernel events (Windows recovered without a blue screen)' -Rows @($lkAgg.Values | Sort-Object Occurrences -Descending) `
            -Note 'Codes 141/117/1b0/193 are graphics hangs that Windows recovered from (screen freezes/flickers/black screens). Dumps are in C:\Windows\LiveKernelReports.'
    }
    if ($gpu.Count -gt 0) {
        Add-Table -Section $S -Title 'Graphics driver errors' -Rows @($gpu | Group-Object ProviderName, Id | ForEach-Object { [pscustomobject]@{ Source = $_.Group[0].ProviderName; 'Event ID' = $_.Group[0].Id; Count = $_.Count; Latest = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated; Example = (Limit-Text $_.Group[0].Message 200) } })
    }
    if ($gpuCount -ge 3) {
        Add-Finding -Severity Medium -Category 'Stability' -Section $S -Title "Graphics driver crashed/recovered $gpuCount times in $lookbackDays days" `
            -Why 'Screen flickers/black screens/game crashes. Usually the GPU driver, overheating, or GPU power delivery.' `
            -Fix 'Clean-install the latest GPU driver (DDU in safe mode if problems persist), check GPU temperatures, and avoid GPU overclocks. Screen recorders/overlays (Discord, GeForce/Adrenalin overlays) are common triggers.'
    }

    # ---------------- application crashes
    $ae = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $since } 2000)
    $ah = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002; StartTime = $since } 1000)
    $appRows = @()
    foreach ($g in ($ae | Group-Object { [string]$_.Properties[0].Value })) {
        $mods = ($g.Group | ForEach-Object { [string]$_.Properties[3].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 2 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
        $appRows += [pscustomobject]@{ Program = $g.Name; Type = 'Crash'; Count = $g.Count; 'Faulting module' = $mods; Latest = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated; _Flag = $(if ($g.Count -ge 10) { 'medium' } elseif ($g.Count -ge 5) { 'low' } else { '' }) }
    }
    foreach ($g in ($ah | Group-Object { [string]$_.Properties[0].Value })) {
        $appRows += [pscustomobject]@{ Program = $g.Name; Type = 'Hang (not responding)'; Count = $g.Count; 'Faulting module' = ''; Latest = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated; _Flag = $(if ($g.Count -ge 10) { 'medium' } elseif ($g.Count -ge 5) { 'low' } else { '' }) }
    }
    $bex = @($crashTypes.Keys | Where-Object { $_ -like 'BEX*' })
    Add-Table -Section $S -Title "Programs that crashed or froze (last $lookbackDays days)" -Rows @($appRows | Sort-Object Count -Descending)
    $frequent = @($appRows | Where-Object { $_.Count -ge 5 } | Sort-Object Count -Descending)
    if ($frequent.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Stability' -Section $S -Title "$($frequent.Count) program(s) crash or freeze repeatedly" -Evidence @($frequent | ForEach-Object { "$($_.Program): $($_.Count)x $($_.Type) $(if ($_.'Faulting module') { '- module ' + $_.'Faulting module' })" }) `
            -Fix 'Update or reinstall those programs. If many different programs crash in the same module (e.g. ntdll.dll, a .dll from an overlay or antivirus), that module is the real culprit.'
    }
    if ($bex.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Stability' -Section $S -Title 'Buffer-overrun crashes (BEX) were reported' -Evidence @($bex | ForEach-Object { "$_ x$($crashTypes[$_])" }) `
            -Why 'BEX crashes are memory-safety violations stopped by Windows. Usually buggy software or injected overlays; occasionally exploitation attempts.' -Fix 'Update the affected programs.'
    }

    # ---------------- services: crashes and NEW services installed
    $sc = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = @(7031, 7034); StartTime = $since } 1000)
    if ($sc.Count) {
        Add-Table -Section $S -Title 'Services that crashed' -Rows @($sc | Group-Object { [string]$_.Properties[0].Value } | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Service = $_.Name; Crashes = $_.Count; Latest = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated } })
    }
    $ns = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7045; StartTime = $since } 500)
    $nsRows = @()
    foreach ($e in $ns) {
        $name = [string]$e.Properties[0].Value; $img = [string]$e.Properties[1].Value
        $risk = Measure-ExecRisk -Command $img -Name $name -Quiet
        $nsRows += [pscustomobject]@{ Time = $e.TimeCreated; Service = $name; Program = $img; 'Start type' = [string]$e.Properties[3].Value; Account = [string]$e.Properties[4].Value; Concerns = $risk.Reasons; _Flag = (ConvertTo-FlagClass $risk.Severity) }
        Add-TimelineEvent $e.TimeCreated 'Service installed' "$name -> $img" $(if ($risk.Severity) { $risk.Severity } else { 'Info' })
        if ($risk.Severity -in 'High', 'Critical') {
            Add-Finding -Severity $risk.Severity -Category 'Persistence' -Section $S -Title "Suspicious service was installed: $name" -Detail $risk.Reasons -Evidence @("Installed $($e.TimeCreated)", "Program: $img") `
                -Fix "As admin: sc.exe stop `"$name`" ; sc.exe delete `"$name`" (only if it is not legitimate software), then delete the program file." `
                -Actions @((New-RepairAction -Kind ServiceStopDisable -Label "Stop and disable service '$name'" -Risk caution -Params @{ Service = $name }),
                    $(if ($risk.Exists -and (Test-UserWritableZone $risk.Zone)) { New-RepairAction -Kind Quarantine -Label "Quarantine $($risk.Target)" -Risk caution -Params @{ Targets = @($risk.Target) } }))
        }
    }
    Add-Table -Section $S -Title "New services installed (last $lookbackDays days)" -Rows @($nsRows | Sort-Object Time -Descending) -Empty 'No new services.' -Note 'Programs that install a background service. A good way to see what was installed and when.'

    # ---------------- log clearing + security log
    $lc = @(Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $since } 50)
    $secRows = @()
    if ($script:IsAdmin) {
        $sec = @(Get-EventsSafe @{ LogName = 'Security'; Id = @(1102, 4720, 4732, 4726); StartTime = $since } 300)
        foreach ($e in $sec) {
            $d = Get-EventData $e
            switch ($e.Id) {
                1102 { $secRows += [pscustomobject]@{ Time = $e.TimeCreated; Event = 'Security log was CLEARED'; Detail = "By $($d['SubjectUserName'])"; _Flag = 'high' } }
                4720 { $secRows += [pscustomobject]@{ Time = $e.TimeCreated; Event = 'User account created'; Detail = "$($d['TargetUserName']) by $($d['SubjectUserName'])"; _Flag = 'medium' } }
                4726 { $secRows += [pscustomobject]@{ Time = $e.TimeCreated; Event = 'User account deleted'; Detail = "$($d['TargetUserName']) by $($d['SubjectUserName'])"; _Flag = '' } }
                4732 {
                    if ($d['TargetSid'] -eq 'S-1-5-32-544') { $secRows += [pscustomobject]@{ Time = $e.TimeCreated; Event = 'Added to Administrators'; Detail = "$($d['MemberName']) $($d['MemberSid']) by $($d['SubjectUserName'])"; _Flag = 'high' } }
                }
            }
        }
        $fail = @(Get-EventsSafe @{ LogName = 'Security'; Id = 4625; StartTime = $since } 5000)
        if ($fail.Count -gt 0) {
            $byType = $fail | Group-Object { (Get-EventData $_)['LogonType'] } | ForEach-Object { "type $($_.Name): $($_.Count)" }
            $secRows += [pscustomobject]@{ Time = ($fail | Select-Object -First 1).TimeCreated; Event = "$($fail.Count) failed sign-in attempts"; Detail = ($byType -join ', ') + ' (type 2 = at the keyboard, 3 = network, 10 = Remote Desktop)'; _Flag = $(if ($fail.Count -gt 100) { 'medium' } else { '' }) }
            if ($fail.Count -gt 100) {
                Add-Finding -Severity Medium -Category 'Accounts & Access' -Section $S -Title "$($fail.Count) failed sign-in attempts in $lookbackDays days" -Detail ($byType -join ', ') `
                    -Why 'Large numbers of network (3) or Remote Desktop (10) failures mean someone is guessing passwords from outside.' -Fix 'Turn off Remote Desktop if not needed, close port forwards on the router, and use a strong password.'
            }
        }
    }
    foreach ($e in $lc) { $secRows += [pscustomobject]@{ Time = $e.TimeCreated; Event = 'An event log was CLEARED'; Detail = (Limit-Text $e.Message 200); _Flag = 'high' } }
    foreach ($r in $secRows) { if ($r._Flag) { Add-TimelineEvent $r.Time 'Security event' "$($r.Event): $($r.Detail)" $(if ($r._Flag -eq 'high') { 'High' } else { 'Medium' }) } }
    Add-Table -Section $S -Title 'Security events' -Rows @($secRows | Sort-Object Time -Descending) -Empty $(if ($script:IsAdmin) { 'Nothing notable.' } else { 'Security log needs administrator rights.' })
    $cleared = @($secRows | Where-Object { $_.Event -like '*CLEARED*' })
    if ($cleared.Count) {
        Add-Finding -Severity High -Category 'Accounts & Access' -Section $S -Title 'Windows event logs were cleared' -Evidence @($cleared | ForEach-Object { "$($_.Time): $($_.Event) $($_.Detail)" }) `
            -Why 'Attackers clear logs to hide what they did. Some "PC cleaner" tools also do it.' -Fix 'Ask whether anyone ran a cleaner tool at that time; otherwise treat the PC as compromised.'
    }
    $admAdd = @($secRows | Where-Object { $_.Event -eq 'Added to Administrators' })
    if ($admAdd.Count) { Add-Finding -Severity Medium -Category 'Accounts & Access' -Section $S -Title 'An account was added to Administrators recently' -Evidence @($admAdd | ForEach-Object { "$($_.Time): $($_.Detail)" }) -Fix 'Confirm this was intentional.' }
    $newUsers = @($secRows | Where-Object { $_.Event -eq 'User account created' })
    if ($newUsers.Count) { Add-Finding -Severity Medium -Category 'Accounts & Access' -Section $S -Title 'New user account(s) were created recently' -Evidence @($newUsers | ForEach-Object { "$($_.Time): $($_.Detail)" }) -Fix 'Confirm every new account was created on purpose.' }

    # ---------------- Defender operational events (protection switched off / settings changed)
    $dv = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = @(5001, 5004, 5007, 5010, 5012, 5013, 1116, 1117, 1118, 1119); StartTime = $since } 1000)
    $dvRows = @()
    foreach ($e in $dv) {
        $what = switch ($e.Id) { 5001 { 'Real-time protection was turned OFF' } 5004 { 'Real-time protection config changed' } 5007 { 'Defender setting changed' } 5010 { 'Malware scanning disabled' } 5012 { 'Virus scanning disabled' } 5013 { 'Tamper Protection BLOCKED a change' } 1116 { 'Threat detected' } 1117 { 'Action taken on threat' } 1118 { 'Action FAILED (non-critical)' } 1119 { 'Action FAILED (critical)' } }
        $detail = ''
        if ($e.Id -eq 5007) {
            $d = Get-EventData $e
            $detail = "$($d['New Value'])"
            # Features\EcsConfigs\* are Microsoft-pushed feature flags (e.g. MpFC_..._Exclusions), not settings anyone changed
            if ($detail -match '(?i)\\Features\\EcsConfigs\\') { continue }
            if ($detail -notmatch '(?i)\\Exclusions\\|DisableRealtime|DisableAntiSpyware|DisableBehavior|DisableIOAV|TamperProtection|SpynetReporting|PUAProtection|MpEnablePus') { continue }
        } elseif ($e.Id -in 1116, 1117, 1118, 1119) {
            $d = Get-EventData $e
            $detail = "$($d['Threat Name']) - $($d['Path'])"
        } else { $detail = Limit-Text $e.Message 200 }
        $flag = if ($e.Id -in 5001, 5010, 5012, 1118, 1119 -or ($e.Id -eq 5007 -and $detail -match '(?i)\\Exclusions\\|Disable')) { 'high' } elseif ($e.Id -eq 5013) { 'medium' } else { '' }
        $dvRows += [pscustomobject]@{ Time = $e.TimeCreated; Event = $what; Detail = (Limit-Text $detail 300); _Flag = $flag }
    }
    Add-Table -Section $S -Title 'Defender events (protection changes and detections)' -Rows @($dvRows | Sort-Object Time -Descending) -Empty 'No Defender protection changes or detections logged.'
    $exAdds = @($dvRows | Where-Object { $_.Event -eq 'Defender setting changed' -and $_.Detail -match '(?i)\\Exclusions\\(Paths|Processes|Extensions|IpAddresses|TemporaryPaths)\\' })
    if ($exAdds.Count) {
        Add-Finding -Severity High -Category 'Antivirus' -Section $S -Title "Defender exclusions were changed $($exAdds.Count) time(s) in the last $lookbackDays days" -Evidence @($exAdds | ForEach-Object { "$($_.Time): $($_.Detail)" }) `
            -Why 'Malware adds exclusions so Defender ignores it. The paths show exactly what was hidden.' -Fix 'Check whether each excluded path is legitimate; remove the rest (Windows Security > Virus & threat protection > Exclusions) and scan those folders.'
        foreach ($r in $exAdds) { Add-TimelineEvent $r.Time 'Defender exclusion changed' $r.Detail 'High' }
    }
    $offs = @($dvRows | Where-Object { $_.Event -in 'Real-time protection was turned OFF', 'Malware scanning disabled', 'Virus scanning disabled' })
    if ($offs.Count) {
        Add-Finding -Severity Medium -Category 'Antivirus' -Section $S -Title "Defender protection was switched off $($offs.Count) time(s)" -Evidence @($offs | Select-Object -First 20 | ForEach-Object { "$($_.Time): $($_.Event)" }) `
            -Why 'People sometimes turn Defender off to install cracks or cheats - which is exactly when infections happen.' -Fix 'Ask what was being installed at those times (see the timeline).'
        foreach ($r in $offs) { Add-TimelineEvent $r.Time 'Defender turned off' $r.Event 'Medium' }
    }
    $tb = @($dvRows | Where-Object { $_.Event -like 'Tamper Protection BLOCKED*' })
    if ($tb.Count) { Add-Finding -Severity Medium -Category 'Antivirus' -Section $S -Title "Something tried to change Defender settings ($($tb.Count)x) and was blocked" -Evidence @($tb | Select-Object -First 10 | ForEach-Object { "$($_.Time): $($_.Detail)" }) -Why 'Malware and activators try to disable Defender; Tamper Protection stopped it.' -Fix 'Find what was running at that time (timeline, persistence).' }

    # ---------------- malicious PowerShell (script block warnings)
    $ps = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = $since } 400)
    $psRows = @()
    $selfRoot = $script:ScannerRoot.ToLowerInvariant()
    foreach ($e in $ps) {
        $text = [string]$e.Properties[2].Value
        $path = [string]$e.Properties[4].Value
        if ($path -and $path.ToLowerInvariant().StartsWith($selfRoot)) { continue }
        if ($text -notmatch $script:StrongCmdRx) { continue }
        $psRows += [pscustomobject]@{ Time = $e.TimeCreated; Script = $(if ($path) { $path } else { '(typed or launched from another program)' }); Snippet = (Limit-Text $text 400); _Flag = 'high' }
    }
    Add-Table -Section $S -Title 'Suspicious PowerShell activity' -Rows $psRows -Empty 'No suspicious PowerShell script blocks logged.'
    if ($psRows.Count) {
        Add-Finding -Severity High -Category 'Malware & PUPs' -Section $S -Title "$($psRows.Count) suspicious PowerShell script(s) ran" -Evidence @($psRows | Select-Object -First 8 | ForEach-Object { "$($_.Time) $($_.Script): $($_.Snippet)" }) `
            -Why 'Downloading and running code in memory is how fake-CAPTCHA ("press Win+R and paste") scams and many stealers work.' `
            -Fix 'Ask whether she pasted a command from a website. If so: change passwords from another device and check the persistence findings.'
        foreach ($r in $psRows) { Add-TimelineEvent $r.Time 'Suspicious PowerShell' $r.Snippet 'High' }
    }

    # ---------------- Run-dialog history (fake CAPTCHA "paste this" scams)
    $runRows = @()
    foreach ($h in $script:Hives) {
        foreach ($v in (Get-RegValues "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")) {
            if ($v.Name -eq 'MRUList') { continue }
            $cmd = ([string]$v.Value) -replace '\\1$', ''
            $bad = $cmd -match $script:StrongCmdRx -or $cmd -match '(?i)(powershell|mshta|curl|wget|bitsadmin|certutil|cmd\s*/c).*(https?://|\d+\.\d+\.\d+\.\d+)'
            $runRows += [pscustomobject]@{ User = (Get-ShortUser $h.User); Command = (Limit-Text $cmd 400); _Flag = $(if ($bad) { 'critical' } else { '' }) }
        }
    }
    Add-Table -Section $S -Title 'Commands typed into the Win+R Run box' -Rows $runRows -Empty 'Run history is empty.'
    $runBad = @($runRows | Where-Object { $_._Flag })
    if ($runBad.Count) {
        Add-Finding -Severity Critical -Category 'Malware & PUPs' -Section $S -Title 'A malicious command was pasted into the Run box' -Evidence @($runBad | ForEach-Object { $_.Command }) `
            -Why 'This is the "fake CAPTCHA / verify you are human" scam: a website tells you to press Win+R and paste a command, which downloads an information stealer.' `
            -Fix 'Assume saved browser passwords, cookies and crypto wallets were stolen. From a DIFFERENT device: change email password first, then banking and other important accounts; sign out all sessions; enable 2FA. Then run a Defender Offline scan here.'
    }

    # ---------------- install history from Windows Installer
    $mi = @(Get-EventsSafe @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = @(11707, 11724); StartTime = $since } 400)
    foreach ($e in $mi) {
        $prod = [string]$e.Properties[0].Value
        $prod = ($prod -replace '^Product:\s*', '' -replace '\s+--\s+.*$', '')
        Add-TimelineEvent $e.TimeCreated $(if ($e.Id -eq 11707) { 'Installed (MSI)' } else { 'Removed (MSI)' }) $prod 'Info'
    }

    # ---------------- dumps on disk
    $dumpRows = @()
    foreach ($dir in @("$env:SystemRoot\Minidump", "$env:SystemRoot\LiveKernelReports")) {
        foreach ($f in (Get-FilesSafe -Root $dir -MaxDepth 1 -Extensions @('.dmp') -MaxFiles 100 -MaxSeconds 5)) { $dumpRows += [pscustomobject]@{ File = $f.FullName; Created = $f.CreationTime; Size = (Format-Bytes $f.Length) } }
    }
    if ([IO.File]::Exists("$env:SystemRoot\MEMORY.DMP")) { $fi = New-Object IO.FileInfo("$env:SystemRoot\MEMORY.DMP"); $dumpRows += [pscustomobject]@{ File = $fi.FullName; Created = $fi.LastWriteTime; Size = (Format-Bytes $fi.Length) } }
    if ($dumpRows.Count) { Add-Table -Section $S -Title 'Crash dump files' -Rows @($dumpRows | Sort-Object Created -Descending) -Note 'Open with WinDbg (!analyze -v) or BlueScreenView to see which driver caused each crash.' }

    # ---------------- reliability index
    try {
        $rm = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction Stop | Sort-Object TimeGenerated -Descending | Select-Object -First 1
        if ($rm) {
            $idx = [Math]::Round($rm.SystemStabilityIndex, 1)
            Add-KV -Section $S -Title 'Windows Reliability Monitor' -Data ([ordered]@{ 'Stability index (1-10)' = $idx; 'As of' = $rm.TimeGenerated; 'Open it' = 'Start > type "reliability history"' })
            if ($idx -lt 5) { Add-Finding -Severity Medium -Category 'Stability' -Section $S -Title "Windows stability index is low ($idx / 10)" -Fix 'Open Reliability Monitor to see which crashes and failures are dragging it down.' }
        }
    } catch {}
}
