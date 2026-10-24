# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# System overview + Windows support lifecycle

function Get-WindowsSupportInfo {
    param([int]$Build, [string]$Edition)
    $ent = $Edition -match 'Enterprise|Education|IoT'
    $ltsc = $Edition -match 'EnterpriseS|IoTEnterpriseS'
    if ($Build -lt 22000) {
        if ($ltsc) { return [pscustomobject]@{ Name = 'Windows 10 LTSC'; End = $null; Known = $true; Note = 'Long-Term Servicing Channel edition (long support window).' } }
        return [pscustomobject]@{ Name = 'Windows 10'; End = [datetime]'2026-10-13'; Known = $true; Note = 'Windows 10 support ended 2025-10-14; the one-year consumer Extended Security Updates (ESU) program ended 2026-10-13.' }
    }
    # build => version, Home/Pro end, Enterprise/Education end
    $table = @{
        22000 = @('21H2', '2023-10-10', '2024-10-08')
        22621 = @('22H2', '2024-10-08', '2025-10-14')
        22631 = @('23H2', '2025-11-11', '2026-11-10')
        26100 = @('24H2', '2026-10-13', '2027-10-12')
        26200 = @('25H2', '2027-10-12', '2028-10-10')
    }
    if ($table.ContainsKey($Build)) {
        $t = $table[$Build]
        $end = if ($ent) { [datetime]$t[2] } else { [datetime]$t[1] }
        return [pscustomobject]@{ Name = "Windows 11 $($t[0])"; End = $end; Known = $true; Note = '' }
    }
    [pscustomobject]@{ Name = "Windows 11 (build $Build)"; End = $null; Known = $false; Note = 'Build is newer than this scanner''s lifecycle table (Insider/preview or a newer release).' }
}

function Invoke-SystemScan {
    $S = 'system'
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $cpus = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue)
    $cv = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $build = [int]$os.BuildNumber
    $display = $cv.DisplayVersion
    if (-not $display) { $display = $cv.ReleaseId }
    $edition = $cv.EditionID
    $uptime = (Get-Date) - $os.LastBootUpTime
    $fwType = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control' 'PEFirmwareType'
    $fwText = switch ($fwType) { 1 { 'Legacy BIOS' } 2 { 'UEFI' } default { 'Unknown' } }
    $chassis = @(Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue | ForEach-Object { $_.ChassisTypes } | Where-Object { $_ })
    $isLaptop = (@($chassis | Where-Object { $_ -in 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32 }).Count -gt 0) -or [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
    $osLine = "$($os.Caption) $display (build $build.$($cv.UBR))"

    $script:Shared.OS = $os
    $script:Shared.Build = $build
    $script:Shared.IsLaptop = $isLaptop
    $script:Shared.OSLine = $osLine
    $script:Shared.Edition = $edition

    $cpuText = (@($cpus | ForEach-Object { "$($_.Name.Trim()) ($($_.NumberOfCores) cores / $($_.NumberOfLogicalProcessors) threads)" }) -join '; ')
    $biosDate = $null
    if ($bios.ReleaseDate) { $biosDate = $bios.ReleaseDate }
    $kv = [ordered]@{
        'Computer name'        = $env:COMPUTERNAME
        'Windows'              = $osLine
        'Edition'              = $edition
        'Architecture'         = $os.OSArchitecture
        'Windows installed'    = $os.InstallDate
        'Last boot'            = $os.LastBootUpTime
        'Uptime'               = ('{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes)
        'Manufacturer / model' = "$($cs.Manufacturer) $($cs.Model)"
        'Form factor'          = $(if ($isLaptop) { 'Laptop / portable' } else { 'Desktop' })
        'Motherboard'          = "$($bb.Manufacturer) $($bb.Product)"
        'BIOS / firmware'      = ("$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)" + $(if ($biosDate) { ' (' + $biosDate.ToString('yyyy-MM-dd') + ')' } else { '' }))
        'Firmware mode'        = $fwText
        'Serial number'        = $bios.SerialNumber
        'CPU'                  = $cpuText
        'Installed RAM'        = (Format-Bytes $cs.TotalPhysicalMemory)
        'Domain / workgroup'   = $(if ($cs.PartOfDomain) { "Domain: $($cs.Domain)" } else { "Workgroup: $($cs.Workgroup)" })
        'Time zone'            = (Get-TimeZone -ErrorAction SilentlyContinue).DisplayName
        'Scanned by'           = "$env:USERDOMAIN\$env:USERNAME" + $(if ($script:IsAdmin) { ' (administrator)' } else { ' (standard rights)' })
    }
    Add-KV -Section $S -Title 'Overview' -Data $kv

    # Windows lifecycle
    $sup = Get-WindowsSupportInfo -Build $build -Edition $edition
    $script:Shared.Support = $sup
    if ($sup.End) {
        $daysLeft = ($sup.End - (Get-Date)).TotalDays
        if ($daysLeft -lt 0) {
            $isWin10 = $build -lt 22000
            if ($isWin10) {
                Add-Finding -Severity High -Category 'Updates' -Section $S -Title 'Windows 10 no longer receives security updates' `
                    -Detail "$osLine. $($sup.Note)" `
                    -Why 'New Windows vulnerabilities are no longer patched on this PC, so browsing and downloads are riskier every month.' `
                    -Fix "Upgrade to Windows 11 if the hardware supports it (Settings > Windows Update, or run Microsoft's PC Health Check). If it does not, plan a replacement PC, and in the meantime keep the browser and antivirus fully updated."
            } else {
                Add-Finding -Severity High -Category 'Updates' -Section $S -Title "$($sup.Name) is past end of servicing" `
                    -Detail "This version stopped receiving security updates on $($sup.End.ToString('yyyy-MM-dd'))." `
                    -Why 'Windows only patches supported versions. This PC is missing monthly security fixes.' `
                    -Fix 'Settings > Windows Update > Check for updates, then install the latest Windows 11 feature update (25H2 or newer). It is usually a quick enablement package.'
            }
        } elseif ($daysLeft -lt 75) {
            Add-Finding -Severity Medium -Category 'Updates' -Section $S -Title "$($sup.Name) support ends soon" `
                -Detail "Security updates for this version end on $($sup.End.ToString('yyyy-MM-dd')) ($([int]$daysLeft) days)." `
                -Fix 'Install the latest Windows 11 feature update from Settings > Windows Update.'
        } else {
            Add-Pass 'Updates' "$($sup.Name) is a supported version" "Security updates until $($sup.End.ToString('yyyy-MM-dd'))"
        }
    } elseif (-not $sup.Known) {
        Add-Finding -Severity Info -Category 'Updates' -Section $S -Title 'Windows build not in the lifecycle table' -Detail "$osLine. $($sup.Note)"
    } else {
        Add-Pass 'Updates' "$($sup.Name)" $sup.Note
    }

    $insider = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\Applicability' 'BranchName'
    if ($insider) {
        Add-Finding -Severity Info -Category 'Updates' -Section $S -Title 'Windows Insider (preview) builds are enabled' -Detail "Insider branch: $insider" `
            -Why 'Preview builds can be less stable.' -Fix 'If this is not intended: Settings > Windows Update > Windows Insider Program > stop getting preview builds.'
    }

    if ($uptime.TotalDays -gt 14) {
        Add-Finding -Severity Low -Category 'Performance' -Section $S -Title "PC has not restarted in $([int]$uptime.TotalDays) days" `
            -Why 'Many updates only finish installing after a restart, and long uptimes can make Windows sluggish.' -Fix 'Restart the PC (Start > Power > Restart, not Shut down - Fast Startup means Shut down is not a full restart).'
    }

    if ($biosDate -and ((Get-Date) - $biosDate).TotalDays -gt 365 * 5) {
        Add-Finding -Severity Info -Category 'Hardware' -Section $S -Title 'BIOS/firmware is more than 5 years old' `
            -Detail "BIOS date $($biosDate.ToString('yyyy-MM-dd'))." -Fix "Check $($cs.Manufacturer)'s support site for a firmware update (only if the PC is stable and you are comfortable updating firmware)."
    }

    # user profiles on this machine
    $rows = foreach ($p in $script:Profiles) {
        [pscustomobject]@{ User = $p.User; Folder = $p.Path; 'Signed in now' = [bool]$p.Loaded; 'Last used' = $p.LastUse }
    }
    Add-Table -Section $S -Title 'User profiles on this PC' -Rows $rows
}
