# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Hardware health: drives (SMART/wear/space), memory, GPU, battery, Device Manager problems, unsigned drivers, temperatures

$script:PnpCodes = @{ 1 = 'Not configured'; 3 = 'Driver corrupted / low memory'; 10 = 'Device cannot start'; 12 = 'Not enough free resources'; 14 = 'Restart needed';
    18 = 'Reinstall drivers'; 19 = 'Registry configuration damaged'; 21 = 'Being removed'; 22 = 'Disabled'; 24 = 'Not present / not working'; 28 = 'Drivers not installed';
    29 = 'Disabled in firmware'; 31 = 'Not working properly'; 32 = 'Driver disabled'; 37 = 'Driver failed to initialise'; 38 = 'Driver already loaded'; 39 = 'Driver missing or corrupt';
    40 = 'Registry info missing'; 41 = 'Driver loaded but device not found'; 43 = 'Device reported a problem (stopped)'; 47 = 'Prepared for removal'; 48 = 'Driver blocked'; 52 = 'Unsigned driver blocked' }

function Invoke-HardwareScan {
    $S = 'hardware'

    # ---------------- physical drives
    $diskRows = @()
    try {
        $pds = @(Get-PhysicalDisk -ErrorAction Stop)
        foreach ($d in $pds) {
            $rel = $null
            if ($script:IsAdmin) { try { $rel = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {} }
            $media = [string]$d.MediaType
            if ($media -eq 'Unspecified' -and $d.SpindleSpeed -eq 0) { $media = 'SSD (reported unspecified)' }
            $health = [string]$d.HealthStatus
            $sev = $null; $why = @()
            if ($health -eq 'Unhealthy') { $sev = 'Critical'; $why += 'Drive reports it is FAILING' }
            elseif ($health -eq 'Warning') { $sev = 'High'; $why += 'Drive reports a health warning' }
            if ($rel) {
                if ($rel.Wear -ge 90) { $sev = Get-MaxSeverity @($sev, 'High'); $why += "SSD life used: $($rel.Wear)%" }
                elseif ($rel.Wear -ge 70) { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += "SSD life used: $($rel.Wear)%" }
                if ($rel.ReadErrorsUncorrected -gt 0 -or $rel.WriteErrorsUncorrected -gt 0) { $sev = Get-MaxSeverity @($sev, 'High'); $why += "Uncorrected errors: read $($rel.ReadErrorsUncorrected), write $($rel.WriteErrorsUncorrected)" }
                if ($rel.Temperature -ge 70) { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += "Hot: $($rel.Temperature) C" }
            }
            $diskRows += [pscustomobject]@{
                Drive = $d.FriendlyName; Type = $media; Bus = [string]$d.BusType; Size = (Format-Bytes $d.Size); Health = $health; Status = ([string]$d.OperationalStatus)
                'Life used %' = $(if ($rel) { $rel.Wear } else { '' }); 'Temp C' = $(if ($rel) { $rel.Temperature } else { '' }); 'Max temp C' = $(if ($rel) { $rel.TemperatureMax } else { '' })
                'Power-on hours' = $(if ($rel) { $rel.PowerOnHours } else { '' }); 'Uncorrected errors' = $(if ($rel) { [int]$rel.ReadErrorsUncorrected + [int]$rel.WriteErrorsUncorrected } else { '' })
                Concerns = ($why -join '; '); _Flag = (ConvertTo-FlagClass $sev); _Id = [string]$d.DeviceId; _Media = $media
            }
            if ($sev) {
                Add-Finding -Severity $sev -Category 'Hardware' -Section $S -Title "Drive problem: $($d.FriendlyName)" -Detail ($why -join '; ') `
                    -Why 'A failing or worn-out drive can lose everything with little warning.' `
                    -Fix 'BACK UP important files now (photos, documents) to an external drive or cloud. Then replace the drive; the vendor tool (Samsung Magician, Crucial Storage Executive, etc.) can confirm.'
            }
        }
        if ($diskRows.Count -gt 0 -and @($diskRows | Where-Object { $_._Flag }).Count -eq 0) { Add-Pass 'Hardware' 'All drives report healthy' ($(if ($script:IsAdmin) { 'Including wear and error counters' } else { 'Basic health only (run as admin for wear/temperature)' })) }
    } catch { Add-Note -Section $S -Text "Could not read physical drives: $($_.Exception.Message)" -Tone warn }
    try {
        $fp = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop | Where-Object { $_.PredictFailure })
        if ($fp.Count -gt 0) {
            Add-Finding -Severity Critical -Category 'Hardware' -Section $S -Title 'SMART predicts a drive failure' -Evidence @($fp | ForEach-Object { "$($_.InstanceName) reason $($_.Reason)" }) `
                -Why 'The drive''s own self-monitoring says it is about to fail.' -Fix 'Back up immediately and replace the drive.'
        }
    } catch {}
    Add-Table -Section $S -Title 'Drives' -Rows $diskRows -Columns @('Drive', 'Type', 'Bus', 'Size', 'Health', 'Status', 'Life used %', 'Temp C', 'Max temp C', 'Power-on hours', 'Uncorrected errors', 'Concerns')

    # system drive media type
    try {
        $sysNum = (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':') -ErrorAction Stop | Get-Disk -ErrorAction Stop).Number
        $sysDisk = $diskRows | Where-Object { $_._Id -eq [string]$sysNum } | Select-Object -First 1
        if ($sysDisk) { $script:Shared.SystemDiskType = $sysDisk._Media }
    } catch {}

    # ---------------- volumes / free space
    $volRows = @()
    try {
        foreach ($v in @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.Size -gt 0 })) {
            $pct = [Math]::Round(($v.SizeRemaining / $v.Size) * 100, 1)
            $isSys = ("$($v.DriveLetter):" -eq $env:SystemDrive)
            $sev = $null
            if ($isSys) {
                if ($pct -lt 10 -or $v.SizeRemaining -lt 10GB) { $sev = 'High' } elseif ($pct -lt 15 -or $v.SizeRemaining -lt 20GB) { $sev = 'Medium' }
            } elseif ($pct -lt 5) { $sev = 'Low' }
            $volRows += [pscustomobject]@{ Drive = "$($v.DriveLetter):"; Label = $v.FileSystemLabel; 'File system' = $v.FileSystem; Size = (Format-Bytes $v.Size); Free = (Format-Bytes $v.SizeRemaining); 'Free %' = $pct; Health = [string]$v.HealthStatus; _Flag = (ConvertTo-FlagClass $sev) }
            if ($sev) {
                Add-Finding -Severity $sev -Category 'Storage' -Section $S -Title "Drive $($v.DriveLetter): is almost full ($pct% free)" -Detail "$(Format-Bytes $v.SizeRemaining) free of $(Format-Bytes $v.Size)." `
                    -Why $(if ($isSys) { 'Windows needs free space for updates, the page file and temporary files. A nearly full C: drive causes slowdowns and failed updates.' } else { '' }) `
                    -Fix 'Settings > System > Storage > Cleanup recommendations / Temporary files. See the Performance section for what can be cleared. Move photos/videos to another drive or cloud.' `
                    -Actions @($(if ($isSys) {
                            (New-RepairAction -Kind Run -Label 'Clear temp folders and the Windows Update download cache' -Params @{ Command = 'cleanmgr-auto' })
                            (New-RepairAction -Kind Run -Label 'Empty the Recycle Bin' -Risk caution -Params @{ Command = 'empty-recyclebin' })
                            (New-RepairAction -Kind Open -Label 'Open Storage settings for the bigger items (apps, Windows.old, Downloads)' -Risk guided -Params @{ Uri = 'ms-settings:storagesense' })
                        }))
            }
            if ([string]$v.HealthStatus -ne 'Healthy' -and $v.HealthStatus) {
                Add-Finding -Severity High -Category 'Storage' -Section $S -Title "Volume $($v.DriveLetter): health is $($v.HealthStatus)" -Fix "Run as admin: chkdsk $($v.DriveLetter): /scan  (then chkdsk /f if it finds problems)." `
                    -Actions @($(if ($isSys) { New-RepairAction -Kind Run -Label 'Scan the file system online (chkdsk /scan)' -Params @{ Command = 'chkdsk-scan' } }))
            }
        }
    } catch {}
    Add-Table -Section $S -Title 'Disk space' -Rows $volRows
    if ($script:IsAdmin) {
        $dq = Invoke-External -File "$env:SystemRoot\System32\fsutil.exe" -Arguments "dirty query $env:SystemDrive" -TimeoutSec 20
        if ($dq.Output -match '(?i)is dirty' -and $dq.Output -notmatch '(?i)not dirty') {
            Add-Finding -Severity Medium -Category 'Storage' -Section $S -Title "File system on $env:SystemDrive is marked as needing repair (dirty bit set)" -Fix "Run as admin: chkdsk $env:SystemDrive /f and restart." `
                -Actions @((New-RepairAction -Kind Run -Label 'Schedule a full disk check for the next restart' -Risk caution -Reboot -Params @{ Command = 'chkdsk-fix-on-boot' }))
        }
    }

    # ---------------- memory
    $cs = Get-CimInstance Win32_ComputerSystem
    $totalGB = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $mods = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
    $memRows = @($mods | ForEach-Object { [pscustomobject]@{ Slot = $_.DeviceLocator; Size = (Format-Bytes $_.Capacity); 'Rated MHz' = $_.Speed; 'Running MHz' = $_.ConfiguredClockSpeed; Maker = ([string]$_.Manufacturer).Trim(); Part = ([string]$_.PartNumber).Trim() } })
    Add-Table -Section $S -Title "Memory ($totalGB GB usable)" -Rows $memRows
    if ($totalGB -lt 3.8) {
        Add-Finding -Severity High -Category 'Performance' -Section $S -Title "Only $totalGB GB of RAM" -Why 'Windows 10/11 plus a browser needs at least 8 GB to run smoothly.' -Fix 'Add RAM if the PC has free slots, or plan an upgrade.'
    } elseif ($totalGB -lt 7.5) {
        Add-Finding -Severity Medium -Category 'Performance' -Section $S -Title "Only $totalGB GB of RAM" -Why '8 GB is the practical minimum today; 16 GB is comfortable.' -Fix 'Adding RAM is usually the cheapest big speed-up.'
    }
    $slow = @($mods | Where-Object { $_.Speed -and $_.ConfiguredClockSpeed -and $_.ConfiguredClockSpeed -lt ($_.Speed * 0.85) })
    if ($slow.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Performance' -Section $S -Title 'RAM is running below its rated speed' -Detail "Rated $($slow[0].Speed) MHz, running $($slow[0].ConfiguredClockSpeed) MHz." `
            -Fix 'On desktops, enabling XMP/EXPO in the BIOS gives free performance (only if the system is stable).'
    }

    # ---------------- GPU
    $gpuRows = @()
    foreach ($g in @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)) {
        $age = if ($g.DriverDate) { [int]((Get-Date) - $g.DriverDate).TotalDays } else { $null }
        $sev = $null; $why = ''
        if ($g.Name -match 'Microsoft Basic Display') { $sev = 'Medium'; $why = 'No real graphics driver installed' }
        elseif ($age -gt 540 -and $g.Name -notmatch '(?i)virtual|remote|mirror|indirect|parsec|spacedesk|basic render|meta ') { $sev = 'Low'; $why = "Driver is $age days old" }
        $gpuRows += [pscustomobject]@{ GPU = $g.Name; 'Driver version' = $g.DriverVersion; 'Driver date' = $g.DriverDate; Resolution = "$($g.CurrentHorizontalResolution) x $($g.CurrentVerticalResolution) @ $($g.CurrentRefreshRate) Hz"; Status = $g.Status; Concern = $why; _Flag = (ConvertTo-FlagClass $sev) }
        if ($sev) {
            Add-Finding -Severity $sev -Category 'Drivers' -Section $S -Title "Graphics: $($g.Name) - $why" `
                -Fix 'Install the latest driver from NVIDIA (nvidia.com/drivers), AMD (amd.com/support) or Intel (intel.com/arc / Driver & Support Assistant) - not from third-party "driver updater" tools.'
        }
    }
    Add-Table -Section $S -Title 'Graphics' -Rows $gpuRows

    # ---------------- battery
    if (Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue) {
        $bkv = [ordered]@{}
        try {
            $design = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop)[0].DesignedCapacity
            $full = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop)[0].FullChargedCapacity
            $cycles = $null
            try { $cycles = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount -ErrorAction Stop)[0].CycleCount } catch {}
            if ($design -gt 0 -and $full -gt 0) {
                $healthPct = [Math]::Round($full / $design * 100)
                $bkv['Design capacity'] = "$design mWh"; $bkv['Full charge capacity'] = "$full mWh"; $bkv['Battery health'] = "$healthPct%"
                if ($cycles) { $bkv['Charge cycles'] = $cycles }
                if ($healthPct -lt 50) { Add-Finding -Severity Medium -Category 'Hardware' -Section $S -Title "Battery is worn out ($healthPct% of original capacity)" -Fix 'A replacement battery will restore run time. Laptops with very worn batteries can also shut down suddenly.' }
                elseif ($healthPct -lt 70) { Add-Finding -Severity Low -Category 'Hardware' -Section $S -Title "Battery has $healthPct% of its original capacity" -Fix 'Normal ageing; consider a replacement if battery life is a problem.' }
                else { Add-Pass 'Hardware' 'Battery health is good' "$healthPct% of design capacity" }
            }
        } catch {}
        if ($script:OutDir) {
            $br = Join-Path $script:OutDir 'battery-report.html'
            $null = Invoke-External -File "$env:SystemRoot\System32\powercfg.exe" -Arguments "/batteryreport /output `"$br`"" -TimeoutSec 60
            if (Test-Path -LiteralPath $br) { $bkv['Detailed report'] = 'battery-report.html (saved next to this report)' }
        }
        if ($bkv.Count -gt 0) { Add-KV -Section $S -Title 'Battery' -Data $bkv }
    }

    # ---------------- Device Manager problems
    $devRows = @()
    foreach ($d in @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction SilentlyContinue)) {
        $code = [int]$d.ConfigManagerErrorCode
        if ($code -in 45) { continue }
        $sev = if ($code -eq 22) { $null } elseif ($code -in 28, 52, 10, 43, 31, 39, 37, 48) { 'Medium' } else { 'Low' }
        $devRows += [pscustomobject]@{ Device = $d.Name; Class = $d.PNPClass; Problem = "Code $code - $($script:PnpCodes[$code])"; 'Hardware ID' = (@($d.HardwareID) | Select-Object -First 1); _Flag = (ConvertTo-FlagClass $sev); _Sev = $sev }
    }
    Add-Table -Section $S -Title 'Device Manager problems' -Rows $devRows -Columns @('Device', 'Class', 'Problem', 'Hardware ID') -Empty 'No devices with problems. Good.'
    $devBad = @($devRows | Where-Object { $_._Sev -eq 'Medium' })
    if ($devBad.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Drivers' -Section $S -Title "$($devBad.Count) device(s) are not working properly" -Evidence @($devBad | ForEach-Object { "$($_.Device): $($_.Problem)" }) `
            -Fix 'Install the driver from the PC/motherboard maker''s support page (or Windows Update > Advanced options > Optional updates). Code 43 often means a faulty cable/device.' `
            -Actions @((New-RepairAction -Kind Open -Label 'Open Windows Update optional updates (driver updates appear there)' -Risk guided -Params @{ Uri = 'ms-settings:windowsupdate-optionalupdates' }),
                (New-RepairAction -Kind Open -Label 'Open Device Manager' -Risk guided -Params @{ Uri = 'devmgmt.msc' }))
    } elseif ($devRows.Count -eq 0) { Add-Pass 'Drivers' 'Device Manager shows no problem devices' }

    # ---------------- unsigned drivers
    try {
        $uns = @(Get-CimInstance Win32_PnPSignedDriver -Filter 'IsSigned = FALSE' -ErrorAction Stop | Where-Object { $_.DeviceName })
        if ($uns.Count -gt 0) {
            Add-Table -Section $S -Title 'Unsigned device drivers' -Rows @($uns | ForEach-Object { [pscustomobject]@{ Device = $_.DeviceName; Driver = $_.InfName; Version = $_.DriverVersion; Provider = $_.DriverProviderName; _Flag = 'medium' } })
            Add-Finding -Severity Medium -Category 'Drivers' -Section $S -Title "$($uns.Count) device driver(s) are not digitally signed" -Evidence @($uns | ForEach-Object { "$($_.DeviceName) ($($_.InfName), $($_.DriverProviderName))" }) `
                -Fix 'Replace with a signed driver from the hardware maker.'
        }
    } catch {}

    # ---------------- temperatures (ACPI; often missing or approximate)
    try {
        $tz = @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)
        $tRows = @($tz | ForEach-Object { $c = [Math]::Round($_.CurrentTemperature / 10 - 273.15, 1); [pscustomobject]@{ Zone = $_.InstanceName; 'Temp C' = $c; _Flag = $(if ($c -ge 90) { 'high' } elseif ($c -ge 80) { 'medium' } else { '' }) } })
        Add-Table -Section $S -Title 'Motherboard thermal zones' -Rows $tRows -Note 'ACPI zones are approximate and not the CPU core temperature. Use HWiNFO for exact readings.'
        $hot = @($tRows | Where-Object { $_.'Temp C' -ge 85 -and $_.'Temp C' -lt 150 })
        if ($hot.Count) { Add-Finding -Severity Medium -Category 'Hardware' -Section $S -Title "System is running hot ($($hot[0].'Temp C') C)" -Fix 'Clean dust from fans/vents, make sure laptop vents are not blocked, check fans spin.' }
    } catch {}
}
