# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Performance: startup load, boot time and what slows it, disk type, power plan, reclaimable space

function Invoke-PerformanceScan {
    $S = 'performance'
    $kv = [ordered]@{}

    $sc = [int]$script:Shared.StartupCount
    $kv['Programs starting with Windows'] = $sc
    if ($sc -gt 15) {
        Add-Finding -Severity Low -Category 'Performance' -Section $S -Title "$sc programs start automatically with Windows" `
            -Why 'Every startup program slows sign-in and uses memory in the background.' -Fix 'Task Manager > Startup apps: disable anything not needed right away (updaters, launchers, chat apps you do not use daily).' `
            -Actions @((New-RepairAction -Kind Open -Label 'Open Startup apps settings' -Risk guided -Params @{ Uri = 'ms-settings:startupapps' }))
    }

    # boot performance
    $bp = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100; StartTime = (Get-Date).AddDays(-90) } 10)
    if ($bp.Count -gt 0) {
        $times = @($bp | ForEach-Object { [double](Get-EventData $_)['BootTime'] } | Where-Object { $_ -gt 0 })
        if ($times.Count) {
            $avg = [Math]::Round((($times | Measure-Object -Average).Average) / 1000)
            $kv['Average boot time (last boots)'] = "$avg s"
            if ($avg -gt 120) { Add-Finding -Severity Medium -Category 'Performance' -Section $S -Title "Slow startup: Windows takes about $avg seconds to boot" -Fix 'Reduce startup programs, check the disk type below, and see "What slows boot" in the Performance section.' }
            elseif ($avg -gt 75) { Add-Finding -Severity Low -Category 'Performance' -Section $S -Title "Startup takes about $avg seconds" -Fix 'Disabling unneeded startup apps usually helps.' }
        }
    }
    $deg = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = @(101, 102, 103, 106, 109); StartTime = (Get-Date).AddDays(-90) } 300)
    if ($deg.Count) {
        $agg = @{}
        foreach ($e in $deg) {
            $d = Get-EventData $e
            $name = if ($d['FriendlyName']) { $d['FriendlyName'] } elseif ($d['Name']) { $d['Name'] } else { "Event $($e.Id)" }
            $kind = switch ($e.Id) { 101 { 'App' } 102 { 'Driver' } 103 { 'Service' } 106 { 'Background task' } 109 { 'Device' } }
            $k = "$kind|$name"
            if (-not $agg.ContainsKey($k)) { $agg[$k] = [pscustomobject]@{ Item = $name; Kind = $kind; Times = 0; 'Avg delay (s)' = 0.0; _sum = 0.0 } }
            $o = $agg[$k]; $o.Times++; $o._sum += [double]$d['DegradationTime']; $o.'Avg delay (s)' = [Math]::Round(($o._sum / $o.Times) / 1000, 1)
        }
        $top = @($agg.Values | Sort-Object 'Avg delay (s)' -Descending | Select-Object -First 12)
        Add-Table -Section $S -Title 'What slows boot (Windows diagnostics, last 90 days)' -Rows $top -Columns @('Item', 'Kind', 'Times', 'Avg delay (s)')
        $worst = @($top | Where-Object { $_.'Avg delay (s)' -ge 5 } | Select-Object -First 4)
        if ($worst.Count) { Add-Finding -Severity Low -Category 'Performance' -Section $S -Title 'Specific programs/drivers are slowing startup' -Evidence @($worst | ForEach-Object { "$($_.Item) ($($_.Kind)): +$($_.'Avg delay (s)') s" }) -Fix 'Disable or update the items listed.' }
    }

    # disk type
    $dt = [string]$script:Shared.SystemDiskType
    if ($dt) {
        $kv['System drive type'] = $dt
        if ($dt -eq 'HDD') {
            Add-Finding -Severity Medium -Category 'Performance' -Section $S -Title 'Windows is installed on a mechanical hard drive (HDD)' `
                -Why 'This is the single biggest cause of a slow PC. An SSD makes boot and app launch several times faster.' -Fix 'Clone the system to an SSD (a 500 GB SATA or NVMe SSD is inexpensive). This is the best upgrade for this PC.'
        }
    }

    # power plan
    $pp = Invoke-External -File "$env:SystemRoot\System32\powercfg.exe" -Arguments '/getactivescheme' -TimeoutSec 15
    if ($pp.Output -match '\(([^)]+)\)\s*$') {
        $plan = $Matches[1]
        $kv['Power plan'] = $plan
        if ($plan -match '(?i)power saver' -and -not $script:Shared.IsLaptop) { Add-Finding -Severity Low -Category 'Performance' -Section $S -Title 'Desktop PC is on the Power saver plan' -Fix 'Control Panel > Power Options > Balanced.' -Actions @((New-RepairAction -Kind Run -Label 'Switch to the Balanced power plan' -Params @{ Command = 'power-balanced' })) }
    }
    $fs = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
    $kv['Fast Startup'] = $(if ($fs -eq 1) { 'On (Shut down is not a full restart - use Restart to apply updates/fixes)' } else { 'Off' })
    $kv['Memory in use now'] = "$($script:Shared.RamUsedPct)%"
    Add-KV -Section $S -Title 'Summary' -Data $kv

    # reclaimable space
    $spRows = @()
    $addSpace = {
        param($What, $Path, $Tip)
        $sz = Get-DirSize -Path $Path -MaxSeconds 15
        if ($sz.Exists -and $sz.Bytes -gt 50MB) { $spRows.Add([pscustomobject]@{ What = $What; Location = $Path; Size = (Format-Bytes $sz.Bytes); _Bytes = $sz.Bytes; 'How to clean' = $Tip; Note = $(if ($sz.Partial) { 'partial count (timed out / access denied)' } else { '' }) }) }
    }
    $spRows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $script:Profiles) { & $addSpace "Temp files ($(Get-ShortUser $p.User))" (Join-Path $p.Path 'AppData\Local\Temp') 'Settings > System > Storage > Temporary files' }
    & $addSpace 'Windows temp files' "$env:SystemRoot\Temp" 'Settings > System > Storage > Temporary files'
    & $addSpace 'Downloaded Windows Update files' "$env:SystemRoot\SoftwareDistribution\Download" 'Disk Cleanup > Clean up system files > Windows Update Cleanup'
    & $addSpace 'Previous Windows installation (Windows.old)' "$env:SystemDrive\Windows.old" 'Settings > System > Storage > Temporary files > Previous Windows installation(s)'
    & $addSpace 'Delivery Optimization cache' "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache" 'Temporary files > Delivery Optimization Files'
    if ($script:IsAdmin) { & $addSpace 'Recycle Bin (all users)' "$env:SystemDrive\`$Recycle.Bin" 'Empty the Recycle Bin' }
    foreach ($p in $script:Profiles) {
        & $addSpace "Chrome cache ($(Get-ShortUser $p.User))" (Join-Path $p.Path 'AppData\Local\Google\Chrome\User Data\Default\Cache') 'Chrome > Delete browsing data > Cached images and files'
        & $addSpace "Edge cache ($(Get-ShortUser $p.User))" (Join-Path $p.Path 'AppData\Local\Microsoft\Edge\User Data\Default\Cache') 'Edge > Clear browsing data > Cached images and files'
        & $addSpace "Downloads folder ($(Get-ShortUser $p.User))" (Join-Path $p.Path 'Downloads') 'Delete old installers and files you no longer need'
    }
    foreach ($f in @("$env:SystemDrive\hiberfil.sys", "$env:SystemDrive\pagefile.sys")) {
        try { $fi = Get-Item -LiteralPath $f -Force -ErrorAction Stop; $spRows.Add([pscustomobject]@{ What = (Split-Path $f -Leaf); Location = $f; Size = (Format-Bytes $fi.Length); _Bytes = 0; 'How to clean' = $(if ($f -match 'hiber') { 'Only if hibernate is never used: powercfg /h off (admin)' } else { 'Managed by Windows - leave it' }); Note = 'system file' }) } catch {}
    }
    $rows = @($spRows | Sort-Object _Bytes -Descending)
    Add-Table -Section $S -Title 'Space that can be reclaimed' -Rows $rows -Columns @('What', 'Size', 'How to clean', 'Location', 'Note')
    $total = ($spRows | Measure-Object _Bytes -Sum).Sum
    if ($total -gt 10GB) {
        Add-Finding -Severity Low -Category 'Storage' -Section $S -Title "About $(Format-Bytes $total) of junk/temporary data can be cleared" -Evidence @($rows | Where-Object { $_._Bytes -gt 500MB } | ForEach-Object { "$($_.What): $($_.Size)" }) `
            -Fix 'Settings > System > Storage > Temporary files (tick everything except Downloads unless reviewed) > Remove files.' `
            -Actions @((New-RepairAction -Kind Run -Label 'Clear temp folders and the Windows Update download cache' -Params @{ Command = 'cleanmgr-auto' }),
                (New-RepairAction -Kind Run -Label 'Empty the Recycle Bin' -Risk caution -Params @{ Command = 'empty-recyclebin' }),
                (New-RepairAction -Kind Open -Label 'Open Storage settings for the rest (Windows.old, Downloads, browser caches)' -Risk guided -Params @{ Uri = 'ms-settings:storagesense' }))
    }
}
