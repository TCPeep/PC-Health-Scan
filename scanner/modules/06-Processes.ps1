# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Running processes: signatures, locations, masquerading, odd parents, suspicious command lines, live CPU/RAM

function Invoke-ProcessesScan {
    $S = 'processes'
    $cim = @(Get-CimInstance Win32_Process)
    $cores = [Environment]::ProcessorCount
    $t1 = @{}
    foreach ($p in (Get-Process)) { try { $t = $p.TotalProcessorTime; if ($null -ne $t) { $t1[$p.Id] = $t.TotalMilliseconds } } catch {} }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 2000
    $cpu = @{}; $ws = @{}
    foreach ($p in (Get-Process)) {
        $ws[$p.Id] = $p.WorkingSet64
        try { $t = $p.TotalProcessorTime; if ($null -ne $t -and $t1.ContainsKey($p.Id)) { $cpu[$p.Id] = [Math]::Round((($t.TotalMilliseconds - $t1[$p.Id]) / $sw.Elapsed.TotalMilliseconds / $cores) * 100, 1) } } catch {}
    }
    $byPid = @{}
    foreach ($c in $cim) { $byPid[[int]$c.ProcessId] = $c }
    # The console/shell that launched this scan (START-SCAN.cmd -> powershell) must not be reported as suspicious.
    $selfChain = @{}
    $cur = $PID
    for ($k = 0; $k -lt 6 -and $cur; $k++) {
        $pp = $byPid[[int]$cur]
        if (-not $pp) { break }
        if ($k -gt 0 -and [string]$pp.Name -notmatch '^(?i)(powershell|pwsh|cmd|conhost|WindowsTerminal|OpenConsole)\.exe$') { break }
        $selfChain[[int]$cur] = $true
        $cur = [int]$pp.ParentProcessId
    }
    $index = @{}
    $rows = @()
    $officeRx = '^(winword|excel|powerpnt|outlook|onenote|msaccess|mspub|acrord32|acrobat)\.exe$'
    $shellRx = '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil)\.exe$'
    $flaggedFindings = @{}

    foreach ($c in $cim) {
        $procId = [int]$c.ProcessId
        $path = $c.ExecutablePath
        $name = [string]$c.Name
        $parent = $byPid[[int]$c.ParentProcessId]
        $parentName = if ($parent) { [string]$parent.Name } else { '' }
        $sev = $null; $reasons = @()
        $sig = $null
        $zone = Get-PathZone $path
        if ($path) {
            $sig = Get-FileSig $path
            if (Test-Masquerade $path) { $sev = Get-MaxSeverity @($sev, 'Critical'); $reasons += "Uses a Windows system process name but runs from $zone" }
            if ($sig.Status -eq 'HashMismatch') { $sev = Get-MaxSeverity @($sev, 'High'); $reasons += 'Signature broken (file modified)' }
            elseif ((-not $sig.Trusted) -and (-not $sig.Skipped) -and $sig.Exists) {
                if ($zone -in 'Temp', 'Downloads', 'AppData\Roaming', 'Users\Public', 'RecycleBin') { $sev = Get-MaxSeverity @($sev, 'High'); $reasons += "Unsigned, running from $zone" }
                elseif (Test-UserWritableZone $zone) { $sev = Get-MaxSeverity @($sev, 'Medium'); $reasons += "Unsigned, running from $zone" }
            }
        }
        $pup = Find-Pup @($name, $path, $(if ($sig) { $sig.Signer } else { '' }), $c.CommandLine)
        if ($pup) { $sev = Get-MaxSeverity @($sev, $pup.Severity); $reasons += "Known adware/PUP: $($pup.Name)" }
        if ($c.CommandLine -and $c.CommandLine -match $script:StrongCmdRx) { $sev = Get-MaxSeverity @($sev, 'High'); $reasons += 'Suspicious command line' }
        if ($parentName -match $officeRx -and $name -match $shellRx) { $sev = Get-MaxSeverity @($sev, 'High'); $reasons += "Started by $parentName (macro/document exploit pattern)" }
        if ($name -eq 'svchost.exe' -and $parent -and $parentName -notin 'services.exe', 'MsMpEng.exe') { $sev = Get-MaxSeverity @($sev, 'High'); $reasons += "svchost.exe started by $parentName instead of services.exe" }
        if ($selfChain.ContainsKey($procId)) { $sev = $null; $reasons = @('This scanner / its console') }
        $knownBad = $pup -or $sev -eq 'Critical' -or ($c.CommandLine -and $c.CommandLine -match $script:StrongCmdRx) -or ($sig -and $sig.Status -eq 'HashMismatch')
        if ($sev -and $path -and -not $knownBad -and (Test-Trusted $path $(if ($sig -and $sig.Trusted) { $sig.Signer } else { '' }))) { $sev = $null; $reasons = @('Trusted by you (trusted.txt)') }

        $signer = if ($sig) { if ($sig.Trusted) { $sig.Signer } elseif ($sig.Signer) { "$($sig.Signer) [$($sig.Status)]" } else { $sig.Status } } else { '' }
        $index[$procId] = [pscustomobject]@{ Name = $name; Path = $path; Signer = $signer; Trusted = $(if ($sig) { $sig.Trusted } else { $null }); IsMicrosoft = $(if ($sig) { $sig.IsMicrosoft } else { $false }); Zone = $zone; Severity = $sev }

        $showRow = $sev -or ($path -and $sig -and -not $sig.IsMicrosoft)
        if ($showRow) {
            $rows += [pscustomobject]@{
                PID = $procId; Name = $name; 'RAM MB' = [int]($ws[$procId] / 1MB); 'CPU %' = $cpu[$procId]; Started = $c.CreationDate
                Signer = $signer; Path = $path; Parent = "$parentName ($([int]$c.ParentProcessId))"; 'Command line' = (Limit-Text $c.CommandLine 400)
                Concerns = ($reasons -join '; '); _Flag = (ConvertTo-FlagClass $sev); _Rank = $(if ($sev) { $script:SevRank[$sev] } else { 0 })
            }
        }
        if ($sev -and $sev -ne 'Info') {
            $key = "$name|$path"
            if (-not $flaggedFindings.ContainsKey($key)) {
                $flaggedFindings[$key] = $true
                $hash = if ($path) { Get-Sha256 $path } else { '' }
                Add-Finding -Severity $sev -Category 'Malware & PUPs' -Section $S -Title "Suspicious running program: $name" `
                    -Detail ($reasons -join '; ') `
                    -Evidence @("Path: $path", "PID: $procId, parent: $parentName", "Signer: $signer", "Command line: $(Limit-Text $c.CommandLine 500)", $(if ($hash) { "SHA256: $hash" })) `
                    -Why $(if ($pup) { $pup.Info } else { 'Malware usually runs unsigned from user folders, borrows Windows process names, or launches hidden scripts.' }) `
                    -Fix $(if ($pup) { 'Uninstall it from Settings > Apps, then delete leftovers listed in the Malware & PUP sweep section and re-run this scan.' } else { 'Look up the SHA256 on VirusTotal (link in the Processes table). If unknown/malicious: end the process, delete the file, remove its autostart entries (Persistence section) and run a Defender full + offline scan.' }) `
                    -Actions $(if ($path -and (Test-UserWritableZone $zone)) {
                            $rm = @((New-RepairAction -Kind StopProcess -Label "End $name" -Risk caution -Params @{ Targets = @($path) }),
                                (New-RepairAction -Kind Quarantine -Label "Quarantine $path" -Risk caution -Params @{ Targets = @($path) }))
                            if ($knownBad) { , $rm } else { New-UnknownProgramActions -Path $path -Name $name -RemoveActions $rm }
                        } elseif ($path) { , @((New-RepairAction -Kind StopProcess -Label "End $name (file is in a system folder, so it is NOT quarantined automatically - verify it first)" -Risk caution -Off:(-not $knownBad) -Params @{ Targets = @($path) })) } else { , @() })
            }
        }
    }
    $script:Shared.ProcIndex = $index

    $rows = @($rows | Sort-Object @{ Expression = '_Rank'; Descending = $true }, Name)
    Add-Table -Section $S -Title 'Non-Microsoft and flagged processes' -Rows $rows `
        -Note "Microsoft-signed Windows processes are hidden to keep this readable. $($cim.Count) processes were running in total." `
        -Columns @('Name', 'PID', 'Concerns', 'Signer', 'Path', 'RAM MB', 'CPU %', 'Parent', 'Started', 'Command line')

    # --- resource usage
    $ramByName = @{}
    foreach ($c in $cim) {
        $n = [string]$c.Name
        if (-not $ramByName.ContainsKey($n)) { $ramByName[$n] = [pscustomobject]@{ Program = $n; Instances = 0; 'RAM MB' = 0; 'CPU %' = 0.0 } }
        $o = $ramByName[$n]; $o.Instances++; $o.'RAM MB' += [int]($ws[[int]$c.ProcessId] / 1MB)
        if ($cpu.ContainsKey([int]$c.ProcessId)) { $o.'CPU %' = [Math]::Round($o.'CPU %' + $cpu[[int]$c.ProcessId], 1) }
    }
    Add-Table -Section $S -Title 'Top memory users (grouped by program)' -Rows @($ramByName.Values | Sort-Object 'RAM MB' -Descending | Select-Object -First 12)
    Add-Table -Section $S -Title 'Top CPU users (2-second sample)' -Rows @($ramByName.Values | Where-Object { $_.'CPU %' -gt 0 } | Sort-Object 'CPU %' -Descending | Select-Object -First 10)

    $os = Get-CimInstance Win32_OperatingSystem
    $usedPct = [Math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) * 100)
    $totalCpu = [Math]::Round((($cpu.Values | Measure-Object -Sum).Sum), 0)
    $script:Shared.RamUsedPct = $usedPct
    Add-KV -Section $S -Title 'Right now' -Data ([ordered]@{ 'Memory in use' = "$usedPct% of $(Format-Bytes ($os.TotalVisibleMemorySize * 1KB))"; 'CPU in use (sample)' = "$totalCpu%"; 'Processes' = $cim.Count })
    if ($usedPct -ge 90) {
        $top = ($ramByName.Values | Sort-Object 'RAM MB' -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Program) $($_.'RAM MB') MB" }) -join ', '
        Add-Finding -Severity Medium -Category 'Performance' -Section $S -Title "Memory is $usedPct% full right now" -Detail "Biggest users: $top" `
            -Why 'When RAM is full Windows swaps to disk and everything slows down.' -Fix 'Close unused programs/browser tabs, remove startup apps you do not need, or add RAM.'
    }
    if ($totalCpu -ge 85) {
        $top = ($ramByName.Values | Sort-Object 'CPU %' -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Program) $($_.'CPU %')%" }) -join ', '
        Add-Finding -Severity Low -Category 'Performance' -Section $S -Title "CPU was $totalCpu% busy during the sample" -Detail "Busiest: $top" -Fix 'If this persists when the PC is idle, investigate the top program (unknown miners show up here).'
    }
}
