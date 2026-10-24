# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# System integrity: component store health, system files (deep), Defender quick scan (deep), pending updates result

function Invoke-IntegrityScan {
    $S = 'integrity'
    $kv = [ordered]@{}

    $pr = @($script:Shared.PendingReboot)
    $kv['Restart pending'] = $(if ($pr.Count) { 'Yes - ' + ($pr -join ', ') } else { 'No' })

    $cf = @($script:CorruptFiles | Where-Object { $_ } | Select-Object -Unique)
    if ($cf.Count -gt 0) {
        Add-Table -Section $S -Title 'Corrupted program files' -Rows @($cf | ForEach-Object { $fi = New-Object IO.FileInfo($_); [pscustomobject]@{ File = $_; Size = (Format-Bytes $fi.Length); Modified = $fi.LastWriteTime; _Flag = 'medium' } }) `
            -Note 'These are referenced by shortcuts, startup entries, services or processes, but the file is not a valid program (usually zero-filled).'
        Add-Finding -Severity Medium -Category 'System Integrity' -Section $S -Title "$($cf.Count) program file(s) are corrupted" -Evidence $cf `
            -Why 'The files are filled with zeros/garbage, which typically happens after a crash or power loss while writing, a completely full disk, or a failing drive. The programs they belong to will not start.' `
            -Fix 'Reinstall the affected programs. Check the drive health and free space in the Hardware section first. If Windows files are among them, run sfc /scannow as admin.' `
            -Actions @((New-RepairAction -Kind Open -Label 'Open Installed apps to repair/reinstall the affected programs' -Risk guided -Params @{ Uri = 'ms-settings:appsfeatures' }))
    }

    if (-not $script:IsAdmin) {
        Add-Note -Section $S -Text 'System file and component-store checks need administrator rights and were skipped.' -Tone warn
    } else {
        Write-Status 'Checking the Windows component store (DISM /CheckHealth)...'
        $dism = Invoke-External -File "$env:SystemRoot\System32\dism.exe" -Arguments '/Online /Cleanup-Image /CheckHealth /English' -TimeoutSec 300
        $state = if ($dism.TimedOut) { 'Timed out' } elseif ($dism.Output -match '(?i)No component store corruption detected') { 'Healthy' } elseif ($dism.Output -match '(?i)repairable') { 'CORRUPTED (repairable)' } elseif ($dism.Output -match '(?i)not repairable') { 'CORRUPTED (not repairable)' } else { 'Unknown' }
        $kv['Component store (DISM)'] = $state
        if ($state -like 'CORRUPTED*') {
            Add-Finding -Severity $(if ($state -match 'not repairable') { 'High' } else { 'Medium' }) -Category 'System Integrity' -Section $S -Title "Windows component store is $state" `
                -Why 'Corruption here breaks Windows Update and can cause random errors.' -Fix 'Run as admin: DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow, then restart.' `
                -Actions @((New-RepairAction -Kind Run -Label 'Repair the component store (DISM /RestoreHealth, 10-30 min)' -Params @{ Command = 'dism-restorehealth' }),
                    (New-RepairAction -Kind Run -Label 'Repair system files (sfc /scannow, 10-20 min)' -Reboot -Params @{ Command = 'sfc-scannow' }))
        } elseif ($state -eq 'Healthy') { Add-Pass 'System Integrity' 'Windows component store is healthy' }

        if ($script:Mode -eq 'Deep') {
            Write-Status 'Verifying Windows system files (sfc /verifyonly) - this can take 10-20 minutes...'
            $sfc = Invoke-External -File "$env:SystemRoot\System32\sfc.exe" -Arguments '/verifyonly' -TimeoutSec 2400
            $sstate = if ($sfc.TimedOut) { 'Timed out' } elseif ($sfc.Output -match '(?i)did not find any integrity violations') { 'No problems' } elseif ($sfc.Output -match '(?i)found integrity violations') { 'INTEGRITY VIOLATIONS FOUND' } elseif ($sfc.Output -match '(?i)could not perform') { 'Could not run' } else { 'Unknown (see raw output)' }
            $kv['System files (SFC)'] = $sstate
            Add-Action 'Ran sfc /verifyonly (read-only check of Windows system files)'
            if ($sstate -like 'INTEGRITY*') {
                Add-Finding -Severity Medium -Category 'System Integrity' -Section $S -Title 'Some Windows system files are damaged or modified' `
                    -Why 'Damaged system files cause crashes and odd errors; malware sometimes patches them.' -Fix 'Run as admin: sfc /scannow (repairs them). If it cannot fix everything, run DISM /Online /Cleanup-Image /RestoreHealth first, then sfc /scannow again.' `
                    -Actions @((New-RepairAction -Kind Run -Label 'Repair the component store first (DISM /RestoreHealth)' -Params @{ Command = 'dism-restorehealth' }),
                        (New-RepairAction -Kind Run -Label 'Repair system files (sfc /scannow)' -Reboot -Params @{ Command = 'sfc-scannow' }))
            } elseif ($sstate -eq 'No problems') { Add-Pass 'System Integrity' 'Windows system files verified OK' }
            if ($sstate -like 'Unknown*') { Add-Note -Section $S -Text ('SFC output: ' + (Limit-Text $sfc.Output 600)) }
        }
    }

    if ($script:Mode -eq 'Deep') {
        try {
            Write-Status 'Updating Defender definitions...'
            Update-MpSignature -ErrorAction Stop
            Add-Action 'Updated Microsoft Defender definitions'
        } catch { Add-Note -Section $S -Text "Defender definition update failed: $($_.Exception.Message)" -Tone warn }
        try {
            Write-Status 'Running a Defender quick scan (a few minutes)...'
            $t0 = Get-Date
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
            Add-Action "Ran a Microsoft Defender quick scan ($([int]((Get-Date) - $t0).TotalMinutes) min)"
            $kv['Defender quick scan'] = 'Completed ' + (Get-Date).ToString('HH:mm')
            $new = @()
            try { $new = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $t0.AddMinutes(-1) }) } catch {}
            $names = @{}
            try { foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $names[[string]$t.ThreatID] = $t.ThreatName } } catch {}
            if ($new.Count -gt 0) {
                $list = @($new | ForEach-Object { "$($names[[string]$_.ThreatID]): $((@($_.Resources) | Select-Object -First 3) -join ', ')" })
                Add-Finding -Severity High -Category 'Malware & PUPs' -Section $S -Title "Defender quick scan found $($new.Count) threat(s) during this scan" -Evidence $list `
                    -Why 'Active threats were on the PC at the time of the scan.' -Fix 'Windows Security > Protection history: make sure each is quarantined/removed, then run a Full scan and a Microsoft Defender Offline scan.'
                $kv['Defender quick scan'] += " - found $($new.Count) threat(s)"
            } else { Add-Pass 'Malware & PUPs' 'Defender quick scan found nothing' 'Run during this scan with fresh definitions' }
        } catch { Add-Note -Section $S -Text "Defender quick scan could not run: $($_.Exception.Message) (another antivirus may be primary)." -Tone warn }
    }
    Add-KV -Section $S -Title 'Checks' -Data $kv

    Complete-PendingUpdateSearch -TimeoutSec $(if ($script:Mode -eq 'Deep') { 360 } else { 150 })
}
