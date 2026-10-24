# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Repair engine self-test: real Apply -> Undo round trips, run WITHOUT admin rights.
# Only touches HKCU\Software\PCHS-SelfTest, one fake HKCU Apps-list entry (PCHS-SelfTestApp) and a temp folder;
# everything is cleaned up at the end. Run after editing lib\Repair.ps1:
#   powershell -NoProfile -ExecutionPolicy Bypass -File dev\repair-selftest.ps1
#
# It can NEVER end a program on this PC: (1) the engine's test mode only logs what it would end, and
# (2) Stop-Process / Stop-Service / restarts are replaced below by stubs that refuse, so even a bug in the
# guard has nothing real to call. (An earlier version without these closed every per-user app. Never again.)
$ErrorActionPreference = 'Stop'
function Stop-Process { throw 'SELFTEST: Stop-Process is disabled in the self-test' }
function Stop-Service { throw 'SELFTEST: Stop-Service is disabled in the self-test' }
function Restart-Computer { throw 'SELFTEST: disabled' }
function Checkpoint-Computer { throw 'SELFTEST: disabled' }
$lib = Join-Path (Split-Path $PSScriptRoot -Parent) 'scanner\lib'
. (Join-Path $lib 'Core.ps1')
. (Join-Path $lib 'Repair.ps1')
$script:RepairNoKill = $true
if ((Get-Command Stop-Process).CommandType -ne 'Function') { throw 'Stop-Process stub not active - aborting before anything runs' }

$tmp = Join-Path $env:TEMP ('pchs-selftest-' + (Get-Date).ToString('HHmmss'))
$script:RepairTestStore = Join-Path $tmp 'store'
New-Item -ItemType Directory -Path $script:RepairTestStore -Force | Out-Null
$ctx = [hashtable]::Synchronized(@{ Base = $script:RepairTestStore; SessionId = 'SELFTEST'; State = [hashtable]::Synchronized(@{ RestorePointDone = $true }); TrustFile = (Join-Path $tmp 'trusted.txt') })
$ctx.Journal = Join-Path $ctx.Base 'undo-journal.jsonl'
$ctx.SessionDir = Join-Path $ctx.Base 'Sessions\SELFTEST'; $ctx.Quarantine = Join-Path $ctx.SessionDir 'Quarantine'; $ctx.Backups = Join-Path $ctx.SessionDir 'Backups'
$logLines = New-Object System.Collections.Generic.List[string]
$log = { param($m) $logLines.Add($m) }
$results = New-Object System.Collections.Generic.List[object]
function Check { param([string]$Name, [bool]$Cond, [string]$Info = '') $results.Add([pscustomobject]@{ Test = $Name; Result = $(if ($Cond) { 'PASS' } else { 'FAIL' }); Info = $Info }) }
function Fix { param([string]$Job, [hashtable]$Action) $c = @{}; foreach ($k in @($ctx.Keys)) { $c[$k] = $ctx[$k] }; $c.Job = $Job; $c.Item = $Job; Invoke-RepairAction -Action $Action -Log $log -Ctx $c }
function UndoJob {
    param([string]$Job)
    $recs = @(Get-UndoJournal $ctx.Journal | Where-Object { $_.job -eq $Job -and -not $_.Undone }); [array]::Reverse($recs)
    $ok = $true
    foreach ($r in $recs) { $c = @{}; foreach ($k in @($ctx.Keys)) { $c[$k] = $ctx[$k] }; $c.Job = "undo-$Job"; if (-not (Invoke-UndoRecord -Record $r -Log $log -Ctx $c).Ok) { $ok = $false } }
    [pscustomobject]@{ Ok = $ok; Count = $recs.Count }
}
$hk = 'Registry::HKEY_CURRENT_USER\Software\PCHS-SelfTest'
$uk = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\PCHS-SelfTestApp'

try {
    # ---- registry values of every type
    New-Item -Path $hk -Force | Out-Null
    New-ItemProperty -LiteralPath $hk -Name 'Str' -PropertyType String -Value 'orig' | Out-Null
    New-ItemProperty -LiteralPath $hk -Name 'Exp' -PropertyType ExpandString -Value '%SystemRoot%\x' | Out-Null
    New-ItemProperty -LiteralPath $hk -Name 'Dw' -PropertyType DWord -Value -5 | Out-Null
    New-ItemProperty -LiteralPath $hk -Name 'Bin' -PropertyType Binary -Value ([byte[]](1, 2, 3, 250)) | Out-Null
    New-ItemProperty -LiteralPath $hk -Name 'Multi' -PropertyType MultiString -Value @('a', 'b c') | Out-Null
    $r = Fix 'reg' (New-RepairAction -Kind RegSetValue -Label 't' -Params @{ Path = $hk; Name = 'Str'; Type = 'String'; Value = 'new' })
    $r2 = Fix 'reg' (New-RepairAction -Kind RegSetValue -Label 't' -Params @{ Path = $hk; Name = 'Absent'; Value = 7 })
    foreach ($n in 'Exp', 'Dw', 'Bin', 'Multi') { $null = Fix 'reg' (New-RepairAction -Kind RegDeleteValue -Label 't' -Params @{ Path = $hk; Name = $n }) }
    Check 'RegSetValue applied' ($r.Ok -and (Get-RegValue $hk 'Str') -eq 'new' -and $r2.Ok -and (Get-RegValue $hk 'Absent') -eq 7)
    Check 'RegDeleteValue applied' ($null -eq (Get-RegValue $hk 'Bin'))
    $u = UndoJob 'reg'
    $k = Get-Item -LiteralPath $hk
    Check 'Reg undo: 6 records, all OK' ($u.Ok -and $u.Count -eq 6) "$($u.Count) records"
    Check 'Reg undo: String restored' ((Get-RegValue $hk 'Str') -eq 'orig')
    Check 'Reg undo: absent value removed again' ($null -eq (Get-RegValue $hk 'Absent'))
    Check 'Reg undo: ExpandString kept unexpanded' ($k.GetValueKind('Exp') -eq 'ExpandString' -and $k.GetValue('Exp', $null, 'DoNotExpandEnvironmentNames') -eq '%SystemRoot%\x')
    Check 'Reg undo: negative DWord' ($k.GetValueKind('Dw') -eq 'DWord' -and $k.GetValue('Dw') -eq -5)
    Check 'Reg undo: Binary bytes' ((@($k.GetValue('Bin')) -join ',') -eq '1,2,3,250')
    Check 'Reg undo: MultiString' ($k.GetValueKind('Multi') -eq 'MultiString' -and (@($k.GetValue('Multi')) -join '|') -eq 'a|b c')

    # ---- whole key (reg export / import)
    New-Item -Path "$hk\Del\Sub" -Force | Out-Null
    New-ItemProperty -LiteralPath "$hk\Del\Sub" -Name 'V' -Value 'deep' | Out-Null
    $r = Fix 'key' (New-RepairAction -Kind RegDeleteKey -Label 't' -Params @{ Path = "$hk\Del" })
    Check 'RegDeleteKey applied' ($r.Ok -and -not (Test-RegKey "$hk\Del"))
    $u = UndoJob 'key'
    Check 'RegDeleteKey undo (reg import)' ($u.Ok -and (Get-RegValue "$hk\Del\Sub" 'V') -eq 'deep')

    # ---- quarantine a program folder + its Apps-list entry, then undo
    $app = Join-Path $tmp 'Users\Jane\FakeApp'
    New-Item -ItemType Directory -Path "$app\bin" -Force | Out-Null
    Set-Content -LiteralPath "$app\bin\x.dat" -Value 'payload'
    Set-Content -LiteralPath "$app\uninst.exe" -Value 'MZ'
    New-Item -Path $uk -Force | Out-Null
    New-ItemProperty -LiteralPath $uk -Name 'DisplayName' -Value 'PCHS SelfTest App' | Out-Null
    New-ItemProperty -LiteralPath $uk -Name 'UninstallString' -Value "`"$app\uninst.exe`"" | Out-Null
    $r = Fix 'quar' (New-RepairAction -Kind Quarantine -Label 't' -Params @{ Targets = @($app) })
    Check 'Quarantine moved folder' ($r.Ok -and -not (Test-Path $app))
    Check 'Quarantine removed orphan Apps entry' (-not (Test-RegKey $uk))
    $u = UndoJob 'quar'
    Check 'Quarantine undo: folder back' ($u.Ok -and (Get-Content "$app\bin\x.dat") -eq 'payload')
    Check 'Quarantine undo: Apps entry back' ((Get-RegValue $uk 'DisplayName') -eq 'PCHS SelfTest App')

    # ---- uninstall whose uninstaller is already gone (the PC App Store case)
    Remove-Item -LiteralPath "$app\uninst.exe" -Force
    $r = Fix 'unin' (New-RepairAction -Kind Uninstall -Label 't' -Params @{ Name = 'PCHS SelfTest App'; Command = "`"$app\uninst.exe`"" })
    Check 'Uninstall with missing uninstaller succeeds' ($r.Ok -and -not (Test-RegKey $uk))
    $u = UndoJob 'unin'
    Check 'Uninstall orphan cleanup undo' ($u.Ok -and (Test-RegKey $uk))

    # ---- refusals: the guard must say no BEFORE any program is considered for ending
    foreach ($bad in @($env:USERPROFILE, $env:LOCALAPPDATA, "$env:LOCALAPPDATA\Programs", $env:APPDATA, "$env:USERPROFILE\Desktop", $env:SystemRoot, "$env:SystemRoot\System32",
            $env:ProgramFiles, "$env:ProgramFiles\Windows Defender", $env:ProgramData, 'C:\', (Split-Path (Split-Path $lib -Parent) -Parent))) {
        Check "Protected: $bad" (Test-ProtectedPath $bad)
    }
    $logLines.Clear()
    $r = Fix 'refuse' (New-RepairAction -Kind Quarantine -Label 't' -Params @{ Targets = @($env:USERPROFILE) })
    Check 'Quarantine of profile refused before ending anything' (-not $r.Ok -and (Test-Path $env:USERPROFILE) -and -not ($logLines -match '^\s+(ended |\[TEST MODE\] would end|\[SIMULATE\] would end)')) ($logLines -join ' | ')
    $logLines.Clear()
    $r = Fix 'refuse' (New-RepairAction -Kind StopProcess -Label 't' -Params @{ Targets = @("$env:LOCALAPPDATA\Programs") })
    Check 'StopProcess on AppData\Local\Programs refused' (-not $r.Ok -and -not ($logLines -match '^\s+(ended |\[TEST MODE\] would end|\[SIMULATE\] would end)'))
    $logLines.Clear()
    $ok = Stop-TargetProcesses -Path "$env:SystemRoot\System32\svchost.exe" -Log $log
    Check 'Never ends Windows processes' (-not $ok -and -not ($logLines -match '^\s+(ended |\[TEST MODE\] would end|\[SIMULATE\] would end)'))
    $pwsh = (Get-Process -Id $PID).Path
    $logLines.Clear()
    $ok = Stop-TargetProcesses -Path $pwsh -Log $log
    Check 'Never ends its own process' (-not $ok -and ($logLines -match 'REFUSED'))
    $logLines.Clear()
    Check 'Never touches Windows services (by list)' ((Test-ProtectedService 'WinDefend' $log) -and (Test-ProtectedService 'wuauserv' $log))
    Check 'Never touches Windows services (Microsoft-signed svchost DLL)' ((Test-ProtectedService 'W32Time' $log) -and (Test-ProtectedService 'Spooler' $log))
    Check 'Plain safe/caution enforcement' ((Get-EnforcedRisk @{ Kind = 'Run'; Command = 'cleanmgr-auto'; Risk = 'safe' }) -eq 'caution' -and (Get-EnforcedRisk @{ Kind = 'Quarantine'; Risk = 'safe' }) -eq 'caution' -and (Get-EnforcedRisk @{ Kind = 'RegSetValue'; Risk = 'safe' }) -eq 'safe')
    $bad = [pscustomobject]@{ id = 'x'; desc = 't'; Undone = $false; undo = [pscustomobject]@{ Kind = 'MoveBack'; From = $app; To = "$env:SystemRoot\pchs-should-not-exist"; Legacy = $true } }
    Check 'Refuses legacy restore into Windows' (-not (Invoke-UndoRecord -Record $bad -Log $log -Ctx $ctx).Ok -and -not (Test-Path "$env:SystemRoot\pchs-should-not-exist"))
    $bad2 = [pscustomobject]@{ id = 'y'; desc = 't'; Undone = $false; undo = [pscustomobject]@{ Kind = 'RegImport'; File = "$tmp\outside.reg" } }
    Set-Content "$tmp\outside.reg" 'Windows Registry Editor Version 5.00'
    Check 'Refuses .reg import from outside the store' (-not (Invoke-UndoRecord -Record $bad2 -Log $log -Ctx $ctx).Ok)

    # ---- trust list
    $r = Fix 'trust' (New-RepairAction -Kind Trust -Label 't' -Params @{ Path = 'C:\Users\x\AppData\Local\Programs\MyApp\MyApp.exe' })
    Import-TrustList $ctx.TrustFile
    Check 'Trust adds path' ($r.Ok -and (Test-Trusted 'C:\Users\x\AppData\Local\Programs\MyApp\MyApp.exe' ''))
    $u = UndoJob 'trust'
    Import-TrustList $ctx.TrustFile
    Check 'Trust undo removes it' ($u.Ok -and -not (Test-Trusted 'C:\Users\x\AppData\Local\Programs\MyApp\MyApp.exe' ''))

    # ---- sideloaded browser extension (the "Success Advanced Success" case)
    $id = 'bdbmheonboafjamladoffpohkdekgeom'
    $prof = Join-Path $tmp 'Users\Jane\AppData\Local\Microsoft\Edge\User Data\Default'
    $side = Join-Path $tmp 'Users\Jane\AppData\Local\599aa\599aac76cf13f828105ea0b36c42333e'
    New-Item -ItemType Directory -Path $prof, $side -Force | Out-Null
    Set-Content -LiteralPath "$side\manifest.json" -Value '{"name":"Success Advanced Success","version":"1.0"}'
    $sideJson = $side -replace '\\', '\\'
    [IO.File]::WriteAllText("$prof\Preferences", "{`"extensions`":{`"settings`":{`"$id`":{`"location`":4,`"path`":`"$sideJson`"}},`"pinned_extensions`":[`"$id`"]},`"homepage`":`"x`"}")
    [IO.File]::WriteAllText("$prof\Secure Preferences", "{`"extensions`":{`"settings`":{`"$id`":{`"location`":4}}},`"protection`":{`"macs`":{`"extensions`":{`"settings`":{`"$id`":`"ABC`"}}}}}")
    $r = Fix 'ext' (New-RepairAction -Kind BrowserReset -Label 't' -Params @{ ProfileDir = $prof; ExtensionId = $id; Process = ''; ExtDir = $side })
    $p1 = [IO.File]::ReadAllText("$prof\Preferences"); $p2 = [IO.File]::ReadAllText("$prof\Secure Preferences")
    Check 'Extension: sideloaded folder quarantined' ($r.Ok -and -not (Test-Path $side))
    Check 'Extension: empty random parent folder removed' (-not (Test-Path (Split-Path $side -Parent)))
    Check 'Extension: removed from both preference files' ($p1 -notmatch $id -and $p2 -notmatch $id -and $p1 -match '"homepage":"x"')
    $u = UndoJob 'ext'
    Check 'Extension undo: folder + both files back' ($u.Ok -and (Test-Path "$side\manifest.json") -and [IO.File]::ReadAllText("$prof\Preferences") -match $id -and [IO.File]::ReadAllText("$prof\Secure Preferences") -match $id)

    # ---- live output streaming (progress with carriage returns, UTF-16 output like sfc)
    $logLines.Clear()
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $sr = Invoke-StreamedProcess -File $ps -Arguments '-NoProfile -Command "foreach ($i in 0..10) { [Console]::Out.Write(\"Verification $($i*10)% complete.`r\"); Start-Sleep -Milliseconds 120 }; [Console]::Out.WriteLine(\"\"); \"done line\""' -TimeoutSec 60 -Log $log
    $prog = @($logLines | Where-Object { $_ -match 'progress' })
    Check 'Streaming: progress lines throttled' ($prog.Count -ge 3 -and $prog.Count -le 11 -and ($logLines -match 'done line')) "$($prog.Count) progress lines"
    $logLines.Clear()
    $sr = Invoke-StreamedProcess -File "$env:SystemRoot\System32\cmd.exe" -Arguments '/u /c echo unicode-ok' -TimeoutSec 30 -Log $log
    Check 'Streaming: UTF-16 output decoded' (($logLines -join ' ') -match 'unicode-ok')

    # ---- legacy MANIFEST import gives old quarantine items a Restore button
    $lq = Join-Path $tmp 'Reports\OLD\Quarantine_2026-10-16_1820'
    New-Item -ItemType Directory -Path $lq -Force | Out-Null
    Set-Content -LiteralPath "$lq\C_Users_Jane_Thing.lnk" -Value 'lnk'
    [IO.File]::WriteAllText("$lq\MANIFEST.txt", "2026-10-16T18:24:58`t$lq\C_Users_Jane_Thing.lnk`tC:\Users\pchs-selftest-nobody\Thing.lnk`r`n")
    $n1 = Import-LegacyQuarantine -Ctx $ctx -ReportsRoot (Join-Path $tmp 'Reports')
    $n2 = Import-LegacyQuarantine -Ctx $ctx -ReportsRoot (Join-Path $tmp 'Reports')
    Check 'Legacy import once (no duplicates)' ($n1 -eq 1 -and $n2 -eq 0) "first=$n1 second=$n2"

    # ---- PC App Store complete removal - FAKE stand-ins only (empty dummy files, fake registry hives under
    #      HKCU\Software\PCHS-SelfTest). The real program is never downloaded or used.
    $jane = Join-Path $tmp 'Users\Jane'
    $pdir = Join-Path $jane 'PCAppStore'
    New-Item -ItemType Directory -Path "$pdir\nwjs", "$pdir\UserData" -Force | Out-Null
    foreach ($n in 'PCAppStore.exe', 'Watchdog.exe', 'AutoUpdater.exe', 'Uninstaller.exe') { Set-Content -LiteralPath (Join-Path $pdir $n) -Value 'fake stand-in, not a program' }
    $sm = Join-Path $jane 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
    New-Item -ItemType Directory -Path $sm, "$jane\Desktop" -Force | Out-Null
    $wsh = New-Object -ComObject WScript.Shell
    foreach ($lp in "$sm\PC App Store.lnk", "$jane\Desktop\PC App Store.lnk") { $s = $wsh.CreateShortcut($lp); $s.TargetPath = "$pdir\PCAppStore.exe"; $s.Save() }
    $decoyLnk = "$jane\Desktop\Notepad.lnk"; $s = $wsh.CreateShortcut($decoyLnk); $s.TargetPath = "$env:SystemRoot\notepad.exe"; $s.Save()
    $fakeHive = "$hk\Hive"; $fakeHklm = "$hk\HKLM"
    $run = "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Run"
    New-Item -Path $run, "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "$fakeHive\Software\PCAppStore", "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore", "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Uninstall\OtherApp" -Force | Out-Null
    New-ItemProperty -LiteralPath $run -Name 'PCAppStore' -Value "`"$pdir\PCAppStore.exe`" /src=autostart" | Out-Null
    New-ItemProperty -LiteralPath $run -Name 'PcAppStoreUpdater' -Value "`"$pdir\AutoUpdater.exe`" /i" | Out-Null
    New-ItemProperty -LiteralPath $run -Name 'Watchdog' -Value "`"$pdir\Watchdog.exe`"" | Out-Null
    New-ItemProperty -LiteralPath $run -Name 'OtherApp' -Value '"C:\Program Files\Other\other.exe"' | Out-Null
    # a uniquely-named PC App Store program living OUTSIDE its folder (must be found + quarantined)...
    $desk = Join-Path $jane 'AppData\Local\Tools\AppStoreDeskTool.exe'
    New-Item -ItemType Directory -Path (Split-Path $desk) -Force | Out-Null; Set-Content -LiteralPath $desk -Value 'fake stand-in'
    New-ItemProperty -LiteralPath $run -Name 'DeskTool' -Value "`"$desk`" --tray" | Out-Null
    # ...and a generically-named Watchdog.exe of some other app outside it (must NOT be touched)
    $otherWd = Join-Path $jane 'AppData\Local\GpuTool\Watchdog.exe'
    New-Item -ItemType Directory -Path (Split-Path $otherWd) -Force | Out-Null; Set-Content -LiteralPath $otherWd -Value 'decoy'
    New-ItemProperty -LiteralPath $run -Name 'GpuWatchdog' -Value "`"$otherWd`"" | Out-Null
    New-ItemProperty -LiteralPath "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name 'PCAppStore' -PropertyType Binary -Value ([byte[]](2, 0, 0, 0)) | Out-Null
    New-ItemProperty -LiteralPath "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore" -Name 'DisplayName' -Value 'PC App Store' | Out-Null
    New-ItemProperty -LiteralPath "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore" -Name 'Publisher' -Value 'Fast Corporation LTD' | Out-Null
    New-ItemProperty -LiteralPath "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Uninstall\OtherApp" -Name 'DisplayName' -Value 'Other App' | Out-Null
    $wowRun = "$fakeHklm\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; $hklmRun = "$fakeHklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    New-Item -Path $wowRun, $hklmRun, "$fakeHklm\SOFTWARE\WOW6432Node\PCAppStore" -Force | Out-Null
    New-ItemProperty -LiteralPath $wowRun -Name 'Watchdog' -Value "`"$pdir\Watchdog.exe`"" | Out-Null
    New-ItemProperty -LiteralPath $hklmRun -Name 'Watchdog' -Value '"C:\Program Files\GPU Vendor\Watchdog.exe"' | Out-Null   # decoy: same name, different program
    $pctx = Get-PcasContext -Profiles @([pscustomobject]@{ Sid = 'S-1-5-21-0-0-0-1001'; User = 'TEST\Jane'; Path = $jane; Hive = $fakeHive }) -MachineRoot $fakeHklm -MachineFolders @() -SkipSystemWide
    $found = @((Find-PCAppStore -Context $pctx).Items)
    $byType = @{}; foreach ($g in ($found | Group-Object Type)) { $byType[$g.Name] = $g.Count }
    $summary = ($byType.Keys | Sort-Object | ForEach-Object { "$_=$($byType[$_])" }) -join ' '
    Check 'PCAppStore: finds everything' ($byType['Folder'] -eq 1 -and $byType['RunValue'] -eq 5 -and $byType['StartupApproved'] -eq 1 -and $byType['RegKey'] -eq 2 -and $byType['AppsListEntry'] -eq 1 -and $byType['Shortcut'] -eq 2 -and $byType['File'] -eq 1) $summary
    Check 'PCAppStore: decoys not matched' (-not ($found | Where-Object { $_.Path -match 'GPU Vendor|GpuTool|other\.exe|notepad' -or $_.Name -in 'OtherApp', 'GpuWatchdog' -or $_.Detail -match 'GpuTool' }))
    Check 'PCAppStore: unique names never matched inside Windows' (-not (Test-PcasPath "$env:SystemRoot\System32\PCAppStore.exe") -and (Test-PcasPath 'C:\Users\x\AppData\Local\Tools\AppStoreDeskTool.exe') -and -not (Test-PcasPath 'C:\Users\x\AppData\Local\GpuTool\Watchdog.exe'))
    $logLines.Clear()
    $c = @{}; foreach ($k in @($ctx.Keys)) { $c[$k] = $ctx[$k] }; $c.Job = 'pcas-sim'; $c.Item = 'pcas'
    $sim = Invoke-PCAppStoreRemoval -Ctx $c -Log $log -DryRun -Context $pctx
    Check 'PCAppStore: Simulate changes nothing' ((Test-Path "$pdir\Watchdog.exe") -and (Get-RegValue $run 'Watchdog') -and @(Get-UndoJournal $ctx.Journal | Where-Object { $_.job -eq 'pcas-sim' }).Count -eq 0)
    $logLines.Clear()
    $c.Job = 'pcas'
    $r = Invoke-PCAppStoreRemoval -Ctx $c -Log $log -Context $pctx
    $left = @((Find-PCAppStore -Context $pctx).Items)
    Check 'PCAppStore: removal reports success' ($r.Ok) (($logLines | Where-Object { $_ -match 'FAILED|STILL|REFUSED' }) -join ' | ')
    Check 'PCAppStore: nothing left afterwards' ($left.Count -eq 0) (($left | ForEach-Object { "$($_.Type) $($_.Path) $($_.Name)" }) -join ' | ')
    Check 'PCAppStore: decoys untouched' ((Get-RegValue $run 'OtherApp') -and (Get-RegValue $run 'GpuWatchdog') -and (Test-Path $otherWd) -and (Get-RegValue $hklmRun 'Watchdog') -and (Test-RegKey "$fakeHive\Software\Microsoft\Windows\CurrentVersion\Uninstall\OtherApp") -and (Test-Path $decoyLnk))
    Check 'PCAppStore: stand-alone program file quarantined' (-not (Test-Path $desk))
    Check 'PCAppStore: startup entries removed before the folder' ([array]::IndexOf(@($logLines), ($logLines | Where-Object { $_ -match "startup entry 'Watchdog'" } | Select-Object -First 1)) -lt [array]::IndexOf(@($logLines), ($logLines | Where-Object { $_ -match 'Quarantine its folder' } | Select-Object -First 1)))
    $u = UndoJob 'pcas'
    Check 'PCAppStore: Undo puts every item back' ($u.Ok -and @((Find-PCAppStore -Context $pctx).Items).Count -eq $found.Count) "$($u.Count) records undone"
} catch {
    Check 'UNEXPECTED ERROR' $false "$($_.Exception.Message) @ line $($_.InvocationInfo.ScriptLineNumber)"
} finally {
    Remove-Item -LiteralPath $hk -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $uk -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
$results | Format-Table -AutoSize | Out-String -Width 200
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' })
if ($failed.Count) { "---- last log lines:"; $logLines | Select-Object -Last 25 }
"{0} passed, {1} failed" -f @($results | Where-Object { $_.Result -eq 'PASS' }).Count, $failed.Count
