# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
<#
.SYNOPSIS
    Renders a sample PC-Health-Report.html from hand-written fake findings. Nothing on this PC is scanned.
    Used for the screenshots in docs/images and for the "live sample report" link in the README.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Build-DemoReport.ps1 -OutDir .\samples
#>
param([string]$OutDir)
$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $root 'samples' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

. (Join-Path $root 'scanner\lib\Core.ps1')
. (Join-Path $root 'scanner\lib\Report.ps1')

$script:Version = '1.0.0'
$script:Days = 30
$script:Cutoff = (Get-Date).AddDays(-$script:Days)
$script:Mode = 'Standard'
$script:IsAdmin = $true

$sections = @(
    @{ Id = 'system';      Title = 'System & lifecycle' }
    @{ Id = 'accounts';    Title = 'Accounts' }
    @{ Id = 'security';    Title = 'Security settings' }
    @{ Id = 'antivirus';   Title = 'Antivirus' }
    @{ Id = 'updates';     Title = 'Windows Update' }
    @{ Id = 'processes';   Title = 'Processes' }
    @{ Id = 'persistence'; Title = 'Auto-start items' }
    @{ Id = 'browsers';    Title = 'Browsers' }
    @{ Id = 'network';     Title = 'Network' }
    @{ Id = 'software';    Title = 'Installed software' }
    @{ Id = 'sweep';       Title = 'Malware & PUP sweep' }
    @{ Id = 'hardware';    Title = 'Hardware' }
    @{ Id = 'stability';   Title = 'Stability (crashes)' }
    @{ Id = 'performance'; Title = 'Performance' }
    @{ Id = 'integrity';   Title = 'System integrity' }
)
foreach ($s in $sections) { Register-Section -Id $s.Id -Title $s.Title }

# --- A believable PC with a mix of problems you'd see over AnyDesk --------------
Add-Finding -Severity Critical -Category 'Malware & PUPs' -Section 'sweep' `
    -Title 'PC App Store (Fast Corporation) adware is installed' `
    -Detail 'All of its unique parts are present: C:\Users\Sam\PCAppStore\, PCAppStore.exe is running, four scheduled tasks named PCAppStore / PcAppStoreUpdater / Watchdog, and startup entries under Run.' `
    -Why 'Pop-ups, forced sign-up pages, slower start-up, and it reinstalls itself through Watchdog if you only uninstall part of it.' `
    -Fix 'Open the Repair Console (RUN-REPAIRS.cmd) and choose "Remove PC App Store completely". It ends the programs, quarantines the folders, and removes the startup entries. Every step can be undone.' `
    -Evidence @('C:\Users\Sam\PCAppStore\PCAppStore.exe (running, PID 7412)', 'C:\Users\Sam\PCAppStore\PcAppStoreSRV.exe', 'Task \PCAppStore (runs at logon)', 'Task \Watchdog (runs every 10 minutes)', 'HKCU\...\Run\PCAppStore') `
    -Actions @((New-RepairAction -Kind Run -Label 'Remove PC App Store completely (recommended)' -Risk caution -Params @{ Command = 'remove-pcappstore' }))

Add-Finding -Severity Critical -Category 'Browser' -Section 'browsers' `
    -Title 'Chrome has a forced policy from "unknown-publisher"' `
    -Detail 'A policy at HKLM\SOFTWARE\Policies\Google\Chrome\ sets a different homepage and a different search engine, and locks them so you cannot change them from Settings.' `
    -Why 'This is what Chrome shows as "Managed by your organization" and is the usual sign of a browser hijacker.' `
    -Fix 'Delete the policy key, then set your real homepage and default search in Chrome.' `
    -Evidence @('HKLM\SOFTWARE\Policies\Google\Chrome\HomepageLocation = https://search-newsworld[.]com/', 'HKLM\SOFTWARE\Policies\Google\Chrome\DefaultSearchProviderEnabled = 1', 'HKLM\SOFTWARE\Policies\Google\Chrome\DefaultSearchProviderSearchURL = https://search-newsworld[.]com/?q={searchTerms}') `
    -Actions @(
        (New-RepairAction -Kind RegDeleteKey -Label 'Delete the Chrome hijack policy key' -Risk caution -Params @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome' }),
        (New-RepairAction -Kind Open -Label 'Open Chrome Settings to set your real search engine' -Risk guided -Params @{ Uri = 'chrome://settings/search' })
    )

Add-Finding -Severity High -Category 'Persistence' -Section 'persistence' `
    -Title 'Scheduled task "SystemHealthHelper" runs an unsigned program from a user folder' `
    -Detail 'Task "SystemHealthHelper" starts at every logon and runs C:\Users\Sam\AppData\Roaming\SysHelper\helper.exe (not signed). Not a Windows task; name designed to look like one.' `
    -Why 'Starting at every logon from a writeable user folder is a common way for adware to keep itself alive.' `
    -Fix 'If you don''t recognise it, delete the task and quarantine the folder. The Repair Console does both.' `
    -Evidence @('Task \SystemHealthHelper -> C:\Users\Sam\AppData\Roaming\SysHelper\helper.exe', 'Signed: no', 'First seen: 12 days ago (shortly after a download of "pc-booster-setup.exe")') `
    -Actions @(
        (New-RepairAction -Kind Run -Label 'Delete the scheduled task' -Risk caution -Params @{ Command = 'task-delete'; Name = '\SystemHealthHelper' }),
        (New-RepairAction -Kind Quarantine -Label 'Quarantine C:\Users\Sam\AppData\Roaming\SysHelper\' -Risk caution -Params @{ Targets = @('C:\Users\Sam\AppData\Roaming\SysHelper') })
    )

Add-Finding -Severity High -Category 'Antivirus' -Section 'antivirus' `
    -Title 'Microsoft Defender has an exclusion for the whole C:\ drive' `
    -Detail 'Folder exclusion: C:\. With this in place, Defender scans nothing on your Windows drive.' `
    -Why 'This is almost always set by malware or a crack to hide itself. Normal programs do not do this.' `
    -Fix 'Remove the exclusion, then run a full Defender scan.' `
    -Evidence @('Preferences\ExclusionPath -> C:\') `
    -Actions @(
        (New-RepairAction -Kind Run -Label 'Remove the C:\ exclusion' -Risk caution -Params @{ Command = 'defender-remove-exclusion'; Path = 'C:\' }),
        (New-RepairAction -Kind Run -Label 'Run a Defender full scan now (slow; up to a few hours)' -Params @{ Command = 'defender-full-scan' })
    )

Add-Finding -Severity High -Category 'Hardware' -Section 'hardware' `
    -Title 'Boot drive is overheating and reports a reallocated-sector count climbing fast' `
    -Detail 'Samsung SSD 870 EVO 1TB: current temperature 71 degC (warning threshold 70). Reallocated sectors went 0 -> 42 in the last 30 days.' `
    -Why 'Both are early-warning signs that the drive is failing. At this rate it could lose data within weeks.' `
    -Fix 'Make a backup today (DeskVault can snapshot to another drive). Then replace the drive. Nothing in this tool can fix a dying drive.' `
    -Evidence @('Model: Samsung SSD 870 EVO 1TB', 'Serial: S5PRNS0R412345L', 'Temperature: 71 degC', 'SMART 05 (reallocated): 42', 'SMART 196 (reallocation events): 7')

Add-Finding -Severity Medium -Category 'Security Settings' -Section 'security' `
    -Title 'User Account Control (UAC) is set to "Never notify"' `
    -Detail 'ConsentPromptBehaviorAdmin = 0 and EnableLUA = 1. UAC is on but the prompt never shows.' `
    -Why 'Every program you (or malware) runs will be elevated without asking. One click away from a system-wide change.' `
    -Fix 'Set UAC back to the Windows default: "Notify me only when programs try to make changes".' `
    -Evidence @('HKLM\...\System\ConsentPromptBehaviorAdmin = 0') `
    -Actions @((New-RepairAction -Kind Run -Label 'Reset UAC to the Windows default' -Params @{ Command = 'uac-default' }))

Add-Finding -Severity Medium -Category 'Accounts & Access' -Section 'accounts' `
    -Title 'Automatic sign-in is on, and the password is in the registry in clear text' `
    -Detail 'Winlogon AutoAdminLogon = 1 for user Sam. DefaultPassword is set and readable by any administrator.' `
    -Why 'Anyone with physical access to the PC (or any admin) can sign in as you or read your password straight out of the registry.' `
    -Fix 'Turn automatic sign-in off and remove the DefaultPassword value.' `
    -Actions @(
        (New-RepairAction -Kind RegSetValue -Label 'Turn automatic sign-in off' -Params @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'AutoAdminLogon'; Type = 'String'; Value = '0' }),
        (New-RepairAction -Kind RegDeleteValue -Label 'Delete the stored password' -Risk caution -Params @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'DefaultPassword' })
    )

Add-Finding -Severity Medium -Category 'Updates' -Section 'updates' `
    -Title 'Windows Update is paused and the pause is 32 days old' `
    -Detail 'PauseUpdatesExpiryTime was set at 32 days ago. New updates will not install while this is set.' `
    -Why 'You miss security fixes while updates are paused.' `
    -Fix 'Clear the pause and let Windows look for updates again.' `
    -Actions @(
        (New-RepairAction -Kind RegDeleteValue -Label 'Clear "pause updates"' -Params @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'; Name = 'PauseUpdatesExpiryTime' }),
        (New-RepairAction -Kind Run -Label 'Scan for updates now' -Params @{ Command = 'wu-scan' })
    )

Add-Finding -Severity Medium -Category 'Software' -Section 'software' `
    -Title '7-Zip 19.00 is years out of date' `
    -Detail '7-Zip 19.00 (released 2019-02-21) is installed. The current version is 24.09.' `
    -Why 'Older 7-Zip has publicly known problems when opening booby-trapped archives.' `
    -Fix 'Update from 7-zip.org or run "winget upgrade 7zip.7zip".' `
    -Actions @((New-RepairAction -Kind Open -Label 'Open the 7-Zip download page' -Risk guided -Params @{ Uri = 'https://7-zip.org/' }))

Add-Finding -Severity Medium -Category 'Stability' -Section 'stability' `
    -Title '3 blue screens in the last 14 days, all with the same stop code' `
    -Detail 'DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xd1). Dump file points to RTWLANU.sys (Realtek Wi-Fi).' `
    -Why 'Same driver crashing three times in a row is almost certainly the cause.' `
    -Fix 'Update the Realtek Wi-Fi driver from the PC maker''s support site, or roll it back if you updated it recently.' `
    -Evidence @('2026-10-15 09:12 - DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xd1) - RTWLANU.sys', '2026-10-18 21:40 - DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xd1) - RTWLANU.sys', '2026-10-22 14:03 - DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xd1) - RTWLANU.sys') `
    -Actions @((New-RepairAction -Kind Open -Label 'Open Device Manager -> Network adapters to update/roll back the driver' -Risk guided -Params @{ Uri = 'devmgmt.msc' }))

Add-Finding -Severity Low -Category 'Performance' -Section 'performance' `
    -Title '14 programs start with Windows and together add 48 seconds to boot' `
    -Detail 'Spotify, Steam, Discord, OneDrive and Teams each delay boot by more than 5 seconds.' `
    -Why 'You don''t need all of them straight away. Starting them from the Start menu when you want them is faster.' `
    -Fix 'Open Task Manager -> Startup and turn off the ones you can wait a few seconds for.' `
    -Actions @((New-RepairAction -Kind Open -Label 'Open Task Manager Startup tab' -Risk guided -Params @{ Uri = 'ms-settings:startupapps' }))

# A few things that are OK, so the "What is fine" section has content
Add-Pass -Category 'Security Settings' -Title 'Firewall is on for all three profiles'
Add-Pass -Category 'Security Settings' -Title 'Secure Boot is on and the 2023 certificates are installed'
Add-Pass -Category 'Security Settings' -Title 'TPM 2.0 is present and enabled'
Add-Pass -Category 'Security Settings' -Title 'BitLocker is on for the Windows drive, recovery key saved to your Microsoft account'
Add-Pass -Category 'Antivirus'          -Title 'Microsoft Defender real-time protection is on and definitions are from today'
Add-Pass -Category 'Accounts & Access'  -Title 'Only one local administrator account; built-in Administrator and Guest are off'
Add-Pass -Category 'Network'            -Title 'DNS is set to Cloudflare (1.1.1.1), no proxy or hosts-file tampering'

# A timeline the "how did this get in" view can read
Add-TimelineEvent -Time (Get-Date).AddDays(-12).AddHours(-5) -Type 'Download'  -Text 'pc-booster-setup.exe downloaded from freewarefiles-pcbooster[.]com (Chrome)' -Severity 'High'
Add-TimelineEvent -Time (Get-Date).AddDays(-12).AddHours(-4.9) -Type 'Install' -Text 'PC Booster 2026 installed (uninstall registered under PC Booster 2026)' -Severity 'High'
Add-TimelineEvent -Time (Get-Date).AddDays(-12).AddHours(-4.85) -Type 'Task'   -Text 'Scheduled task \SystemHealthHelper created' -Severity 'High'
Add-TimelineEvent -Time (Get-Date).AddDays(-12).AddHours(-4.8) -Type 'Install' -Text 'PC App Store (Fast Corporation) installed' -Severity 'Critical'
Add-TimelineEvent -Time (Get-Date).AddDays(-11)                -Type 'Defender' -Text 'Defender quick scan finished, 0 detections (exclusion for C:\ was already in place)' -Severity 'Medium'
Add-TimelineEvent -Time (Get-Date).AddDays(-6)                 -Type 'Policy'   -Text 'Chrome hijack policy written to HKLM\...\Policies\Google\Chrome' -Severity 'Critical'
Add-TimelineEvent -Time (Get-Date).AddDays(-5)                 -Type 'Crash'    -Text 'Blue screen DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xd1) - RTWLANU.sys' -Severity 'Medium'
Add-TimelineEvent -Time (Get-Date).AddDays(-2)                 -Type 'Crash'    -Text 'Blue screen DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xd1) - RTWLANU.sys' -Severity 'Medium'

$script:ModuleLog.Add([pscustomobject]@{ Module = '01-System';        Seconds = 2.1; Result = 'OK' })
$script:ModuleLog.Add([pscustomobject]@{ Module = '04-Antivirus';     Seconds = 3.5; Result = 'OK' })
$script:ModuleLog.Add([pscustomobject]@{ Module = '07-Persistence';   Seconds = 6.7; Result = 'OK' })
$script:ModuleLog.Add([pscustomobject]@{ Module = '08-Browsers';      Seconds = 4.2; Result = 'OK' })
$script:ModuleLog.Add([pscustomobject]@{ Module = '11-MalwareSweep';  Seconds = 9.8; Result = 'OK' })
$script:ModuleLog.Add([pscustomobject]@{ Module = '12-Hardware';      Seconds = 5.3; Result = 'OK' })

$meta = [pscustomobject]@{
    Computer = 'DESKTOP-SAMPLE'; OSLine = 'Windows 11 Pro 24H2 (build 26100.2314)'; User = 'DESKTOP-SAMPLE\Sam'
    Started = (Get-Date).AddMinutes(-6); Duration = '5m 42s'; Mode = $script:Mode; Admin = $true; Days = $script:Days
    Version = $script:Version
}

$reportPath = Join-Path $OutDir 'PC-Health-Report_sample.html'
$findingsPath = Join-Path $OutDir 'demo-findings.json'
New-HtmlReport -Path $reportPath -Meta $meta

$data = [ordered]@{
    Meta     = $meta
    Findings = @($script:Findings | Sort-Object Rank -Descending | Select-Object Id, Severity, Category, Title, Detail, Why, Fix, Evidence, Section, Actions)
    Passed   = $script:Passes.ToArray()
    Timeline = @($script:Timeline | Select-Object Time, Type, Event, Severity)
    Sections = @()
}
$data | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $findingsPath -Encoding UTF8

Write-Host "wrote $reportPath"
Write-Host "wrote $findingsPath"
