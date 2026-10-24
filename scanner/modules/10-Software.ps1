# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Installed software: inventory, adware/PUP matches, outdated/vulnerable software, remote-access tools

$script:RemoteTools = @(
    @{ Name = 'AnyDesk'; Rx = 'anydesk' }, @{ Name = 'TeamViewer'; Rx = 'teamviewer' }, @{ Name = 'RustDesk'; Rx = 'rustdesk' },
    @{ Name = 'ScreenConnect / ConnectWise Control'; Rx = 'screenconnect|connectwise control' }, @{ Name = 'Splashtop'; Rx = 'splashtop' },
    @{ Name = 'LogMeIn / GoTo'; Rx = 'logmein|gotoassist|goto resolve|goto opener' }, @{ Name = 'UltraViewer'; Rx = 'ultraviewer' },
    @{ Name = 'Supremo'; Rx = 'supremo' }, @{ Name = 'AeroAdmin'; Rx = 'aeroadmin' }, @{ Name = 'Ammyy Admin'; Rx = 'ammyy' },
    @{ Name = 'NetSupport'; Rx = 'netsupport|client32\.exe' }, @{ Name = 'Remote Utilities'; Rx = 'remote utilities|rutserv|rfusclient' },
    @{ Name = 'Atera'; Rx = '\batera' }, @{ Name = 'DWService'; Rx = 'dwservice|dwagent' }, @{ Name = 'Zoho Assist'; Rx = 'zoho assist|zohomeeting' },
    @{ Name = 'BeyondTrust / Bomgar'; Rx = 'bomgar|beyondtrust' }, @{ Name = 'Radmin'; Rx = '\bradmin' }, @{ Name = 'VNC'; Rx = 'tightvnc|ultravnc|realvnc|tigervnc|vnc server' },
    @{ Name = 'Chrome Remote Desktop'; Rx = 'chrome remote desktop|remoting_host' }, @{ Name = 'RemotePC'; Rx = 'remotepc' }, @{ Name = 'Action1'; Rx = 'action1' },
    @{ Name = 'MeshCentral agent'; Rx = 'meshagent|mesh agent' }, @{ Name = 'SimpleHelp'; Rx = 'simplehelp|simple-help|remote access service' }, @{ Name = 'Level'; Rx = 'level\.io|levelagent' },
    @{ Name = 'Tactical RMM'; Rx = 'tactical rmm|tacticalagent' }, @{ Name = 'NinjaOne'; Rx = 'ninjarmm' }, @{ Name = 'HopToDesk'; Rx = 'hoptodesk' },
    @{ Name = 'Getscreen'; Rx = 'getscreen' }, @{ Name = 'Iperius Remote'; Rx = 'iperius remote' }, @{ Name = 'FleetDeck'; Rx = 'fleetdeck' }, @{ Name = 'Parsec'; Rx = 'parsec' }
)

function ConvertTo-VersionSafe {
    param([string]$Text)
    if ($Text -match '(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?') {
        $parts = @($Matches[1], $Matches[2], $(if ($Matches[3]) { $Matches[3] } else { '0' }), $(if ($Matches[4]) { $Matches[4] } else { '0' }))
        try { return [version]($parts -join '.') } catch {}
    }
    $null
}

function Invoke-SoftwareScan {
    $S = 'software'
    $sources = @(
        @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'All users (64-bit)' },
        @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'All users (32-bit)' }
    )
    foreach ($h in $script:Hives) { $sources += @{ Path = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "User $(Get-ShortUser $h.User)" } }
    $apps = @()
    $seen = @{}
    foreach ($src in $sources) {
        foreach ($k in (Get-ChildItem -LiteralPath $src.Path -ErrorAction SilentlyContinue)) {
            $name = [string]$k.GetValue('DisplayName')
            if (-not $name) { continue }
            if ($k.GetValue('SystemComponent') -eq 1) { continue }
            if ($k.GetValue('ParentKeyName') -or ([string]$k.GetValue('ReleaseType')) -match 'Update|Hotfix') { continue }
            $ver = [string]$k.GetValue('DisplayVersion')
            $key = "$name|$ver|$($src.Scope)".ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $idate = $null
            $raw = [string]$k.GetValue('InstallDate')
            $tmp = [datetime]::MinValue
            foreach ($fmt in 'yyyyMMdd', 'yyyyddMM', 'M/d/yyyy', 'MM/dd/yyyy') {
                if ([datetime]::TryParseExact($raw, $fmt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$tmp) -and $tmp -le (Get-Date).AddDays(1)) { $idate = $tmp.AddHours(12); break }
            }
            $size = $k.GetValue('EstimatedSize')
            $apps += [pscustomobject]@{
                Name = $name; Version = $ver; Publisher = [string]$k.GetValue('Publisher'); Installed = $idate; Scope = $src.Scope
                Location = [string]$k.GetValue('InstallLocation'); Size = $(if ($size) { Format-Bytes ([double]$size * 1KB) } else { '' })
                Uninstall = [string]$k.GetValue('UninstallString')
                Concerns = ''; _Flag = ''; _Sev = $null; _Key = $k.Name
            }
        }
    }
    $script:Shared.Apps = $apps

    $eol = @()
    foreach ($a in $apps) {
        $why = @(); $sev = $null
        $pup = Find-Pup @($a.Name, $a.Publisher, $a.Location, $a.Uninstall)
        if ($pup) { $sev = $pup.Severity; $why += "Adware/PUP: $($pup.Name)"; $script:Shared.PupHits += , $pup.Name }
        $v = ConvertTo-VersionSafe $a.Version
        if ($a.Name -match '(?i)adobe flash') { $sev = Get-MaxSeverity @($sev, 'High'); $why += 'Flash Player is dead since 2020 and full of holes' }
        if ($a.Name -match '(?i)^winrar' -and $v -and $v -lt [version]'7.13') { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += 'WinRAR older than 7.13 has actively-exploited flaws (CVE-2025-8088) and does not auto-update' }
        if ($a.Name -match '(?i)^7-zip' -and $v) {
            if ($v -lt [version]'24.09') { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += '7-Zip older than 24.09 can bypass Windows download warnings (CVE-2025-0411)' }
            elseif ($v -lt [version]'25.1') { $sev = Get-MaxSeverity @($sev, 'Low'); $why += '7-Zip older than 25.01 (archive path-traversal fix)' }
        }
        if ($a.Name -match '(?i)quicktime') { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += 'QuickTime for Windows is abandoned with unpatched vulnerabilities' }
        if ($a.Name -match '(?i)shockwave') { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += 'Shockwave Player is discontinued' }
        if ($a.Name -match '(?i)silverlight') { $sev = Get-MaxSeverity @($sev, 'Low'); $why += 'Silverlight support ended 2021' }
        if ($a.Name -match '(?i)^python 2\.') { $sev = Get-MaxSeverity @($sev, 'Low'); $why += 'Python 2 is end-of-life' }
        if ($a.Name -match '(?i)^vlc media player' -and $v -and $v -lt [version]'3.0.21') { $sev = Get-MaxSeverity @($sev, 'Low'); $why += 'VLC older than 3.0.21 has known security fixes missing' }
        if ($a.Name -match '(?i)microsoft office.*\b(2007|2010|2013|2016|2019)\b' -or $a.Name -match '(?i)microsoft (office|word|excel|outlook)\s.*\b(2007|2010|2013|2016|2019)\b') {
            $sev = Get-MaxSeverity @($sev, 'Medium'); $why += 'This Office version no longer gets security updates (2016/2019 ended Oct 2025)'
        }
        if ($a.Name -match '(?i)microsoft office.*\b2021\b' -and (Get-Date) -gt [datetime]'2026-10-13') { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += 'Office 2021 support ended 2026-10-13' }
        if ($a.Name -match '(?i)^java(\(tm\))? \d+ update (\d+)' -or $a.Name -match '(?i)^java 8') { $sev = Get-MaxSeverity @($sev, 'Low'); $why += 'Java runtime installed - remove if nothing needs it' }
        if ($why) {
            $a.Concerns = $why -join '; '; $a._Sev = $sev; $a._Flag = ConvertTo-FlagClass $sev
            if (-not $pup) { $eol += $a }
        }
        if ($a.Installed) { Add-TimelineEvent $a.Installed 'Program installed' "$($a.Name) $($a.Version) ($($a.Publisher))" $(if ($sev) { $sev } else { 'Info' }) }
    }

    # adware / PUP findings, grouped by family
    $pupApps = @($apps | Where-Object { $_.Concerns -like 'Adware/PUP*' })
    foreach ($g in ($pupApps | Group-Object { ($_.Concerns -split ';')[0] })) {
        $first = $g.Group[0]
        $pup = Find-Pup @($first.Name, $first.Publisher, $first.Location, $first.Uninstall)
        $names = @($g.Group | ForEach-Object { $_.Name } | Select-Object -Unique)
        $title = 'Installed: ' + (($names | Select-Object -First 3) -join ', ') + $(if ($names.Count -gt 3) { " (+$($names.Count - 3) more)" } else { '' })
        if ($pup.Name -like 'PC App Store*' -and @($names | Where-Object { $_ -notmatch '(?i)^PC ?App ?Store' }).Count -eq 0) {
            # its own uninstaller is interactive, needs it closed first and often leaves the app running - use the dedicated removal instead
            Add-Finding -Severity Info -Category 'Malware & PUPs' -Section $S -Title "$title (see the PC App Store finding)" `
                -Detail ("Listed in Installed apps: " + (($g.Group | ForEach-Object { "$($_.Name) $($_.Version) [$($_.Scope)]" }) -join '; ')) `
                -Evidence @($g.Group | ForEach-Object { "Uninstall: $($_.Uninstall)"; "Registry: $($_._Key)" }) `
                -Fix 'Use "Remove PC App Store completely" (Malware & adware file sweep section). It also removes this Apps-list entry.'
            continue
        }
        Add-Finding -Severity $pup.Severity -Category 'Malware & PUPs' -Section $S -Title $title `
            -Detail ("Family: $($pup.Name). " + (($g.Group | ForEach-Object { "$($_.Name) $($_.Version) [$($_.Scope)]" }) -join '; ')) `
            -Evidence @($g.Group | ForEach-Object { "Uninstall: $($_.Uninstall)"; if ($_.Location) { "Folder: $($_.Location)" }; "Registry: $($_._Key)" }) `
            -Why $pup.Info `
            -Fix 'Settings > Apps > Installed apps > uninstall it. If the uninstaller is missing or fails, run the Uninstall command shown above from an admin prompt, then delete the leftover folder and re-run this scan to confirm nothing remains (tasks, startup entries, extensions).' `
            -Actions @(@($g.Group | Where-Object { $_.Uninstall -or $_._Key } | ForEach-Object { New-RepairAction -Kind Uninstall -Label "Uninstall $($_.Name) $($_.Version) (if its uninstaller is already gone, the leftover Apps-list entry is removed instead)" -Risk caution -Params @{ Name = $_.Name; Command = $_.Uninstall; Key = "Registry::$($_._Key)" } }) +
                @($g.Group | Where-Object { $_.Location -and (Test-Path -LiteralPath $_.Location) -and (Test-UserWritableZone (Get-PathZone $_.Location)) } | ForEach-Object { New-RepairAction -Kind Quarantine -Label "Quarantine leftover folder $($_.Location)" -Risk caution -Params @{ Targets = @($_.Location) } }))
    }
    foreach ($a in $eol) {
        if ($a._Sev -eq 'Low' -and $a.Concerns -match 'Java') { continue }
        $dl = if ($a.Name -match '(?i)winrar') { 'https://www.win-rar.com/download.html' } elseif ($a.Name -match '(?i)7-zip') { 'https://7-zip.org/' } elseif ($a.Name -match '(?i)vlc') { 'https://www.videolan.org/vlc/' } else { '' }
        Add-Finding -Severity $a._Sev -Category 'Software' -Section $S -Title "Outdated/unsupported: $($a.Name) $($a.Version)" -Detail $a.Concerns `
            -Fix 'Update it from the vendor''s official website, or uninstall it if it is not used.' `
            -Actions @($(if ($dl) { New-RepairAction -Kind Open -Label "Open the official download page ($dl)" -Risk guided -Params @{ Uri = $dl } }
                    elseif ($a.Uninstall) { New-RepairAction -Kind Uninstall -Label "Uninstall $($a.Name)" -Risk caution -Params @{ Name = $a.Name; Command = $a.Uninstall; Key = "Registry::$($a._Key)" } }))
    }
    $java = @($eol | Where-Object { $_.Concerns -match 'Java' })
    if ($java.Count -gt 0) { Add-Finding -Severity Low -Category 'Software' -Section $S -Title 'Java runtime is installed' -Evidence @($java | ForEach-Object { "$($_.Name) $($_.Version)" }) -Fix 'Uninstall it unless a program needs it (Minecraft bundles its own Java).' }

    # remote access tools
    $rtRows = @()
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
    $pi = $script:Shared.ProcIndex
    foreach ($rt in $script:RemoteTools) {
        $inst = @($apps | Where-Object { $_.Name -match $rt.Rx -or $_.Publisher -match $rt.Rx })
        $svc = @($svcs | Where-Object { $_.Name -match $rt.Rx -or $_.DisplayName -match $rt.Rx -or $_.PathName -match $rt.Rx })
        $procs = @()
        if ($pi) { $procs = @($pi.Values | Where-Object { $_.Name -match $rt.Rx -or $_.Path -match $rt.Rx } | ForEach-Object { $_.Name } | Select-Object -Unique) }
        if ($inst.Count -eq 0 -and $svc.Count -eq 0 -and $procs.Count -eq 0) { continue }
        $idate = ($inst | Where-Object { $_.Installed } | Sort-Object Installed -Descending | Select-Object -First 1).Installed
        $alwaysOn = @($svc | Where-Object { $_.StartMode -eq 'Auto' }).Count -gt 0
        $rtRows += [pscustomobject]@{
            Tool = $rt.Name; Installed = $(if ($inst) { ($inst | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; ' } else { 'Portable / not in Apps list' })
            'Install date' = $idate; 'Background service' = $(if ($svc) { ($svc | ForEach-Object { "$($_.Name) ($($_.StartMode), $($_.State))" }) -join '; ' } else { 'No' })
            'Running now' = ($procs -join ', '); _Flag = $(if ($alwaysOn) { 'medium' } else { 'low' }); _AlwaysOn = $alwaysOn; _Recent = ($idate -and $idate -ge $script:Cutoff); _Apps = $inst
        }
    }
    Add-Table -Section $S -Title 'Remote-access software' -Rows $rtRows -Empty 'No remote-access tools found.' `
        -Note 'Tech-support scammers install these to get back in later. AnyDesk is expected if this scan was run over AnyDesk.'
    $others = @($rtRows | Where-Object { $_.Tool -ne 'AnyDesk' })
    if ($others.Count -gt 0) {
        $sev = if (@($others | Where-Object { $_._AlwaysOn -or $_._Recent }).Count -gt 0) { 'Medium' } else { 'Low' }
        Add-Finding -Severity $sev -Category 'Accounts & Access' -Section $S -Title "Remote-access software installed: $(($others | ForEach-Object { $_.Tool }) -join ', ')" `
            -Evidence @($others | ForEach-Object { "$($_.Tool): $($_.Installed); service: $($_.'Background service')" }) `
            -Why 'Anyone with the ID/password of these tools can control the PC. If she did not set one up herself (or for someone she trusts), assume a scammer did.' `
            -Fix 'Uninstall every tool nobody can account for (Settings > Apps). If a scammer had access: change passwords from another device, check bank accounts, and run a full + offline Defender scan.' `
            -Actions @($others | ForEach-Object { $_._Apps } | Where-Object { $_ -and $_.Uninstall } | ForEach-Object { New-RepairAction -Kind Uninstall -Label "Uninstall $($_.Name) (only if nobody set it up on purpose)" -Risk caution -Params @{ Name = $_.Name; Command = $_.Uninstall } })
    }
    $ad = $rtRows | Where-Object { $_.Tool -eq 'AnyDesk' } | Select-Object -First 1
    if ($ad -and $ad._AlwaysOn) {
        Add-Finding -Severity Low -Category 'Accounts & Access' -Section $S -Title 'AnyDesk is installed as an always-on service' `
            -Why 'An installed AnyDesk can accept connections whenever the PC is on. If unattended access is configured, nobody needs to click Accept.' `
            -Fix 'After this session: uninstall AnyDesk, or in AnyDesk Settings > Security disable unattended access and remove any saved passwords.'
    }

    # AnyDesk / TeamViewer incoming-connection logs (scam evidence)
    $logRows = @()
    $traces = @("$env:ProgramData\AnyDesk\connection_trace.txt")
    foreach ($p in $script:Profiles) { $traces += (Join-Path $p.Path 'AppData\Roaming\AnyDesk\connection_trace.txt') }
    foreach ($t in $traces) {
        try {
            foreach ($l in @(Get-Content -LiteralPath $t -Tail 25 -ErrorAction Stop)) {
                if ($l.Trim()) { $logRows += [pscustomobject]@{ Tool = 'AnyDesk'; Log = $t; Entry = ($l -replace '\s+', ' ').Trim() } }
            }
        } catch {}
    }
    foreach ($t in @("${env:ProgramFiles}\TeamViewer\Connections_incoming.txt", "${env:ProgramFiles(x86)}\TeamViewer\Connections_incoming.txt")) {
        try {
            foreach ($l in @(Get-Content -LiteralPath $t -Tail 25 -ErrorAction Stop)) {
                if ($l.Trim()) { $logRows += [pscustomobject]@{ Tool = 'TeamViewer'; Log = $t; Entry = ($l -replace '\s+', ' ').Trim() } }
            }
        } catch {}
    }
    Add-Table -Section $S -Title 'Recent incoming remote-control sessions (from AnyDesk/TeamViewer logs)' -Rows $logRows -Empty 'No incoming-connection logs found.' `
        -Note 'Each line is a session where someone connected IN to this PC. Ask her whether she recognises each one - unknown IDs are a red flag for a scam.'

    $recent = @($apps | Where-Object { $_.Installed -and $_.Installed -ge $script:Cutoff } | Sort-Object Installed -Descending)
    Add-Table -Section $S -Title "Installed in the last $($script:Days) days" -Rows $recent -Columns @('Name', 'Version', 'Publisher', 'Installed', 'Scope', 'Concerns', 'Location')
    Add-Table -Section $S -Title "All installed programs ($($apps.Count))" -Rows @($apps | Sort-Object Name) -Columns @('Name', 'Version', 'Publisher', 'Installed', 'Scope', 'Size', 'Concerns', 'Location', 'Uninstall')
    if ($pupApps.Count -eq 0) { Add-Pass 'Software' 'No known adware/PUP in the installed programs list' "$($apps.Count) programs checked" }
}
