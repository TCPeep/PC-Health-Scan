# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# PC Health Scan - core helpers
# Windows PowerShell 5.1 compatible. Keep this file ASCII-only (PS 5.1 reads BOM-less files as ANSI).

$script:SevRank   = @{ Critical = 5; High = 4; Medium = 3; Low = 2; Info = 1; None = 0 }
$script:Findings  = New-Object System.Collections.Generic.List[object]
$script:Passes    = New-Object System.Collections.Generic.List[object]
$script:Sections  = New-Object System.Collections.Generic.List[object]
$script:ModuleLog = New-Object System.Collections.Generic.List[object]
$script:Timeline  = New-Object System.Collections.Generic.List[object]
$script:Actions   = New-Object System.Collections.Generic.List[object]
$script:SigCache  = @{}
$script:HashCache = @{}
$script:FindingKeys = @{}
$script:CorruptFiles = @()   # program files whose header is not a valid executable (zero-filled etc.)
$script:Shared    = @{}   # data handed between modules

# ---------------------------------------------------------------- basics

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Status {
    param([string]$Text, [string]$Color = 'DarkGray')
    Write-Host ('     ' + $Text) -ForegroundColor $Color
}

function Get-MaxSeverity {
    param([object[]]$Severities)
    $best = 'None'
    foreach ($s in $Severities) {
        if ($s -and $script:SevRank.ContainsKey([string]$s) -and $script:SevRank[[string]$s] -gt $script:SevRank[$best]) { $best = [string]$s }
    }
    if ($best -eq 'None') { return $null }
    $best
}

function ConvertTo-FlagClass {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 'critical' } 'High' { 'high' } 'Medium' { 'medium' } 'Low' { 'low' } 'Good' { 'good' } 'Info' { 'info' } default { '' }
    }
}

function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    '{0} B' -f [int64]$Bytes
}

function Format-Age {
    param($Date)
    if ($null -eq $Date) { return '' }
    $d = (Get-Date) - [datetime]$Date
    if ($d.TotalDays -ge 1) { return ('{0:N0} days ago' -f $d.TotalDays) }
    if ($d.TotalHours -ge 1) { return ('{0:N0} hours ago' -f $d.TotalHours) }
    '{0:N0} min ago' -f [Math]::Max(0, $d.TotalMinutes)
}

function Limit-Text {
    param([string]$Text, [int]$Max = 300)
    if (-not $Text) { return '' }
    $t = $Text -replace '\s+', ' '
    if ($t.Length -le $Max) { return $t }
    $t.Substring(0, $Max) + ' ...'
}

# ---------------------------------------------------------------- report model

function Register-Section {
    param([string]$Id, [string]$Title, [string]$Intro)
    foreach ($x in $script:Sections) { if ($x.Id -eq $Id) { return } }
    $script:Sections.Add([pscustomobject]@{ Id = $Id; Title = $Title; Intro = $Intro; Blocks = (New-Object System.Collections.Generic.List[object]) })
}

function Get-SectionObj {
    param([string]$Id)
    foreach ($x in $script:Sections) { if ($x.Id -eq $Id) { return $x } }
    Register-Section -Id $Id -Title $Id
    foreach ($x in $script:Sections) { if ($x.Id -eq $Id) { return $x } }
}

function Add-Table {
    param([string]$Section, [string]$Title, [object[]]$Rows, [string[]]$Columns, [string]$Note, [string]$Empty = 'Nothing found.')
    $sec = Get-SectionObj $Section
    $rowsArr = @($Rows | Where-Object { $null -ne $_ })
    if ((-not $Columns) -and $rowsArr.Count -gt 0) {
        $Columns = @($rowsArr[0].PSObject.Properties | Where-Object { $_.Name -notlike '_*' } | ForEach-Object { $_.Name })
    }
    $sec.Blocks.Add([pscustomobject]@{ Kind = 'table'; Title = $Title; Rows = $rowsArr; Columns = $Columns; Note = $Note; Empty = $Empty; Text = ''; Tone = '' })
}

function Add-KV {
    param([string]$Section, [string]$Title, $Data, [string]$Note)
    $rows = @()
    foreach ($k in $Data.Keys) { $rows += [pscustomobject]@{ Item = $k; Value = $Data[$k] } }
    $sec = Get-SectionObj $Section
    $sec.Blocks.Add([pscustomobject]@{ Kind = 'kv'; Title = $Title; Rows = $rows; Columns = @('Item', 'Value'); Note = $Note; Empty = ''; Text = ''; Tone = '' })
}

function Add-Note {
    param([string]$Section, [string]$Text, [string]$Tone = 'info')
    (Get-SectionObj $Section).Blocks.Add([pscustomobject]@{ Kind = 'note'; Title = ''; Rows = @(); Columns = @(); Note = ''; Empty = ''; Text = $Text; Tone = $Tone })
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Title,
        [string]$Detail, [string]$Why, [string]$Fix, [object[]]$Evidence, [string]$Section,
        # Repair steps for the Repair Console: an array of hashtables made by New-RepairAction (plain data, no code).
        [object[]]$Actions)
    $key = "$Category|$Title|$Detail"
    if ($script:FindingKeys.ContainsKey($key)) { return }
    $script:FindingKeys[$key] = $true
    $ev = @($Evidence | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if ($ev.Count -gt 60) { $more = $ev.Count - 60; $ev = @($ev[0..59]) + "... and $more more" }
    $acts = @($Actions | Where-Object { $_ })
    $script:Findings.Add([pscustomobject]@{
            Id = 'f' + $script:Findings.Count; Severity = $Severity; Rank = $script:SevRank[$Severity]; Category = $Category
            Title = $Title; Detail = $Detail; Why = $Why; Fix = $Fix; Evidence = $ev; Section = $Section; Actions = $acts
        })
    $color = switch ($Severity) { 'Critical' { 'Magenta' } 'High' { 'Red' } 'Medium' { 'Yellow' } 'Low' { 'Cyan' } default { 'DarkGray' } }
    if ($Severity -ne 'Info') { Write-Host ('     [{0}] {1}' -f $Severity.ToUpper(), $Title) -ForegroundColor $color }
}

# One repair step. Kind is interpreted by lib\Repair.ps1; everything else is a plain parameter for that kind.
# Risk: 'safe' = reversible/settings-only, 'caution' = removes or disables something (quarantined, still reversible),
# 'guided' = opens the right place for a human to finish (no change made by the tool).
# -Off: the step starts UNticked in the Repair Console (used where the item may well be legitimate).
function New-RepairAction {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Label,
        [ValidateSet('safe', 'caution', 'guided')][string]$Risk = 'safe',
        [hashtable]$Params = @{},
        [switch]$Reboot,
        [switch]$Off)
    $a = [ordered]@{ Kind = $Kind; Label = $Label; Risk = $Risk; Reboot = [bool]$Reboot; Off = [bool]$Off }
    foreach ($k in $Params.Keys) {
        $v = $Params[$k]
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = @($v | ForEach-Object { [string]$_ }) } else { $v = [string]$v }
        $a[[string]$k] = $v
    }
    $a
}

function Add-Pass {
    param([string]$Category, [string]$Title, [string]$Detail)
    $script:Passes.Add([pscustomobject]@{ Category = $Category; Title = $Title; Detail = $Detail })
}

function Add-TimelineEvent {
    param($Time, [string]$Type, [string]$Text, [string]$Severity = 'Info')
    if ($null -eq $Time) { return }
    try { $t = [datetime]$Time } catch { return }
    if ($t -lt $script:Cutoff -or $t -gt (Get-Date).AddDays(1)) { return }
    $script:Timeline.Add([pscustomobject]@{ Time = $t; Type = $Type; Event = $Text; Severity = $Severity; _Flag = (ConvertTo-FlagClass $Severity) })
}

function Add-Action {
    param([string]$Text)
    $script:Actions.Add([pscustomobject]@{ Time = (Get-Date); Action = $Text })
}

# ---------------------------------------------------------------- registry / users

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $k.GetValue($Name)
    } catch { return $null }
}

function Test-RegKey {
    param([string]$Path)
    try { return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) } catch { return $false }
}

function Get-RegValues {
    param([string]$Path)
    $out = @()
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($n in $k.GetValueNames()) {
            $out += [pscustomobject]@{ Name = $n; Value = $k.GetValue($n); Kind = [string]$k.GetValueKind($n) }
        }
    } catch {}
    $out
}

function Resolve-Sid {
    param([string]$Sid)
    try { return (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { return $Sid }
}

function Get-UserHives {
    $list = @()
    foreach ($k in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -match '^S-1-5-21-[\d-]+$' -or $sid -match '^S-1-12-1-[\d-]+$') {
            $list += [pscustomobject]@{ Sid = $sid; User = (Resolve-Sid $sid); Root = "Registry::HKEY_USERS\$sid" }
        }
    }
    $list
}

function Get-UserProfiles {
    $out = @()
    foreach ($p in (Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue)) {
        if ($p.Special) { continue }
        if (-not $p.LocalPath) { continue }
        if ($p.LocalPath -match '\\(systemprofile|LocalService|NetworkService)$') { continue }
        if ($p.LocalPath.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not (Test-Path -LiteralPath $p.LocalPath -ErrorAction SilentlyContinue)) { continue }
        $out += [pscustomobject]@{ Sid = $p.SID; User = (Resolve-Sid $p.SID); Path = $p.LocalPath; Loaded = $p.Loaded; LastUse = $p.LastUseTime }
    }
    if ($out.Count -eq 0) {
        $out += [pscustomobject]@{ Sid = ''; User = "$env:USERDOMAIN\$env:USERNAME"; Path = $env:USERPROFILE; Loaded = $true; LastUse = (Get-Date) }
    }
    $out
}

function Get-ShortUser {
    param([string]$User)
    if (-not $User) { return '' }
    ($User -split '\\')[-1]
}

# ---------------------------------------------------------------- files, signatures, paths

function Get-FileSig {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Status = 'NoPath'; Signer = ''; Trusted = $false; IsMicrosoft = $false; Exists = $false; Skipped = $false }
    }
    $k = $Path.ToLowerInvariant()
    if ($script:SigCache.ContainsKey($k)) { return $script:SigCache[$k] }
    $r = $null
    $exists = $false
    try { $exists = [IO.File]::Exists($Path) } catch {}
    if (-not $exists) {
        $r = [pscustomobject]@{ Status = 'Missing'; Signer = ''; Trusted = $false; IsMicrosoft = $false; Exists = $false; Skipped = $false }
    } else {
        $len = 0
        try { $len = (New-Object IO.FileInfo($Path)).Length } catch {}
        $corrupt = $false
        if ($Path -match '(?i)\.(exe|dll|sys|scr|cpl|ocx|com)$') {
            try {
                $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                $hdr = New-Object byte[] 2
                $nread = $fs.Read($hdr, 0, 2)
                $fs.Dispose()
                $corrupt = ($nread -lt 2) -or ($hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A)
            } catch {}
        }
        if ($corrupt) {
            $r = [pscustomobject]@{ Status = 'Corrupt'; Signer = ''; Trusted = $false; IsMicrosoft = $false; Exists = $true; Skipped = $true; Path = $Path }
            $script:CorruptFiles += , $Path
        } elseif ($len -gt 300MB) {
            $r = [pscustomobject]@{ Status = 'NotChecked (large file)'; Signer = ''; Trusted = $false; IsMicrosoft = $false; Exists = $true; Skipped = $true }
        } else {
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
                $signer = ''
                if ($s.SignerCertificate) { $signer = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
                $status = [string]$s.Status
                $trusted = ($status -eq 'Valid')
                $isMs = $trusted -and ($signer -match '^Microsoft (Windows|Corporation|Windows Publisher|Windows Third Party Component|Code Signing PCA)')
                $r = [pscustomobject]@{ Status = $status; Signer = $signer; Trusted = $trusted; IsMicrosoft = [bool]$isMs; Exists = $true; Skipped = $false }
            } catch {
                $r = [pscustomobject]@{ Status = 'Error'; Signer = ''; Trusted = $false; IsMicrosoft = $false; Exists = $true; Skipped = $true }
            }
        }
    }
    $script:SigCache[$k] = $r
    $r
}

function Get-Sha256 {
    param([string]$Path)
    if (-not $Path) { return '' }
    $k = $Path.ToLowerInvariant()
    if ($script:HashCache.ContainsKey($k)) { return $script:HashCache[$k] }
    $h = ''
    try {
        $fi = New-Object IO.FileInfo($Path)
        if ($fi.Exists -and $fi.Length -lt 300MB) { $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    } catch {}
    $script:HashCache[$k] = $h
    $h
}

function Get-PathZone {
    param([string]$Path)
    if (-not $Path) { return 'Unknown' }
    $p = $Path.ToLowerInvariant()
    if ($p -match '\\\$recycle\.bin\\') { return 'RecycleBin' }
    if ($p -match '\\(temp|tmp)\\') { return 'Temp' }
    if ($p -match '\\downloads\\') { return 'Downloads' }
    if ($p -match '\\appdata\\roaming\\') { return 'AppData\Roaming' }
    if ($p -match '\\appdata\\locallow\\') { return 'AppData\LocalLow' }
    if ($p -match '\\appdata\\local\\') { return 'AppData\Local' }
    if ($p -match '^[a-z]:\\users\\public\\') { return 'Users\Public' }
    if ($p -match '^[a-z]:\\users\\') { return 'UserProfile' }
    if ($p -match '^[a-z]:\\programdata\\') { return 'ProgramData' }
    if ($p -match '^[a-z]:\\windows\\') { return 'Windows' }
    if ($p -match '^[a-z]:\\program files') { return 'ProgramFiles' }
    'Other'
}

function Test-UserWritableZone {
    param([string]$Zone)
    $Zone -in @('RecycleBin', 'Temp', 'Downloads', 'AppData\Roaming', 'AppData\LocalLow', 'AppData\Local', 'Users\Public', 'UserProfile', 'ProgramData')
}

$script:ScriptHosts = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
    'javaw.exe', 'java.exe', 'conhost.exe', 'msiexec.exe', 'forfiles.exe', 'bitsadmin.exe', 'certutil.exe', 'msbuild.exe',
    'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'odbcconf.exe', 'pcalua.exe', 'explorer.exe', 'node.exe', 'python.exe', 'pythonw.exe', 'autoit3.exe')

function Resolve-LaunchTarget {
    param([string]$Command)
    $res = [pscustomobject]@{ Raw = $Command; Host = ''; Target = ''; Args = ''; IsHost = $false }
    if ([string]::IsNullOrWhiteSpace($Command)) { return $res }
    try {
        $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
        $c = $c -replace '^\\\?\?\\', ''
        $c = $c -replace '^(?i)\\SystemRoot\\', ($env:SystemRoot + '\')
        $c = $c -replace '^(?i)System32\\', ($env:SystemRoot + '\System32\')
        $exe = $null; $rest = ''
        if ($c.StartsWith('"')) {
            $end = $c.IndexOf('"', 1)
            if ($end -gt 0) { $exe = $c.Substring(1, $end - 1); $rest = $c.Substring($end + 1).Trim() } else { $exe = $c.Trim('"') }
        } else {
            $parts = @($c -split '\s+')
            for ($i = 0; $i -lt $parts.Count; $i++) {
                $cand = (@($parts[0..$i]) -join ' ').TrimEnd(',')
                $ok = $false
                try { $ok = [IO.File]::Exists($cand) } catch {}
                if ($ok) { $exe = $cand; $rest = (@($parts | Select-Object -Skip ($i + 1)) -join ' '); break }
                if ($cand -notmatch '\.[a-z0-9]{2,4}$') {
                    try { $ok = [IO.File]::Exists($cand + '.exe') } catch {}
                    if ($ok) { $exe = $cand + '.exe'; $rest = (@($parts | Select-Object -Skip ($i + 1)) -join ' '); break }
                }
            }
            if (-not $exe) {
                if ($c -match '^(.+?\.(exe|dll|sys|com|scr|bat|cmd))(\s|,|$)') { $exe = $Matches[1]; $rest = $c.Substring($Matches[1].Length).Trim() }
                else { $exe = $parts[0]; $rest = (@($parts | Select-Object -Skip 1) -join ' ') }
            }
        }
        if ($exe -and $exe -notmatch '\\') {
            $name = $exe
            if ($name -notmatch '\.[a-z0-9]{2,4}$') { $name += '.exe' }
            foreach ($d in @("$env:SystemRoot\System32", $env:SystemRoot, "$env:SystemRoot\System32\WindowsPowerShell\v1.0", "$env:SystemRoot\SysWOW64")) {
                $cand = Join-Path $d $name
                if ([IO.File]::Exists($cand)) { $exe = $cand; break }
            }
        }
        $res.Host = $exe; $res.Args = $rest; $res.Target = $exe
        $leaf = ''
        try { $leaf = [IO.Path]::GetFileName($exe).ToLowerInvariant() } catch {}
        if ($script:ScriptHosts -contains $leaf) {
            $res.IsHost = $true
            if ($rest -match '(?i)"?([a-z]:\\[^"<>|*?\r\n,]+?\.(dll|exe|ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd|scr|cpl|jar|ocx|py|au3))"?') {
                $res.Target = $Matches[1]
            }
        }
    } catch {}
    $res
}

# Suspicious command-line markers. Built from pieces so this scanner's own source does not look like the thing it hunts.
$script:StrongCmdRx = '(?i)(' + ((
        '\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{24,}',
        ('from' + 'base64' + 'string'),
        ('download' + '(string|file|data)'),
        ('invoke-' + 'expression'),
        '\biex\s*[\(\$]',
        ('net\.' + 'webclient'),
        ('invoke-' + 'webrequest'),
        ('start-' + 'bitstransfer'),
        'bitsadmin.*?/transfer',
        'certutil.*?-urlcache',
        'mshta(\.exe)?"?\s+"?(https?|vbscript|javascript):',
        'regsvr32.*?/i:https?',
        'scrobj\.dll',
        ('stratum' + '\+tcp'),
        ('--donate' + '-level'),
        'curl(\.exe)?\s.*https?://.*\|\s*(cmd|powershell)'
    ) -join '|') + ')'
$script:WeakCmdRx = '(?i)(-w(indowstyle)?\s+h(idden)?\b|-nop(rofile)?\b.*-w|\s-ep?\s+b(ypass)?\b|-exec(utionpolicy)?\s+b(ypass)?\b)'

# Known adware / PUP / risky software families. Patterns are lower-case substrings matched against names, paths, publishers and command lines.
$script:PupDb = @(
    @{ Name = 'PC App Store (Fast Corporation)'; Severity = 'High'; Patterns = @('pcappstore', 'pc app store', 'fast corporation', 'fastcorporation', 'nw_store.exe');
        Info = 'Adware "app store" that installs per-user, auto-starts, pushes notifications/ads and other downloads. Flagged as a PUP by most antivirus vendors.' },
    @{ Name = 'OneLaunch'; Severity = 'High'; Patterns = @('onelaunch'); Info = 'Adware desktop search bar / browser bundled with free downloads.' },
    @{ Name = 'WaveBrowser (Wavesor)'; Severity = 'High'; Patterns = @('wavebrowser', 'wave browser', 'wavesor', 'swiftsearch', 'swift search'); Info = 'Browser hijacker that changes search and shows ads.' },
    @{ Name = 'OneStart browser'; Severity = 'High'; Patterns = @('onestart.ai', 'onestart browser', '\onestart\', 'onestart.exe', 'onestartbar'); Info = 'Adware Chromium browser that installs per-user and auto-starts.' },
    @{ Name = 'AppSuite PDF Editor / ManualFinder (backdoored, 2025)'; Severity = 'High'; Patterns = @('appsuite pdf', 'appsuite-pdf', 'echo infini', 'glint software', 'summit nexus', 'manualfinder', 'manual finder'); Info = 'Signed "free PDF editor" family that was found to carry a backdoor/infostealer in 2025.' },
    @{ Name = 'JustAskJacky'; Severity = 'High'; Patterns = @('justaskjacky', 'just ask jacky'); Info = 'Trojan disguised as an AI assistant app.' },
    @{ Name = 'Segurazo / SAntivirus'; Severity = 'High'; Patterns = @('segurazo', 'santivirus realtime', 'santivirus.exe'); Info = 'Rogue antivirus that is hard to uninstall.' },
    @{ Name = 'Wajam / Social2Search'; Severity = 'High'; Patterns = @('wajam', 'social2search', 'searchawesome', 'search awesome'); Info = 'Ad-injecting browser hijacker.' },
    @{ Name = 'Search hijacker / toolbar'; Severity = 'High'; Patterns = @('conduit', 'ask toolbar', 'apnsetup', 'ask.com', 'babylon toolbar', 'delta-search', 'deltasearch', 'search protect', 'searchprotect', 'sweetpacks', 'ilivid', 'snap.do', 'trovi.com', 'mystart.com', 'istartsurf', 'yontoo', 'superfish', 'browsefox', 'crossrider', 'nationzoom', 'safesearch.net', 'mixisearch', 'search baron', 'searchbaron', 'qone8', 'myway.com', 'mywebsearch', 'mindspark', 'dealply', 'relevantknowledge', 'premieropinion'); Info = 'Changes the browser search engine/home page and injects ads.' },
    @{ Name = 'Piracy activator (often trojanized)'; Severity = 'High'; Patterns = @('kmspico', 'kmsauto', 'autokms', 'kms_vl_all', 'kmsnano', 'kms tools', 'microsoft toolkit', 'windows loader', 'hwidgen', 're-loader'); Info = 'Unofficial Windows/Office activators. Many copies in circulation carry malware, and they usually add antivirus exclusions.' },
    @{ Name = 'Crypto miner'; Severity = 'Medium'; Patterns = @('xmrig', 'nicehash', 'minergate', 'phoenixminer', 'nbminer', 'lolminer', 'gminer', 'cgminer', 'bfgminer', 'ethminer', 'cpuminer', 't-rex miner', 'teamredminer', 'srbminer'); Info = 'Cryptocurrency mining software. Fine if installed on purpose; otherwise a strong sign of infection.' },
    @{ Name = 'Unwanted browser'; Severity = 'Medium'; Patterns = @('chromstera', 'olcinium', 'qword browser', 'crossbrowser', 'cross browser', 'torch browser', 'bobrowser', 'avant browser', 'baidu browser', 'ucbrowser', 'uc browser', 'epibrowser', 'shift browser'); Info = 'Low-reputation Chromium browser usually installed via bundles.' },
    @{ Name = 'Fake optimizer / scareware'; Severity = 'Medium'; Patterns = @('reimage', 'restoro', 'fortect', 'outbyte', 'pc accelerate', 'pcaccelerate', 'advanced system repair', 'pc optimizer pro', 'speedypc', 'speedy pc', 'pckeeper', 'mypc utilities', 'pc helpsoft', 'total system care', 'driver support one', 'driversupport', 'slimware', 'slimcleaner', 'winzip driver updater', 'winzip system utilities', 'systweak', 'advanced system optimizer', 'tweakbit', 'smart pc fixer', 'pc speed maximizer', 'registry reviver', 'reviversoft', 'driver reviver', 'one system care', 'advanced pc cleanup', 'winthruster', 'solvusoft', 'driverdoc', 'advanced driver updater', 'driverfix', 'pc app booster'); Info = '"PC cleaner/driver updater" software that exaggerates problems to sell a license. Not needed on Windows 10/11.' },
    @{ Name = 'Bundleware / adware platform'; Severity = 'Medium'; Patterns = @('web companion', 'webcompanion', 'lavasoft', 'adaware web', 'bytefence', 'installcore', 'opencandy', 'amonetize', 'somoto', 'outbrowse', 'download valley', 'downloadvalley', 'ironsource', 'wincore', 'mypcbackup', 'softonic downloader'); Info = 'Software that comes bundled with free downloads to show ads or install more software.' },
    @{ Name = 'Bundled "extra" / low-trust utility'; Severity = 'Low'; Patterns = @('mcafee webadvisor', 'webadvisor', 'avast secure browser', 'avg secure browser', 'ccleaner browser', 'norton safe search', 'iobit', 'driver booster', 'advanced systemcare', 'utorrent', 'bittorrent', 'yandex', 'hola vpn', 'hola better internet', 'totalav', 'total av', 'pcprotect', 'pc protect', 'scanguard', 'shield antivirus', 'protected.net', 'opera crypto'); Info = 'Usually arrives bundled with other installers. Not malware, but rarely wanted. Remove if not used.' }
)

function Find-Pup {
    param([object[]]$Text)
    $parts = @($Text | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if ($parts.Count -eq 0) { return $null }
    $hay = ($parts -join ' | ').ToLowerInvariant()
    foreach ($e in $script:PupDb) {
        foreach ($p in $e.Patterns) {
            if ($hay.Contains($p)) { return [pscustomobject]@{ Name = $e.Name; Severity = $e.Severity; Info = $e.Info; Pattern = $p } }
        }
    }
    $null
}

# ---------------------------------------------------------------- trust list
# trusted.txt (next to START-SCAN.cmd) lists programs the technician has vouched for. Lines:
#   path <full path, wildcards allowed>     sha256 <hash>     signer <exact certificate name>
# Trusted items are not flagged; they are listed in one Info finding so nothing is hidden silently.
$script:TrustList = @{ Paths = @(); Hashes = @{}; Signers = @(); File = '' }
$script:TrustHits = @{}

function Import-TrustList {
    param([string]$File)
    $script:TrustList = @{ Paths = @(); Hashes = @{}; Signers = @(); File = $File }
    if (-not $File -or -not [IO.File]::Exists($File)) { return }
    foreach ($line in [IO.File]::ReadAllLines($File)) {
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        if ($l -match '^(?i)sha256\s+([0-9a-f]{64})$') { $script:TrustList.Hashes[$Matches[1].ToUpperInvariant()] = $true }
        elseif ($l -match '^(?i)path\s+(.+)$') { $script:TrustList.Paths += $Matches[1].Trim().Trim('"') }
        elseif ($l -match '^(?i)signer\s+(.+)$') { $script:TrustList.Signers += $Matches[1].Trim() }
    }
}

function Test-Trusted {
    # $Signer is only honoured when the signature is valid; callers pass '' otherwise.
    param([string]$Path, [string]$Signer)
    if (-not $Path) { return $false }
    $hit = $null
    foreach ($p in $script:TrustList.Paths) { if ($Path -like $p) { $hit = "path $p"; break } }
    if (-not $hit -and $Signer) { foreach ($s in $script:TrustList.Signers) { if ($Signer -eq $s) { $hit = "signer $s"; break } } }
    if (-not $hit -and $script:TrustList.Hashes.Count -gt 0) {
        $h = Get-Sha256 $Path
        if ($h -and $script:TrustList.Hashes.ContainsKey($h)) { $hit = 'sha256' }
    }
    if ($hit) { $script:TrustHits[$Path.ToLowerInvariant()] = "$Path  ($hit)"; return $true }
    $false
}

# Evaluate anything that launches a program (autorun, task, service, shortcut) and explain why it is or is not risky.
function Measure-ExecRisk {
    param([string]$Command, [string]$Name, [switch]$Quiet)
    $lt = Resolve-LaunchTarget $Command
    $sig = Get-FileSig $lt.Target
    $zone = Get-PathZone $lt.Target
    $reasons = New-Object System.Collections.Generic.List[string]
    $sev = $null
    if ($sig.Exists -and $Command -notmatch $script:StrongCmdRx -and (Test-Trusted $lt.Target $(if ($sig.Trusted) { $sig.Signer } else { '' }))) {
        return [pscustomobject]@{
            Target = $lt.Target; Host = $lt.Host; Signer = $sig.Signer; SigStatus = $sig.Status; Trusted = $sig.Trusted
            IsMicrosoft = $sig.IsMicrosoft; Exists = $sig.Exists; Zone = $zone; Severity = $null; Reasons = 'Trusted by you (trusted.txt)'; Pup = $null; UserTrusted = $true
        }
    }
    $pup = Find-Pup @($Name, $Command, $sig.Signer)
    if ($pup) { $reasons.Add("Known adware/PUP: $($pup.Name)"); $sev = Get-MaxSeverity @($sev, $pup.Severity) }
    if (-not $sig.Exists) {
        if ($lt.Target -and $sig.Status -eq 'Missing') { $reasons.Add('Target file no longer exists (leftover entry)'); $sev = Get-MaxSeverity @($sev, 'Low') }
    } elseif ($sig.Status -eq 'HashMismatch') {
        $reasons.Add('Digital signature is BROKEN - file was modified after signing'); $sev = Get-MaxSeverity @($sev, 'High')
    } elseif ((-not $sig.Trusted) -and (-not $sig.Skipped)) {
        if (Test-UserWritableZone $zone) { $reasons.Add("Unsigned program in $zone"); $sev = Get-MaxSeverity @($sev, 'High') }
        elseif (-not $Quiet) { $reasons.Add('Not digitally signed'); $sev = Get-MaxSeverity @($sev, 'Low') }
    }
    if ($Command -match $script:StrongCmdRx) { $reasons.Add('Suspicious command line (encoded/download/miner)'); $sev = Get-MaxSeverity @($sev, 'High') }
    elseif ($Command -match $script:WeakCmdRx) { $reasons.Add('Runs hidden / bypasses script policy'); $sev = Get-MaxSeverity @($sev, 'Low') }
    if ($lt.IsHost -and $lt.Target -ne $lt.Host -and (Test-UserWritableZone (Get-PathZone $lt.Target))) {
        $reasons.Add('Script or DLL launched from a user-writable folder'); $sev = Get-MaxSeverity @($sev, 'Medium')
    }
    if ($Command -match '(?i)(explorer|cmd|rundll32)(\.exe)?"?\s+.*https?://') { $reasons.Add('Opens a web page automatically'); $sev = Get-MaxSeverity @($sev, 'Medium') }
    [pscustomobject]@{
        Target = $lt.Target; Host = $lt.Host; Signer = $sig.Signer; SigStatus = $sig.Status; Trusted = $sig.Trusted
        IsMicrosoft = $sig.IsMicrosoft; Exists = $sig.Exists; Zone = $zone; Severity = $sev; Reasons = ($reasons -join '; '); Pup = $pup; UserTrusted = $false
    }
}

# Repair steps for an unsigned-but-not-known-bad program: everything starts unticked, with "trust it" offered first,
# so a one-click Apply can never remove something legitimate the technician has not looked at.
function New-UnknownProgramActions {
    param([string]$Path, [string]$Name, [object[]]$RemoveActions)
    $acts = @()
    if ($Path) { $acts += New-RepairAction -Kind Trust -Label "I recognise $Name - trust it and stop flagging it (adds it to trusted.txt)" -Off -Params @{ Path = $Path } }
    foreach ($a in @($RemoveActions | Where-Object { $_ })) { $a['Off'] = $true; $acts += $a }
    , $acts
}

function Get-SigLabel {
    param($Risk)
    if (-not $Risk.Exists) { return $Risk.SigStatus }
    if ($Risk.Trusted) { return $Risk.Signer }
    if ($Risk.Signer) { return "$($Risk.Signer) [$($Risk.SigStatus)]" }
    $Risk.SigStatus
}

# Enumerate files without throwing on access-denied folders; skips junctions/symlinks.
function Get-FilesSafe {
    param([string]$Root, [int]$MaxDepth = 3, [string[]]$Extensions, [datetime]$Since = [datetime]::MinValue,
        [int]$MaxFiles = 5000, [int]$MaxSeconds = 45, [string[]]$SkipDirRx, [string]$NameRx)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Root) { return , $out }
    try { if (-not [IO.Directory]::Exists($Root)) { return , $out } } catch { return , $out }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($Root, 0))
    $extSet = @{}
    foreach ($e in $Extensions) { $extSet[$e.ToLowerInvariant()] = $true }
    while ($stack.Count -gt 0) {
        if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds -or $out.Count -ge $MaxFiles) { break }
        $item = $stack.Pop(); $dir = [string]$item[0]; $depth = [int]$item[1]
        $di = New-Object IO.DirectoryInfo($dir)
        try {
            foreach ($f in $di.EnumerateFiles()) {
                if ($extSet.Count -gt 0 -and -not $extSet.ContainsKey($f.Extension.ToLowerInvariant())) { continue }
                if ($NameRx -and $f.Name -notmatch $NameRx) { continue }
                if ($f.LastWriteTime -lt $Since -and $f.CreationTime -lt $Since) { continue }
                $out.Add($f)
                if ($out.Count -ge $MaxFiles) { break }
            }
        } catch {}
        if ($depth -lt $MaxDepth) {
            try {
                foreach ($d in $di.EnumerateDirectories()) {
                    if (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $skip = $false
                    foreach ($rx in $SkipDirRx) { if ($d.FullName -match $rx) { $skip = $true; break } }
                    if (-not $skip) { $stack.Push(@($d.FullName, ($depth + 1))) }
                }
            } catch {}
        }
    }
    , $out
}

function Get-DirSize {
    param([string]$Path, [int]$MaxSeconds = 15)
    $total = [int64]0; $count = 0; $partial = $false
    try { if (-not [IO.Directory]::Exists($Path)) { return [pscustomobject]@{ Bytes = 0; Files = 0; Partial = $false; Exists = $false } } } catch { return [pscustomobject]@{ Bytes = 0; Files = 0; Partial = $true; Exists = $false } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $partial = $true; break }
        $di = New-Object IO.DirectoryInfo($stack.Pop())
        try { foreach ($f in $di.EnumerateFiles()) { $total += $f.Length; $count++ } } catch { $partial = $true }
        try {
            foreach ($d in $di.EnumerateDirectories()) {
                if (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($d.FullName) }
            }
        } catch { $partial = $true }
    }
    [pscustomobject]@{ Bytes = $total; Files = $count; Partial = $partial; Exists = $true }
}

function Get-ShortcutInfo {
    param([string]$Path)
    try {
        if (-not $script:WShell) { $script:WShell = New-Object -ComObject WScript.Shell }
        $s = $script:WShell.CreateShortcut($Path)
        return [pscustomobject]@{ Target = $s.TargetPath; Args = $s.Arguments; WorkDir = $s.WorkingDirectory }
    } catch { return $null }
}

function Get-ZoneInfo {
    param([string]$Path)
    $r = [pscustomobject]@{ Zone = ''; HostUrl = ''; ReferrerUrl = '' }
    try {
        $lines = Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop
        foreach ($l in $lines) {
            if ($l -match '^ZoneId=(\d)') { $r.Zone = @{ '0' = 'Local'; '1' = 'Intranet'; '2' = 'Trusted'; '3' = 'Internet'; '4' = 'Restricted' }[$Matches[1]] }
            elseif ($l -match '^HostUrl=(.+)$') { $r.HostUrl = $Matches[1] }
            elseif ($l -match '^ReferrerUrl=(.+)$') { $r.ReferrerUrl = $Matches[1] }
        }
    } catch {}
    $r
}

# ---------------------------------------------------------------- events, JSON, processes

function Get-EventsSafe {
    # One query per provider: a single provider that does not exist on this PC (e.g. nvlddmkm on an AMD
    # machine) would otherwise make Get-WinEvent fail the whole query and silently return nothing.
    param([hashtable]$Filter, [int]$Max = 500)
    $provs = @($Filter['ProviderName'])
    if ($provs.Count -le 1) {
        try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
    }
    $all = @()
    foreach ($p in $provs) {
        $f = $Filter.Clone()
        $f['ProviderName'] = $p
        try { $all += @(Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction Stop) } catch {}
    }
    @($all | Sort-Object TimeCreated -Descending | Select-Object -First $Max)
}

function ConvertTo-PlainData {
    # Reduce any object graph to strings/numbers/bools/arrays/hashtables so ConvertTo-Json (PS 5.1) cannot choke on it.
    param($Value, [int]$Depth = 0)
    if ($null -eq $Value) { return $null }
    if ($Depth -gt 14) { return [string]$Value }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToString('s') }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { return $Value }
    if ($Value -is [ValueType]) { return [string]$Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $Value.Keys) { $h[[string]$k] = ConvertTo-PlainData $Value[$k] ($Depth + 1) }
        return $h
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $arr = New-Object System.Collections.Generic.List[object]
        foreach ($x in $Value) { $arr.Add((ConvertTo-PlainData $x ($Depth + 1))) }
        return , $arr.ToArray()
    }
    $h = [ordered]@{}
    foreach ($p in $Value.PSObject.Properties) {
        if ($p.Name -like '_*') { continue }
        $h[$p.Name] = ConvertTo-PlainData $p.Value ($Depth + 1)
    }
    $h
}

function Get-EventData {
    # Named EventData fields from an event's XML, as a hashtable.
    param($EventRecord)
    $h = @{}
    try {
        $x = [xml]$EventRecord.ToXml()
        foreach ($d in $x.Event.EventData.Data) {
            if ($d.Name) { $h[$d.Name] = $d.'#text' }
        }
    } catch {}
    $h
}

function ConvertFrom-JsonFast {
    param([string]$Text)
    if (-not $script:JsSer) {
        Add-Type -AssemblyName System.Web.Extensions
        $script:JsSer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $script:JsSer.MaxJsonLength = [int]::MaxValue
        $script:JsSer.RecursionLimit = 1000
    }
    , $script:JsSer.DeserializeObject($Text)
}

function Read-JsonFile {
    param([string]$Path)
    try {
        if (-not [IO.File]::Exists($Path)) { return $null }
        $txt = [IO.File]::ReadAllText($Path)
        return , (ConvertFrom-JsonFast $txt)
    } catch { return $null }
}

function Get-JVal {
    param($Obj, [string]$Path)
    $cur = $Obj
    foreach ($k in $Path.Split('.')) {
        if ($cur -is [System.Collections.IDictionary] -and $cur.ContainsKey($k)) { $cur = $cur[$k] } else { return $null }
    }
    # arrays are emitted element by element so callers can rebuild them with @(); dictionaries pass through whole
    $cur
}

function Invoke-External {
    param([string]$File, [string]$Arguments, [int]$TimeoutSec = 120)
    $tmpOut = [IO.Path]::GetTempFileName(); $tmpErr = [IO.Path]::GetTempFileName()
    $r = [pscustomobject]@{ Output = ''; ExitCode = $null; TimedOut = $false }
    try {
        $p = Start-Process -FilePath $File -ArgumentList $Arguments -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr -NoNewWindow -PassThru -ErrorAction Stop
        $null = $p.Handle
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            $r.TimedOut = $true
            try { $p.Kill() } catch {}
        } else { $r.ExitCode = $p.ExitCode }
        $bytes = [IO.File]::ReadAllBytes($tmpOut)
        $zeros = 0
        foreach ($b in ($bytes | Select-Object -First 400)) { if ($b -eq 0) { $zeros++ } }
        if ($zeros -gt 50) { $r.Output = [Text.Encoding]::Unicode.GetString($bytes) } else { $r.Output = [Text.Encoding]::Default.GetString($bytes) }
        $r.Output = ($r.Output -replace "`0", '') -replace "`r", ''
    } catch {
        $r.Output = 'Failed to run: ' + $_.Exception.Message
    } finally {
        Remove-Item -LiteralPath $tmpOut, $tmpErr -Force -ErrorAction SilentlyContinue
    }
    $r
}

$script:SystemProcNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'explorer.exe',
    'spoolsv.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe', 'dwm.exe', 'lsm.exe', 'sihost.exe', 'ctfmon.exe',
    'searchindexer.exe', 'runtimebroker.exe', 'fontdrvhost.exe', 'wuauclt.exe', 'msmpeng.exe', 'audiodg.exe', 'regsvr32.exe', 'userinit.exe')

function Test-Masquerade {
    # True when a file uses a core Windows process name but lives outside the Windows directory.
    param([string]$Path)
    if (-not $Path) { return $false }
    $leaf = ''
    try { $leaf = [IO.Path]::GetFileName($Path).ToLowerInvariant() } catch { return $false }
    if ($script:SystemProcNames -notcontains $leaf) { return $false }
    $p = $Path.ToLowerInvariant()
    if ($p -match '^[a-z]:\\windows\\') { return $false }
    if ($leaf -eq 'msmpeng.exe' -and $p -match '\\(windows defender|microsoft\\windows defender)') { return $false }
    $true
}

# dedicated PC App Store detection/removal (used by both the scanner and the Repair Console)
. (Join-Path $PSScriptRoot 'PCAppStore.ps1')
