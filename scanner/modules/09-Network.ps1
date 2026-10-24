# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Network: connections, listeners, DNS, proxy, hosts file, firewall exceptions, shares, root certificates

function Test-PrivateIp {
    param([string]$Ip)
    if (-not $Ip) { return $true }
    # fec0:0:0:ffff::1-3 are Windows' built-in IPv6 DNS placeholders, not real servers
    $Ip -match '^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1$|::$|fe80:|fec0:|fc|fd|::ffff:(10|127|192\.168)\.)'
}

function Get-Ipv6Prefix64 {
    param([string]$Ip)
    try {
        $a = [System.Net.IPAddress]::Parse(($Ip -split '%')[0])
        if ($a.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }
        return ([BitConverter]::ToString($a.GetAddressBytes(), 0, 8))
    } catch { return $null }
}

function Invoke-NetworkScan {
    $S = 'network'
    $pi = $script:Shared.ProcIndex
    if (-not $pi) { $pi = @{} }

    # ---- adapters + DNS
    $adRows = @(); $dnsBad = @()
    $goodDns = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15',
        '76.76.2.0', '76.76.10.0', '185.228.168.9', '185.228.169.9', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3', '9.9.9.11', '149.112.112.11', '64.6.64.6', '64.6.65.6',
        '2001:4860:4860::8888', '2001:4860:4860::8844', '2606:4700:4700::1111', '2606:4700:4700::1001', '2620:fe::fe', '2620:fe::9')
    try {
        foreach ($a in @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })) {
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
            $ip = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
            $gw = @(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop })
            # IPv6: home routers hand out their own global address as DNS (e.g. 2603:...::1 on Spectrum). Same /64 as this PC = the local router.
            $v6Prefixes = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { Get-Ipv6Prefix64 $_.IPAddress } | Where-Object { $_ })
            $gw6 = @(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop })
            $isLocal = { param($s) (Test-PrivateIp $s) -or ($gw -contains $s) -or ($gw6 -contains $s) -or ((Get-Ipv6Prefix64 $s) -and $v6Prefixes -contains (Get-Ipv6Prefix64 $s)) }
            $odd = @($dns | Where-Object { -not (& $isLocal $_) -and $goodDns -notcontains $_ })
            # static (typed-in) DNS lives in NameServer; DHCP-supplied DNS in DhcpNameServer
            $static = @()
            foreach ($stack in 'Tcpip', 'Tcpip6') {
                $ns = [string](Get-RegValue "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$stack\Parameters\Interfaces\$($a.InterfaceGuid)" 'NameServer')
                if ($ns.Trim()) { $static += @($ns -split '[,\s]+' | Where-Object { $_ }) }
            }
            $dnsBad += @($odd | ForEach-Object { [pscustomobject]@{ Server = $_; Adapter = $a.Name; If = $a.ifIndex; Static = ($static -contains $_) } })
            $adRows += [pscustomobject]@{ Adapter = $a.Name; Description = $a.InterfaceDescription; Speed = $a.LinkSpeed; IPv4 = ($ip -join ', '); Gateway = ($gw -join ', '); 'DNS servers' = ($dns -join ', '); 'DNS set by' = $(if ($static) { 'Typed in manually' } else { 'Router (DHCP)' }); _Flag = $(if ($odd) { 'medium' } else { '' }); _If = $a.ifIndex }
        }
    } catch { Add-Note -Section $S -Text "Could not read network adapters: $($_.Exception.Message)" -Tone warn }
    Add-Table -Section $S -Title 'Active network adapters' -Rows $adRows
    if ($dnsBad.Count -gt 0) {
        $staticBad = @($dnsBad | Where-Object { $_.Static })
        $sev = if ($staticBad.Count -gt 0 -and @($staticBad | Where-Object { $_.Server -notmatch ':' }).Count -gt 0) { 'Medium' } else { 'Low' }
        Add-Finding -Severity $sev -Category 'Network' -Section $S -Title 'DNS is set to unrecognised public servers' `
            -Evidence @($dnsBad | ForEach-Object { "$($_.Server) on $($_.Adapter) - $(if ($_.Static) { 'typed in manually on this PC' } else { 'handed out by the router' })" }) `
            -Why 'DNS decides which server a website name goes to. Malware (e.g. DNSChanger-style) points it at rogue servers to redirect banking or search sites. It can also simply be your ISP''s DNS - check the owner.' `
            -Fix $(if ($staticBad.Count) { 'Look the address up (e.g. whois). If it is not your ISP or a provider you chose: Settings > Network & internet > adapter > DNS server assignment > Automatic (DHCP).' } else { 'This PC is already on automatic DNS, so the router supplies these. Look the address up (whois); if it is not your internet provider, check the router''s DNS settings and change its admin password.' }) `
            -Actions $(if ($staticBad.Count) { , @((New-RepairAction -Kind DnsAuto -Label 'Set DNS back to automatic (DHCP) on the adapters where it was typed in' -Risk caution -Params @{ InterfaceIndex = @($staticBad | ForEach-Object { $_.If } | Select-Object -Unique) })) } else { , @() })
    } elseif ($adRows.Count -gt 0) { Add-Pass 'Network' 'DNS servers look normal' }

    # ---- proxy
    $pxRows = @()
    foreach ($h in $script:Hives) {
        $k = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $en = Get-RegValue $k 'ProxyEnable'; $srv = Get-RegValue $k 'ProxyServer'; $pac = Get-RegValue $k 'AutoConfigURL'
        if ($en -eq 1 -or $pac) {
            $pxRows += [pscustomobject]@{ Scope = "User $(Get-ShortUser $h.User)"; 'Proxy enabled' = ($en -eq 1); 'Proxy server' = $srv; 'PAC script' = $pac; Bypass = (Get-RegValue $k 'ProxyOverride'); _Flag = 'high' }
        }
    }
    $wh = Invoke-External -File "$env:SystemRoot\System32\netsh.exe" -Arguments 'winhttp show proxy' -TimeoutSec 20
    $whProxy = $null
    if ($wh.Output -match '(?im)Proxy Server\(s\)\s*:\s*(\S.*)$') { $whProxy = $Matches[1].Trim() }
    if ($whProxy) { $pxRows += [pscustomobject]@{ Scope = 'WinHTTP (system services)'; 'Proxy enabled' = $true; 'Proxy server' = $whProxy; 'PAC script' = ''; Bypass = ''; _Flag = 'high' } }
    Add-Table -Section $S -Title 'Proxy settings' -Rows $pxRows -Empty 'No proxy configured (direct connection). Good.'
    if ($pxRows.Count -gt 0) {
        Add-Finding -Severity High -Category 'Network' -Section $S -Title 'Internet traffic is routed through a proxy' -Evidence @($pxRows | ForEach-Object { "$($_.Scope): $($_.'Proxy server') $($_.'PAC script')" }) `
            -Why 'On a home PC a proxy or PAC script is a classic adware/banking-trojan trick: all browsing passes through someone else''s server where ads can be injected and traffic watched.' `
            -Fix 'Settings > Network & internet > Proxy: turn off "Use a proxy server" and "Use setup script". For WinHTTP, run as admin: netsh winhttp reset proxy. Then find what set it (check persistence findings).' `
            -Actions @((New-RepairAction -Kind ProxyReset -Label 'Remove the proxy / setup script for all users and reset WinHTTP' -Risk caution))
    } else { Add-Pass 'Network' 'No proxy or PAC redirection' }

    # ---- hosts file
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hRows = @()
    try {
        foreach ($l in [IO.File]::ReadAllLines($hostsPath)) {
            $t = ($l -replace '#.*$', '').Trim()
            if (-not $t) { continue }
            $parts = @($t -split '\s+')
            if ($parts.Count -lt 2) { continue }
            $ip = $parts[0]
            foreach ($name in $parts[1..($parts.Count - 1)]) {
                $flag = ''
                $why = ''
                if ($name -match '(?i)(microsoft|windowsupdate|windows\.com|msftncsi|live\.com|office|defender|wdcp|wd\.microsoft|google|bing|facebook|paypal|apple|amazon|bank|chase|wellsfargo|avast|avg|kaspersky|eset|norton|mcafee|malwarebytes|bitdefender|sophos|trendmicro|virustotal)') {
                    if ($ip -notin '127.0.0.1', '0.0.0.0', '::1') { $flag = 'critical'; $why = 'Redirects an important site to another server' }
                    else { $flag = 'high'; $why = 'Blocks a security/update or major site' }
                } elseif ($ip -notin '127.0.0.1', '0.0.0.0', '::1') { $flag = 'medium'; $why = 'Redirects a site to a specific server' }
                $hRows += [pscustomobject]@{ IP = $ip; Hostname = $name; Concern = $why; _Flag = $flag }
            }
        }
    } catch { Add-Note -Section $S -Text 'Could not read the hosts file.' -Tone warn }
    Add-Table -Section $S -Title 'Hosts file entries' -Rows $hRows -Empty 'Hosts file is empty (default). Good.' -Note $hostsPath
    $hc = @($hRows | Where-Object { $_._Flag -eq 'critical' }); $hh = @($hRows | Where-Object { $_._Flag -eq 'high' }); $hm = @($hRows | Where-Object { $_._Flag -eq 'medium' })
    $hostsFix = { param($rows, $lbl) , @((New-RepairAction -Kind HostsRemove -Label $lbl -Risk caution -Params @{ Hostnames = @($rows | ForEach-Object { $_.Hostname }) })) }
    if ($hc.Count) { Add-Finding -Severity Critical -Category 'Network' -Section $S -Title 'Hosts file redirects important websites' -Evidence @($hc | ForEach-Object { "$($_.IP) $($_.Hostname)" }) -Why 'Phishing malware edits the hosts file so real bank/login sites go to fake servers.' -Fix "Open Notepad as admin, edit $hostsPath, delete those lines, then run: ipconfig /flushdns" -Actions (& $hostsFix $hc 'Remove the redirecting hosts entries (backup kept) and flush DNS') }
    if ($hh.Count) { Add-Finding -Severity High -Category 'Network' -Section $S -Title "Hosts file blocks $($hh.Count) security/update or major site(s)" -Evidence @($hh | ForEach-Object { "$($_.IP) $($_.Hostname)" }) -Why 'Malware and piracy tools block antivirus and Windows Update servers this way. Some privacy tools block Microsoft telemetry too.' -Fix "Edit $hostsPath as admin and remove entries you do not recognise, then ipconfig /flushdns." -Actions (& $hostsFix $hh 'Remove the blocking hosts entries (backup kept) and flush DNS') }
    if ($hm.Count) { Add-Finding -Severity Medium -Category 'Network' -Section $S -Title "Hosts file redirects $($hm.Count) site(s)" -Evidence @($hm | ForEach-Object { "$($_.IP) $($_.Hostname)" }) -Fix "Remove unrecognised lines from $hostsPath (as admin)." -Actions (& $hostsFix $hm 'Remove these hosts entries (backup kept) and flush DNS') }
    if ($hRows.Count -eq 0) { Add-Pass 'Network' 'Hosts file is clean' }

    # ---- connections
    $connRows = @(); $listenRows = @()
    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop)
        foreach ($c in $tcp) {
            $p = $pi[[int]$c.OwningProcess]
            $pname = if ($p) { $p.Name } else { "PID $($c.OwningProcess)" }
            $sig = if ($p) { $p.Signer } else { '' }
            $bad = $p -and $p.Severity -in 'Critical', 'High', 'Medium'
            $unsignedUser = $p -and $p.Path -and ($p.Trusted -eq $false) -and (Test-UserWritableZone $p.Zone)
            if ([string]$c.State -eq 'Listen') {
                if ($c.LocalAddress -in '127.0.0.1', '::1') { continue }
                $listenRows += [pscustomobject]@{ Program = $pname; PID = $c.OwningProcess; Address = $c.LocalAddress; Port = $c.LocalPort; Signer = $sig; Path = $(if ($p) { $p.Path } else { '' }); _Flag = $(if ($bad -or $unsignedUser) { 'high' } else { '' }) }
            } elseif ([string]$c.State -eq 'Established' -and -not (Test-PrivateIp $c.RemoteAddress)) {
                $connRows += [pscustomobject]@{ Program = $pname; PID = $c.OwningProcess; Remote = "$($c.RemoteAddress):$($c.RemotePort)"; Local = "$($c.LocalAddress):$($c.LocalPort)"; Signer = $sig; Path = $(if ($p) { $p.Path } else { '' }); _Flag = $(if ($bad -or $unsignedUser) { 'high' } else { '' }) }
            }
        }
    } catch { Add-Note -Section $S -Text "Could not list TCP connections: $($_.Exception.Message)" -Tone warn }
    Add-Table -Section $S -Title 'Open internet connections (right now)' -Rows @($connRows | Sort-Object Program) -Note 'Remote addresses are shown as IPs only; nothing was looked up online.'
    Add-Table -Section $S -Title 'Programs accepting incoming connections' -Rows @($listenRows | Sort-Object Port -Unique)
    $badConn = @($connRows + $listenRows | Where-Object { $_._Flag -eq 'high' } | Select-Object -ExpandProperty Program -Unique)
    if ($badConn.Count -gt 0) {
        Add-Finding -Severity High -Category 'Network' -Section $S -Title 'Suspicious programs are talking to the internet' -Evidence $badConn `
            -Why 'Unsigned programs from user folders with live internet connections fit the pattern of adware, remote-access trojans or miners.' `
            -Fix 'See the Processes section for each program. Remove the software or block it, then re-scan.'
    }

    # ---- firewall exceptions for user-folder programs
    $fwRows = @()
    try {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($r in $fw.Rules) {
            if (-not $r.Enabled -or $r.Direction -ne 1 -or $r.Action -ne 1) { continue }
            $app = [string]$r.ApplicationName
            if (-not $app) { continue }
            $app = [Environment]::ExpandEnvironmentVariables($app)
            $zone = Get-PathZone $app
            $pup = Find-Pup @($r.Name, $app)
            if (-not (Test-UserWritableZone $zone) -and -not $pup) { continue }
            $sig = Get-FileSig $app
            $sev = $null
            if ($pup) { $sev = $pup.Severity }
            elseif ($sig.Exists -and -not $sig.Trusted -and -not $sig.Skipped) { $sev = 'Medium' }
            elseif (-not $sig.Exists) { $sev = 'Low' }
            $fwRows += [pscustomobject]@{ Rule = $r.Name; Program = $app; Signer = $(if ($sig.Trusted) { $sig.Signer } else { $sig.Status }); Ports = $r.LocalPorts; Profiles = $r.Profiles; _Flag = (ConvertTo-FlagClass $sev); _Sev = $sev }
        }
    } catch {}
    Add-Table -Section $S -Title 'Inbound firewall exceptions for programs in user folders' -Rows $fwRows -Columns @('Rule', 'Program', 'Signer', 'Ports') -Empty 'None.'
    $fwBad = @($fwRows | Where-Object { $_._Sev -in 'High', 'Medium' })
    $fwBadProgs = @($fwBad | ForEach-Object { $_.Program.ToLowerInvariant() } | Select-Object -Unique)
    if ($fwBad.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Network' -Section $S -Title "$($fwBadProgs.Count) unsigned program(s) in user folders are allowed through the firewall" -Evidence $fwBadProgs `
            -Why 'Remote-access trojans add themselves as firewall exceptions so they can be reached from outside.' `
            -Fix 'Windows Security > Firewall & network protection > Allow an app through firewall: remove the entries you do not recognise.' `
            -Actions @((New-RepairAction -Kind FirewallRuleRemove -Label 'Remove the firewall exceptions for these programs only (they will ask again if they need one)' -Risk caution -Params @{ Rules = @($fwBad | ForEach-Object { $_.Rule } | Select-Object -Unique); Programs = $fwBadProgs }))
    }
    $fwStale = @($fwRows | Where-Object { $_._Sev -eq 'Low' })
    if ($fwStale.Count -gt 5) {
        Add-Finding -Severity Low -Category 'Network' -Section $S -Title "$($fwStale.Count) firewall exceptions point to programs that no longer exist" -Fix 'Harmless clutter; clean up via "Allow an app through firewall" if you like.' `
            -Actions @((New-RepairAction -Kind FirewallRuleRemove -Label 'Remove the exceptions that point to programs which no longer exist' -Risk caution -Params @{ Rules = @($fwStale | ForEach-Object { $_.Rule } | Select-Object -Unique); Programs = @($fwStale | ForEach-Object { $_.Program.ToLowerInvariant() } | Select-Object -Unique) }))
    }

    # ---- shares
    try {
        $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|print\$|[A-Z]\$)$' })
        $shRows = @($shares | ForEach-Object { [pscustomobject]@{ Share = $_.Name; Path = $_.Path; Description = $_.Description; _Flag = $(if ($_.Path -match '^[A-Za-z]:\\?$') { 'medium' } else { '' }) } })
        Add-Table -Section $S -Title 'Shared folders' -Rows $shRows -Empty 'No folders are shared on the network.'
        $whole = @($shRows | Where-Object { $_._Flag -eq 'medium' })
        if ($whole.Count) { Add-Finding -Severity Medium -Category 'Network' -Section $S -Title 'An entire drive is shared on the network' -Evidence @($whole | ForEach-Object { "$($_.Share) -> $($_.Path)" }) -Fix 'Stop sharing it (right-click the drive > Properties > Sharing > Advanced Sharing) unless this is intentional.' }
    } catch {}

    # ---- root certificates
    $certRows = @()
    $badRootRx = '(?i)superfish|edellroot|dsdtestprovider|privdog|komodia|sendori|wiresearch|lavasoft|adguard personal'
    $mitmRx = '(?i)fiddler|mitmproxy|charles proxy|burp|do_not_trust|portswigger|httptoolkit|proxyman'
    $avRx = '(?i)avast|avg|kaspersky|eset|bitdefender|norton|sophos|trend micro|f-secure|webroot|zscaler|netskope|forcepoint|fortinet|cisco umbrella'
    try {
        foreach ($c in (Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop)) {
            $why = ''; $flag = ''
            if ($c.Subject -match $badRootRx) { $why = 'Known malicious/adware root certificate'; $flag = 'critical' }
            elseif ($c.HasPrivateKey -and $c.Subject -notmatch '(?i)CN=localhost') { $why = 'Root certificate with its private key on this PC (lets software impersonate any website)'; $flag = 'high' }
            elseif ($c.Subject -match $mitmRx) { $why = 'HTTPS interception/debugging tool root'; $flag = 'medium' }
            elseif ($c.Subject -match $avRx) { $why = 'Antivirus/web-filter HTTPS scanning root'; $flag = '' }
            else { continue }
            $certRows += [pscustomobject]@{ Store = 'Machine'; Subject = $c.Subject; Issuer = $c.Issuer; 'Valid until' = $c.NotAfter; Thumbprint = $c.Thumbprint; Concern = $why; _Flag = $flag }
        }
    } catch {}
    foreach ($h in $script:Hives) {
        foreach ($k in (Get-ChildItem -LiteralPath "$($h.Root)\Software\Microsoft\SystemCertificates\Root\Certificates" -ErrorAction SilentlyContinue)) {
            $thumb = $k.PSChildName
            $subj = ''
            try { $cc = Get-Item -LiteralPath "Cert:\CurrentUser\Root\$thumb" -ErrorAction Stop; $subj = $cc.Subject } catch {}
            $flag = 'low'; $why = 'Root certificate installed by the user (not by Windows)'
            if ($subj -match $badRootRx) { $flag = 'critical'; $why = 'Known malicious/adware root certificate' }
            elseif ($subj -match $mitmRx) { $flag = 'medium'; $why = 'HTTPS interception/debugging tool root' }
            elseif ($subj -match $avRx) { $flag = ''; $why = 'Antivirus/web-filter HTTPS scanning root' }
            $certRows += [pscustomobject]@{ Store = "User $(Get-ShortUser $h.User)"; Subject = $(if ($subj) { $subj } else { '(subject readable only by that user)' }); Issuer = ''; 'Valid until' = $null; Thumbprint = $thumb; Concern = $why; _Flag = $flag }
        }
    }
    Add-Table -Section $S -Title 'Notable trusted root certificates' -Rows $certRows -Empty 'No unusual root certificates found.' `
        -Note 'Root certificates decide which HTTPS sites are trusted. Extra roots let software read encrypted traffic.'
    foreach ($sev in 'Critical', 'High', 'Medium') {
        $hits = @($certRows | Where-Object { $_._Flag -eq $sev.ToLower() })
        if ($hits.Count -eq 0) { continue }
        Add-Finding -Severity $sev -Category 'Network' -Section $S -Title "$($hits.Count) risky trusted root certificate(s)" -Evidence @($hits | ForEach-Object { "$($_.Store): $($_.Subject) [$($_.Thumbprint)] - $($_.Concern)" }) `
            -Why 'A rogue root certificate lets adware or an attacker silently read and alter HTTPS traffic, including banking and email.' `
            -Fix 'Run certlm.msc (machine) / certmgr.msc (user) > Trusted Root Certification Authorities > Certificates, delete the listed thumbprints (unless it belongs to a developer tool you use).' `
            -Actions @($hits | ForEach-Object { New-RepairAction -Kind CertRemove -Label "Remove root certificate $(Limit-Text $_.Subject 60) [$($_.Thumbprint)] (a copy is kept in quarantine)" -Risk caution -Params @{ Store = $(if ($_.Store -eq 'Machine') { 'LocalMachine' } else { 'CurrentUser' }); Thumbprint = $_.Thumbprint } })
    }
}
