# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Browsers: extensions, homepage/search/startup hijacks, policies ("managed by your organization"), notification spam, shortcut hijacks

$script:KnownBrowsers = @(
    @{ Name = 'Google Chrome'; Rel = 'Google\Chrome\User Data' },
    @{ Name = 'Chrome Beta'; Rel = 'Google\Chrome Beta\User Data' },
    @{ Name = 'Microsoft Edge'; Rel = 'Microsoft\Edge\User Data' },
    @{ Name = 'Edge Beta'; Rel = 'Microsoft\Edge Beta\User Data' },
    @{ Name = 'Brave'; Rel = 'BraveSoftware\Brave-Browser\User Data' },
    @{ Name = 'Vivaldi'; Rel = 'Vivaldi\User Data' },
    @{ Name = 'Chromium'; Rel = 'Chromium\User Data' },
    @{ Name = 'Yandex'; Rel = 'Yandex\YandexBrowser\User Data' },
    @{ Name = 'Arc'; Rel = 'Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data' }
)
$script:StoreUpdateRx = 'clients2\.google\.com/service/update2/crx|edge\.microsoft\.com/extensionwebstorebase|extension-updates\.opera\.com|addons\.opera\.com|chrome\.google\.com/webstore'
$script:KnownEngineRx = '(?i)(^|\.)(google\.[a-z.]+|bing\.com|duckduckgo\.com|yahoo\.com|search\.yahoo\.com|ecosia\.org|startpage\.com|search\.brave\.com|qwant\.com|yandex\.[a-z]+|baidu\.com|naver\.com|kagi\.com|perplexity\.ai|you\.com|chatgpt\.com|msn\.com|microsoft\.com|youtube\.com|wikipedia\.org)$'
$script:SpamTldRx = '(?i)\.(xyz|top|online|site|club|icu|buzz|live|click|link|monster|rest|cfd|sbs|cyou|quest|fun|space|website|work|life|today|news|pw|best|uno)$'
$script:LocationNames = @{ 1 = 'Store/user install'; 2 = 'Installed by a program'; 3 = 'Installed by a program (registry)'; 4 = 'UNPACKED (developer mode)'; 5 = 'Built-in'; 6 = 'Installed by a program'; 7 = 'Forced by policy'; 8 = 'Loaded from command line'; 9 = 'Forced by policy'; 10 = 'Built-in' }
$script:SafeExtIds = @('ghbmnnjooekpmoecnnnilnnbdlolhkhi', 'nmmhkkegccagdldgiimedpiccmgmieda', 'jmjflgjpcpepeafmmgdpfkogkghcpiha', 'pkedcjkdefgpdelpbcmbmeomcjbeemfm', 'mhjfbmdgcfjbbpaeojofohoefgiehjai', 'neajdppkdcdipfabeoofebfddakdcjhd')

function Get-UrlHost {
    param([string]$Url)
    if (-not $Url) { return '' }
    if ($Url -match '^(?i)[a-z][a-z0-9+.-]*://(\[?[^/:?#\]]+)') { return $Matches[1].ToLowerInvariant() }
    if ($Url -match '^(?i)([a-z0-9.-]+\.[a-z]{2,})') { return $Matches[1].ToLowerInvariant() }
    ''
}

function Get-ExtName {
    param([string]$Dir, $Manifest)
    $n = [string]$Manifest['name']
    if ($n -match '^__MSG_(.+)__$') {
        $key = $Matches[1]
        $loc = [string]$Manifest['default_locale']
        foreach ($l in @($loc, 'en', 'en_US', 'en_GB')) {
            if (-not $l) { continue }
            $msgs = Read-JsonFile (Join-Path $Dir "_locales\$l\messages.json")
            if ($msgs) {
                foreach ($k in $msgs.Keys) { if ($k -ieq $key) { return [string]$msgs[$k]['message'] } }
            }
        }
        return $key
    }
    $n
}

function Get-ChromiumUserDataDirs {
    $list = @()
    $seen = @{}
    foreach ($p in $script:Profiles) {
        $local = Join-Path $p.Path 'AppData\Local'
        $roam = Join-Path $p.Path 'AppData\Roaming'
        $u = Get-ShortUser $p.User
        foreach ($kb in $script:KnownBrowsers) {
            $d = Join-Path $local $kb.Rel
            if ([IO.File]::Exists((Join-Path $d 'Local State')) -and -not $seen.ContainsKey($d.ToLower())) { $seen[$d.ToLower()] = $true; $list += [pscustomobject]@{ Browser = $kb.Name; Dir = $d; User = $u; Known = $true; Flat = $false } }
        }
        foreach ($op in @(@('Opera', 'Opera Software\Opera Stable'), @('Opera GX', 'Opera Software\Opera GX Stable'))) {
            $d = Join-Path $roam $op[1]
            if ([IO.Directory]::Exists($d) -and -not $seen.ContainsKey($d.ToLower())) {
                $seen[$d.ToLower()] = $true
                $flat = [IO.File]::Exists((Join-Path $d 'Preferences'))
                $list += [pscustomobject]@{ Browser = $op[0]; Dir = $d; User = $u; Known = $true; Flat = $flat }
            }
        }
        # anything else Chromium-shaped under AppData\Local (adware browsers live here)
        $found = Get-FilesSafe -Root $local -MaxDepth 3 -MaxFiles 50 -MaxSeconds 20 -NameRx '^Local State$' -SkipDirRx @('\\Packages$', '\\Microsoft\\(Windows|Office|Teams|OneDrive)', '\\Temp$', '\\(npm-cache|pip|NVIDIA|D3DSCache|CrashDumps|Steam|EpicGamesLauncher)$')
        foreach ($f in $found) {
            if ($f.Name -ne 'Local State') { continue }
            $d = $f.DirectoryName
            if ($d -notmatch '\\User Data$') { continue }
            if ($seen.ContainsKey($d.ToLower())) { continue }
            $seen[$d.ToLower()] = $true
            $rel = $d.Substring($local.Length).Trim('\') -replace '\\User Data$', ''
            # Real Chromium browsers keep their exe in a sibling "Application" folder; app web-views (Copilot etc.) do not.
            $appDir = Join-Path (Split-Path $d -Parent) 'Application'
            $hasExe = $false
            try { $hasExe = @([IO.Directory]::GetFiles($appDir, '*.exe')).Count -gt 0 } catch {}
            if (-not $hasExe -and -not (Find-Pup @($rel))) { continue }
            if ($rel -match '^(?i)Microsoft\\' -and -not (Find-Pup @($rel))) { continue }
            $list += [pscustomobject]@{ Browser = "Unrecognized: $rel"; Dir = $d; User = $u; Known = $false; Flat = $false }
        }
    }
    $list
}

function Invoke-BrowsersScan {
    $S = 'browsers'
    $extRows = @(); $setRows = @(); $notifRows = @(); $browserRows = @()
    $userDirs = @(Get-ChromiumUserDataDirs)

    foreach ($ud in $userDirs) {
        if (-not $ud.Known) {
            $pup = Find-Pup @($ud.Browser, $ud.Dir)
            $sev = if ($pup) { $pup.Severity } else { 'Medium' }
            Add-Finding -Severity $sev -Category 'Malware & PUPs' -Section $S -Title "Unrecognized Chromium-based browser installed: $($ud.Browser -replace '^Unrecognized: ', '')" `
                -Detail "Profile data at $($ud.Dir) (user $($ud.User))" `
                -Why $(if ($pup) { $pup.Info } else { 'Adware frequently installs its own copy of Chromium (OneStart, WaveBrowser, OneLaunch and many lookalikes) and makes it the default browser.' }) `
                -Fix 'If it is not a browser she chose: uninstall it from Settings > Apps, set the default browser back, then delete the leftover folder.' `
                -Actions @((New-RepairAction -Kind Quarantine -Label "Close it and quarantine its folder: $(Split-Path $ud.Dir -Parent)" -Risk caution -Params @{ Targets = @((Split-Path $ud.Dir -Parent)) }),
                    (New-RepairAction -Kind Open -Label 'Open Default apps to set the proper browser back' -Risk guided -Params @{ Uri = 'ms-settings:defaultapps' }))
            if ($pup) { $script:Shared.PupHits += , $pup.Name }
        }
        $profDirs = @()
        if ($ud.Flat) { $profDirs = @($ud.Dir) }
        else {
            try { $profDirs = @([IO.Directory]::GetDirectories($ud.Dir) | Where-Object { [IO.File]::Exists((Join-Path $_ 'Preferences')) -and ((Split-Path $_ -Leaf) -match '^(Default|Profile \d+|Guest Profile)$' -or $ud.Browser -like 'Opera*' -or -not $ud.Known) }) } catch {}
        }
        $localState = Read-JsonFile (Join-Path $ud.Dir 'Local State')
        foreach ($pd in $profDirs) {
            $profName = Split-Path $pd -Leaf
            $friendly = $profName
            $ic = Get-JVal $localState "profile.info_cache.$profName"
            if ($ic -and $ic['name']) { $friendly = "$profName ($($ic['name']))" }
            $where = "$($ud.Browser) / $friendly / $($ud.User)"
            $prefs = Read-JsonFile (Join-Path $pd 'Preferences')
            $sprefs = Read-JsonFile (Join-Path $pd 'Secure Preferences')
            $browserRows += [pscustomobject]@{ Browser = $ud.Browser; Profile = $friendly; User = $ud.User; Folder = $pd }

            # ---- extensions
            $settings = @{}
            foreach ($src in @($prefs, $sprefs)) {
                $es = Get-JVal $src 'extensions.settings'
                if ($es -is [System.Collections.IDictionary]) { foreach ($k in $es.Keys) { $settings[$k] = $es[$k] } }
            }
            $ids = @{}
            foreach ($k in $settings.Keys) { $ids[$k] = $true }
            $extRoot = Join-Path $pd 'Extensions'
            try { foreach ($d in [IO.Directory]::GetDirectories($extRoot)) { $ids[(Split-Path $d -Leaf)] = $true } } catch {}
            foreach ($id in $ids.Keys) {
                if ($id -notmatch '^[a-p]{32}$') { continue }
                $st = $settings[$id]
                $loc = if ($st -and $null -ne $st['location']) { [int]$st['location'] } else { 0 }
                if ($loc -in 5, 10) { continue }
                $dir = $null
                if ($loc -eq 4 -and $st['path']) { $dir = [string]$st['path'] }
                else {
                    try { $dir = @([IO.Directory]::GetDirectories((Join-Path $extRoot $id)) | Sort-Object | Select-Object -Last 1)[0] } catch {}
                }
                $man = $null
                if ($dir) { $man = Read-JsonFile (Join-Path $dir 'manifest.json') }
                if (-not $man -and $st -and $st['manifest']) { $man = $st['manifest'] }
                if (-not $man) { continue }
                $name = Get-ExtName -Dir $dir -Manifest $man
                $ver = [string]$man['version']
                $upd = [string]$man['update_url']
                $fromStore = ($st -and $st['from_webstore'] -eq $true) -or ($upd -match $script:StoreUpdateRx)
                $enabled = $true
                if ($st) {
                    $dr = $st['disable_reasons']
                    if (($dr -is [array] -and $dr.Count -gt 0) -or ($dr -is [int] -and $dr -ne 0)) { $enabled = $false }
                    elseif ($null -ne $st['state'] -and [int]$st['state'] -eq 0) { $enabled = $false }
                }
                $installed = $null
                if ($st -and $st['install_time']) { try { $installed = [DateTime]::FromFileTimeUtc([int64]$st['install_time'] * 10).ToLocalTime() } catch {} }
                $perms = @(@($man['permissions']) + @($man['host_permissions']) + @($man['optional_permissions']) | Where-Object { $_ -is [string] })
                foreach ($cs in @($man['content_scripts'])) { if ($cs -is [System.Collections.IDictionary]) { $perms += @($cs['matches'] | Where-Object { $_ -is [string] }) } }
                $broad = @($perms | Where-Object { $_ -in '<all_urls>', '*://*/*', 'http://*/*', 'https://*/*' }).Count -gt 0
                $risky = @($perms | Where-Object { $_ -in 'proxy', 'debugger', 'nativeMessaging', 'management', 'webRequestBlocking', 'cookies', 'history', 'downloads', 'declarativeNetRequestWithHostAccess', 'scripting' } | Select-Object -Unique)
                $overrides = @()
                $cso = $man['chrome_settings_overrides']
                if ($cso -is [System.Collections.IDictionary]) {
                    if ($cso['search_provider']) { $overrides += 'search engine' }
                    if ($cso['homepage']) { $overrides += 'homepage' }
                    if ($cso['startup_pages']) { $overrides += 'startup pages' }
                }
                $cuo = $man['chrome_url_overrides']
                if ($cuo -is [System.Collections.IDictionary] -and $cuo['newtab']) { $overrides += 'new tab page' }

                $sev = $null; $why = @()
                $pup = Find-Pup @($name, $upd, $dir)
                if ($pup) { $sev = $pup.Severity; $why += "Known adware/PUP: $($pup.Name)" }
                if ($loc -in 4, 8) { $sev = Get-MaxSeverity @($sev, 'High'); $why += $script:LocationNames[$loc] }
                elseif ($loc -in 7, 9) { $sev = Get-MaxSeverity @($sev, $(if ($fromStore) { 'Medium' } else { 'High' })); $why += 'Force-installed by policy (cannot be removed normally)' }
                elseif (-not $fromStore -and $script:SafeExtIds -notcontains $id) { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += 'Not from an official extension store' }
                elseif ($loc -in 2, 3, 6 -and $script:SafeExtIds -notcontains $id) { $sev = Get-MaxSeverity @($sev, 'Low'); $why += 'Installed by another program' }
                if ($overrides | Where-Object { $_ -ne 'new tab page' }) { $sev = Get-MaxSeverity @($sev, $(if ($fromStore) { 'Medium' } else { 'High' })); $why += 'Takes over ' + (($overrides | Where-Object { $_ -ne 'new tab page' }) -join ', ') }
                elseif ($overrides) { $why += 'Replaces the new tab page' }
                if ($broad -and -not $fromStore) { $sev = Get-MaxSeverity @($sev, 'High'); $why += 'Can read/change every website' }
                if (-not $enabled) {
                    # already switched off (by the browser or an antivirus): still worth removing, but not urgent
                    if ($sev -eq 'High') { $sev = 'Medium'; $why += 'Currently disabled' } elseif ($sev -in 'Medium', 'Low') { $sev = 'Low' }
                }

                $extRows += [pscustomobject]@{
                    Extension = $name; Browser = $where; Enabled = $enabled; Concerns = ($why -join '; '); Source = $(if ($script:LocationNames.ContainsKey($loc)) { $script:LocationNames[$loc] } else { "location $loc" })
                    'Official store' = $fromStore; 'All-sites access' = $broad; 'Sensitive permissions' = ($risky -join ', '); Installed = $installed; Version = $ver; ID = $id
                    _Flag = (ConvertTo-FlagClass $sev); _Sev = $sev
                }
                if ($installed) { Add-TimelineEvent $installed 'Browser extension installed' "$name ($where)" $(if ($sev) { $sev } else { 'Info' }) }
                if ($sev -in 'Critical', 'High', 'Medium') {
                    if ($pup) { $script:Shared.PupHits += , $pup.Name }
                    Add-Finding -Severity $sev -Category 'Browser' -Section $S -Title "Suspicious browser extension: $name" -Detail "$($why -join '; ') - $where" `
                        -Evidence @("ID: $id", "Version: $ver", "Update URL: $upd", "Folder: $dir", "Permissions: $(($perms | Select-Object -Unique) -join ', ')") `
                        -Why 'Malicious or adware extensions inject ads, redirect searches, and can read everything typed into websites (including passwords and banking pages).' `
                        -Fix $(if ($loc -in 7, 9) { 'It is forced by policy - remove the policy first (see the browser policies table), then remove the extension from the browser''s extensions page.' } else { "Open the browser's extensions page (chrome://extensions or edge://extensions) and click Remove. If it comes back, a program or policy is re-installing it." }) `
                        -Actions @($(if ($loc -notin 7, 9) {
                                $procName = switch -Wildcard ($ud.Browser) { 'Google Chrome' { 'chrome' } 'Chrome Beta' { 'chrome' } 'Microsoft Edge' { 'msedge' } 'Edge Beta' { 'msedge' } 'Brave' { 'brave' } 'Vivaldi' { 'vivaldi' } 'Opera*' { 'opera' } 'Chromium' { 'chrome' } default { '' } }
                                New-RepairAction -Kind BrowserReset -Label "Remove the extension '$name' from $($ud.Browser) profile $profName (close $($ud.Browser) yourself first - it is never closed for you; its files go to quarantine)" -Risk caution -Params @{ ProfileDir = $pd; ExtensionId = $id; Process = $procName; ExtDir = $(if ($dir) { $dir } else { '' }) }
                            }))
                }
            }

            # ---- homepage / startup / search
            $hp = [string](Get-JVal $prefs 'homepage')
            $hpNtp = Get-JVal $prefs 'homepage_is_newtabpage'
            $restore = Get-JVal $prefs 'session.restore_on_startup'
            $urls = @(Get-JVal $prefs 'session.startup_urls' | Where-Object { $_ })
            $dse = [string](Get-JVal $prefs 'default_search_provider_data.template_url_data.url')
            $dseName = [string](Get-JVal $prefs 'default_search_provider_data.template_url_data.short_name')
            $startup = switch ([int]$restore) { 1 { 'Continue where you left off' } 4 { 'Open specific pages' } 5 { 'New tab page' } default { 'Default (new tab)' } }
            $concern = @(); $sev = $null
            $toCheck = @()
            if ($hp -and $hpNtp -ne $true) { $toCheck += $hp }
            if ([int]$restore -eq 4) { $toCheck += $urls }
            foreach ($u in $toCheck) {
                $h = Get-UrlHost ([string]$u)
                if (-not $h) { continue }
                if (Find-Pup @($u)) { $sev = Get-MaxSeverity @($sev, 'High'); $concern += "Adware page: $u" }
                elseif ($h -match $script:SpamTldRx) { $sev = Get-MaxSeverity @($sev, 'Medium'); $concern += "Suspicious page: $u" }
                elseif ($h -notmatch $script:KnownEngineRx) { $sev = Get-MaxSeverity @($sev, 'Low'); $concern += "Opens $h at start (check it was chosen on purpose)" }
            }
            if ($dse) {
                $h = Get-UrlHost $dse
                if (Find-Pup @($dse)) { $sev = Get-MaxSeverity @($sev, 'High'); $concern += "Search engine is adware: $dse" }
                elseif ($h -and $h -notmatch $script:KnownEngineRx) { $sev = Get-MaxSeverity @($sev, 'Medium'); $concern += "Unusual search engine: $h" }
            }
            $dev = Get-JVal $prefs 'extensions.ui.developer_mode'
            $setRows += [pscustomobject]@{
                Browser = $where; 'On startup' = $startup; 'Startup pages' = ($urls -join ' | '); Homepage = $(if ($hpNtp -eq $true -or -not $hp) { 'New tab page' } else { $hp })
                'Search engine' = $(if ($dse) { "$dseName ($(Get-UrlHost $dse))" } else { 'Browser default' }); 'Developer mode' = [bool]$dev; Concerns = ($concern -join '; '); _Flag = (ConvertTo-FlagClass $sev)
            }
            if ($sev -in 'High', 'Medium') {
                Add-Finding -Severity $sev -Category 'Browser' -Section $S -Title "Browser start page or search engine looks hijacked ($($ud.Browser))" -Detail ($concern -join '; ') `
                    -Why 'Hijackers redirect searches through ad networks and track browsing.' `
                    -Fix 'Remove suspicious extensions first, then Settings > Reset settings > Restore settings to their original defaults. Also check for browser policies (below) that re-apply the hijack.'
            }

            # ---- notification permissions (the #1 source of fake "virus" pop-ups)
            $notif = Get-JVal $prefs 'profile.content_settings.exceptions.notifications'
            if ($notif -is [System.Collections.IDictionary]) {
                foreach ($k in $notif.Keys) {
                    $v = $notif[$k]
                    if (-not ($v -is [System.Collections.IDictionary]) -or [int]$v['setting'] -ne 1) { continue }
                    $site = ($k -split ',')[0]
                    $h = Get-UrlHost $site
                    $spam = ($h -match $script:SpamTldRx) -or ($h -match '(?i)(captcha|robot|verify|allow|push|notif|news\d|clicks?|prize|reward|win\d|antivirus|security-?alert|virus)')
                    $notifRows += [pscustomobject]@{ Site = $site; Browser = $where; Looks = $(if ($spam) { 'Likely notification spam' } else { 'Review' }); _Flag = $(if ($spam) { 'medium' } else { '' }) }
                }
            }
        }
    }

    # ---- Firefox
    foreach ($p in $script:Profiles) {
        $root = Join-Path $p.Path 'AppData\Roaming\Mozilla\Firefox\Profiles'
        $u = Get-ShortUser $p.User
        $fdirs = @()
        try { $fdirs = @([IO.Directory]::GetDirectories($root)) } catch {}
        foreach ($fd in $fdirs) {
            $where = "Firefox / $(Split-Path $fd -Leaf) / $u"
            $browserRows += [pscustomobject]@{ Browser = 'Firefox'; Profile = (Split-Path $fd -Leaf); User = $u; Folder = $fd }
            $ej = Read-JsonFile (Join-Path $fd 'extensions.json')
            foreach ($a in @(Get-JVal $ej 'addons')) {
                if (-not ($a -is [System.Collections.IDictionary])) { continue }
                if ([string]$a['type'] -ne 'extension') { continue }
                $locn = [string]$a['location']
                if ($locn -in 'app-builtin', 'app-system-defaults', 'app-system-addons') { continue }
                $name = [string](Get-JVal $a 'defaultLocale.name')
                if (-not $name) { $name = [string]$a['id'] }
                $signed = [int]$a['signedState']
                $sev = $null; $why = @()
                $pup = Find-Pup @($name, [string]$a['id'], [string]$a['sourceURI'])
                if ($pup) { $sev = $pup.Severity; $why += "Known adware/PUP: $($pup.Name)" }
                if ($signed -le 0 -and $locn -eq 'app-profile') { $sev = Get-MaxSeverity @($sev, 'High'); $why += 'Not signed by Mozilla' }
                if ($locn -ne 'app-profile') { $sev = Get-MaxSeverity @($sev, 'Medium'); $why += "Installed outside the profile ($locn)" }
                $inst = $null
                if ($a['installDate']) { try { $inst = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$a['installDate']).LocalDateTime } catch {} }
                $extRows += [pscustomobject]@{ Extension = $name; Browser = $where; Enabled = [bool]$a['active']; Concerns = ($why -join '; '); Source = $locn; 'Official store' = ($signed -ge 2); 'All-sites access' = ''; 'Sensitive permissions' = ''; Installed = $inst; Version = [string]$a['version']; ID = [string]$a['id']; _Flag = (ConvertTo-FlagClass $sev); _Sev = $sev }
                if ($inst) { Add-TimelineEvent $inst 'Browser extension installed' "$name ($where)" $(if ($sev) { $sev } else { 'Info' }) }
                if ($sev -in 'High', 'Medium') {
                    Add-Finding -Severity $sev -Category 'Browser' -Section $S -Title "Suspicious Firefox add-on: $name" -Detail "$($why -join '; ') - $where" -Fix 'Firefox menu > Add-ons and themes > Remove.'
                }
            }
            if ([IO.File]::Exists((Join-Path $fd 'user.js'))) {
                $uj = (Get-Content -LiteralPath (Join-Path $fd 'user.js') -TotalCount 40 -ErrorAction SilentlyContinue) -join "`n"
                Add-Finding -Severity Medium -Category 'Browser' -Section $S -Title "Firefox profile has a user.js override file ($u)" -Detail (Join-Path $fd 'user.js') -Evidence @(Limit-Text $uj 800) `
                    -Why 'user.js forces settings every time Firefox starts. Hijackers use it to lock the homepage/search engine; privacy tweakers use it legitimately.' -Fix 'If nobody created it on purpose, close Firefox and delete user.js.' `
                    -Actions @((New-RepairAction -Kind Quarantine -Label 'Quarantine user.js (close Firefox first)' -Risk caution -Params @{ Targets = @((Join-Path $fd 'user.js')) }))
            }
            $pj = Join-Path $fd 'prefs.js'
            if ([IO.File]::Exists($pj)) {
                $lines = @(Get-Content -LiteralPath $pj -ErrorAction SilentlyContinue | Where-Object { $_ -match 'browser\.startup\.homepage"|network\.proxy\.(type|http"|autoconfig_url)' })
                $proxyType = ($lines | Where-Object { $_ -match 'network\.proxy\.type",\s*(\d)' } | ForEach-Object { $Matches[1] } | Select-Object -First 1)
                $hpLine = ($lines | Where-Object { $_ -match 'browser\.startup\.homepage",\s*"([^"]+)"' } | ForEach-Object { $Matches[1] } | Select-Object -First 1)
                $setRows += [pscustomobject]@{ Browser = $where; 'On startup' = ''; 'Startup pages' = ''; Homepage = $hpLine; 'Search engine' = '(stored in search.json.mozlz4)'; 'Developer mode' = ''; Concerns = $(if ($proxyType -in '1', '2') { 'Manual/PAC proxy configured' } else { '' }); _Flag = $(if ($proxyType -in '1', '2') { 'high' } else { '' }) }
                if ($proxyType -in '1', '2') {
                    Add-Finding -Severity High -Category 'Browser' -Section $S -Title "Firefox is set to use a proxy ($u)" -Evidence $lines `
                        -Why 'A proxy can see and modify browsing traffic. Adware uses this to inject ads.' -Fix 'Firefox Settings > Network Settings > Use system proxy settings / No proxy.'
                }
            }
        }
    }

    # ---- policies (managed by your organization)
    $polRows = @()
    $polRoots = @(@('HKLM', 'Registry::HKEY_LOCAL_MACHINE'))
    foreach ($h in $script:Hives) { $polRoots += , @("HKCU ($(Get-ShortUser $h.User))", $h.Root) }
    foreach ($pr in $polRoots) {
        foreach ($sub in 'Google\Chrome', 'Microsoft\Edge', 'BraveSoftware\Brave', 'Chromium', 'Mozilla\Firefox', 'Vivaldi', 'Opera Software') {
            $base = "$($pr[1])\SOFTWARE\Policies\$sub"
            if (-not (Test-RegKey $base)) { continue }
            $keys = @(Get-Item -LiteralPath $base -ErrorAction SilentlyContinue) + @(Get-ChildItem -LiteralPath $base -Recurse -ErrorAction SilentlyContinue)
            foreach ($k in $keys) {
                if (-not $k) { continue }
                foreach ($n in $k.GetValueNames()) {
                    $val = [string]$k.GetValue($n)
                    $relKey = ($k.Name -replace '^HKEY_[A-Z_]+\\(S-1-[\d-]+\\)?SOFTWARE\\Policies\\', '')
                    $sev = $null
                    if ($relKey -match 'ExtensionInstallForcelist|ExtensionSettings|Extensions\\Install' -or ($relKey -match 'Firefox' -and $n -match 'Extensions')) { $sev = 'High' }
                    elseif ($n -match '^(DefaultSearchProvider|HomepageLocation|HomepageIsNewTabPage|RestoreOnStartupURLs|NewTabPageLocation|ProxySettings|ProxyServer|ProxyPacUrl|ProxyMode|SearchEngines)' -or $relKey -match 'RestoreOnStartupURLs|SearchEngines') { $sev = 'High' }
                    elseif ($n -match 'SmartScreen|SafeBrowsing|ExtensionInstallBlocklist|DeveloperToolsAvailability|BlockExternalExtensions') { $sev = 'Medium' }
                    $polRows += [pscustomobject]@{ Scope = $pr[0]; Browser = $sub; Key = $relKey; Policy = $n; Value = $val; _Flag = (ConvertTo-FlagClass $sev); _Sev = $sev; _Base = $base }
                }
            }
        }
    }
    foreach ($fxDir in @("$env:ProgramFiles\Mozilla Firefox\distribution", "${env:ProgramFiles(x86)}\Mozilla Firefox\distribution")) {
        $pf = Join-Path $fxDir 'policies.json'
        if ([IO.File]::Exists($pf)) { $polRows += [pscustomobject]@{ Scope = 'File'; Browser = 'Mozilla\Firefox'; Key = $pf; Policy = 'policies.json'; Value = (Limit-Text ([IO.File]::ReadAllText($pf)) 600); _Flag = 'medium'; _Sev = 'Medium'; _Base = $pf } }
    }
    Add-Table -Section $S -Title 'Browser policies ("Managed by your organization")' -Rows $polRows -Columns @('Scope', 'Browser', 'Key', 'Policy', 'Value') -Empty 'No browser policies. Good - nothing is forcing settings or extensions.'
    $hiPol = @($polRows | Where-Object { $_._Sev -eq 'High' })
    if ($hiPol.Count -gt 0) {
        Add-Finding -Severity High -Category 'Browser' -Section $S -Title 'Browser settings or extensions are being forced by policy' -Evidence @($hiPol | ForEach-Object { "$($_.Scope) $($_.Key)\$($_.Policy) = $($_.Value)" }) `
            -Why 'On a home PC, policies like these are almost always planted by adware so the user cannot remove an extension or change the search engine ("Managed by your organization").' `
            -Fix 'As admin, delete the listed policy keys (regedit: HKLM\SOFTWARE\Policies\Google\Chrome, ...\Microsoft\Edge, and the same under HKCU). Restart the browser and check chrome://policy or edge://policy shows nothing.' `
            -Actions @($hiPol | ForEach-Object { $_._Base } | Select-Object -Unique | ForEach-Object {
                    if ($_ -like 'Registry::*') { New-RepairAction -Kind RegDeleteKey -Label "Delete browser policy key $($_ -replace '^Registry::HKEY_LOCAL_MACHINE', 'HKLM' -replace '^Registry::HKEY_USERS\\S-1-[\d-]+', 'HKCU')" -Risk caution -Params @{ Path = $_ } }
                    else { New-RepairAction -Kind Quarantine -Label "Quarantine $_" -Risk caution -Params @{ Targets = @($_) } } })
    } elseif ($polRows.Count -gt 0) {
        Add-Finding -Severity Low -Category 'Browser' -Section $S -Title "$($polRows.Count) browser policy value(s) are set" -Evidence @($polRows | ForEach-Object { "$($_.Scope) $($_.Key)\$($_.Policy) = $($_.Value)" }) `
            -Why 'Not necessarily harmful (some tools set these), but on a home PC every policy should be explained.' -Fix 'Review at chrome://policy or edge://policy.'
    } else { Add-Pass 'Browser' 'No browser policies forcing settings or extensions' }

    # ---- extensions pre-installed by programs via registry
    $regExt = @()
    foreach ($k in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome\Extensions', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Google\Chrome\Extensions',
            'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Edge\Extensions', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions')) {
        foreach ($sk in (Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue)) {
            $upd = [string]$sk.GetValue('update_url'); $path = [string]$sk.GetValue('path')
            $ok = $upd -match $script:StoreUpdateRx
            $regExt += [pscustomobject]@{ ID = $sk.PSChildName; Key = $k -replace '^Registry::HKEY_LOCAL_MACHINE', 'HKLM'; 'Update URL' = $upd; 'CRX path' = $path; _Flag = $(if ($ok) { '' } else { 'high' }) }
            if (-not $ok) {
                Add-Finding -Severity High -Category 'Browser' -Section $S -Title "A program pre-installs a browser extension from outside the store ($($sk.PSChildName))" -Detail "$k\$($sk.PSChildName)" -Evidence @("update_url: $upd", "path: $path") `
                    -Fix "Delete the registry key $($sk.Name) (as admin) and remove the extension from the browser." `
                    -Actions @((New-RepairAction -Kind RegDeleteKey -Label "Delete the extension registration $($sk.PSChildName)" -Risk caution -Params @{ Path = "Registry::$($sk.Name)" }))
            }
        }
    }
    if ($regExt.Count -gt 0) { Add-Table -Section $S -Title 'Extensions registered by installed programs' -Rows $regExt }

    # ---- shortcut hijacks
    $lnkRows = @()
    $browserExeRx = '(?i)\\(chrome|msedge|firefox|brave|opera|launcher|vivaldi|iexplore)\.exe$'
    $lnkDirs = @("$env:PUBLIC\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
    foreach ($p in $script:Profiles) {
        $lnkDirs += (Join-Path $p.Path 'Desktop')
        $lnkDirs += (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs')
        $lnkDirs += (Join-Path $p.Path 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')
        try { foreach ($od in [IO.Directory]::GetDirectories($p.Path, 'OneDrive*')) { $lnkDirs += (Join-Path $od 'Desktop') } } catch {}
    }
    foreach ($d in $lnkDirs) {
        foreach ($f in (Get-FilesSafe -Root $d -MaxDepth 2 -Extensions @('.lnk', '.url') -MaxFiles 1500 -MaxSeconds 15)) {
            if ($f.Extension -eq '.url') { continue }
            $si = Get-ShortcutInfo $f.FullName
            if (-not $si -or -not $si.Target) { continue }
            # only real browser brands: plenty of legit apps are called "... Browser" (exam/kiosk browsers such as Guardian Browser)
            $isBrowserName = $f.BaseName -match '(?i)^(google chrome|chrome|microsoft edge|edge|mozilla firefox|firefox|brave|opera( gx)?|vivaldi|internet explorer)\b'
            $sev = $null; $why = @()
            if ($si.Target -match $browserExeRx -and $si.Args -match '(?i)(https?://|www\.|\.(com|net|org|xyz|info|top)\b|--load-extension|--disable-extensions-except)') { $sev = 'High'; $why += "Browser shortcut opens extra arguments: $($si.Args)" }
            if ($isBrowserName -and $si.Target -match '\.exe$') {
                $sig = Get-FileSig $si.Target
                $vendorOk = $sig.Trusted -and $sig.Signer -match '(?i)Google|Microsoft|Mozilla|Brave|Opera|Vivaldi|Yandex'
                if ($sig.Status -eq 'Corrupt') { $why += 'Target program file is corrupted (handled in System integrity)' }
                elseif ($sig.Exists -and -not $sig.Trusted -and -not $sig.Skipped) { $sev = Get-MaxSeverity @($sev, 'High'); $why += "Shortcut named like a browser launches $($si.Target), which is not properly signed ($($sig.Status))" }
                elseif ($sig.Exists -and -not $vendorOk -and -not $sig.Skipped) { $sev = Get-MaxSeverity @($sev, 'Low'); $why += "Shortcut named like a browser launches $($si.Target) (signed by $($sig.Signer), not the browser maker)" }
            }
            $pup = Find-Pup @($f.Name, $si.Target, $si.Args)
            if ($pup) { $sev = Get-MaxSeverity @($sev, $pup.Severity); $why += "Known adware/PUP: $($pup.Name)" }
            if ($sev) {
                $lnkRows += [pscustomobject]@{ Shortcut = $f.FullName; Target = $si.Target; Arguments = $si.Args; Concerns = ($why -join '; '); _Flag = (ConvertTo-FlagClass $sev) }
                $onlyPup = $pup -and $why.Count -eq 1
                if ($onlyPup -and $sev -eq 'Low') { continue }   # already reported under Installed software
                Add-Finding -Severity $sev -Category 'Browser' -Section $S -Title $(if ($onlyPup) { "Shortcut for adware/PUP: $($f.Name)" } else { "Tampered browser shortcut: $($f.Name)" }) -Detail ($why -join '; ') -Evidence @($f.FullName, "Target: $($si.Target) $($si.Args)") `
                    -Fix $(if ($onlyPup) { 'Uninstall the program (Software section), then delete the shortcut.' } else { 'Delete the shortcut and re-pin the browser from the Start menu (or right-click > Properties and remove everything after the closing quote in Target).' }) `
                    -Actions @((New-RepairAction -Kind Quarantine -Label "Quarantine the shortcut $($f.Name) (re-pin the browser from the Start menu afterwards)" -Risk caution -Params @{ Targets = @($f.FullName) }))
            }
        }
    }
    Add-Table -Section $S -Title 'Suspicious shortcuts' -Rows $lnkRows -Empty 'No hijacked browser shortcuts found.'

    Add-Table -Section $S -Title 'Browser profiles found' -Rows $browserRows
    Add-Table -Section $S -Title 'Extensions / add-ons' -Rows @($extRows | Sort-Object @{ Expression = { if ($_._Sev) { $script:SevRank[$_._Sev] } else { 0 } }; Descending = $true }, Browser, Extension) `
        -Columns @('Extension', 'Browser', 'Enabled', 'Concerns', 'Source', 'Official store', 'All-sites access', 'Sensitive permissions', 'Installed', 'Version', 'ID')
    Add-Table -Section $S -Title 'Startup page, homepage and search engine' -Rows $setRows
    Add-Table -Section $S -Title 'Sites allowed to send notifications' -Rows $notifRows -Empty 'No sites can send notifications.' `
        -Note 'Fake "your PC is infected" pop-ups in the corner of the screen almost always come from a website that was allowed to send notifications.'
    $spamN = @($notifRows | Where-Object { $_._Flag -eq 'medium' })
    if ($spamN.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Browser' -Section $S -Title "$($spamN.Count) spammy website(s) can push notifications" -Evidence @($spamN | ForEach-Object { "$($_.Site) ($($_.Browser))" }) `
            -Why 'These sites produce the fake virus warnings and "click here" pop-ups that look like they come from Windows.' `
            -Fix 'Chrome: chrome://settings/content/notifications, Edge: edge://settings/content/notifications - remove them from "Allowed" and consider "Don''t allow sites to send notifications".'
    } elseif ($notifRows.Count -gt 5) {
        Add-Finding -Severity Low -Category 'Browser' -Section $S -Title "$($notifRows.Count) websites can send notifications" -Evidence @($notifRows | ForEach-Object { $_.Site }) -Fix 'Remove any that are not wanted (browser settings > Site settings > Notifications).'
    }
    if (@($extRows | Where-Object { $_._Sev -in 'High', 'Critical', 'Medium' }).Count -eq 0 -and $extRows.Count -gt 0) { Add-Pass 'Browser' 'Browser extensions look clean' "$($extRows.Count) extension(s) checked" }
}
