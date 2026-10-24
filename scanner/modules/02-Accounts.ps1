# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Local accounts, administrators, auto-logon, hidden accounts

function Get-LocalAdminNames {
    $names = @()
    try {
        $names = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name })
    } catch {
        try {
            $grp = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $adsi = [ADSI]"WinNT://./$grp,group"
            foreach ($m in @($adsi.Invoke('Members'))) {
                $path = ([ADSI]$m).Path
                $names += ($path -replace '^WinNT://', '' -replace '/', '\')
            }
        } catch {}
    }
    $names
}

function Invoke-AccountsScan {
    $S = 'accounts'
    $admins = @(Get-LocalAdminNames)
    $adminShort = @($admins | ForEach-Object { ($_ -split '\\')[-1].ToLowerInvariant() })
    $hidden = @{}
    foreach ($v in (Get-RegValues 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList')) {
        if ([string]$v.Value -eq '0') { $hidden[$v.Name.ToLowerInvariant()] = $true }
    }

    $users = @()
    try { $users = @(Get-LocalUser -ErrorAction Stop) } catch { Add-Note -Section $S -Text "Could not list local users: $($_.Exception.Message)" -Tone warn }
    $rows = @()
    foreach ($u in $users) {
        $isAdmin = $adminShort -contains $u.Name.ToLowerInvariant()
        $flag = ''
        $notes = @()
        $sidStr = [string]$u.SID
        if ($u.Enabled) {
            if ($sidStr -match '-501$') {
                $flag = 'high'; $notes += 'Guest account enabled'
                Add-Finding -Severity High -Category 'Accounts & Access' -Section $S -Title 'Guest account is enabled' `
                    -Why 'Anyone can sign in to the PC without a password.' -Fix 'Run as admin: net user guest /active:no' `
                    -Actions @((New-RepairAction -Kind Run -Label 'Disable the Guest account' -Params @{ Command = 'guest-off' }))
            }
            if ($sidStr -match '-500$') {
                $flag = 'medium'; $notes += 'Built-in Administrator enabled'
                Add-Finding -Severity Medium -Category 'Accounts & Access' -Section $S -Title 'Built-in Administrator account is enabled' `
                    -Detail "Account: $($u.Name)" -Why 'This account is a well-known target and bypasses some UAC protections.' `
                    -Fix 'Unless you need it, disable it: net user administrator /active:no (run as admin).' `
                    -Actions @((New-RepairAction -Kind Run -Label 'Disable the built-in Administrator account' -Risk caution -Params @{ Command = 'builtin-admin-off' }))
            }
            if (-not $u.PasswordRequired -and $sidStr -notmatch '-(500|501|503|504)$') {
                if (-not $flag) { $flag = 'medium' }
                $notes += 'Password not required'
                Add-Finding -Severity Medium -Category 'Accounts & Access' -Section $S -Title "Account '$($u.Name)' does not require a password" `
                    -Why 'If the account has an empty password, anyone with physical access can sign in.' `
                    -Fix 'Set a password or PIN for the account (Settings > Accounts > Sign-in options).'
            }
            if ($hidden.ContainsKey($u.Name.ToLowerInvariant())) {
                $flag = 'high'; $notes += 'Hidden from sign-in screen'
                $sev = if ($isAdmin) { 'High' } else { 'Medium' }
                Add-Finding -Severity $sev -Category 'Accounts & Access' -Section $S -Title "Account '$($u.Name)' is hidden from the sign-in screen" `
                    -Detail $(if ($isAdmin) { 'It is an administrator.' } else { '' }) `
                    -Why 'Attackers and tech-support scammers sometimes create hidden admin accounts to get back in later.' `
                    -Fix 'If nobody recognises this account, disable or delete it (lusrmgr.msc or: net user <name> /active:no) and change passwords.'
            }
        }
        $rows += [pscustomobject]@{
            Name = $u.Name; Enabled = $u.Enabled; Administrator = $isAdmin; 'Last sign-in' = $u.LastLogon
            'Password required' = $u.PasswordRequired; 'Password last set' = $u.PasswordLastSet; Source = [string]$u.PrincipalSource
            Notes = ($notes -join '; '); Description = $u.Description; _Flag = $flag
        }
    }
    Add-Table -Section $S -Title 'Local user accounts' -Rows $rows
    Add-Table -Section $S -Title 'Members of the Administrators group' -Rows @($admins | ForEach-Object { [pscustomobject]@{ Member = $_ } })

    $enabledAdmins = @($rows | Where-Object { $_.Enabled -and $_.Administrator })
    if ($enabledAdmins.Count -gt 2) {
        Add-Finding -Severity Low -Category 'Accounts & Access' -Section $S -Title "$($enabledAdmins.Count) enabled administrator accounts" `
            -Detail (($enabledAdmins | ForEach-Object { $_.Name }) -join ', ') -Fix 'Make sure every admin account is recognised. Remove admin rights from accounts that do not need them.'
    }

    # Auto-logon (password stored in plain text)
    $wl = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $auto = [string](Get-RegValue $wl 'AutoAdminLogon')
    $defPw = Get-RegValue $wl 'DefaultPassword'
    if ($auto -eq '1') {
        if ($null -ne $defPw) {
            Add-Finding -Severity High -Category 'Accounts & Access' -Section $S -Title 'Automatic sign-in is on with the password stored in plain text' `
                -Detail "User: $(Get-RegValue $wl 'DefaultUserName'). (The password itself is not shown in this report.)" `
                -Why 'Any program (including malware) can read the password from the registry, and anyone who turns the PC on is signed in.' `
                -Fix 'Turn off auto sign-in: run netplwiz and tick "Users must enter a user name and password", then delete the DefaultPassword value under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon.' `
                -Actions @((New-RepairAction -Kind RegDeleteValue -Label 'Delete the stored plain-text password' -Params @{ Path = $wl; Name = 'DefaultPassword' }),
                    (New-RepairAction -Kind RegSetValue -Label 'Turn automatic sign-in off' -Params @{ Path = $wl; Name = 'AutoAdminLogon'; Type = 'String'; Value = '0' }))
        } else {
            Add-Finding -Severity Low -Category 'Accounts & Access' -Section $S -Title 'Automatic sign-in is enabled' -Fix 'Turn it off with netplwiz if the PC is ever out of your sight.'
        }
    } else {
        Add-Pass 'Accounts & Access' 'No automatic sign-in configured'
    }

    if ($rows.Count -gt 0 -and @($rows | Where-Object { $_._Flag -in 'high', 'medium' }).Count -eq 0) {
        Add-Pass 'Accounts & Access' 'Local accounts look normal' "$(@($rows | Where-Object { $_.Enabled }).Count) enabled account(s)"
    }
}
