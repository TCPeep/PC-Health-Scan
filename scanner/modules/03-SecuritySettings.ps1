# PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
# Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
# Core Windows security settings: UAC, firewall, SmartScreen, Secure Boot, TPM, VBS, BitLocker, RDP, SMB1, boot flags, restore points

function Invoke-SecuritySettingsScan {
    $S = 'security'
    $rows = New-Object System.Collections.Generic.List[object]
    $addRow = {
        param($Check, $State, $Expected, $Sev)
        $rows.Add([pscustomobject]@{ Setting = $Check; 'Current state' = $State; Recommended = $Expected; _Flag = (ConvertTo-FlagClass $Sev) })
    }
    $isHome = $script:Shared.Edition -match '^Core'

    # --- UAC
    $pol = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-RegValue $pol 'EnableLUA'
    $cpba = Get-RegValue $pol 'ConsentPromptBehaviorAdmin'
    $posd = Get-RegValue $pol 'PromptOnSecureDesktop'
    if ($lua -eq 0) {
        & $addRow 'User Account Control' 'OFF' 'On' 'Critical'
        Add-Finding -Severity Critical -Category 'Security Settings' -Section $S -Title 'User Account Control (UAC) is turned off' `
            -Why 'Every program runs with full administrator power, so anything malicious can change the whole system silently.' `
            -Fix 'Control Panel > User Accounts > Change User Account Control settings > move the slider back to the default (third notch), then restart.' `
            -Actions @((New-RepairAction -Kind RegSetValue -Label 'Turn UAC back on (default level)' -Reboot -Params @{ Path = $pol; Name = 'EnableLUA'; Value = 1 }),
                (New-RepairAction -Kind RegSetValue -Label 'Prompt for consent on admin actions' -Params @{ Path = $pol; Name = 'ConsentPromptBehaviorAdmin'; Value = 5 }),
                (New-RepairAction -Kind RegSetValue -Label 'Show prompts on the secure desktop' -Params @{ Path = $pol; Name = 'PromptOnSecureDesktop'; Value = 1 }))
    } elseif ($cpba -eq 0) {
        & $addRow 'User Account Control' 'On, but admins are elevated without a prompt' 'Prompt for consent' 'High'
        Add-Finding -Severity High -Category 'Security Settings' -Section $S -Title 'UAC never asks before giving programs admin rights' `
            -Why 'Programs can silently gain administrator access. Adware and malware rely on this.' `
            -Fix 'Control Panel > User Accounts > Change User Account Control settings > set to "Notify me only when apps try to make changes" (default).' `
            -Actions @((New-RepairAction -Kind RegSetValue -Label 'Prompt for consent on admin actions (UAC default)' -Params @{ Path = $pol; Name = 'ConsentPromptBehaviorAdmin'; Value = 5 }))
    } else {
        $desc = 'On'
        $sev = $null
        if ($posd -eq 0) { $desc = 'On (prompt NOT on secure desktop)'; $sev = 'Low' }
        & $addRow 'User Account Control' $desc 'On, secure desktop' $sev
        if ($posd -eq 0) {
            Add-Finding -Severity Low -Category 'Security Settings' -Section $S -Title 'UAC prompts are not shown on the secure desktop' `
                -Why 'Other programs can see or interact with the UAC prompt. Remote-support tools sometimes change this so the helper can click "Yes".' `
                -Fix 'Set UAC back to the default level (Control Panel > User Accounts > Change User Account Control settings).' `
                -Actions @((New-RepairAction -Kind RegSetValue -Label 'Show UAC prompts on the secure desktop' -Params @{ Path = $pol; Name = 'PromptOnSecureDesktop'; Value = 1 }))
        } else { Add-Pass 'Security Settings' 'User Account Control is on' }
    }

    # --- Firewall
    try {
        $fwp = @(Get-NetFirewallProfile -ErrorAction Stop)
        $thirdFw = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName })
        $off = @($fwp | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
        foreach ($p in $fwp) { & $addRow "Windows Firewall ($($p.Name))" $(if ([string]$p.Enabled -eq 'True') { 'On' } else { 'OFF' }) 'On' $(if ([string]$p.Enabled -ne 'True' -and $thirdFw.Count -eq 0) { 'High' } else { $null }) }
        if ($thirdFw.Count -gt 0) { & $addRow 'Third-party firewall' ($thirdFw -join ', ') '' $null }
        if ($off.Count -gt 0 -and $thirdFw.Count -eq 0) {
            Add-Finding -Severity High -Category 'Security Settings' -Section $S -Title "Windows Firewall is off ($($off -join ', ') profile)" `
                -Why 'Without a firewall, services on this PC are exposed to the network (including public Wi-Fi).' `
                -Fix 'Windows Security > Firewall & network protection > turn each network profile back on.' `
                -Actions @((New-RepairAction -Kind FirewallOn -Label 'Turn Windows Firewall on for all network profiles'))
        } elseif ($off.Count -eq 0) { Add-Pass 'Security Settings' 'Windows Firewall is on for all network profiles' }
    } catch { & $addRow 'Windows Firewall' "Could not read ($($_.Exception.Message))" 'On' $null }

    # --- SmartScreen
    $ssPol = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
    $ssExp = [string](Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')
    $ssEdge = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'
    if ($ssPol -eq 0 -or $ssExp -eq 'Off') {
        & $addRow 'SmartScreen (apps and files)' 'OFF' 'On' 'Medium'
        Add-Finding -Severity Medium -Category 'Security Settings' -Section $S -Title 'SmartScreen for apps and files is turned off' `
            -Why 'SmartScreen warns before running unknown or known-bad downloads - exactly how adware like PC App Store gets in.' `
            -Fix 'Windows Security > App & browser control > Reputation-based protection > turn on "Check apps and files" and "Potentially unwanted app blocking".' `
            -Actions @($(if ($ssPol -eq 0) { New-RepairAction -Kind RegDeleteValue -Label 'Remove the policy that disables SmartScreen' -Params @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen' } }),
                (New-RepairAction -Kind Run -Label 'Turn SmartScreen for apps and files back on' -Params @{ Command = 'smartscreen-on' }))
    } else { & $addRow 'SmartScreen (apps and files)' 'On' 'On' $null }
    if ($ssEdge -eq 0) {
        & $addRow 'SmartScreen in Microsoft Edge (policy)' 'OFF' 'On' 'Medium'
        Add-Finding -Severity Medium -Category 'Security Settings' -Section $S -Title 'Microsoft Edge SmartScreen is disabled by policy' `
            -Fix 'Delete the SmartScreenEnabled value under HKLM\SOFTWARE\Policies\Microsoft\Edge (or reset Edge policies).' `
            -Actions @((New-RepairAction -Kind RegDeleteValue -Label 'Remove the Edge SmartScreen-off policy' -Params @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'; Name = 'SmartScreenEnabled' }))
    }

    # --- Secure Boot + firmware
    $fwType = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control' 'PEFirmwareType'
    $sbOn = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    if ($fwType -eq 1) {
        & $addRow 'Secure Boot' 'Unavailable (Legacy BIOS mode)' 'UEFI + Secure Boot' 'Medium'
        Add-Finding -Severity Medium -Category 'Security Settings' -Section $S -Title 'PC boots in Legacy BIOS mode (no Secure Boot)' `
            -Why 'Secure Boot blocks boot-level malware (bootkits) and is required for Windows 11.' `
            -Fix 'Advanced: convert the disk with mbr2gpt, then switch the firmware to UEFI and enable Secure Boot. Back up first.'
    } elseif ($sbOn -eq 1) {
        & $addRow 'Secure Boot' 'On' 'On' $null
        Add-Pass 'Security Settings' 'Secure Boot is on'
        if ($script:IsAdmin) {
            try {
                $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
                $txt = [Text.Encoding]::ASCII.GetString($db.Bytes)
                if ($txt -match 'Windows UEFI CA 2023') { & $addRow 'Secure Boot 2023 certificates' 'Installed' 'Installed' $null }
                else {
                    & $addRow 'Secure Boot 2023 certificates' 'Not yet installed' 'Installed' 'Low'
                    Add-Finding -Severity Low -Category 'Security Settings' -Section $S -Title 'Secure Boot certificates have not been updated to the 2023 versions' `
                        -Why "Microsoft's original 2011 Secure Boot certificates expire during 2026. PCs keep booting, but without the 2023 certificates they cannot receive future boot-security fixes." `
                        -Fix 'Install all Windows updates and the latest BIOS/firmware from the PC or motherboard maker; Windows rolls the new certificates out automatically on supported devices.'
                }
            } catch {}
        }
    } elseif ($sbOn -eq 0) {
        & $addRow 'Secure Boot' 'OFF' 'On' 'Medium'
        Add-Finding -Severity Medium -Category 'Security Settings' -Section $S -Title 'Secure Boot is turned off' `
            -Why 'Secure Boot stops malware from loading before Windows starts.' -Fix 'Enable Secure Boot in the BIOS/UEFI setup (usually under Boot or Security). Must be done by someone at the PC - it cannot be switched on from Windows.' `
            -Actions @((New-RepairAction -Kind Run -Label 'Restart straight into the BIOS/UEFI setup (someone must be at the PC; this ends any remote session)' -Risk caution -Off -Reboot -Params @{ Command = 'reboot-to-firmware' }))
    } else { & $addRow 'Secure Boot' 'Unknown' 'On' $null }

    # --- TPM
    $tpmText = $null
    try {
        $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
        if ($tpm) { $tpmText = 'TPM ' + (([string]$tpm.SpecVersion -split ',')[0]) + $(if ($tpm.IsEnabled_InitialValue) { ', enabled' } else { ', DISABLED' }) }
    } catch {}
    if (-not $tpmText) {
        $dev = Get-CimInstance Win32_PnPEntity -Filter "PNPClass='SecurityDevices'" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Trusted Platform' } | Select-Object -First 1
        if ($dev) { $tpmText = $dev.Name }
    }
    if ($tpmText) { & $addRow 'TPM security chip' $tpmText 'TPM 2.0' $(if ($tpmText -match 'DISABLED|1\.2') { 'Low' } else { $null }) }
    else {
        & $addRow 'TPM security chip' 'Not detected' 'TPM 2.0' 'Low'
        Add-Finding -Severity Low -Category 'Security Settings' -Section $S -Title 'No TPM security chip detected' `
            -Why 'A TPM 2.0 is needed for Windows 11, BitLocker and Windows Hello. Many PCs have one that is just turned off in the BIOS (Intel PTT / AMD fTPM).' `
            -Fix 'Check the BIOS/UEFI setup for "PTT", "fTPM" or "TPM" and enable it.'
    }

    # --- Virtualization-based security / memory integrity
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        $hvci = @($dg.SecurityServicesRunning) -contains 2
        $vbs = switch ([int]$dg.VirtualizationBasedSecurityStatus) { 0 { 'Off' } 1 { 'Enabled, not running' } 2 { 'Running' } default { 'Unknown' } }
        & $addRow 'Virtualization-based security' $vbs 'Running' $null
        & $addRow 'Core isolation - memory integrity' $(if ($hvci) { 'On' } else { 'Off' }) 'On' $(if (-not $hvci) { 'Low' } else { $null })
        if (-not $hvci) {
            Add-Finding -Severity Low -Category 'Security Settings' -Section $S -Title 'Core isolation (memory integrity) is off' `
                -Why 'Memory integrity blocks malicious or vulnerable drivers from tampering with Windows. It can be blocked by old drivers (often RGB/fan-control or anti-cheat software).' `
                -Fix 'Windows Security > Device security > Core isolation details > Memory integrity: On. If it refuses, it lists the incompatible drivers to update or remove.' `
                -Actions @((New-RepairAction -Kind Open -Label 'Open Core isolation settings (turn Memory integrity on there; Windows checks driver compatibility first)' -Risk guided -Params @{ Uri = 'windowsdefender://coreisolation'; Note = 'If the switch refuses, the page lists the incompatible drivers.' }))
        } else { Add-Pass 'Security Settings' 'Memory integrity (core isolation) is on' }
    } catch {}

    $ppl = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    & $addRow 'LSA protection (protects saved credentials)' $(if ($ppl -in 1, 2) { 'On' } else { 'Off / default' }) 'On' $null

    # --- BitLocker / device encryption
    $blText = $null; $blOn = $null
    if ($script:IsAdmin) {
        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            $blOn = ([string]$bl.ProtectionStatus -eq 'On')
            $blText = "$($bl.ProtectionStatus) ($($bl.VolumeStatus), $($bl.EncryptionPercentage)%)"
            if ($bl.KeyProtector) { $blText += ' - protectors: ' + ((@($bl.KeyProtector) | ForEach-Object { [string]$_.KeyProtectorType }) -join ', ') }
        } catch {}
    }
    if (-not $blText) {
        try {
            $v = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection')
            $map = @{ 1 = 'On'; 2 = 'Off'; 3 = 'Encrypting'; 4 = 'Decrypting'; 5 = 'Suspended'; 6 = 'On (locked)' }
            if ($null -ne $v -and $map.ContainsKey([int]$v)) { $blText = $map[[int]$v]; $blOn = ([int]$v -in 1, 3, 6) }
        } catch {}
    }
    if ($blText) {
        $sev = $null
        if ($blOn -eq $false -and $script:Shared.IsLaptop) { $sev = 'Low' }
        if ($blText -match 'Suspended') { $sev = 'Medium' }
        & $addRow "Drive encryption ($env:SystemDrive)" $blText $(if ($script:Shared.IsLaptop) { 'On for laptops' } else { 'Optional on desktops' }) $sev
        if ($blText -match 'Suspended') {
            Add-Finding -Severity Medium -Category 'Security Settings' -Section $S -Title 'BitLocker protection is suspended' `
                -Fix 'Resume it: Control Panel > BitLocker Drive Encryption > Resume protection (or manage-bde -protectors -enable C:).' `
                -Actions @((New-RepairAction -Kind Run -Label 'Resume BitLocker protection' -Params @{ Command = 'bitlocker-resume' }))
        } elseif ($blOn -eq $false -and $script:Shared.IsLaptop) {
            Add-Finding -Severity Low -Category 'Security Settings' -Section $S -Title 'Laptop drive is not encrypted' `
                -Why 'If the laptop is lost or stolen, anyone can read the files by removing the drive.' `
                -Fix 'Turn on Device encryption / BitLocker (Settings > Privacy & security > Device encryption) and save the recovery key to the Microsoft account first.'
        } elseif ($blOn) {
            Add-Finding -Severity Info -Category 'Security Settings' -Section $S -Title 'Drive is encrypted - make sure the recovery key is saved' `
                -Why 'BIOS updates or hardware changes can trigger a BitLocker recovery screen. Without the key, the data is gone.' `
                -Fix 'Check https://account.microsoft.com/devices/recoverykey (or print/save the key from Control Panel > BitLocker).'
        }
    }

    # --- Remote Desktop / Remote Assistance
    $ts = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $deny = Get-RegValue $ts 'fDenyTSConnections'
    $nla = Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
    if ($deny -eq 0 -and -not $isHome) {
        $sev = if ($nla -eq 0) { 'High' } else { 'Medium' }
        & $addRow 'Remote Desktop (incoming)' $(if ($nla -eq 0) { 'ON without Network Level Authentication' } else { 'ON' }) 'Off unless needed' $sev
        Add-Finding -Severity $sev -Category 'Accounts & Access' -Section $S -Title 'Remote Desktop is enabled' `
            -Detail $(if ($nla -eq 0) { 'Network Level Authentication is OFF.' } else { '' }) `
            -Why 'Remote Desktop lets people sign in to this PC over the network. Scammers often switch it on.' `
            -Fix 'If nobody uses it: Settings > System > Remote Desktop > Off.' `
            -Actions @((New-RepairAction -Kind RegSetValue -Label 'Turn incoming Remote Desktop off' -Risk caution -Params @{ Path = $ts; Name = 'fDenyTSConnections'; Value = 1 }))
    } else { & $addRow 'Remote Desktop (incoming)' 'Off' 'Off unless needed' $null }
    $ra = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
    & $addRow 'Remote Assistance invitations' $(if ($ra -eq 1) { 'Allowed' } else { 'Off' }) 'Off unless needed' $(if ($ra -eq 1) { 'Low' } else { $null })
    if ($ra -eq 1) {
        Add-Finding -Severity Low -Category 'Accounts & Access' -Section $S -Title 'Remote Assistance connections are allowed' `
            -Fix 'Control Panel > System > Remote settings > untick "Allow Remote Assistance connections to this computer".' `
            -Actions @((New-RepairAction -Kind RegSetValue -Label 'Turn Remote Assistance invitations off' -Params @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Name = 'fAllowToGetHelp'; Value = 0 }))
    }

    # --- SMBv1
    $smb1Server = $null
    try { $smb1Server = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
    $mrx = Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
    $smb1Client = ($null -ne $mrx -and $mrx -ne 4)
    if ($smb1Server -or $smb1Client) {
        & $addRow 'SMBv1 file sharing protocol' $(if ($smb1Server) { 'Server ON' } else { 'Client ON' }) 'Removed' 'High'
        Add-Finding -Severity High -Category 'Network' -Section $S -Title 'Obsolete SMBv1 file-sharing protocol is enabled' `
            -Why 'SMBv1 is what WannaCry and NotPetya used to spread. Nothing modern needs it.' `
            -Fix 'Run as admin: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol, then restart.' `
            -Actions @((New-RepairAction -Kind WindowsFeatureDisable -Label 'Remove the SMBv1 protocol' -Reboot -Params @{ Feature = 'SMB1Protocol' }))
    } else { & $addRow 'SMBv1 file sharing protocol' 'Off' 'Removed' $null; Add-Pass 'Network' 'SMBv1 is disabled' }

    # --- boot flags (test signing / integrity checks off)
    $sso = [string](Get-RegValue 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control' 'SystemStartOptions')
    $flags = @()
    if ($sso -match '(^|\s)TESTSIGNING') { $flags += 'Test signing mode' }
    if ($sso -match 'DISABLE_INTEGRITY_CHECKS') { $flags += 'Driver signature checks disabled' }
    if ($sso -match '(^|\s)DEBUG(\s|=|$)') { $flags += 'Kernel debugging enabled' }
    & $addRow 'Boot options' $(if ($flags) { $flags -join ', ' } else { 'Normal' }) 'Normal' $(if ($flags) { 'High' } else { $null })
    if ($flags) {
        Add-Finding -Severity High -Category 'Security Settings' -Section $S -Title 'Windows driver protections are switched off at boot' `
            -Detail (($flags -join ', ') + ". Boot options: $sso") `
            -Why 'This lets unsigned kernel drivers load - used by game cheats and rootkits.' `
            -Fix 'Run as admin: bcdedit /set testsigning off ; bcdedit /set nointegritychecks off ; bcdedit /debug off - then restart.' `
            -Actions @((New-RepairAction -Kind Run -Label 'Restore normal boot protections (test signing / integrity checks / debug off)' -Reboot -Params @{ Command = 'bcd-normal' }))
    }

    # --- PowerShell 2.0 (admin only, it is slow-ish)
    if ($script:IsAdmin) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
            if ($f -and [string]$f.State -eq 'Enabled') {
                & $addRow 'PowerShell 2.0 engine' 'Installed' 'Removed' 'Low'
                Add-Finding -Severity Low -Category 'Security Settings' -Section $S -Title 'Legacy PowerShell 2.0 is installed' `
                    -Why 'Attackers use PowerShell 2.0 to dodge modern script logging and antivirus scanning.' `
                    -Fix 'Run as admin: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' `
                    -Actions @((New-RepairAction -Kind WindowsFeatureDisable -Label 'Remove PowerShell 2.0' -Params @{ Feature = 'MicrosoftWindowsPowerShellV2Root' }))
            }
        } catch {}
    }

    # --- System Restore
    if ($script:IsAdmin) {
        try {
            $rps = @(Get-ComputerRestorePoint -ErrorAction Stop)
            if ($rps.Count -eq 0) {
                & $addRow 'System Restore points' 'None' 'At least one recent' 'Low'
                Add-Finding -Severity Low -Category 'System Integrity' -Section $S -Title 'No System Restore points exist' `
                    -Why 'A restore point is the easiest undo button if a cleanup or driver change goes wrong.' `
                    -Fix 'Control Panel > System > System protection > select C: > Configure > Turn on, then click Create. Do this BEFORE removing software.' `
                    -Actions @((New-RepairAction -Kind Run -Label 'Turn on System Protection and create a restore point now' -Params @{ Command = 'restore-point' }))
            } else {
                $last = ($rps | ForEach-Object { [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime) } | Sort-Object -Descending | Select-Object -First 1)
                & $addRow 'System Restore points' "$($rps.Count) (latest $($last.ToString('yyyy-MM-dd')))" 'At least one recent' $null
                Add-Pass 'System Integrity' 'System Restore is active' "$($rps.Count) restore point(s), latest $($last.ToString('yyyy-MM-dd'))"
            }
        } catch {}
    }

    Add-Table -Section $S -Title 'Security settings' -Rows $rows
}
