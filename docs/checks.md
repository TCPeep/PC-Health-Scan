# What PC Health Scan checks

Everything below runs read-only during the scan. Fixes are available separately in the Repair Console. See [safety.md](safety.md).

## Security

### Known adware / PUP families
- PC App Store, OneLaunch, OneStart, WaveBrowser, Wave Browser clones.
- Fake "optimizers" (PC Booster, Driver Updater, Registry Reviver, &hellip;).
- Toolbars and hijackers (Yahoo!, MyWay, Delta Search family, &hellip;).
- Piracy activators (KMSPico, AutoKMS, HWIDGen, &hellip;).
- Miners (XMRig and known wrappers).
- Bundleware (anything bundled alongside Discord, uTorrent, &hellip;).

Looked for in: installed apps, leftover folders, running processes, startup entries, scheduled tasks, services, browser extensions, Start-menu shortcuts, Desktop shortcuts, downloads.

### Everything that auto-starts
Run keys (all users), Startup folders, scheduled tasks, services, kernel drivers, WMI event subscriptions, Winlogon shell / userinit / Notify, IFEO (Image File Execution Options) debugger hijacks, AppInit DLLs, LSA packages, Active Setup, print monitors.

### Running processes
Digital signatures, file locations, fake Windows names (`svchosts.exe` with an s, `explorer.exe` in your user folder, &hellip;), Office &rarr; shell launches, suspicious command lines.

### Browsers
Chrome, Edge, Brave, Opera, Vivaldi, Firefox, unknown Chromium clones:
- Extensions and their permissions (webRequest, nativeMessaging, &hellip;).
- Hijacked start page / search engine / startup URLs.
- Forced policies (the "Managed by your organization" message).
- Notification spam from obscure domains.
- Tampered shortcuts (`chrome.exe --load-extension=...`).

### Microsoft Defender
Health status, exclusions (per-path, per-process, per-extension), disable policies, threat history, tamper-protection and exclusion-change events, expired or unregistered third-party antivirus.

### Windows settings
UAC level, firewall (per profile), SmartScreen, Secure Boot (and 2023 certificates), TPM presence/version, Memory Integrity (HVCI), BitLocker, RDP, SMBv1, test-signing, number of restore points.

### Accounts
Local administrators, hidden accounts, Guest, auto-logon with password in registry.

### Network
DNS servers, proxy and PAC file, hosts file, listening ports, firewall exceptions, shares, rogue root certificates.

### Remote-access tools
Inventory, plus AnyDesk and TeamViewer **incoming session logs** &mdash; a common signature of tech-support scams. Win+R "fake CAPTCHA" clipboard-paste commands. Known malicious PowerShell encoded strings in recent history.

### Updates
Windows Update history, failures, pause markers, blocked channels. End-of-support warnings per Windows version. Outdated risky software: WinRAR, 7-Zip, Office, Flash remnants.

## Health

### Drives
Model, serial, firmware. SMART attributes (reallocated sectors, pending sectors, UDMA errors). Current and max temperature. Free space, free-space warnings, file-system errors.

### Blue screens and stability
BSOD stop codes (decoded with the module that caused it), GPU hangs (`VIDEO_TDR_FAILURE`), power losses, WHEA hardware errors, crashing programs, Device Manager problem codes, unsigned drivers.

### Hardware
RAM (configured channels, slot layout), GPU driver age, battery wear (plus Windows' own battery report).

### Performance
Boot time and what slows it (startup load, Prefetch), startup load counter, reclaimable disk space.

### Integrity
Corrupted program files, component store health (`DISM /CheckHealth`), system files (`sfc /verifyonly` in Deep mode).
