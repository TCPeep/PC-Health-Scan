# FAQ

### Does the scan change anything on my PC?
No. START-SCAN.cmd is read-only. In Deep mode it also updates Defender's definitions and runs a Defender quick scan &mdash; both are Windows features, not changes to your settings. All other changes happen in the separate Repair Console.

### Does any data leave my PC?
No. The report stays in the `Reports\` folder. SHA256 links in the report open a VirusTotal **search page** &mdash; nothing is uploaded. Website addresses in the report are deliberately not clickable.

### Can I run it over AnyDesk?
Yes. Copy the whole folder to the remote PC, keep the structure intact, and double-click START-SCAN.cmd. The UAC prompt appears on the remote PC's **secure desktop** &mdash; the person there may need to click it.

### Does it need PowerShell 7?
No. It uses the Windows-built-in **PowerShell 5.1**. 7 would also work but adds nothing here, and 5.1 is always present on Windows 10/11.

### Why PowerShell 5.1 and no modules to install?
Because the common use case is one-off runs on other people's PCs over AnyDesk. Nothing to install means nothing to clean up and nothing to approve.

### Can the Repair Console make my PC worse?
It can, if you tick every box without thinking. The defaults are conservative: items that *might* be legitimate start unticked, "safe" steps only change settings, and everything is undoable (quarantine + undo journal + session restore point). But the sum of many changes still deserves a backup first.

### Why not just use Autoruns?
Autoruns is great. This tool overlaps with it on persistence, but adds: a plain-English report with scoring, timeline reconstruction (how adware got in), a Repair Console with per-step undo, Defender-settings auditing, Chrome/Firefox policy auditing, hardware health, and the dedicated PC App Store removal. For a quick "what's on this PC that starts at boot" look, Autoruns is faster.

### Is it a replacement for antivirus?
No. It's a diagnostic that catches what Defender missed (PUPs, policy hijacks, manual configuration drift) and gives you a report you can share. Keep Defender (or another AV) on.

### Where's the undo journal?
`C:\ProgramData\PCHealthScan\` (administrators only). Sessions, backups, quarantine, journal.

### Can I trust a program and have the scan stop flagging it?
Yes. In the Repair Console, each unsigned-but-maybe-legitimate step has an **"I recognise it &mdash; trust it"** option. Trusting a program adds its path (or hash, or signer) to `trusted.txt`. Future scans still list it under **Informational notes** so nothing is hidden silently.

### Can I run just one module?
Yes:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scanner\PCHealthScan.ps1 -Skip 04-Antivirus,05-Updates
```
Or run one directly after dot-sourcing `Core.ps1` and `Report.ps1`, then call its `Invoke-*Scan` function. See [checks.md](checks.md) for the module list.

### How often should I run it?
On a PC you own: whenever something feels off. On other people's PCs: before you start working, so you have a baseline, and again after fixes to confirm they stuck.
