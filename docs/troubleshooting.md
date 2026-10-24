# Troubleshooting

### "Windows protected your PC" on START-SCAN.cmd (SmartScreen)
Click **More info &rarr; Run anyway**. This happens because the file was downloaded from the internet. Verify the file hash from the latest [Release](https://github.com/TCPeep/PC-Health-Scan/releases/latest) first if you want to be careful.

### Antivirus (Defender or a third-party) blocks a script
Each module runs independently, so one failure never stops the rest of the scan. Check `scan-log.txt` to see which module was blocked.

If **Defender's AMSI** blocks a script, it's likely a false positive triggered by a string the module reads (adware names, &hellip;). Run `dev\amsi-check.ps1` to see which script is being flagged. Open an [issue](https://github.com/TCPeep/PC-Health-Scan/issues) with the script name and the line Defender points at &mdash; the maintainers can usually reword the string to clear the flag without losing the check.

### "Not running as administrator" warning
Click **Yes** on the UAC prompt. Without admin, Defender exclusions, drive wear, security event logs, other users' folders and system-file checks are skipped. The scan still runs, just with less visibility.

### Over AnyDesk, UAC doesn't appear
UAC prompts show on Windows' **secure desktop**, which AnyDesk can only pass through if the operator has permission for it. The person at the remote PC may need to click Yes once.

### The report is huge
A busy PC with lots of adware can produce a report over a megabyte. That's expected and still opens in any browser.

### `findings.json` won't load in the Repair Console
Normally the console finds the newest one by itself. If you need to point it at a specific one:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scanner\RepairConsole.ps1 -FindingsPath "C:\path\to\findings.json"
```

### "Access to the path is denied" in scan-log.txt
Normal and dropped from the error log on purpose. Windows protects certain registry keys, service folders and system files even from administrators.

### A fix was applied but didn't stick
Open the Repair Console again, click **Undo & restore** at the top, and look at the row's details. The usual reason is that the browser or program the step targeted restarts itself (Watchdog patterns). The PC App Store removal handles this specifically by stopping Watchdog first.

### How do I re-run the scan to verify a fix?
Double-click `START-SCAN.cmd` again. Each scan writes to its own dated folder under `Reports\`.

### Command line
```powershell
powershell -ExecutionPolicy Bypass -File scanner\PCHealthScan.ps1 -Mode Standard -Days 60
```
Switches: `-Mode Quick|Standard|Deep` (default Standard), `-Days N` (look-back window, default 30), `-OutputDir <path>`, `-NoOpen`, `-Skip <module names>`.
