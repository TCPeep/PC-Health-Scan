# Contributing to PC Health Scan

Thanks for your interest. Small, focused PRs are easiest to merge.

## Golden rule

The scan is **read-only**. Any PR to a module must not add anything that ends, stops, deletes or installs. All of that lives in the Repair Console under the hard rules in [docs/safety.md](docs/safety.md).

## Setup

Windows 10 or 11. PowerShell 5.1 (already installed). Nothing else to install.

Clone and run against a scratch folder so your real reports aren't mixed in:

```powershell
git clone https://github.com/TCPeep/PC-Health-Scan.git
cd PC-Health-Scan
powershell -NoProfile -ExecutionPolicy Bypass -File scanner\PCHealthScan.ps1 -Mode Quick -OutputDir .\scratch
```

## After editing anything in `scanner\`

Run both checks, every time:

```powershell
# Defender's AMSI must not flag any script
powershell -NoProfile -ExecutionPolicy Bypass -File dev\amsi-check.ps1

# repair engine round-trip: real apply + undo, cannot end any program
powershell -NoProfile -ExecutionPolicy Bypass -File dev\repair-selftest.ps1
```

A PR that doesn't pass both will not be merged.

## Code style

- **ASCII only** in `scanner\lib\Core.ps1`, `Report.ps1`, `Repair.ps1` and all module files. PowerShell 5.1 reads BOM-less files as ANSI, which breaks non-ASCII characters. Everything you want to show the user that *isn't* ASCII goes through `[System.Net.WebUtility]::HtmlEncode` or a specific utf-8 writer.
- Follow the surrounding code: comment density, naming, idioms.
- Each module is independent. Catch and swallow its own errors (one broken module must not stop the scan).

## Adding a new finding

In the right `modules\*.ps1`:

```powershell
Add-Finding -Severity Medium -Category 'Security Settings' -Section $S `
    -Title 'The specific, falsifiable thing you found' `
    -Detail 'What was found, in one plain sentence.' `
    -Why 'Why this matters, in one plain sentence.' `
    -Fix 'What to do, in one plain sentence.' `
    -Evidence @('one', 'two', 'three') `
    -Actions @((New-RepairAction -Kind RegSetValue -Label '...' -Params @{ ... }))
```

- **Evidence** is what the finding is *based on*. Don't pad; one line per real signal.
- **Fix** is a plain-English imperative. Don't tell people to open a specific registry editor.
- Prefer **Medium** or **Low** if you're not sure. "Critical" is for things that are almost certainly bad on any PC.

## Adding a repair action

Every action is a plain hashtable produced by `New-RepairAction`. If an existing `Kind` doesn't fit, add a new one in `scanner\lib\Repair.ps1` with its backup-first, apply, undo and simulate implementations &mdash; and cover it in `dev\repair-selftest.ps1`.

## Pull requests

- One topic per PR.
- Include before/after screenshots of the report or Repair Console for UI changes.
- Update [docs/checks.md](docs/checks.md) when adding a new check and [docs/safety.md](docs/safety.md) when adding a new fix type.

## Security

Never open an issue for a security problem &mdash; see [SECURITY.md](SECURITY.md).

## License

By submitting a PR you agree your contribution is licensed under the project's GPL-3.0 license with the additional terms in [NOTICE](NOTICE).
