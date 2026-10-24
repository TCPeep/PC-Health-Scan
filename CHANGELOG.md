# Changelog

All notable changes to PC Health Scan are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] &mdash; 2026-10-24

First public release.

- 15 scanner modules covering system, accounts, security settings, antivirus, updates, processes, persistence, browsers, network, software, malware & PUP sweep, hardware, events, performance, system integrity.
- Self-contained HTML report with Security and Health grades, "What needs attention", "Technician notes & actions taken", sortable section tables, Timeline.
- Repair Console with per-step Simulate / Apply, risk tags, undo journal, quarantine, System Restore point.
- Dedicated **PC App Store (Fast Corporation)** detection and complete removal, also available from the Repair Console menu for when the browser is unusable.
- Dev tooling: `dev\amsi-check.ps1` (AMSI false-positive check) and `dev\repair-selftest.ps1` (real apply/undo round trip).
- Sample report and sample Repair Console pages shipped under `samples/`, built from `scripts\Build-DemoReport.ps1`.

[1.0.0]: https://github.com/TCPeep/PC-Health-Scan/releases/tag/v1.0.0
