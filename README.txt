PC HEALTH & SECURITY SCAN
=========================

Full documentation and screenshots: https://github.com/TCPeep/PC-Health-Scan
(also in README.md next to this file).

QUICK USE
---------
1. Double-click  START-SCAN.cmd
2. Click Yes on the administrator prompt (or decline for a limited scan).
3. Pick a mode:
     1 Standard  (recommended, ~3-8 min)
     2 Deep      (adds Defender quick scan + system file verification)
     3 Quick     (fewer file-signature checks)
4. The report opens by itself.
   Saved under:  Reports\<COMPUTERNAME>_<date-time>\PC-Health-Report_....html

REPAIRS (optional)
------------------
After a scan, double-click RUN-REPAIRS.cmd. It opens a page with a
Simulate / Apply button per issue. Every change is reversible
(quarantine + undo journal + System Restore point).

Safety rules are built into the engine; read docs/safety.md first.

LICENSE
-------
GPL-3.0 with additional terms (keep the credit) - see LICENSE and NOTICE.
Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
