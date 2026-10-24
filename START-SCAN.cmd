@echo off
rem PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
rem Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
setlocal
title PC Health ^& Security Scan
cd /d "%~dp0"

rem --- elevate (UAC) unless we already are admin -------------------------------
fltmc >nul 2>&1
if not errorlevel 1 goto menu
if /i "%~1"=="--elevated" goto limited
echo.
echo   Asking for administrator rights - click YES on the Windows prompt.
echo   (Over AnyDesk the prompt appears on the remote PC's screen.)
powershell -NoProfile -Command "try { Start-Process -FilePath \"%~f0\" -ArgumentList '--elevated' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if not errorlevel 1 exit /b
:limited
echo.
echo   Administrator rights were declined - the scan will be LIMITED.

:menu
echo.
echo   ==========================================================
echo     PC HEALTH ^& SECURITY SCAN
echo     Read-only: it looks, it does not change anything
echo   ==========================================================
echo.
echo     [1] Standard scan - everything, about 3-8 minutes  (recommended)
echo     [2] Deep scan     - Standard + Defender quick scan + system file check
echo                         (20-40 min; also updates Defender definitions)
echo     [3] Quick scan    - fewer file signature checks, about 2-4 minutes
echo     [Q] Quit
echo.
choice /c 123Q /n /m "    Choose 1, 2, 3 or Q: "
if errorlevel 4 exit /b
if errorlevel 3 (set MODE=Quick) else if errorlevel 2 (set MODE=Deep) else (set MODE=Standard)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scanner\PCHealthScan.ps1" -Mode %MODE%
echo.
pause
