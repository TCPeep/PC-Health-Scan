@echo off
rem PC Health Scan - Copyright (C) 2026 TCPeep - https://github.com/TCPeep/PC-Health-Scan
rem Licensed under GPL-3.0 with attribution terms (keep the credit). See LICENSE and NOTICE.
setlocal
title PC Health Scan - Repair Console
cd /d "%~dp0"

rem --- the Repair Console changes system settings, so it must run elevated -----
fltmc >nul 2>&1
if not errorlevel 1 goto run
if /i "%~1"=="--elevated" goto denied
echo.
echo   Asking for administrator rights - click YES on the Windows prompt.
powershell -NoProfile -Command "try { Start-Process -FilePath \"%~f0\" -ArgumentList '--elevated' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if not errorlevel 1 exit /b
:denied
echo.
echo   Administrator rights are required for repairs. Nothing was changed.
pause
exit /b 1

:run
echo.
echo   ==========================================================
echo     REPAIR CONSOLE
echo     Opens a page with a Simulate / Apply button per issue.
echo   ==========================================================
echo.
echo     [1] Normal      - Simulate or Apply per issue (recommended)
echo     [2] Simulate-only - nothing can be changed (safe to explore)
echo.
echo     PC App Store, right here in this window (for when its full-screen page
echo     makes the browser unusable - no web page needed):
echo     [3] Show what would be removed (changes nothing)
echo     [4] Remove PC App Store now (every step can be undone later via option 1)
echo     [Q] Quit
echo.
choice /c 1234Q /n /m "    Choose 1, 2, 3, 4 or Q: "
if errorlevel 5 exit /b
if errorlevel 4 goto pcas
if errorlevel 3 goto pcassim
if errorlevel 2 (set EXTRA=-DryRun) else (set EXTRA=)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scanner\RepairConsole.ps1" %EXTRA%
echo.
pause
exit /b

:pcassim
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scanner\RemovePCAppStore.ps1" -DryRun
echo.
pause
exit /b

:pcas
echo.
echo   This ends PC App Store's own programs, removes its startup entries, moves its
echo   folders/shortcuts to quarantine and removes its registry keys. Nothing else.
echo   Save any open work first.
choice /c YN /n /m "    Remove PC App Store now? (Y/N): "
if errorlevel 2 exit /b
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scanner\RemovePCAppStore.ps1"
echo.
pause
