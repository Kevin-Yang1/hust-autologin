@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "SETUP_PS1=%SCRIPT_DIR%windows_autostart.ps1"

if not exist "%SETUP_PS1%" (
  echo Cannot find "%SETUP_PS1%".
  pause
  exit /b 1
)

where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo Cannot find powershell.exe.
  pause
  exit /b 1
)

echo Starting HUST Autologin startup setup...
echo A Windows UAC prompt may appear. Please choose Yes.
echo.

set "HUST_AUTOLOGIN_SETUP_PS1=%SETUP_PS1%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$script = $env:HUST_AUTOLOGIN_SETUP_PS1; $quotedScript = [char]34 + $script + [char]34; Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',$quotedScript,'-RunNow')"

if errorlevel 1 (
  echo Failed to start the elevated PowerShell setup.
  pause
  exit /b 1
)

echo Setup window launched. You can close this window.
timeout /t 3 >nul
