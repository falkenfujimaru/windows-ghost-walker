@echo off
setlocal EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
set "SDEL="
if exist "%SCRIPT_DIR%sdelete64.exe" set "SDEL=%SCRIPT_DIR%sdelete64.exe"
if not defined SDEL if exist "%SCRIPT_DIR%sdelete.exe" set "SDEL=%SCRIPT_DIR%sdelete.exe"
if not defined SDEL (
  echo [>] SDelete not found. Fetching from Sysinternals...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$temp=$env:TEMP; $zip=Join-Path $temp 'SDelete.zip'; Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing; Expand-Archive -Path $zip -DestinationPath '%SCRIPT_DIR%' -Force"
  if exist "%SCRIPT_DIR%sdelete64.exe" set "SDEL=%SCRIPT_DIR%sdelete64.exe"
  if not defined SDEL if exist "%SCRIPT_DIR%sdelete.exe" set "SDEL=%SCRIPT_DIR%sdelete.exe"
)
if not exist "%SDEL%" (
  echo [!] Error: The shredder (sdelete.exe) is missing and download failed from Sysinternals
  echo [!] Operation aborted. Check your network or place SDelete next to this script.
  exit /b 1
)

:: Elevate to God-Mode (Admin Check)
net session >nul 2>&1
if not %errorlevel%==0 (
  echo [!] Access Denied. I need God-Mode permissions to go Ghost.
  echo [>] Relaunching with elevated clearance...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

"%SDEL%" -accepteula >nul 2>&1

:: ===============================================================
::  PROJECT: GHOST-WALKER // VOID PROTOCOL v2.0
::  Coded by: Falken Fujimaru [The Digital Phantom]
::  License: Private // Authorized Access Only
:: ===============================================================

title GHOST-WALKER // VOID PROTOCOL - Falken Fujimaru
echo ===============================================================
echo   GHOST-WALKER : THE ULTIMATE TRACE VAPORIZER
echo   System Scrub by Falken Fujimaru — [PRIVATE LICENSE]
echo ===============================================================
echo.
echo [!] WARNING: You are about to enter Stealth Mode. 
echo [!] Everything you've done on this box will be NUKED.
echo [>] Booting the Void Engine... Time to vanish.

:: 1. Force Close Apps (Executioner Mode)
echo [>] Flatlining active witnesses (apps) to unlock data vaults...
taskkill /F /IM chrome.exe /IM msedge.exe /IM brave.exe /IM firefox.exe /IM opera.exe /IM Discord.exe /IM DiscordCanary.exe /IM DiscordPTB.exe /IM WhatsApp.exe /IM Telegram.exe /IM explorer.exe /T >nul 2>&1

:: 2. Secure Delete Personal Folders
echo [>] Zeroing out the personal vaults. No history, no mystery.
if exist "%USERPROFILE%\Downloads\" (
  echo >>> Nuking Downloads... shredding every byte.
  "%SDEL%" -p 3 -s -q "%USERPROFILE%\Downloads\*"
  echo >>> Downloads folder: VAPORIZED.
)
if exist "%USERPROFILE%\Documents\" (
  echo >>> Sanitizing Documents... leave no trace.
  "%SDEL%" -p 3 -s -q "%USERPROFILE%\Documents\*"
  echo >>> Documents folder: GHOSTED.
)
if exist "%USERPROFILE%\Pictures\" (
  echo >>> Obliterating Media archives... 
  "%SDEL%" -p 3 -s -q "%USERPROFILE%\Pictures\*"
  echo >>> Pictures folder: PURGED.
)
if exist "%USERPROFILE%\Videos\" (
  echo >>> Cleaning Video tracks... going dark.
  "%SDEL%" -p 3 -s -q "%USERPROFILE%\Videos\*"
  echo >>> Videos folder: PURGED.
)

:: 3. Secure Delete Browser Data & ALL Caches
echo [>] Memory Wipe: Browsers and Comms are going offline.
echo [>] Choose your Purge Mode: [A]ll-Out / [S]elect / [N]one
choice /c ASN /n /t 15 /d N
set "MODE_APP=N"
if errorlevel 3 set "MODE_APP=N"
if errorlevel 2 set "MODE_APP=S"
if errorlevel 1 set "MODE_APP=A"

if /I "!MODE_APP!"=="A" (
  set "DO_CHROME=Y" & set "DO_EDGE=Y" & set "DO_BRAVE=Y" & set "DO_FIREFOX=Y" & set "DO_OPERA=Y" & set "DO_DISCORD=Y" & set "DO_WHATSAPP=Y" & set "DO_TELEGRAM=Y"
) else if /I "!MODE_APP!"=="S" (
  echo [?] Nuke Chrome? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_CHROME=Y"
  echo [?] Nuke Edge? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_EDGE=Y"
  echo [?] Nuke Brave? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_BRAVE=Y"
  echo [?] Nuke Firefox? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_FIREFOX=Y"
  echo [?] Nuke Opera? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_OPERA=Y"
  echo [?] Nuke Discord (all variants)? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_DISCORD=Y"
  echo [?] Nuke WhatsApp? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_WHATSAPP=Y"
  echo [?] Nuke Telegram? [Y/N]
  choice /c YN /n /t 10 /d N
  if errorlevel 1 set "DO_TELEGRAM=Y"
  :: Add more prompts as needed...
)

if /I "!DO_CHROME!"=="Y" if exist "%LocalAppData%\Google\Chrome\User Data\" (
  echo >>> Chrome shadows: Vaporizing...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\Google\Chrome\User Data\*"
  echo >>> Chrome cache: VAPORIZED.
)
if /I "!DO_EDGE!"=="Y" if exist "%LocalAppData%\Microsoft\Edge\User Data\" (
  echo >>> Edge fingerprints: Shredding...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\Microsoft\Edge\User Data\*"
  echo >>> Edge cache: VAPORIZED.
)
if /I "!DO_BRAVE!"=="Y" if exist "%LocalAppData%\BraveSoftware\Brave-Browser\User Data\" (
  echo >>> Brave profiles: Obliterating...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\BraveSoftware\Brave-Browser\User Data\*"
  echo >>> Brave cache: VAPORIZED.
)
if /I "!DO_FIREFOX!"=="Y" if exist "%AppData%\Mozilla\Firefox\Profiles\" (
  echo >>> Firefox profiles: Erasing...
  "%SDEL%" -p 3 -s -q "%AppData%\Mozilla\Firefox\Profiles\*"
  echo >>> Firefox profiles: VAPORIZED.
)
if /I "!DO_FIREFOX!"=="Y" if exist "%LocalAppData%\Mozilla\Firefox\Profiles\" (
  echo >>> Firefox local profiles: Erasing...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\Mozilla\Firefox\Profiles\*"
  echo >>> Firefox local profiles: VAPORIZED.
)
if /I "!DO_FIREFOX!"=="Y" if exist "%AppData%\Mozilla\Firefox\Crash Reports\" (
  echo >>> Firefox crash reports: Erasing...
  "%SDEL%" -p 3 -s -q "%AppData%\Mozilla\Firefox\Crash Reports\*"
  echo >>> Firefox crash reports: VAPORIZED.
)
if /I "!DO_OPERA!"=="Y" if exist "%AppData%\Opera Software\Opera Stable\" (
  echo >>> Opera cache: Erasing...
  "%SDEL%" -p 3 -s -q "%AppData%\Opera Software\Opera Stable\*"
  echo >>> Opera cache: VAPORIZED.
)
if /I "!DO_OPERA!"=="Y" if exist "%LocalAppData%\Opera Software\Opera Stable\" (
  echo >>> Opera local cache: Erasing...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\Opera Software\Opera Stable\*"
  echo >>> Opera local cache: VAPORIZED.
)
if /I "!DO_DISCORD!"=="Y" if exist "%AppData%\discord\" (
  echo >>> Discord cache: Erasing...
  "%SDEL%" -p 3 -s -q "%AppData%\discord\*"
  echo >>> Discord cache: VAPORIZED.
)
if /I "!DO_DISCORD!"=="Y" if exist "%AppData%\discordcanary\" (
  echo >>> Discord Canary cache: Erasing...
  "%SDEL%" -p 3 -s -q "%AppData%\discordcanary\*"
  echo >>> Discord Canary cache: VAPORIZED.
)
if /I "!DO_DISCORD!"=="Y" if exist "%AppData%\discordptb\" (
  echo >>> Discord PTB cache: Erasing...
  "%SDEL%" -p 3 -s -q "%AppData%\discordptb\*"
  echo >>> Discord PTB cache: VAPORIZED.
)
if /I "!DO_DISCORD!"=="Y" if exist "%LocalAppData%\Discord\" (
  echo >>> Discord local cache: Erasing...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\Discord\*"
  echo >>> Discord local cache: VAPORIZED.
)
if /I "!DO_TELEGRAM!"=="Y" if exist "%AppData%\Telegram Desktop\" (
  echo >>> Telegram session: Deleted from reality.
  "%SDEL%" -p 3 -s -q "%AppData%\Telegram Desktop\*"
  echo >>> Telegram session: VAPORIZED.
)
if /I "!DO_WHATSAPP!"=="Y" if exist "%LocalAppData%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\" (
  echo >>> WhatsApp Desktop: Erasing...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\*"
  echo >>> WhatsApp Desktop: VAPORIZED.
)
if /I "!DO_WHATSAPP!"=="Y" if exist "%AppData%\WhatsApp\" (
  echo >>> WhatsApp Roaming: Erasing...
  "%SDEL%" -p 3 -s -q "%AppData%\WhatsApp\*"
  echo >>> WhatsApp Roaming: VAPORIZED.
)

:: 5. DEEP CLEAN EVENT VIEWER LOGS
echo [>] Timeline Eraser: Flattening the Event Logs.
for /F "tokens=*" %%G in ('wevtutil.exe el') do (
  echo >>> Reality check: Cleaning log %%G
  wevtutil.exe cl "%%G"
  echo >>> Event log %%G: FLATTENED.
)

:: 6. TRACKER & REGISTRY CLEANUP
echo [>] Digital Breadcrumbs: Deleting the Registry echoes.
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" >nul 2>&1 && (reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f & echo >>> UserAssist: DELETED)
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" >nul 2>&1 && (reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f & echo >>> Shell BagMRU: DELETED)
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" >nul 2>&1 && (reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f & echo >>> Shell Bags: DELETED)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" >nul 2>&1 && (reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f & echo >>> RunMRU: DELETED)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" >nul 2>&1 && (reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f & echo >>> TypedPaths: DELETED)
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" >nul 2>&1 && (reg delete "HKCU\Software\Microsoft\Terminal Server Client\Servers" /f & echo >>> RDP Servers: DELETED)
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" >nul 2>&1 && (reg delete "HKCU\Software\Microsoft\Terminal Server Client\Default" /f & echo >>> RDP Default: DELETED)
reg query "HKCU\Software\Microsoft\Terminal Server Client" /v UsernameHint >nul 2>&1 && (reg delete "HKCU\Software\Microsoft\Terminal Server Client" /v UsernameHint /f & echo >>> RDP Hints: DELETED)
echo >>> RDP Registry MRU: Purging...
reg delete "HKCU\Software\Microsoft\Terminal Server Client\Default" /va /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Terminal Server Client\Servers" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Terminal Server Client\Servers" /f >nul 2>&1
if exist "%USERPROFILE%\Documents\Default.rdp" (
  echo >>> RDP file (Documents\Default.rdp): Erasing...
  attrib -s -h "%USERPROFILE%\Documents\Default.rdp" >nul 2>&1
  "%SDEL%" -p 3 -q "%USERPROFILE%\Documents\Default.rdp"
  echo >>> RDP file (Documents\Default.rdp): VAPORIZED.
)
if exist "%USERPROFILE%\Default.rdp" (
  echo >>> RDP file (Default.rdp): Erasing...
  attrib -s -h "%USERPROFILE%\Default.rdp" >nul 2>&1
  "%SDEL%" -p 3 -q "%USERPROFILE%\Default.rdp"
  echo >>> RDP file (Default.rdp): VAPORIZED.
)
if exist "%LocalAppData%\Microsoft\Terminal Server Client\Cache\" (
  echo >>> RDP bitmap cache: Erasing...
  "%SDEL%" -p 3 -s -q "%LocalAppData%\Microsoft\Terminal Server Client\Cache\*"
  echo >>> RDP bitmap cache: VAPORIZED.
)
echo >>> Removing stored RDP credentials...
for /f "tokens=2 delims=:" %%H in ('cmdkey /list ^| findstr /I "TERMSRV/"') do (
  set "TARGET=%%H"
  set "TARGET=!TARGET: =!"
  if defined TARGET cmdkey /delete:!TARGET! >nul 2>&1 & echo >>> RDP credentials !TARGET!: DELETED.
)
if exist "%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\1b4dd67f29cb1962.automaticDestinations-ms" (
  "%SDEL%" -p 3 -q "%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\1b4dd67f29cb1962.automaticDestinations-ms"
)
reg add "HKCU\Software\Microsoft\Terminal Server Client\Default" /f >nul 2>&1

:: 7. CLEAR POWERSHELL & COMMAND HISTORY
echo [>] Shell Silence: Muting the command echoes.
if exist "%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
  "%SDEL%" -p 3 -q "%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
sethistory -c >nul 2>&1

:: 8. CLEAN RECENT DOCUMENTS, JUMP LISTS, & THUMBNAILS
echo [>] Shortcut Purge: Burning the Recent Files and Thumbnails.
if exist "%AppData%\Microsoft\Windows\Recent\" (
  echo >>> Recent files: Erasing...
  "%SDEL%" -p 3 -q "%AppData%\Microsoft\Windows\Recent\*"
  echo >>> Recent files: VAPORIZED.
)
if exist "%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\" (
  echo >>> JumpLists (AutomaticDestinations): Erasing...
  "%SDEL%" -p 3 -q "%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*"
  echo >>> JumpLists (AutomaticDestinations): VAPORIZED.
)
if exist "%AppData%\Microsoft\Windows\Recent\CustomDestinations\" (
  echo >>> JumpLists (CustomDestinations): Erasing...
  "%SDEL%" -p 3 -q "%AppData%\Microsoft\Windows\Recent\CustomDestinations\*"
  echo >>> JumpLists (CustomDestinations): VAPORIZED.
)
if exist "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db" (
  echo >>> Thumbnail caches: Erasing...
  "%SDEL%" -p 3 -q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db"
  echo >>> Thumbnail caches: VAPORIZED.
)

:: 9. SYSTEM TEMP & LINT
echo [>] System Flush: Draining the Temp and Error reports.
if exist "%temp%\" (
  echo >>> Temp folder: Erasing...
  "%SDEL%" -p 1 -q "%temp%\*"
  echo >>> Temp folder: VAPORIZED.
)
if exist "%systemroot%\Temp\" (
  echo >>> Windows Temp: Erasing...
  "%SDEL%" -p 1 -q "%systemroot%\Temp\*"
  echo >>> Windows Temp: VAPORIZED.
)
if exist "%LocalAppData%\Microsoft\Windows\WER\" (
  echo >>> WER (Local): Erasing...
  "%SDEL%" -p 1 -q "%LocalAppData%\Microsoft\Windows\WER\*"
  echo >>> WER (Local): VAPORIZED.
)
if exist "%ProgramData%\Microsoft\Windows\WER\" (
  echo >>> WER (ProgramData): Erasing...
  "%SDEL%" -p 1 -q "%ProgramData%\Microsoft\Windows\WER\*"
  echo >>> WER (ProgramData): VAPORIZED.
)
if exist "%systemroot%\Prefetch\" (
  echo >>> Prefetch: Erasing...
  "%SDEL%" -p 1 -q "%systemroot%\Prefetch\*"
  echo >>> Prefetch: VAPORIZED.
)
if exist "%systemroot%\SoftwareDistribution\Download\" (
  echo >>> Windows Update downloads: Erasing...
  "%SDEL%" -p 1 -q "%systemroot%\SoftwareDistribution\Download\*"
  echo >>> Windows Update downloads: VAPORIZED.
)
if exist "%systemroot%\Logs\CBS\" (
  echo >>> CBS logs: Erasing...
  "%SDEL%" -p 1 -q "%systemroot%\Logs\CBS\*"
  echo >>> CBS logs: VAPORIZED.
)
if exist "%systemroot%\Logs\WindowsUpdate\" (
  echo >>> Windows Update logs: Erasing...
  "%SDEL%" -p 1 -q "%systemroot%\Logs\WindowsUpdate\*"
  echo >>> Windows Update logs: VAPORIZED.
)
if exist "%ProgramData%\USOShared\Logs\" (
  echo >>> USOShared logs: Erasing...
  "%SDEL%" -p 1 -q "%ProgramData%\USOShared\Logs\*"
  echo >>> USOShared logs: VAPORIZED.
)

:: 10. CLEAR CLIPBOARD & RECYCLE BIN
echo [>] Final Pockets: Emptying the Bin and Clipboard.
echo off | clip
if exist "%LocalAppData%\Microsoft\Windows\Clipboard\" (
  echo >>> Clipboard history: Erasing...
  "%SDEL%" -p 1 -q "%LocalAppData%\Microsoft\Windows\Clipboard\*"
  echo >>> Clipboard history: VAPORIZED.
)
if exist "%systemdrive%\$Recycle.Bin" (
  echo >>> Recycle Bin: Erasing...
  "%SDEL%" -p 3 -s -q "%systemdrive%\$Recycle.Bin"
  echo >>> Recycle Bin: VAPORIZED.
)

:: 11. FREE SPACE SANITIZER
echo [>] Void Filling: Overwriting free space on %systemdrive% (Sanitize Mode)
"%SDEL%" -z %systemdrive%
for /f "skip=1 tokens=1" %%D in ('wmic logicaldisk where "drivetype=3" get name') do (
  if not "%%D"=="" if /I not "%%D"=="%systemdrive%" set "DRIVES=%%D !DRIVES!"
)
if defined DRIVES (
  echo [>] Fixed non-system drives detected: !DRIVES!
  echo [>] Choose free-space wipe: [A]ll / [S]elect / [N]one
  choice /c ASN /n /t 15 /d N
  set "MODE_FS=N"
  if errorlevel 3 set "MODE_FS=N"
  if errorlevel 2 set "MODE_FS=S"
  if errorlevel 1 set "MODE_FS=A"
  if /I "!MODE_FS!"=="A" (
    for %%D in (!DRIVES!) do (
      echo >>> Free space %%D: Erasing...
      "%SDEL%" -z %%D
      echo >>> Free space %%D: SANITIZED.
    )
  ) else if /I "!MODE_FS!"=="S" (
    for %%D in (!DRIVES!) do (
      echo [>] Overwrite free space on %%D ? [Y/N]
      choice /c YN /n /t 10 /d N
      if errorlevel 2 (
        echo >>> Free space %%D: SKIPPED.
      ) else (
        echo >>> Free space %%D: Erasing...
        "%SDEL%" -z %%D
        echo >>> Free space %%D: SANITIZED.
      )
    )
  ) else (
    echo >>> Non-system drive free-space wipe: SKIPPED.
  )
)

:: Restart Explorer
start explorer.exe

echo.
echo ===============================================================
echo  OPERATION COMPLETE — SYSTEM IS NOW STERILE.
echo  Your forensic footprint has been vaporized into the void.
echo  Logs: DEAD. Session: DEAD. History: DEAD.
echo ===============================================================
echo.

:: 11. EXIT STRATEGY
echo [1] Full Reboot (Clear RAM Shadows)
echo [2] Hard Shutdown (Ghost Out)
echo [3] Stealth Exit (Self-Destruct Script)
echo.
choice /c 123 /n /t 15 /d 3
if errorlevel 3 goto S_EXIT
if errorlevel 2 goto S_SHUTDOWN
if errorlevel 1 goto S_RESTART

:S_RESTART
echo [>] Initializing System Reset... Fade to black.
start /b "" cmd /c del "%~f0"&shutdown /r /t 5 /f
exit

:S_SHUTDOWN
echo [>] Initializing Hard Shutdown... Going dark.
start /b "" cmd /c del "%~f0"&shutdown /s /t 5 /f
exit

:S_EXIT
echo [>] Shredding Ghost-Walker script... Bye.
start /b "" cmd /c del "%~f0"&exit
