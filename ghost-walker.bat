@echo off
setlocal EnableDelayedExpansion
chcp 65001

:: ===============================================================
::  PROJECT: GHOST-WALKER // VOID PROTOCOL v3.1
::  Coded by: Falken Fujimaru [The Digital Phantom]
::  Status: DEBUGGED & OPTIMIZED
:: ===============================================================

title GHOST-WALKER v3.1 // SHADOW PROTOCOL
color 0A
mode con: cols=100 lines=45

:: --- INITIALIZATION ---
set "VERSION=3.1"
set "LOG_FILE=%temp%\ghostwalker_%random%.log"
set "SDEL_EXE=sdelete64.exe"
set "SCRIPT_DIR=%~dp0"

:: --- 1. PRIVILEGE CHECK ---
net session
if not %errorlevel%==0 (
    echo [!] God-Mode permissions required.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: --- 2. HEADER DISPLAY ---
cls
echo =======================================================================================================
echo    GHOST-WALKER // ULTIMATE TRACE VAPORIZER v!VERSION!
echo    [ System Sterilization Suite - No Trace Left ]
echo =======================================================================================================
echo.
echo    Crafted by 乍丹し片ヨ几　乍凵勹工冊丹尺凵
echo    Breaking Codes, Not Hearts.
echo.
echo =======================================================================================================
echo.

:: --- 3. SDELETE VALIDATION ---
if exist "%SCRIPT_DIR%sdelete64.exe" (
    set "SDEL=%SCRIPT_DIR%sdelete64.exe"
) else if exist "%SCRIPT_DIR%sdelete.exe" (
    set "SDEL=%SCRIPT_DIR%sdelete.exe"
) else (
    echo [~] SDelete not found. Fetching from Sysinternals...
    powershell -NoProfile -Command "(New-Object System.Net.WebClient).DownloadFile('https://download.sysinternals.com/files/SDelete.zip', '%temp%\SDelete.zip'); Expand-Archive -Path '%temp%\SDelete.zip' -DestinationPath '%SCRIPT_DIR%' -Force; Remove-Item '%temp%\SDelete.zip' -Force"
    if exist "%SCRIPT_DIR%sdelete64.exe" (set "SDEL=%SCRIPT_DIR%sdelete64.exe") else (set "SDEL=%SCRIPT_DIR%sdelete.exe")
)

if not exist "!SDEL!" (
    echo [✗] CRITICAL: SDelete failed to materialize. Operation aborted.
    pause & exit /b
)
"!SDEL!" -accepteula

:: --- 4. CONFIRMATION ---
echo [!] WARNING: THIS ACTION IS IRREVERSIBLE.
set /p CONFIRM="[?] Type 'GHOST' to proceed, anything else to abort: "
if /i not "!CONFIRM!"=="GHOST" (
    echo [~] Aborted. System safe. & timeout /t 3 & exit /b
)

:: ===============================================================
::  MAIN EXECUTION BRAIN (The Fix)
:: ===============================================================
:: Perubahan krusial: Memanggil modul menggunakan CALL agar kembali ke sini.

call :MODULE_PROCESS_KILL
call :MODULE_PERSONAL_DATA
call :MODULE_BROWSER_DATA
call :MODULE_COM_APPS
call :MODULE_EVENT_LOGS
call :MODULE_REGISTRY
call :MODULE_SHELL_HISTORY
call :MODULE_TEMP_DATA
call :MODULE_RECYCLE_CLIPBOARD
call :MODULE_MFT_FILLER
call :MODULE_FREE_SPACE

goto :COMPLETION

:: ===============================================================
::  MODULE DEFINITIONS
:: ===============================================================

:MODULE_PROCESS_KILL
echo [1/11] Vaporizing Active Witnesses...
set "PLIST=chrome.exe msedge.exe brave.exe firefox.exe opera.exe Discord.exe WhatsApp.exe Telegram.exe explorer.exe"
for %%P in (%PLIST%) do (
    taskkill /F /IM %%P /T
    if !errorlevel! equ 0 echo [~] %%P: TERMINATED
)
echo.
goto :eof

:MODULE_PERSONAL_DATA
echo [2/11] Vaporizing Personal Stash...
:: Use PowerShell to resolve real paths (handling OneDrive/Redirection)
for /f "usebackq delims=" %%F in (`powershell -NoProfile -Command "foreach($n in 'Desktop','MyDocuments','MyPictures','MyVideos','MyMusic'){[Environment]::GetFolderPath($n)};$env:USERPROFILE+'\Downloads'"`) do (
    if exist "%%F\" (
        echo [~] Shredding %%F...
        "!SDEL!" -p 3 -s -q "%%F\*"
        echo [✓] %%F: VAPORIZED
    )
)
echo.
goto :eof

:MODULE_BROWSER_DATA
echo [3/11] Scorching Browser Footprints...
set "B_PATHS="%LocalAppData%\Google\Chrome\User Data\*" "%LocalAppData%\Microsoft\Edge\User Data\*" "%LocalAppData%\BraveSoftware\Brave-Browser\User Data\*""
for %%P in (%B_PATHS%) do (
    if exist %%P (
        "!SDEL!" -p 3 -s -q %%P
        echo [✓] Browser Path Cleansed: %%P
    )
)
echo.
goto :eof

:MODULE_COM_APPS
echo [4/11] Scorching Comms History...
if exist "%AppData%\Telegram Desktop\" "!SDEL!" -p 3 -s -q "%AppData%\Telegram Desktop\*"
if exist "%AppData%\discord\" "!SDEL!" -p 3 -s -q "%AppData%\discord\*"
echo [✓] Comms: SCRAMBLED
echo.
goto :eof

:MODULE_EVENT_LOGS
echo [5/11] Flattening Event Logs (Timeline Eraser)...
for /F "tokens=*" %%G in ('wevtutil.exe el') do (
    wevtutil.exe cl "%%G"
)
echo [✓] Event Logs: FLATTENED
echo.
goto :eof

:MODULE_REGISTRY
echo [6/11] Purging Registry Echoes...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
echo [✓] Registry Trackers: PURGED
echo.
goto :eof

:MODULE_SHELL_HISTORY
echo [7/11] Wiping Shell Memory...
if exist "%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
    "!SDEL!" -p 3 -q "%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
doskey /reinstall
echo [✓] Shell History: SILENCED
echo.
goto :eof

:MODULE_TEMP_DATA
echo [8/11] Draining System Buffers...
"!SDEL!" -p 1 -q "%temp%\*"
"!SDEL!" -p 1 -q "%systemroot%\Temp\*"
"!SDEL!" -p 1 -q "%systemroot%\Prefetch\*"
echo [✓] Temp Caches: DRAINED
echo.
goto :eof

:MODULE_RECYCLE_CLIPBOARD
echo [9/11] Final Pocket Cleanup...
echo off | clip
"!SDEL!" -p 3 -s -q "$Recycle.Bin"
echo [✓] Recycle/Clipboard: WIPED
echo.
goto :eof

:MODULE_MFT_FILLER
echo [10/11] Burying MFT Evidence (Filenames Overwrite)...
mkdir %temp%\void_fill
for /L %%i in (1,1,1000) do (echo ghost > %temp%\void_fill\%%i.tmp)
"!SDEL!" -p 1 -q %temp%\void_fill\*.tmp
rmdir /s /q %temp%\void_fill
echo [✓] MFT: OBSCURED
echo.
goto :eof

:MODULE_FREE_SPACE
echo [11/11] Unleashing the Void (Free Space Sanitization)...
"!SDEL!" -z %systemdrive%
echo [✓] Free Space: SANITIZED
echo.
goto :eof

:: =================== FINALIZATION ===================

:COMPLETION
cls
echo ===============================================================
echo   MISSION COMPLETE. YOU ARE NOW A GHOST.
echo ===============================================================
echo [1] REBOOT (Clear RAM)  [2] SHUTDOWN  [3] SELF-DESTRUCT & EXIT
echo.
echo Press any key to select...
pause

choice /c 123 /n /t 20 /d 3
if %errorlevel% equ 3 goto :SELF_DESTRUCT
if %errorlevel% equ 2 shutdown /s /t 5 /f
if %errorlevel% equ 1 shutdown /r /t 5 /f

:SELF_DESTRUCT
echo [~] Erasing script evidence...
echo [~] Press any key to vanish...
pause
start /b "" cmd /c del "%~f0"&exit
