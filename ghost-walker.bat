@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul

:: ===============================================================
::  PROJECT: GHOST-WALKER // VOID PROTOCOL v3.0
::  Coded by: Falken Fujimaru [The Digital Phantom]
::  Enhanced by: AI Assistant
::  License: Shadow Protocol // Vanishing Act
:: ===============================================================

title GHOST-WALKER v3.0 // SHADOW PROTOCOL
color 0A
mode con: cols=100 lines=45

:: =================== INITIALIZATION ===================
set "VERSION=3.0"
set "SCRIPT_NAME=%~nx0"
set "SCRIPT_PATH=%~f0"
set "START_TIME=%time%"
set "LOG_FILE=%temp%\ghostwalker_%random%.log"
set "ERROR_COUNT=0"
set "SUCCESS_COUNT=0"
set "TOTAL_OPERATIONS=0"

:: =================== LOGGING SYSTEM ===================
:LOG
set "LOG_TIMESTAMP=[!date! !time:~0,8!]"
echo !LOG_TIMESTAMP! %* >> "%LOG_FILE%"
echo !LOG_TIMESTAMP! [~] %*
exit /b

:: =================== VISUAL ELEMENTS ===================
:HEADER
cls
echo.
echo =======================================================================================================
echo    ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██╗    ██╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗ 
echo    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██║    ██║██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
echo    ██║  ███╗███████║██║   ██║███████╗   ██║       ██║ █╗ ██║███████║██║     █████╔╝ █████╗  ██████╔╝
echo    ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██║███╗██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
echo    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ╚███╔███╔╝██║  ██║███████╗██║  ██╗███████╗██║  ██║
echo     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
echo =======================================================================================================
echo                ULTIMATE TRACE VAPORIZER v!VERSION!
echo            [ System Sterilization Suite - No Trace Left ]
echo =======================================================================================================
echo.
echo    Crafted by 乍丹し片ヨ几　乍凵勹工冊丹尺凵
echo    Japanese Indonesian Ethical Hacker
echo    Breaking Codes, Not Hearts: A Cybersecurity Journey Fueled by Love.
echo.
echo =======================================================================================================
echo.
call :LOG "=== GHOST-WALKER v!VERSION! INITIALIZATION ==="
call :LOG "Start Time: !date! !START_TIME!"
call :LOG "User: %USERNAME%@%COMPUTERNAME%"
call :LOG "Session ID: %SESSIONNAME%"
exit /b

:: =================== MAIN EXECUTION ===================
call :HEADER

:: ---------- PRIVILEGE CHECK ----------
call :LOG "Checking privilege clearance..."
net session >nul 2>&1
if not %errorlevel%==0 (
    call :LOG "Access Denied. Need God-Mode clearance."
    echo.
    echo [~] [WARNING] ACCESS DENIED
    echo [~] I need God-Mode permissions to access the void.
    echo [~] Elevating to shadow clearance...
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList 'silent'"
    call :LOG "Relaunching with elevated privileges"
    timeout /t 3 /nobreak >nul
    exit /b 1
)
call :LOG "Privilege check PASSED - Running with admin rights"
echo [✓] God-Mode: ACTIVATED
echo.

:: ---------- SDELETE VALIDATION ----------
call :LOG "Validating SDelete existence..."
set "SDEL="
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%sdelete64.exe" set "SDEL=%SCRIPT_DIR%sdelete64.exe"
if not defined SDEL if exist "%SCRIPT_DIR%sdelete.exe" set "SDEL=%SCRIPT_DIR%sdelete.exe"

if not defined SDEL (
    call :LOG "SDelete not found locally, downloading..."
    echo [~] SDelete not in local cache. Fetching from Sysinternals...
    echo [~] Contacting the void network... (this may take a moment)
    
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "$ProgressPreference = 'SilentlyContinue'; ^
         $temp = $env:TEMP; ^
         $zip = Join-Path $temp 'SDelete.zip'; ^
         try { ^
             Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing; ^
             if (Test-Path $zip) { ^
                 Expand-Archive -Path $zip -DestinationPath '%SCRIPT_DIR%' -Force; ^
                 Remove-Item $zip -Force; ^
                 Write-Host '[✓] SDelete acquired from the void' -ForegroundColor Green; ^
             } ^
         } catch { ^
             Write-Host '[!] Network unreachable' -ForegroundColor Red; ^
         }"
    
    if exist "%SCRIPT_DIR%sdelete64.exe" set "SDEL=%SCRIPT_DIR%sdelete64.exe"
    if not defined SDEL if exist "%SCRIPT_DIR%sdelete.exe" set "SDEL=%SCRIPT_DIR%sdelete.exe"
)

if not exist "%SDEL%" (
    call :LOG "ERROR: SDelete download failed"
    echo.
    echo [✗] CRITICAL ERROR
    echo [✗] The shredder (SDelete) failed to materialize.
    echo [✗] Possible causes:
    echo [✗]   1. Network connection severed
    echo [✗]   2. Sysinternals portal unreachable
    echo [✗]   3. Security protocols blocking download
    echo.
    echo [~] Manual option: Place sdelete.exe/sdelete64.exe in script directory.
    echo.
    pause
    exit /b 1
)

"%SDEL%" -accepteula >nul 2>&1
call :LOG "SDelete validated and accepted EULA"
echo [✓] Void Engine: ONLINE (SDelete v!SDEL_VERSION!)
echo.

:: ---------- WARNING MESSAGE ----------
echo ===============================================================
echo                    [ FINAL WARNING ]
echo ===============================================================
echo [!] YOU ARE ABOUT TO INITIATE GHOST PROTOCOL
echo [!] THIS ACTION IS:
echo [!]   - IRREVERSIBLE
echo [!]   - COMPREHENSIVE
echo [!]   - UNSAVABLE
echo.
echo [~] The following will be VAPORIZED:
echo [~]   • Personal files & documents
echo [~]   • Browser histories & caches
echo [~]   • System logs & event trails
echo [~]   • Registry footprints
echo [~]   • Temporary data shadows
echo [~]   • Free space ghosts
echo.
set /p CONFIRM="[?] Type 'GHOST' to proceed, anything else to abort: "
if /i not "!CONFIRM!"=="GHOST" (
    call :LOG "User aborted operation"
    echo.
    echo [~] Operation ABORTED by user.
    echo [~] System remains untouched.
    timeout /t 3 /nobreak >nul
    exit /b 0
)

call :LOG "User confirmed destruction with keyword: GHOST"
echo.
echo [~] Ghost Protocol: ENGAGED
echo [~] Initializing sterilization sequence...
echo.

:: =================== MODULES ===================

:: ---------- MODULE 1: PROCESS TERMINATION ----------
:MODULE_PROCESS_KILL
call :LOG "=== MODULE 1: PROCESS TERMINATION ==="
echo [1/10] Terminating witness processes...
echo [~] Silencing digital witnesses...

set "PROCESS_LIST=chrome.exe msedge.exe brave.exe firefox.exe opera.exe Discord.exe DiscordCanary.exe DiscordPTB.exe WhatsApp.exe Telegram.exe explorer.exe OneDrive.exe outlook.exe steam.exe battle.net.exe"
set "KILL_COUNT=0"

for %%P in (%PROCESS_LIST%) do (
    tasklist /FI "IMAGENAME eq %%P" 2>nul | find /I "%%P" >nul
    if !errorlevel! equ 0 (
        call :LOG "Terminating process: %%P"
        taskkill /F /IM %%P /T >nul 2>&1
        if !errorlevel! equ 0 (
            set /a "KILL_COUNT+=1"
            echo [~] Process %%P: TERMINATED
        ) else (
            echo [~] Process %%P: RESISTANT (continuing...)
        )
    )
)

call :LOG "Terminated !KILL_COUNT! processes"
echo [✓] !KILL_COUNT! witnesses silenced
echo.
exit /b

:: ---------- MODULE 2: PERSONAL DATA ERASURE ----------
:MODULE_PERSONAL_DATA
call :LOG "=== MODULE 2: PERSONAL DATA ERASURE ==="
echo [2/10] Vaporizing personal vaults...
echo [~] Zeroing personal data sectors...

set "PERSONAL_FOLDERS=Downloads Documents Pictures Videos Music Desktop"
set "ERASED_COUNT=0"

for %%F in (%PERSONAL_FOLDERS%) do (
    if exist "%USERPROFILE%\%%F\" (
        call :LOG "Shredding folder: %%F"
        echo [~] Shredding %%F... 
        
        :: Show progress animation
        echo | set /p "=    ["
        for /l %%i in (1,1,20) do (
            ping -n 1 -w 50 127.0.0.1 >nul
            echo | set /p "=#"
        )
        echo | set /p "=]"
        
        "%SDEL%" -p 3 -s "%USERPROFILE%\%%F\*" >nul 2>&1
        if !errorlevel! equ 0 (
            set /a "ERASED_COUNT+=1"
            echo [✓] %%F: VAPORIZED
            call :LOG "Folder vaporized: %%F"
        ) else (
            echo [~] %%F: PARTIAL (some files locked)
            call :LOG "Partial vaporization: %%F"
        )
    ) else (
        echo [~] %%F: NOT FOUND (already void)
    )
)

call :LOG "Vaporized !ERASED_COUNT! personal folders"
echo [✓] Personal vaults: PURGED
echo.
exit /b

:: ---------- MODULE 3: BROWSER DATA DESTRUCTION ----------
:MODULE_BROWSER_DATA
call :LOG "=== MODULE 3: BROWSER DATA DESTRUCTION ==="
echo [3/10] Incinerating browser footprints...
echo [~] Select purge intensity:"

echo     [A] APOCALYPSE - Everything burns
echo     [S] SURGICAL  - Select targets
echo     [N] NEGATE    - Skip browser purge
echo.

choice /c ASN /n /t 10 /d A
set "PURGE_MODE=!errorlevel!"
if !PURGE_MODE! equ 3 goto :BROWSER_SKIP
if !PURGE_MODE! equ 2 goto :BROWSER_SELECTIVE

:: Apocalypse Mode (Default)
:BROWSER_APOCALYPSE
call :LOG "Browser purge mode: APOCALYPSE"
echo [~] APOCALYPSE MODE: All browser data will burn

set "BROWSER_PATHS="
set "BROWSER_PATHS=!BROWSER_PATHS! "%LocalAppData%\Google\Chrome\User Data\*""
set "BROWSER_PATHS=!BROWSER_PATHS! "%LocalAppData%\Microsoft\Edge\User Data\*""
set "BROWSER_PATHS=!BROWSER_PATHS! "%LocalAppData%\BraveSoftware\Brave-Browser\User Data\*""
set "BROWSER_PATHS=!BROWSER_PATHS! "%AppData%\Mozilla\Firefox\Profiles\*""
set "BROWSER_PATHS=!BROWSER_PATHS! "%AppData%\Opera Software\Opera Stable\*""
set "BROWSER_PATHS=!BROWSER_PATHS! "%LocalAppData%\Opera Software\Opera Stable\*""

goto :BROWSER_EXECUTE

:BROWSER_SELECTIVE
call :LOG "Browser purge mode: SELECTIVE"
echo [~] SURGICAL STRIKE: Select targets to eliminate

set "BROWSER_PATHS="
set "TARGETS=0"

echo [?] Chrome shadows? [Y/N]
choice /c YN /n /t 5 /d Y
if !errorlevel! equ 1 (
    set "BROWSER_PATHS=!BROWSER_PATHS! "%LocalAppData%\Google\Chrome\User Data\*""
    set /a "TARGETS+=1"
)

echo [?] Edge fingerprints? [Y/N]
choice /c YN /n /t 5 /d Y
if !errorlevel! equ 1 (
    set "BROWSER_PATHS=!BROWSER_PATHS! "%LocalAppData%\Microsoft\Edge\User Data\*""
    set /a "TARGETS+=1"
)

echo [?] Firefox ghosts? [Y/N]
choice /c YN /n /t 5 /d Y
if !errorlevel! equ 1 (
    set "BROWSER_PATHS=!BROWSER_PATHS! "%AppData%\Mozilla\Firefox\Profiles\*""
    set /a "TARGETS+=1"
)

echo [?] Brave trails? [Y/N]
choice /c YN /n /t 5 /d Y
if !errorlevel! equ 1 (
    set "BROWSER_PATHS=!BROWSER_PATHS! "%LocalAppData%\BraveSoftware\Brave-Browser\User Data\*""
    set /a "TARGETS+=1"
)

echo [~] !TARGETS! targets acquired
goto :BROWSER_EXECUTE

:BROWSER_EXECUTE
set "BROWSER_COUNT=0"
for %%P in (!BROWSER_PATHS!) do (
    if exist %%~P (
        call :LOG "Shredding browser path: %%P"
        echo [~] Burning path...
        "%SDEL%" -p 3 -s %%P >nul 2>&1
        if !errorlevel! equ 0 (
            set /a "BROWSER_COUNT+=1"
            echo [✓] Path incinerated
            call :LOG "Browser path destroyed"
        )
    )
)

call :LOG "Destroyed !BROWSER_COUNT! browser data paths"
echo [✓] Browser histories: INCINERATED
goto :BROWSER_END

:BROWSER_SKIP
call :LOG "Browser purge skipped by user"
echo [~] Browser purge: NEGATED
:BROWSER_END
echo.
exit /b

:: ---------- MODULE 4: COMMUNICATION APP CLEANUP ----------
:MODULE_COM_APPS
call :LOG "=== MODULE 4: COMMUNICATION APP CLEANUP ==="
echo [4/10] Erasing communication trails...
echo [~] Scrambling digital conversations...

set "COM_APPS=0"
set "COM_PATHS="

:: Discord
if exist "%AppData%\discord\" (
    set "COM_PATHS=!COM_PATHS! "%AppData%\discord\*""
    set /a "COM_APPS+=1"
)
if exist "%AppData%\discordcanary\" (
    set "COM_PATHS=!COM_PATHS! "%AppData%\discordcanary\*""
    set /a "COM_APPS+=1"
)
if exist "%AppData%\discordptb\" (
    set "COM_PATHS=!COM_PATHS! "%AppData%\discordptb\*""
    set /a "COM_APPS+=1"
)

:: Telegram
if exist "%AppData%\Telegram Desktop\" (
    set "COM_PATHS=!COM_PATHS! "%AppData%\Telegram Desktop\*""
    set /a "COM_APPS+=1"
)

:: WhatsApp
if exist "%LocalAppData%\Packages\5319275A.WhatsAppDesktop_*\" (
    for /d %%D in ("%LocalAppData%\Packages\5319275A.WhatsAppDesktop_*") do (
        set "COM_PATHS=!COM_PATHS! "%%D\*""
        set /a "COM_APPS+=1"
    )
)

if !COM_APPS! gtr 0 (
    echo [~] Found !COM_APPS! communication apps
    for %%P in (!COM_PATHS!) do (
        call :LOG "Cleaning coms: %%P"
        "%SDEL%" -p 3 -s %%P >nul 2>&1
        echo [~] Comms scrambled...
    )
    echo [✓] Communication trails: SCRAMBLED
) else (
    echo [~] No communication apps detected
)
echo.
exit /b

:: ---------- MODULE 5: EVENT LOG ANNIHILATION ----------
:MODULE_EVENT_LOGS
call :LOG "=== MODULE 5: EVENT LOG ANNIHILATION ==="
echo [5/10] Flattening event logs...
echo [~] Rewriting digital history...

set "LOG_COUNT=0"
for /F "tokens=*" %%G in ('wevtutil.exe el') do (
    set /a "LOG_COUNT+=1"
    echo | set /p "=."
    wevtutil.exe cl "%%G" >nul 2>&1
    call :LOG "Cleared event log: %%G"
)

echo.
echo [✓] !LOG_COUNT! event logs: FLATTENED
call :LOG "Cleared !LOG_COUNT! event logs"
echo.
exit /b

:: ---------- MODULE 6: REGISTRY PURGE ----------
:MODULE_REGISTRY
call :LOG "=== MODULE 6: REGISTRY PURGE ==="
echo [6/10] Purging registry echoes...
echo [~] Deleting digital breadcrumbs...

set "REG_KEYS="
set "REG_KEYS=!REG_KEYS! "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist""
set "REG_KEYS=!REG_KEYS! "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU""
set "REG_KEYS=!REG_KEYS! "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags""
set "REG_KEYS=!REG_KEYS! "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU""
set "REG_KEYS=!REG_KEYS! "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths""
set "REG_KEYS=!REG_KEYS! "HKCU\Software\Microsoft\Terminal Server Client\Servers""
set "REG_KEYS=!REG_KEYS! "HKCU\Software\Microsoft\Terminal Server Client\Default""

set "REG_COUNT=0"
for %%K in (!REG_KEYS!) do (
    reg query %%K >nul 2>&1
    if !errorlevel! equ 0 (
        reg delete %%K /f >nul 2>&1
        set /a "REG_COUNT+=1"
        echo [~] Registry key purged
        call :LOG "Deleted registry: %%K"
    )
)

:: Clear RDP credentials
for /f "tokens=2 delims=:" %%H in ('cmdkey /list ^| findstr /I "TERMSRV/"') do (
    set "TARGET=%%H"
    set "TARGET=!TARGET: =!"
    if defined TARGET (
        cmdkey /delete:!TARGET! >nul 2>&1
        set /a "REG_COUNT+=1"
        call :LOG "Deleted RDP credential: !TARGET!"
    )
)

echo [✓] !REG_COUNT! registry entries: PURGED
echo.
exit /b

:: ---------- MODULE 7: SHELL HISTORY CLEANSE ----------
:MODULE_SHELL_HISTORY
call :LOG "=== MODULE 7: SHELL HISTORY CLEANSE ==="
echo [7/10] Muting command echoes...
echo [~] Erasing shell memory...

set "SHELL_CLEANED=0"

:: PowerShell History
if exist "%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
    "%SDEL%" -p 3 "%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" >nul 2>&1
    set /a "SHELL_CLEANED+=1"
    call :LOG "Cleared PowerShell history"
)

:: CMD History (Windows 10+)
doskey /reinstall >nul 2>&1
if !errorlevel! equ 0 (
    set /a "SHELL_CLEANED+=1"
    call :LOG "Cleared CMD history"
)

:: Bash History (WSL)
if exist "%USERPROFILE%\.bash_history" (
    "%SDEL%" -p 3 "%USERPROFILE%\.bash_history" >nul 2>&1
    set /a "SHELL_CLEANED+=1"
    call :LOG "Cleared bash history"
)

echo [✓] !SHELL_CLEANED! shell histories: SILENCED
echo.
exit /b

:: ---------- MODULE 8: TEMPORARY DATA PURGE ----------
:MODULE_TEMP_DATA
call :LOG "=== MODULE 8: TEMPORARY DATA PURGE ==="
echo [8/10] Draining temporary caches...
echo [~] Flushing system buffers...

set "TEMP_PATHS="
set "TEMP_PATHS=!TEMP_PATHS! "%temp%\*""
set "TEMP_PATHS=!TEMP_PATHS! "%systemroot%\Temp\*""
set "TEMP_PATHS=!TEMP_PATHS! "%LocalAppData%\Temp\*""
set "TEMP_PATHS=!TEMP_PATHS! "%systemroot%\Prefetch\*""

if exist "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db" (
    set "TEMP_PATHS=!TEMP_PATHS! "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db""
)

set "TEMP_COUNT=0"
for %%P in (!TEMP_PATHS!) do (
    if exist %%~P (
        "%SDEL%" -p 1 %%P >nul 2>&1
        set /a "TEMP_COUNT+=1"
        echo | set /p "=#"
        call :LOG "Cleared temp: %%P"
    )
)

echo.
echo [✓] !TEMP_COUNT! temp caches: DRAINED
echo.
exit /b

:: ---------- MODULE 9: RECYCLE & CLIPBOARD CLEAR ----------
:MODULE_RECYCLE_CLIPBOARD
call :LOG "=== MODULE 9: RECYCLE & CLIPBOARD CLEAR ==="
echo [9/10] Emptying recycle bins...
echo [~] Final pocket cleanup...

:: Recycle Bin
if exist "%systemdrive%\$Recycle.Bin" (
    echo [~] Shredding recycle bin...
    "%SDEL%" -p 2 -s "%systemdrive%\$Recycle.Bin" >nul 2>&1
    call :LOG "Cleared recycle bin"
    echo [✓] Recycle bin: INCINERATED
) else (
    echo [~] Recycle bin: ALREADY VOID
)

:: Clipboard
echo off | clip
if exist "%LocalAppData%\Microsoft\Windows\Clipboard\" (
    "%SDEL%" -p 1 "%LocalAppData%\Microsoft\Windows\Clipboard\*" >nul 2>&1
    call :LOG "Cleared clipboard cache"
    echo [✓] Clipboard: WIPED"
)

echo.
exit /b

:: ---------- MODULE 10: FREE SPACE SANITIZATION ----------
:MODULE_FREE_SPACE
call :LOG "=== MODULE 10: FREE SPACE SANITIZATION ==="
echo [10/10] Sanitizing free space...
echo [~] This may take some time. Overwriting empty space with void data..."
echo.

echo [~] System drive (%systemdrive%): Initializing...
"%SDEL%" -z %systemdrive%
call :LOG "Sanitized free space on %systemdrive%"
echo [✓] System drive free space: SANITIZED

:: Additional drives
set "DRIVE_LIST="
for /f "skip=1 tokens=1" %%D in ('wmic logicaldisk where "drivetype=3" get name') do (
    if not "%%D"=="" if /I not "%%D"=="%systemdrive%" (
        set "DRIVE_LIST=!DRIVE_LIST! %%D"
    )
)

if defined DRIVE_LIST (
    echo.
    echo [~] Additional drives detected:!DRIVE_LIST!
    echo [?] Sanitize free space on additional drives? [Y/N]
    choice /c YN /n /t 10 /d N
    if !errorlevel! equ 1 (
        for %%D in (!DRIVE_LIST!) do (
            echo [~] Drive %%D: Sanitizing...
            "%SDEL%" -z %%D
            call :LOG "Sanitized free space on %%D"
            echo [✓] Drive %%D free space: CLEANSED
        )
    ) else (
        echo [~] Additional drives: SKIPPED
    )
)

echo.
exit /b

:: =================== EXECUTE MODULES ===================
call :MODULE_PROCESS_KILL
call :MODULE_PERSONAL_DATA
call :MODULE_BROWSER_DATA
call :MODULE_COM_APPS
call :MODULE_EVENT_LOGS
call :MODULE_REGISTRY
call :MODULE_SHELL_HISTORY
call :MODULE_TEMP_DATA
call :MODULE_RECYCLE_CLIPBOARD
call :MODULE_FREE_SPACE

:: =================== FINALIZATION ===================
:COMPLETION
set "END_TIME=%time%"
call :LOG "=== OPERATION COMPLETE ==="
call :LOG "Start: !START_TIME! | End: !END_TIME!"

cls
echo.
echo ===============================================================
echo                    OPERATION COMPLETE
echo ===============================================================
echo.
echo [✓] SYSTEM STERILIZATION: SUCCESSFUL
echo [✓] FORENSIC FOOTPRINT: VAPORIZED
echo [✓] DIGITAL GHOSTING: COMPLETE
echo.
echo [!] Your system is now a digital ghost:
echo [!] • No personal traces remain
echo [!] • No browser histories exist
echo [!] • No system logs contain evidence
echo [!] • No registry echoes persist
echo [!] • Free space contains only void
echo.
echo ===============================================================
echo           GHOST-WALKER v!VERSION! - MISSION COMPLETE
echo ===============================================================
echo.

:: ---------- FINAL ACTIONS ----------
echo [~] Final phase - Choose exit strategy:
echo.
echo     [1] REBOOT SYSTEM - Clear RAM shadows (Recommended)
echo     [2] FULL SHUTDOWN - Complete blackout
echo     [3] STEALTH EXIT  - Return to desktop
echo     [4] SELF-DESTRUCT - Erase script and evidence
echo.

choice /c 1234 /n /t 30 /d 1
set "EXIT_MODE=!errorlevel!"

if !EXIT_MODE! equ 4 goto :SELF_DESTRUCT
if !EXIT_MODE! equ 3 goto :STEALTH_EXIT
if !EXIT_MODE! equ 2 goto :SHUTDOWN
if !EXIT_MODE! equ 1 goto :REBOOT

:REBOOT
call :LOG "User selected: REBOOT"
echo [~] Initializing system reboot...
echo [~] RAM shadows will be cleared on restart...
start /b "" cmd /c del "%~f0"&shutdown /r /t 10 /c "Ghost-Walker: System sterilization complete. Rebooting..." /f
exit /b

:SHUTDOWN
call :LOG "User selected: SHUTDOWN"
echo [~] Initializing full shutdown...
echo [~] System going dark...
start /b "" cmd /c del "%~f0"&shutdown /s /t 10 /c "Ghost-Walker: Sterilization complete. Shutting down..." /f
exit /b

:STEALTH_EXIT
call :LOG "User selected: STEALTH_EXIT"
echo [~] Restoring desktop...
start explorer.exe >nul 2>&1
echo [~] Returning to stealth mode...
timeout /t 3 /nobreak >nul
goto :SELF_DESTRUCT

:SELF_DESTRUCT
call :LOG "Initiating self-destruct sequence"
echo [~] Activating self-destruct protocol...
echo [~] Erasing execution traces...

:: Delete log file
if exist "%LOG_FILE%" (
    "%SDEL%" -p 3 "%LOG_FILE%" >nul 2>&1
)

:: Delete script itself with multiple passes
echo [~] Shredding Ghost-Walker script...
for /l %%i in (1,1,3) do (
    echo. > "%~f0"
)
del "%~f0" >nul 2>&1

echo [✓] All traces eliminated
echo [✓] Ghost-Walker has vanished
echo.
echo ===============================================================
echo          YOU ARE NOW A GHOST IN THE MACHINE
echo ===============================================================
echo.

:: Final pause before exit
timeout /t 5 /nobreak >nul
exit /b 0

:: =================== END OF SCRIPT ===================