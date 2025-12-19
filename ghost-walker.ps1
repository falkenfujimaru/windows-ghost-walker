$ErrorActionPreference = 'Continue'
$version = "3.0"

# =================== VISUAL ELEMENTS ===================
function Show-Header {
    Clear-Host
    Write-Host ""
    Write-Host "=======================================================================================================" -ForegroundColor Green
    Write-Host "   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██╗    ██╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗ " -ForegroundColor Green
    Write-Host "   ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██║    ██║██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗" -ForegroundColor Green
    Write-Host "   ██║  ███╗███████║██║   ██║███████╗   ██║       ██║ █╗ ██║███████║██║     █████╔╝ █████╗  ██████╔╝" -ForegroundColor Green
    Write-Host "   ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██║███╗██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗" -ForegroundColor Green
    Write-Host "   ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ╚███╔███╔╝██║  ██║███████╗██║  ██╗███████╗██║  ██║" -ForegroundColor Green
    Write-Host "    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝" -ForegroundColor Green
    Write-Host "=======================================================================================================" -ForegroundColor Green
    Write-Host "                ULTIMATE TRACE VAPORIZER v$version" -ForegroundColor Green
    Write-Host "            [ System Sterilization Suite - No Trace Left ]" -ForegroundColor Green
    Write-Host "=======================================================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "   Crafted by 乍丹し片ヨ几　乍凵勹工冊丹尺凵" -ForegroundColor Cyan
    Write-Host "   Japanese Indonesian Ethical Hacker" -ForegroundColor Cyan
    Write-Host "   Breaking Codes, Not Hearts: A Cybersecurity Journey Fueled by Love." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "=======================================================================================================" -ForegroundColor Green
    Write-Host ""
}

Show-Header

# =================== PRIVILEGE CHECK ===================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[~] [WARNING] ACCESS DENIED" -ForegroundColor Yellow
    Write-Host "[~] I need God-Mode permissions to access the void." -ForegroundColor Yellow
    Write-Host "[~] Elevating to shadow clearance..." -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 2
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
Write-Host "[✓] God-Mode: ACTIVATED" -ForegroundColor Green
Write-Host ""

# =================== SDELETE VALIDATION ===================
$arch64 = [Environment]::Is64BitOperatingSystem
$sdelName = if ($arch64) { 'sdelete64.exe' } else { 'sdelete.exe' }
$SDEL = Join-Path $PSScriptRoot $sdelName

# Check local existence first
if (!(Test-Path $SDEL)) {
    # Fallback check for alternate version
    $altName = if ($arch64) { 'sdelete.exe' } else { 'sdelete64.exe' }
    $altPath = Join-Path $PSScriptRoot $altName
    if (Test-Path $altPath) { $SDEL = $altPath }
}

if (!(Test-Path $SDEL)) {
    Write-Host "[~] SDelete not in local cache. Fetching from Sysinternals..." -ForegroundColor Cyan
    Write-Host "[~] Contacting the void network... (this may take a moment)" -ForegroundColor Cyan
    try {
        $zip = Join-Path $env:TEMP 'SDelete.zip'
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $PSScriptRoot -Force
        Remove-Item $zip -Force
        Write-Host "[✓] SDelete acquired from the void" -ForegroundColor Green
    } catch {
        Write-Host "[!] Error downloading SDelete: $_" -ForegroundColor Red
    }
    
    # Re-check after download
    if (Test-Path (Join-Path $PSScriptRoot 'sdelete64.exe')) { $SDEL = Join-Path $PSScriptRoot 'sdelete64.exe' }
    elseif (Test-Path (Join-Path $PSScriptRoot 'sdelete.exe')) { $SDEL = Join-Path $PSScriptRoot 'sdelete.exe' }
}

if (!(Test-Path $SDEL)) {
    Write-Host ""
    Write-Host "[✗] CRITICAL ERROR" -ForegroundColor Red
    Write-Host "[✗] The shredder (SDelete) failed to materialize." -ForegroundColor Red
    Write-Host "[✗] Possible causes:" -ForegroundColor Red
    Write-Host "[✗]   1. Network connection severed" -ForegroundColor Red
    Write-Host "[✗]   2. Sysinternals portal unreachable" -ForegroundColor Red
    Write-Host "[✗]   3. Security protocols blocking download" -ForegroundColor Red
    Write-Host ""
    Write-Host "[~] Manual option: Place sdelete.exe/sdelete64.exe in script directory." -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit 1
}

Start-Process -FilePath $SDEL -ArgumentList "-accepteula" -NoNewWindow -Wait
Write-Host "[✓] Void Engine: ONLINE ($($SDEL | Split-Path -Leaf))" -ForegroundColor Green
Write-Host ""

# =================== WARNING MESSAGE ===================
Write-Host "===============================================================" -ForegroundColor Red
Write-Host "                    [ FINAL WARNING ]" -ForegroundColor Red
Write-Host "===============================================================" -ForegroundColor Red
Write-Host "[!] YOU ARE ABOUT TO INITIATE GHOST PROTOCOL" -ForegroundColor Red
Write-Host "[!] THIS ACTION IS:" -ForegroundColor Red
Write-Host "[!]   - IRREVERSIBLE" -ForegroundColor Red
Write-Host "[!]   - COMPREHENSIVE" -ForegroundColor Red
Write-Host "[!]   - UNSAVABLE" -ForegroundColor Red
Write-Host ""
Write-Host "[~] The following will be VAPORIZED:" -ForegroundColor Yellow
Write-Host "[~]   • Personal files & documents" -ForegroundColor Yellow
Write-Host "[~]   • Browser histories & caches" -ForegroundColor Yellow
Write-Host "[~]   • System logs & event trails" -ForegroundColor Yellow
Write-Host "[~]   • Registry footprints" -ForegroundColor Yellow
Write-Host "[~]   • Temporary data shadows" -ForegroundColor Yellow
Write-Host "[~]   • Free space ghosts" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "[?] Type 'GHOST' to proceed, anything else to abort"
if ($confirm -ne 'GHOST') {
    Write-Host ""
    Write-Host "[~] Operation ABORTED by user." -ForegroundColor Yellow
    Write-Host "[~] System remains untouched." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    exit 0
}

Write-Host ""
Write-Host "[~] Ghost Protocol: ENGAGED" -ForegroundColor Green
Write-Host "[~] Initializing sterilization sequence..." -ForegroundColor Green
Write-Host ""

# =================== MODULE 1: PROCESS TERMINATION ===================
Write-Host "=== MODULE 1: PROCESS TERMINATION ===" -ForegroundColor Cyan
Write-Host "[1/10] Terminating witness processes..."
Write-Host "[~] Silencing digital witnesses..."
$processes = "chrome","msedge","brave","firefox","opera","Discord","DiscordCanary","DiscordPTB","WhatsApp","Telegram","explorer","OneDrive","outlook","steam","battle.net"
$killCount = 0
foreach ($proc in $processes) {
    if (Get-Process -Name $proc -ErrorAction SilentlyContinue) {
        Stop-Process -Name $proc -Force -ErrorAction Continue
        $killCount++
        Write-Host "[~] Process $proc : TERMINATED"
    }
}
Write-Host "[✓] $killCount witnesses silenced" -ForegroundColor Green
Write-Host ""

# =================== MODULE 2: PERSONAL DATA ERASURE ===================
Write-Host "=== MODULE 2: PERSONAL DATA ERASURE ===" -ForegroundColor Cyan
Write-Host "[2/10] Vaporizing personal vaults..."
Write-Host "[~] Zeroing personal data sectors..."

function Wipe-Path($path, $name) {
    if (Test-Path $path) {
        Write-Host "[~] Shredding $name..."
        & $SDEL -p 3 -s $path
        Write-Host "[✓] $name: VAPORIZED" -ForegroundColor Green
    } else {
        Write-Host "[~] $name: NOT FOUND (already void)"
    }
}

Wipe-Path "$env:USERPROFILE\Downloads\*" "Downloads"
Wipe-Path "$env:USERPROFILE\Documents\*" "Documents"
Wipe-Path "$env:USERPROFILE\Pictures\*" "Pictures"
Wipe-Path "$env:USERPROFILE\Videos\*" "Videos"
Wipe-Path "$env:USERPROFILE\Music\*" "Music"
Wipe-Path "$env:USERPROFILE\Desktop\*" "Desktop"
Write-Host "[✓] Personal vaults: PURGED" -ForegroundColor Green
Write-Host ""

# =================== MODULE 3: BROWSER DATA DESTRUCTION ===================
Write-Host "=== MODULE 3: BROWSER DATA DESTRUCTION ===" -ForegroundColor Cyan
Write-Host "[3/10] Incinerating browser footprints..."
Write-Host "[~] Select purge intensity:"
Write-Host "    [A] APOCALYPSE - Everything burns"
Write-Host "    [S] SURGICAL  - Select targets"
Write-Host "    [N] NEGATE    - Skip browser purge"
Write-Host ""

$purgeMode = Read-Host "Choice [A/S/N] (Default: A)"
if ([string]::IsNullOrWhiteSpace($purgeMode)) { $purgeMode = 'A' }
$purgeMode = $purgeMode.Substring(0,1).ToUpper()

$DO_CHROME=$false;$DO_EDGE=$false;$DO_BRAVE=$false;$DO_FIREFOX=$false;$DO_OPERA=$false

if ($purgeMode -eq 'N') {
    Write-Host "[~] Browser purge: NEGATED" -ForegroundColor Yellow
} else {
    if ($purgeMode -eq 'A') {
        Write-Host "[~] APOCALYPSE MODE: All browser data will burn" -ForegroundColor Red
        $DO_CHROME=$true;$DO_EDGE=$true;$DO_BRAVE=$true;$DO_FIREFOX=$true;$DO_OPERA=$true
    } elseif ($purgeMode -eq 'S') {
        Write-Host "[~] SURGICAL STRIKE: Select targets to eliminate" -ForegroundColor Yellow
        function Ask($q){ $r = Read-Host $q; if ([string]::IsNullOrWhiteSpace($r)) { return $true } else { return $r.Trim().ToUpper().StartsWith('Y') } }
        if (Ask "[?] Chrome shadows? [Y/N]") { $DO_CHROME=$true }
        if (Ask "[?] Edge fingerprints? [Y/N]") { $DO_EDGE=$true }
        if (Ask "[?] Firefox ghosts? [Y/N]") { $DO_FIREFOX=$true }
        if (Ask "[?] Brave trails? [Y/N]") { $DO_BRAVE=$true }
        if (Ask "[?] Opera cache? [Y/N]") { $DO_OPERA=$true }
    }

    if ($DO_CHROME) { Wipe-Path "$env:LocalAppData\Google\Chrome\User Data\*" "Chrome Data" }
    if ($DO_EDGE) { Wipe-Path "$env:LocalAppData\Microsoft\Edge\User Data\*" "Edge Data" }
    if ($DO_BRAVE) { Wipe-Path "$env:LocalAppData\BraveSoftware\Brave-Browser\User Data\*" "Brave Data" }
    if ($DO_FIREFOX) { 
        Wipe-Path "$env:AppData\Mozilla\Firefox\Profiles\*" "Firefox Profiles" 
        Wipe-Path "$env:LocalAppData\Mozilla\Firefox\Profiles\*" "Firefox Local Profiles"
    }
    if ($DO_OPERA) { 
        Wipe-Path "$env:AppData\Opera Software\Opera Stable\*" "Opera Data" 
        Wipe-Path "$env:LocalAppData\Opera Software\Opera Stable\*" "Opera Local Data"
    }
    Write-Host "[✓] Browser histories: INCINERATED" -ForegroundColor Green
}
Write-Host ""

# =================== MODULE 4: COMMUNICATION APP CLEANUP ===================
Write-Host "=== MODULE 4: COMMUNICATION APP CLEANUP ===" -ForegroundColor Cyan
Write-Host "[4/10] Erasing communication trails..."
Write-Host "[~] Scrambling digital conversations..."

Wipe-Path "$env:AppData\discord\*" "Discord Cache"
Wipe-Path "$env:AppData\discordcanary\*" "Discord Canary"
Wipe-Path "$env:AppData\discordptb\*" "Discord PTB"
Wipe-Path "$env:AppData\Telegram Desktop\*" "Telegram Session"
Wipe-Path "$env:LocalAppData\Packages\5319275A.WhatsAppDesktop_*\*" "WhatsApp Desktop"
Wipe-Path "$env:AppData\WhatsApp\*" "WhatsApp Roaming"

Write-Host "[✓] Communication trails: SCRAMBLED" -ForegroundColor Green
Write-Host ""

# =================== MODULE 5: EVENT LOG ANNIHILATION ===================
Write-Host "=== MODULE 5: EVENT LOG ANNIHILATION ===" -ForegroundColor Cyan
Write-Host "[5/10] Flattening event logs..."
Write-Host "[~] Rewriting digital history..."

$logs = Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue
$logCount = 0
foreach ($log in $logs) {
    try {
        wevtutil.exe cl $log.LogName
        $logCount++
        Write-Host -NoNewline "."
    } catch {}
}
Write-Host ""
Write-Host "[✓] $logCount event logs: FLATTENED" -ForegroundColor Green
Write-Host ""

# =================== MODULE 6: REGISTRY PURGE ===================
Write-Host "=== MODULE 6: REGISTRY PURGE ===" -ForegroundColor Cyan
Write-Host "[6/10] Purging registry echoes..."
Write-Host "[~] Deleting digital breadcrumbs..."

$regKeys = @(
    "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    "Registry::HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "Registry::HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    "Registry::HKCU\Software\Microsoft\Terminal Server Client\Servers",
    "Registry::HKCU\Software\Microsoft\Terminal Server Client\Default"
)

foreach ($key in $regKeys) {
    if (Test-Path $key) {
        Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[~] Registry key purged: $key"
    }
}

# RDP Credentials
Write-Host "[~] Removing stored RDP credentials..."
$cmdkeyList = cmdkey /list
foreach($line in $cmdkeyList){ 
    $m=[regex]::Match($line,'TERMSRV\/[^\s]+'); 
    if($m.Success){ 
        cmdkey /delete:$($m.Value); 
        Write-Host ">>> RDP credentials $($m.Value): DELETED." 
    } 
}

Write-Host "[✓] Registry entries: PURGED" -ForegroundColor Green
Write-Host ""

# =================== MODULE 7: SHELL HISTORY CLEANSE ===================
Write-Host "=== MODULE 7: SHELL HISTORY CLEANSE ===" -ForegroundColor Cyan
Write-Host "[7/10] Muting command echoes..."
Write-Host "[~] Erasing shell memory..."

# PowerShell
if (Test-Path "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") {
    & $SDEL -p 3 "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    Write-Host "[~] PowerShell history: VAPORIZED"
}

# Bash (WSL)
if (Test-Path "$env:USERPROFILE\.bash_history") {
    & $SDEL -p 3 "$env:USERPROFILE\.bash_history"
    Write-Host "[~] Bash history: VAPORIZED"
}

Write-Host "[✓] Shell histories: SILENCED" -ForegroundColor Green
Write-Host ""

# =================== MODULE 8: TEMPORARY DATA PURGE ===================
Write-Host "=== MODULE 8: TEMPORARY DATA PURGE ===" -ForegroundColor Cyan
Write-Host "[8/10] Draining temporary caches..."
Write-Host "[~] Flushing system buffers..."

Wipe-Path "$env:TEMP\*" "User Temp"
Wipe-Path "$env:SystemRoot\Temp\*" "Windows Temp"
Wipe-Path "$env:LocalAppData\Temp\*" "Local AppData Temp"
Wipe-Path "$env:SystemRoot\Prefetch\*" "Prefetch"

# Thumbnails
if (Get-ChildItem "$env:LocalAppData\Microsoft\Windows\Explorer" -Filter "thumbcache_*.db" -ErrorAction SilentlyContinue) {
    & $SDEL -p 3 "$env:LocalAppData\Microsoft\Windows\Explorer\thumbcache_*.db"
    Write-Host "[~] Thumbnail caches: VAPORIZED"
}

Write-Host "[✓] Temp caches: DRAINED" -ForegroundColor Green
Write-Host ""

# =================== MODULE 9: RECYCLE & CLIPBOARD CLEAR ===================
Write-Host "=== MODULE 9: RECYCLE & CLIPBOARD CLEAR ===" -ForegroundColor Cyan
Write-Host "[9/10] Emptying recycle bins..."
Write-Host "[~] Final pocket cleanup..."

if (Test-Path "$env:SystemDrive\$Recycle.Bin") {
    Write-Host "[~] Shredding recycle bin..."
    & $SDEL -p 2 -s "$env:SystemDrive\$Recycle.Bin"
    Write-Host "[✓] Recycle bin: INCINERATED" -ForegroundColor Green
}

Set-Clipboard -Value ""
if (Test-Path "$env:LocalAppData\Microsoft\Windows\Clipboard\") {
    & $SDEL -p 1 "$env:LocalAppData\Microsoft\Windows\Clipboard\*"
    Write-Host "[✓] Clipboard: WIPED" -ForegroundColor Green
}
Write-Host ""

# =================== MODULE 10: FREE SPACE SANITIZATION ===================
Write-Host "=== MODULE 10: FREE SPACE SANITIZATION ===" -ForegroundColor Cyan
Write-Host "[10/10] Sanitizing free space..."
Write-Host "[~] This may take some time. Overwriting empty space with void data..."
Write-Host ""

Write-Host "[~] System drive ($env:SystemDrive): Initializing..."
& $SDEL -z $env:SystemDrive
Write-Host "[✓] System drive free space: SANITIZED" -ForegroundColor Green

$fixed = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Name -ne ("$env:SystemDrive" + "\") }
if ($fixed.Count -gt 0) {
    Write-Host ""
    Write-Host "[~] Additional drives detected: $($fixed.Name -join ', ')"
    $sanitizeMore = Read-Host "[?] Sanitize free space on additional drives? [Y/N] (Default: N)"
    if ($sanitizeMore -match '^Y') {
        foreach ($drive in $fixed) {
            Write-Host "[~] Drive $($drive.Name): Sanitizing..."
            & $SDEL -z $drive.Name.TrimEnd('\')
            Write-Host "[✓] Drive $($drive.Name) free space: CLEANSED" -ForegroundColor Green
        }
    } else {
        Write-Host "[~] Additional drives: SKIPPED" -ForegroundColor Yellow
    }
}
Write-Host ""

# =================== FINALIZATION ===================
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "                    OPERATION COMPLETE" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "[✓] SYSTEM STERILIZATION: SUCCESSFUL" -ForegroundColor Green
Write-Host "[✓] FORENSIC FOOTPRINT: VAPORIZED" -ForegroundColor Green
Write-Host "[✓] DIGITAL GHOSTING: COMPLETE" -ForegroundColor Green
Write-Host ""
Write-Host "[!] Your system is now a digital ghost:" -ForegroundColor Green
Write-Host "[!] • No personal traces remain" -ForegroundColor Green
Write-Host "[!] • No browser histories exist" -ForegroundColor Green
Write-Host "[!] • No system logs contain evidence" -ForegroundColor Green
Write-Host "[!] • No registry echoes persist" -ForegroundColor Green
Write-Host "[!] • No free space contains ghosts" -ForegroundColor Green
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "           GHOST-WALKER v$version - MISSION COMPLETE" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""

Start-Process explorer.exe
Read-Host "Press Enter to exit..."
