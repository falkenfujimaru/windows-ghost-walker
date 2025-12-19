# ===============================================================
#  PROJECT: GHOST-WALKER // VOID PROTOCOL v3.5 (PS1)
#  Coded by: Falken Fujimaru [The Digital Phantom]
#  Counter-Forensic: Timing Gaps, State Sync, MFT Overwriting
# ===============================================================

$ErrorActionPreference = 'Continue'
$version = "3.5-PRO"

function Show-Header {
    Clear-Host
    $G = "Green"; $C = "Cyan"; $Y = "Yellow"; $R = "Red"
    Write-Host "=======================================================================================================" -FG $G
    Write-Host "   PHANTOM-LEAP // GHOST-WALKER v$version " -FG $G
    Write-Host "   [ STATUS: COUNTER-FORENSIC ACTIVE ]" -FG $G
    Write-Host "=======================================================================================================" -FG $G
    Write-Host ""
    Write-Host "   Crafted by 乍丹し片ヨ几　乍凵勹工冊丹尺凵" -FG $C
    Write-Host "   Breaking Codes, Not Hearts." -FG $C
    Write-Host ""
    Write-Host "=======================================================================================================" -FG $G
}

# --- PRIVILEGE CHECK ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] HOL UP! God-Mode permissions required. Elevating privileges..." -FG $R
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- SDELETE VALIDATION ---
$SDEL = Join-Path $PSScriptRoot (if ([Environment]::Is64BitOperatingSystem) { 'sdelete64.exe' } else { 'sdelete.exe' })
if (!(Test-Path $SDEL)) {
    Write-Host "[~] Summoning the Void Shredder (SDelete)..." -FG $C
    $zip = "$env:TEMP\s.zip"
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $PSScriptRoot -Force
    Remove-Item $zip -Force
}
& $SDEL -accepteula

Show-Header

# --- FINAL WARNING ---
Write-Host "[!] MISSION: Kill Traces, Bury MFT, Zero-Out Everything." -FG $Y
$confirm = Read-Host "[?] Ready to disappear? Type 'GHOST' to execute"
if ($confirm -ne 'GHOST') { 
    Read-Host "Aborted. Press Enter to exit..."
    exit 
}

# ===============================================================
#  COUNTER-FORENSIC MODULES
# ===============================================================

# --- MODULE 1: TELEMETRY BLACKOUT ---
Write-Host "[1/12] Cutting the Cord: Microsoft Telemetry Blackout..." -FG $C
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "`n0.0.0.0 oca.telemetry.microsoft.com`n0.0.0.0 telemetry.microsoft.com"

# --- MODULE 2: STATE INCONSISTENCY (DEEP CLEAN) ---
Write-Host "[2/12] Nuking Deep Artifacts (Shimcache/Amcache)..." -FG $C
# Shimcache & AppCompat
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Explorer" -Recurse -Force
# BAM (Background Activity Moderator)
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*" -Recurse -Force

# --- MODULE 3: MFT BURIAL (THE BURIER) ---
Write-Host "[3/12] Burying the Evidence: MFT Overwrite Sequence..." -FG $C
$targetDir = "$env:TEMP\void_fill"
New-Item -ItemType Directory -Path $targetDir -Force
for ($i=1; $i -le 3000; $i++) {
    New-Item -Path "$targetDir\ghost_$i.tmp" -ItemType File -Value "VOID"
}
& $SDEL -p 1 -q "$targetDir\*.tmp"
Remove-Item $targetDir -Recurse -Force

# --- MODULE 4: PROCESS & DATA VAPORIZATION ---
Write-Host "[4/12] Vaporizing Active Witnesses & Personal Stash..." -FG $C
$procs = "chrome","msedge","brave","firefox","opera","Discord","WhatsApp","Telegram","explorer"
Stop-Process -Name $procs -Force
Start-Sleep -Seconds 2

$folders = "Downloads","Documents","Pictures","Videos","Desktop"
foreach ($f in $folders) {
    if (Test-Path "$env:USERPROFILE\$f") {
        & $SDEL -p 3 -s -q "$env:USERPROFILE\$f\*"
    }
}

# --- MODULE 5: BROWSER & COMMS OBLIVION ---
Write-Host "[5/12] Scorching Browser & Comms History..." -FG $C
$appData = @("$env:LocalAppData\Google\Chrome\User Data", "$env:LocalAppData\Microsoft\Edge\User Data", "$env:AppData\Telegram Desktop")
foreach ($path in $appData) { if (Test-Path $path) { & $SDEL -p 2 -s -q "$path\*" } }

# --- MODULE 6: TIMING GAP FILLER (THE NOISE) ---
Write-Host "[6/12] Injecting Digital Noise (Timing Gap Filler)..." -FG $C
# Pertama, bersihkan log asli
$logs = Get-WinEvent -ListLog * -Force
foreach ($l in $logs) { try { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l.LogName) } catch {} }
# Kedua, injeksi log palsu agar tidak terlihat 'kosong'
for ($i=1; $i -le 20; $i++) {
    Write-EventLog -LogName Application -Source "MsiInstaller" -EntryType Information -EventId 1033 -Message "Windows Installer reconfigured the product. Control Panel\Programs\Features. Transaction: $i."
}

# --- MODULE 7: SHELL & RDP PURGE ---
Write-Host "[7/12] Wiping Shell Memory & RDP Tracks..." -FG $C
Clear-History
if (Test-Path "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") {
    & $SDEL -p 3 -q "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
}
$rdpKeys = @("HKCU:\Software\Microsoft\Terminal Server Client\Servers", "HKCU:\Software\Microsoft\Terminal Server Client\Default")
foreach ($k in $rdpKeys) { if (Test-Path $k) { Remove-Item $k -Recurse -Force } }

# --- MODULE 8: FREE SPACE SANITIZATION ---
Write-Host "[8/12] Unleashing the Void: Free Space Sanitization..." -FG $C
& $SDEL -z $env:SystemDrive

# ===============================================================
#  FINALIZATION
# ===============================================================
Write-Host "===============================================================" -FG $G
Write-Host "   MISSION COMPLETE. YOU ARE NOW A GHOST." -FG $G
Write-Host "===============================================================" -FG $G

$choice = Read-Host "[1] Reboot & Vanish (Recommended) [2] Self-Destruct Script Only"
if ($choice -eq '1') {
    $scriptPath = $PSCommandPath
    Start-Process cmd.exe -ArgumentList "/c timeout /t 5 && del `"$scriptPath`" && shutdown /r /t 0 /f" -WindowStyle Hidden
    exit
} else {
    Start-Process explorer.exe
    Remove-Item $PSCommandPath -Force
    Read-Host "Press Enter to exit..."
    exit
}
