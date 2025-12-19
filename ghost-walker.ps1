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
$is64 = [Environment]::Is64BitOperatingSystem
$sdelName = if ($is64) { 'sdelete64.exe' } else { 'sdelete.exe' }
$SDEL = Join-Path $PSScriptRoot $sdelName

if ([string]::IsNullOrWhiteSpace($SDEL)) {
    Write-Host "[!] CRITICAL ERROR: Unable to determine SDelete path." -FG $R
    exit
}

if (!(Test-Path $SDEL)) {
    Write-Host "[~] Summoning the Void Shredder (SDelete)..." -FG $C
    $zip = "$env:TEMP\s.zip"
    try {
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $PSScriptRoot -Force
        Remove-Item $zip -Force
    } catch {
        Write-Host "[!] Failed to download SDelete. Please ensure internet connection." -FG $R
        Write-Host "[!] Error: $_" -FG $R
    }
}

if (!(Test-Path $SDEL)) {
    Write-Host "[!] SDelete not found at $SDEL. Cannot proceed safely." -FG $R
    Read-Host "Press Enter to exit..."
    exit
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

# Helper to safely remove registry keys
function Safe-RegDelete {
    param($Path)
    if (Test-Path $Path) {
        try {
            # Try taking ownership and adding permissions before deleting (if needed)
            $acl = Get-Acl $Path
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("Administrators","FullControl","Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $Path $acl -ErrorAction SilentlyContinue
            
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[!] Access Denied or Locked: $Path (Skipping)" -FG $R
        }
    }
}

# Shimcache & AppCompat
Safe-RegDelete "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
Safe-RegDelete "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Explorer"

# BAM (Background Activity Moderator)
# BAM is protected by System. We try, but suppress fatal errors.
$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object { Safe-RegDelete $_.PSPath }
}

# --- MODULE 3: MFT BURIAL (THE BURIER) ---
Write-Host "[3/12] Burying the Evidence: MFT Overwrite Sequence..." -FG $C
$targetDir = "$env:TEMP\void_fill"
New-Item -ItemType Directory -Path $targetDir -Force -ErrorAction SilentlyContinue | Out-Null
# Optimize: Reduce count, increase speed. 1000 files is enough to clutter MFT.
for ($i=1; $i -le 1000; $i++) {
    $null = New-Item -Path "$targetDir\ghost_$i.tmp" -ItemType File -Value "VOID" -Force
}
if (Test-Path $SDEL) {
    & $SDEL -p 1 -q "$targetDir\*.tmp"
}
Remove-Item $targetDir -Recurse -Force -ErrorAction SilentlyContinue

# --- MODULE 4: PROCESS & DATA VAPORIZATION ---
Write-Host "[4/12] Vaporizing Active Witnesses & Personal Stash..." -FG $C
$procs = "chrome","msedge","brave","firefox","opera","Discord","WhatsApp","Telegram","explorer"
Stop-Process -Name $procs -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Helper function to get real paths from Registry (User Shell Folders)
function Get-RealUserPath {
    param($KeyName)
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $val = (Get-ItemProperty -Path $regPath -Name $KeyName -ErrorAction SilentlyContinue).$KeyName
        if ($val) {
            return [System.Environment]::ExpandEnvironmentVariables($val)
        }
    } catch {}
    return $null
}

$folders = @(
    (Get-RealUserPath "Personal"),          # Documents
    (Get-RealUserPath "My Pictures"),       # Pictures
    (Get-RealUserPath "My Video"),          # Videos
    (Get-RealUserPath "Desktop"),           # Desktop
    (Get-RealUserPath "{374DE290-123F-4565-9164-39C4925E467B}"), # Downloads GUID
    (Get-RealUserPath "My Music")           # Music
)

# Filter out nulls and duplicates
$folders = $folders | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

foreach ($f in $folders) {
    if ($f -and (Test-Path $f)) {
        # Safety: Don't wipe the entire UserProfile if path resolution fails or returns root
        if ($f -eq $env:USERPROFILE -or $f -eq "C:\" -or $f -eq "C:\Users") { continue }
        
        Write-Host "[~] Shredding contents of: $f" -FG $Y
        # Use Get-ChildItem to safely pass paths to SDelete
        $target = Join-Path $f "*"
        if (Test-Path $SDEL) {
            & $SDEL -p 3 -s -q $target
        }
    }
}

# --- MODULE 5: BROWSER, COMMS & SYSTEM ARTIFACTS ---
Write-Host "[5/12] Scorching Browser, Comms & System Artifacts..." -FG $C
$appData = @(
    "$env:LocalAppData\Google\Chrome\User Data",
    "$env:LocalAppData\Microsoft\Edge\User Data",
    "$env:AppData\Telegram Desktop",
    "$env:TEMP",
    "$env:WINDIR\Temp",
    "$env:WINDIR\Prefetch"
)

# 1. Clear Clipboard
Write-Host "[~] Vaporizing Clipboard..." -FG $Y
Set-Clipboard $null -ErrorAction SilentlyContinue

# 2. Clear Recycle Bin
Write-Host "[~] Emptying Recycle Bin..." -FG $Y
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# 3. Wipe Artifact Paths
foreach ($path in $appData) {
    if (Test-Path $path) {
        Write-Host "[~] Wiping: $path" -FG $Y
        if(Test-Path $SDEL) {
             # Use specific params for Temp folders to avoid locking issues
             & $SDEL -p 2 -s -q "$path\*" 2>$null
        }
    }
}

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
    if (Test-Path $SDEL) {
        & $SDEL -p 3 -q "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }
}
$rdpKeys = @("HKCU:\Software\Microsoft\Terminal Server Client\Servers", "HKCU:\Software\Microsoft\Terminal Server Client\Default")
foreach ($k in $rdpKeys) { if (Test-Path $k) { Remove-Item $k -Recurse -Force } }

# --- MODULE 8: FREE SPACE SANITIZATION ---
Write-Host "[8/12] Unleashing the Void: Free Space Sanitization..." -FG $C
Write-Host "[!] Note: This cleans UNUSED space. Existing files are safe." -FG $Y
Write-Host "[!] Warning: This process can take time. Press Ctrl+C if you need to abort early." -FG $Y
if (Test-Path $SDEL) {
    & $SDEL -z $env:SystemDrive
}

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
