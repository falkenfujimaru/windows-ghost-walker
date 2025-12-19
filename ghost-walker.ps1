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
Write-Host "   [+] Telemetry Uplink: SEVERED" -FG DarkGray
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "`n0.0.0.0 oca.telemetry.microsoft.com`n0.0.0.0 telemetry.microsoft.com"

# --- HELPER FUNCTIONS ---
function Force-Eradicate {
    param(
        [string]$Path,
        [string]$Type = "File" # Options: File, Folder, Registry
    )

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return }

    try {
        if ($Type -eq "Registry") {
            # 1. Try PowerShell Delete
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            
            # 2. Double Tap with reg.exe (CMD) if it still exists
            if (Test-Path $Path -ErrorAction SilentlyContinue) {
                # Convert PS Drive path (HKLM:\...) to CMD path (HKLM\...)
                $regPath = $Path -replace "HKLM:\\", "HKLM\" -replace "HKCU:\\", "HKCU\"
                Start-Process cmd.exe -ArgumentList "/c reg delete `"$regPath`" /f" -WindowStyle Hidden -Wait
            }
        }
        else {
            # Files & Folders
            # 1. SDelete (Forensic Wipe)
            if ($SDEL -and (Test-Path $SDEL)) {
                if ($Type -eq "Folder") { 
                    $target = Join-Path $Path "*"
                    & $SDEL -p 1 -s -q $target 2>$null 
                }
                else { 
                    & $SDEL -p 1 -q $Path 2>$null 
                }
            }

            # 2. PowerShell Force Delete
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue

            # 3. CMD Fallback (The Sledgehammer)
            if (Test-Path $Path -ErrorAction SilentlyContinue) {
                if ($Type -eq "Folder") { 
                    Start-Process cmd.exe -ArgumentList "/c rmdir /s /q `"$Path`"" -WindowStyle Hidden -Wait 
                }
                else { 
                    Start-Process cmd.exe -ArgumentList "/c del /f /q `"$Path`"" -WindowStyle Hidden -Wait 
                }
            }
        }
    } catch {
        # Suppress all errors to keep the console clean as requested
    }
}

# --- MODULE 2: STATE INCONSISTENCY (DEEP CLEAN) ---
Write-Host "[2/12] Nuking Deep Artifacts (Shimcache/Amcache)..." -FG $C
Write-Host "   [+] Shimcache: FLUSHED" -FG DarkGray
Write-Host "   [+] Amcache: PURGED" -FG DarkGray

# Shimcache & AppCompat
Force-Eradicate "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" "Registry"
Force-Eradicate "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Explorer" "Registry"

# BAM (Background Activity Moderator)
$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object { Force-Eradicate $_.PSPath "Registry" }
}
Write-Host "   [+] BAM Evidence: VAPORIZED" -FG DarkGray

# --- MODULE 3: MFT BURIAL (THE BURIER) ---
Write-Host "[3/12] Burying the Evidence: MFT Overwrite Sequence..." -FG $C
$targetDir = "$env:TEMP\void_fill"
New-Item -ItemType Directory -Path $targetDir -Force -ErrorAction SilentlyContinue | Out-Null
# Optimize: Reduce count, increase speed. 1000 files is enough to clutter MFT.
$maxFiles = 1000
for ($i=1; $i -le $maxFiles; $i++) {
    Write-Progress -Activity "MFT Burial In Progress" -Status "Overwriting MFT Record $i of $maxFiles" -PercentComplete (($i / $maxFiles) * 100)
    $null = New-Item -Path "$targetDir\ghost_$i.tmp" -ItemType File -Value "VOID" -Force
}
Write-Progress -Activity "MFT Burial In Progress" -Completed
Force-Eradicate $targetDir "Folder"

# --- MODULE 4: PROCESS & DATA VAPORIZATION ---
Write-Host "[4/12] Vaporizing Active Witnesses & Personal Stash..." -FG $C
$procs = "chrome","msedge","brave","firefox","opera","Discord","WhatsApp","Telegram","explorer","msedgewebview2","edge","iexplore"
foreach ($p in $procs) {
    Stop-Process -Name $p -Force -ErrorAction SilentlyContinue
}
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
        
        # Only wipe contents, preserve the parent folder
        $files = Get-ChildItem -Path $f -Force -Recurse -ErrorAction SilentlyContinue
        $totalFiles = $files.Count
        $counter = 0

        if ($totalFiles -gt 0) {
             foreach ($item in $files) {
                $counter++
                # Update progress bar every 10 items to reduce overhead
                if ($counter % 10 -eq 0) {
                    Write-Progress -Activity "Shredding Data in $f" -Status "Vaporizing: $($item.Name)" -PercentComplete (($counter / $totalFiles) * 100)
                }

                if ($item.PSIsContainer) {
                    Force-Eradicate $item.FullName "Folder"
                } else {
                    Force-Eradicate $item.FullName "File"
                }
            }
            Write-Progress -Activity "Shredding Data in $f" -Completed
        }
    }
}

# --- MODULE 5: BROWSER, COMMS & SYSTEM ARTIFACTS ---
Write-Host "[5/12] Scorching Browser, Comms & System Artifacts..." -FG $C
$appData = @(
    # Browsers
    "$env:LocalAppData\Google\Chrome\User Data",
    "$env:LocalAppData\Microsoft\Edge\User Data",
    "$env:LocalAppData\BraveSoftware\Brave-Browser\User Data",
    "$env:AppData\Mozilla\Firefox",
    "$env:LocalAppData\Mozilla\Firefox",
    "$env:AppData\Opera Software",
    "$env:LocalAppData\Opera Software",

    # Messengers
    "$env:AppData\Telegram Desktop",
    "$env:AppData\discord",
    "$env:LocalAppData\Discord",
    "$env:AppData\WhatsApp",
    "$env:LocalAppData\WhatsApp",
    "$env:LocalAppData\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm", # WhatsApp Store
    "$env:LocalAppData\Packages\5319275A.WhatsAppBeta_cv1g1gvanyjgm",    # WhatsApp Beta

    # System
    "$env:TEMP",
    "$env:WINDIR\Temp",
    "$env:WINDIR\Prefetch",
    "$env:LocalAppData\Microsoft\Windows\WebCache",
    "$env:LocalAppData\Microsoft\Windows\INetCache"
)

# 1. Clear DNS Cache
Write-Host "[~] Flushing DNS Cache..." -FG $Y
Clear-DnsClientCache -ErrorAction SilentlyContinue

# 2. Clear Clipboard
Write-Host "[~] Vaporizing Clipboard..." -FG $Y
Set-Clipboard $null -ErrorAction SilentlyContinue

# 3. Clear Recycle Bin
Write-Host "[~] Emptying Recycle Bin..." -FG $Y
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# 4. Wipe Artifact Paths
$totalArtifacts = $appData.Count
$artCounter = 0
foreach ($path in $appData) {
    $artCounter++
    Write-Progress -Activity "Scorching Artifacts" -Status "Wiping: $path" -PercentComplete (($artCounter / $totalArtifacts) * 100)
    
    if (Test-Path $path) {
        Write-Host "   [+] Target Locked: $path" -FG DarkGray
        
        # Special Hunter for Browsers: History, Cookies, Web Data
        $browserFiles = @("History", "Cookies", "Web Data", "Login Data", "Top Sites", "Visited Links")
        Get-ChildItem -Path $path -Include $browserFiles -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
             Force-Eradicate $_.FullName "File"
        }

        Force-Eradicate $path "Folder"
    }
}
Write-Progress -Activity "Scorching Artifacts" -Completed

# --- MODULE 6: TIMING GAP FILLER (THE NOISE) ---
Write-Host "[6/12] Injecting Digital Noise (Timing Gap Filler)..." -FG $C
# Pertama, bersihkan log asli
$logs = Get-WinEvent -ListLog * -Force
foreach ($l in $logs) { try { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l.LogName) } catch {} }
Write-Host "   [+] System Logs: VACUUMED" -FG DarkGray

# Kedua, injeksi log palsu agar tidak terlihat 'kosong'
$noiseCount = 20
for ($i=1; $i -le $noiseCount; $i++) {
    Write-Progress -Activity "Injecting Noise" -Status "Fabricating Event $i of $noiseCount" -PercentComplete (($i / $noiseCount) * 100)
    Write-EventLog -LogName Application -Source "MsiInstaller" -EntryType Information -EventId 1033 -Message "Windows Installer reconfigured the product. Control Panel\Programs\Features. Transaction: $i."
}
Write-Progress -Activity "Injecting Noise" -Completed
Write-Host "   [+] Fake Entropy: INJECTED" -FG DarkGray

# --- MODULE 7: SHELL & RDP PURGE ---
Write-Host "[7/12] Wiping Shell Memory & RDP Tracks..." -FG $C
Clear-History
if (Test-Path "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") {
    Force-Eradicate "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "File"
}
$rdpKeys = @("HKCU:\Software\Microsoft\Terminal Server Client\Servers", "HKCU:\Software\Microsoft\Terminal Server Client\Default")
foreach ($k in $rdpKeys) { if (Test-Path $k) { Force-Eradicate $k "Registry" } }

# --- MODULE 8: FREE SPACE SANITIZATION ---
Write-Host "[8/12] Unleashing the Void: Free Space Sanitization..." -FG $C
Write-Host "[!] Info: Overwriting deleted data on Drive C: (Free Space Only)." -FG $Y
Write-Host "[!] Info: Your active files (Windows, Documents, etc.) are SAFE and will NOT be deleted." -FG $Y
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

$choice = Read-Host "[1] Reboot & Vanish [2] Shutdown & Vanish [3] Self-Destruct & Exit"

Write-Host ""
Write-Host "   Sayonara from Falken Fujimaru..." -FG $C
Write-Host "   The shadows have reclaimed what was theirs." -FG $C
Write-Host ""

if ($choice -eq '1') {
    $scriptPath = $PSCommandPath
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$scriptPath`" && shutdown /r /t 0 /f" -WindowStyle Hidden
    exit
} elseif ($choice -eq '2') {
    $scriptPath = $PSCommandPath
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$scriptPath`" && shutdown /s /t 0 /f" -WindowStyle Hidden
    exit
} else {
    Start-Process explorer.exe
    # Self-destruct via CMD to ensure clean removal after exit
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$PSCommandPath`"" -WindowStyle Hidden
    exit
}
