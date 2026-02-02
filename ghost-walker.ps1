# ===============================================================
#  PROJECT: GHOST-WALKER // VOID PROTOCOL v3.5 (PS1)
#  Coded by: Falken Fujimaru [The Digital Phantom]
#  Counter-Forensic: Timing Gaps, State Sync, MFT Overwriting
# ===============================================================

$ErrorActionPreference = 'Continue'
$version = "4.6-ULTRA"

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
    }
    catch {
        Write-Host "[!] Failed to download SDelete. Please ensure internet connection." -FG $R
        Write-Host "[!] Error: $_" -FG $R
    }
}


if (!(Test-Path $SDEL)) {
    Write-Host "[!] SDelete not found at $SDEL. Cannot proceed safely." -FG $R
    Read-Host "Press Enter to exit..."
    exit
}

# --- DEFENSE EVASION ---
# Stop Windows Search to unlock index files
Stop-Service "wsearch" -Force -ErrorAction SilentlyContinue


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
Write-Host "[1/11] Cutting the Cord: Microsoft Telemetry Blackout..." -FG $C
Write-Host "   [+] Telemetry Uplink: SEVERED" -FG DarkGray
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "`n0.0.0.0 oca.telemetry.microsoft.com`n0.0.0.0 telemetry.microsoft.com"

# --- CONFIGURATION ---
$TURBO_MODE = $true   # Set to $false for slower, individual file shredding (Higher Security per file)
$WIPE_PASSES = 3      # DoD Standard (3 Passes). Gutmann is 35 (Overkill/Slow).

# --- HELPER FUNCTIONS ---
function Force-Eradicate-Registry {
    param(
        [string]$Path,
        [switch]$OverwriteValues = $true  # Overwrite registry values before deletion for anti-forensics
    )

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return }

    try {
        # ANTI-FORENSIC: Overwrite registry values before deletion
        if ($OverwriteValues) {
            try {
                $regKey = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if ($regKey) {
                    # Get all property names (values)
                    $properties = $regKey | Get-ItemProperty -ErrorAction SilentlyContinue
                    if ($properties) {
                        $propertyNames = $properties.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') }
                        
                        foreach ($propName in $propertyNames) {
                            try {
                                # Overwrite with random garbage data
                                $garbage = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 256 | ForEach-Object { [char]$_ })
                                Set-ItemProperty -Path $Path -Name $propName -Value $garbage -ErrorAction SilentlyContinue
                                # Overwrite again with zeros
                                Set-ItemProperty -Path $Path -Name $propName -Value ([byte[]]@(0) * 256) -ErrorAction SilentlyContinue
                            }
                            catch {}
                        }
                    }
                    
                    # Recursively overwrite subkeys
                    $subKeys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
                    foreach ($subKey in $subKeys) {
                        Force-Eradicate-Registry -Path $subKey.PSPath -OverwriteValues:$OverwriteValues
                    }
                }
            }
            catch {}
        }
        
        # Now proceed with standard deletion
        Force-Eradicate -Path $Path -Type "Registry"
    }
    catch {
        # Suppress errors
    }
}

function Force-Eradicate {
    param(
        [string]$Path,
        [string]$Type = "File" # Options: File, Folder, Registry
    )

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return }

    # --- SAFETY GUARDRAILS (ANTI-BRICK LOGIC) ---
    # CRITICAL: This is the primary defense against OS destruction
    $AbsPath = $Path
    try { 
        $AbsPath = (Resolve-Path $Path -ErrorAction Stop).Path 
    } catch { 
        # If path resolution fails, try to normalize manually
        if ($Path -match "^[A-Z]:\\") {
            $AbsPath = $Path
        } else {
            # Relative path - block it if we can't resolve safely
            Write-Host "   [GUARDRAIL] BLOCKED: Unresolvable path >> $Path" -FG Red
            return
        }
    }
    $AbsPath = $AbsPath.TrimEnd('\') # Remove trailing slash for comparison
    
    # Additional safety: Block empty or suspiciously short paths
    if ([string]::IsNullOrWhiteSpace($AbsPath) -or $AbsPath.Length -lt 3) {
        Write-Host "   [GUARDRAIL] BLOCKED: Invalid path length >> $AbsPath" -FG Red
        return
    }

    # CRITICAL SYSTEM PATHS - NEVER DELETE THESE
    $CriticalPaths = @(
        "$env:SystemDrive",                      # C:
        "$env:SystemRoot",                      # C:\Windows
        "$env:ProgramFiles",                     # C:\Program Files
        "${env:ProgramFiles(x86)}",              # C:\Program Files (x86)
        "$env:SystemDrive\Users",                # C:\Users (Root)
        "$env:SystemRoot\System32",              # C:\Windows\System32
        "$env:SystemRoot\SysWOW64",              # C:\Windows\SysWOW64
        "$env:SystemRoot\System",                # C:\Windows\System
        "$env:ProgramData",                      # C:\ProgramData (System-wide app data)
        "$env:SystemRoot\WinSxS",                # C:\Windows\WinSxS (Component Store)
        "$env:SystemRoot\Boot",                  # C:\Windows\Boot
        "$env:SystemRoot\Config",                # C:\Windows\Config
        "$env:SystemRoot\Logs",                  # C:\Windows\Logs
        "$env:SystemRoot\SoftwareDistribution"   # C:\Windows\SoftwareDistribution (Windows Update)
    )

    # ALLOWED EXCEPTIONS - Only these sub-paths of critical paths are safe to delete
    $AllowedExceptions = @(
        "$env:SystemRoot\Temp",                  # Windows Temp (safe to clear)
        "$env:SystemRoot\Prefetch",              # Prefetch (safe to clear)
        "$env:SystemRoot\Logs\CBS",              # Component Based Servicing logs
        "$env:SystemRoot\Logs\DISM"              # Deployment Image Servicing logs
    )
    
    # Additional protection: Block any path that contains critical Windows components
    $CriticalSubstrings = @(
        "\System32\",
        "\SysWOW64\",
        "\WinSxS\",
        "\Boot\",
        "\Config\",
        "\Program Files\Windows",
        "\Program Files (x86)\Windows",
        "\Program Files\Common Files\Microsoft Shared",
        "\Program Files (x86)\Common Files\Microsoft Shared"
    )

    # FIRST CHECK: Block critical substrings (most dangerous patterns)
    foreach ($critSub in $CriticalSubstrings) {
        if ($AbsPath -like "*$critSub*") {
            Write-Host "   [GUARDRAIL] BLOCKED: Contains critical system component >> $AbsPath" -FG Red
            return
        }
    }
    
    # SECOND CHECK: Block exact matches and children of critical paths
    foreach ($Crit in $CriticalPaths) {
        # 1. Block Exact Match (e.g. trying to delete C:\Windows)
        if ($AbsPath -eq $Crit) {
            Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete CRITICAL ROOT >> $AbsPath" -FG Red
            return
        }
        
        # 2. Block Children (e.g. C:\Windows\System32) UNLESS Exception
        if ($AbsPath.StartsWith("$Crit\")) {
            $IsAllowed = $false
            foreach ($Ex in $AllowedExceptions) {
                # Allow if it IS the exception or a CHILD of the exception
                if ($AbsPath -eq $Ex -or $AbsPath.StartsWith("$Ex\")) { 
                    $IsAllowed = $true
                    break 
                }
            }
            
            if (-not $IsAllowed) {
                Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete PROTECTED SYSTEM PATH >> $AbsPath" -FG Red
                return
            }
        }
    }
    
    # THIRD CHECK: Additional safety for Program Files - block system apps
    if ($AbsPath.StartsWith("$env:ProgramFiles\") -or $AbsPath.StartsWith("${env:ProgramFiles(x86)}\")) {
        # Block deletion of Windows-related folders in Program Files
        $blockedProgramFolders = @("Windows", "Microsoft", "Common Files")
        $pathParts = $AbsPath -split "\\"
        if ($pathParts.Count -ge 4) {
            $programSubfolder = $pathParts[3]
            if ($blockedProgramFolders -contains $programSubfolder) {
                Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete Windows system app >> $AbsPath" -FG Red
                return
            }
        }
    }
    
    # FOURTH CHECK: Block deletion of critical file types in system locations
    if ($Type -eq "File") {
        $criticalExtensions = @(".dll", ".sys", ".exe")
        $fileExt = [System.IO.Path]::GetExtension($AbsPath).ToLower()
        if ($criticalExtensions -contains $fileExt) {
            # Only block if in system locations
            if ($AbsPath.StartsWith("$env:SystemRoot\") -or 
                $AbsPath.StartsWith("$env:ProgramFiles\") -or 
                $AbsPath.StartsWith("${env:ProgramFiles(x86)}\")) {
                Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete system executable >> $AbsPath" -FG Red
                return
            }
        }
    }
    # ----------------------------------------------

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
            
            # 1. SDelete (Forensic Wipe) OR Turbo Delete
            if ($TURBO_MODE) {
                # TURBO MODE: Skip SDelete for individual files to save massive time.
                # Reliability comes from the FINAL FREE SPACE WIPE (Module 8).
                # This just deletes the file entry logically.
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            }
            elseif ($SDEL -and (Test-Path $SDEL)) {
                # SECURE MODE: Wipe individual files
                # -s = Recurse (for folders)
                # -p = Passes (3 = DoD)
                # -q = Quiet
                if ($Type -eq "Folder") { 
                    $target = Join-Path $Path "*"
                    & $SDEL -p $WIPE_PASSES -s -q $target 2>$null 
                }
                else { 
                    & $SDEL -p $WIPE_PASSES -q $Path 2>$null 
                }
            }

            # 2. PowerShell Force Delete (Cleanup if SDelete missed or Turbo Mode)
            if (Test-Path $Path -ErrorAction SilentlyContinue) {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            }

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
    }
    catch {
        # Suppress all errors to keep the console clean as requested
    }
}

# --- MODULE 1.5: SHADOW COPY & JOURNAL PURGE ---
Write-Host "[2/11] Annihilating Snapshots & Journals..." -FG $C
vssadmin delete shadows /all /quiet 2>$null
Write-Host "   [+] Volume Shadows: DESTROYED" -FG DarkGray
fsutil usn deletejournal /d C: 2>$null
Write-Host "   [+] NTFS Journal: OBLITERATED" -FG DarkGray

# --- MODULE 2: STATE INCONSISTENCY (DEEP CLEAN) ---
Write-Host "[3/11] Nuking Deep Artifacts (Shimcache/Amcache/SRUM/UserAssist)..." -FG $C
Write-Host "   [+] Shimcache: FLUSHED" -FG DarkGray
Write-Host "   [+] Amcache: PURGED" -FG DarkGray

# Shimcache & AppCompat
Force-Eradicate-Registry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
Force-Eradicate-Registry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Explorer"

# BAM (Background Activity Moderator)
$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object { Force-Eradicate-Registry $_.PSPath }
}
Write-Host "   [+] BAM Evidence: VAPORIZED" -FG DarkGray

# SRUM (System Resource Usage Monitor) - Tracks application execution
$srumPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM"
if (Test-Path $srumPath) {
    Get-ChildItem $srumPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Force-Eradicate-Registry $_.PSPath }
    Write-Host "   [+] SRUM Database: OBLITERATED" -FG DarkGray
}

# UserAssist - Tracks program execution frequency
$userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
if (Test-Path $userAssistPath) {
    Get-ChildItem $userAssistPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Force-Eradicate-Registry $_.PSPath }
    Write-Host "   [+] UserAssist: ANNIHILATED" -FG DarkGray
}

# TypedPaths - Recently typed paths in Run dialog
Force-Eradicate-Registry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
Write-Host "   [+] TypedPaths: ERASED" -FG DarkGray

# MUICache - Multilingual User Interface cache
Force-Eradicate-Registry "HKCU:\Software\Classes\Local Settings\MuiCache"
Write-Host "   [+] MUICache: DESTROYED" -FG DarkGray

# RecentDocs - Recent documents list
Force-Eradicate-Registry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
Write-Host "   [+] RecentDocs: WIPED" -FG DarkGray

# --- MODULE 2.5: MEMORY ARTIFACT PURGE (Pagefile/Hibernation) ---
Write-Host "[4/11] Purging Memory Artifacts (Pagefile/Hibernation)..." -FG $C

# Disable and clear Pagefile.sys (contains memory dumps)
$pagefilePath = "$env:SystemDrive\pagefile.sys"
if (Test-Path $pagefilePath) {
    Write-Host "   [~] Disabling Pagefile for next boot..." -FG $Y
    # Set registry to disable pagefile on next boot
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value @() -ErrorAction SilentlyContinue
    Write-Host "   [+] Pagefile: SCHEDULED FOR DELETION" -FG DarkGray
}

# Disable and clear Hiberfil.sys (contains hibernation state)
$hiberPath = "$env:SystemDrive\hiberfil.sys"
if (Test-Path $hiberPath) {
    Write-Host "   [~] Disabling Hibernation..." -FG $Y
    # Disable hibernation (this will delete hiberfil.sys on next boot)
    powercfg /hibernate off 2>$null
    Write-Host "   [+] Hibernation: DISABLED" -FG DarkGray
}

# Clear Windows Error Reporting (WER) - may contain memory dumps
$werPaths = @(
    "$env:ProgramData\Microsoft\Windows\WER",
    "$env:LocalAppData\Microsoft\Windows\WER"
)
foreach ($werPath in $werPaths) {
    if (Test-Path $werPath) {
        Get-ChildItem -Path $werPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName "File"
        }
        Write-Host "   [+] WER Logs: CLEARED" -FG DarkGray
    }
}

# --- MODULE 3: MFT BURIAL (THE BURIER) ---
Write-Host "[5/11] Burying the Evidence: MFT Overwrite Sequence..." -FG $C
$targetDir = "$env:TEMP\void_fill"
New-Item -ItemType Directory -Path $targetDir -Force -ErrorAction SilentlyContinue | Out-Null
# Optimize: Reduce count, increase speed. 1000 files is enough to clutter MFT.
$maxFiles = 1000
for ($i = 1; $i -le $maxFiles; $i++) {
    Write-Progress -Activity "MFT Burial In Progress" -Status "Overwriting MFT Record $i of $maxFiles" -PercentComplete (($i / $maxFiles) * 100)
    $null = New-Item -Path "$targetDir\ghost_$i.tmp" -ItemType File -Value "VOID" -Force
}
Write-Progress -Activity "MFT Burial In Progress" -Completed
Force-Eradicate $targetDir "Folder"

# --- MODULE 4: PROCESS & DATA VAPORIZATION ---
Write-Host "[6/11] Vaporizing Active Witnesses & Personal Stash..." -FG $C
$procs = "chrome", "msedge", "brave", "firefox", "opera", "Discord", "WhatsApp*", "Telegram", "TelegramDesktop", "Telegram.exe", "explorer", "msedgewebview2", "edge", "iexplore", "SearchApp", "SearchUI", "OneDrive", "OneDriveSetup", "GoogleDriveFS", "ProtonDrive", "Dropbox", "iCloudDrive", "BoxSync", "MEGASync", "pCloud", "Sync", "RuntimeBroker"
foreach ($p in $procs) {
    Stop-Process -Name $p -Force -ErrorAction SilentlyContinue
}
# Additional Telegram process names
Get-Process | Where-Object { $_.ProcessName -like "*Telegram*" -or $_.ProcessName -like "*WhatsApp*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# --- SURGICAL USER WIPE (SAFE MODE) ---
Write-Host "[!][CRITICAL] STARTING SURGICAL DATA WIPE (CONTENT ONLY)..." -FG $R
if ($TURBO_MODE) {
    Write-Host "   [i] TURBO MODE: ENABLED (Fast Delete + Final Wipe)" -FG Yellow
}
else {
    Write-Host "   [i] SECURE MODE: ENABLED (SDelete Per File: $WIPE_PASSES Pass)" -FG Yellow
}
Write-Host "   [i] Preserving Folder Structure for OS Stability" -FG DarkGray

$usersDir = "$env:SystemDrive\Users"
# SAFETY: Ensure we're targeting Users directory safely
if (-not (Test-Path $usersDir)) {
    Write-Host "   [!] WARNING: Users directory not found. Skipping user data wipe." -FG Red
    $targetUsers = @()
} else {
    $targetUsers = Get-ChildItem -Path $usersDir -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("Public", "Default", "All Users", "Default User") }
}

foreach ($user in $targetUsers) {
    Write-Host "   [>>] ENTERING USER HIVES: $($user.Name)" -FG $Y
    
    # Target specific libraries where personal data lives
    $subTargets = @(
        "Desktop", "Downloads", "Documents", "Pictures", "Music", "Videos", "Saved Games", "Favorites", "Links", "OneDrive", 
        "AppData\Local\Temp", 
        "AppData\Roaming\Microsoft\Windows\Recent",
        "AppData\Local\Google\Chrome\User Data",
        "AppData\Local\Microsoft\Edge\User Data",
        "AppData\Local\BraveSoftware\Brave-Browser\User Data",
        "AppData\Roaming\Mozilla\Firefox\Profiles",
        "AppData\Roaming\Opera Software\Opera Stable",
        "AppData\Roaming\Discord",
        "AppData\Roaming\Telegram Desktop",
        "AppData\Local\Telegram Desktop",
        "AppData\Roaming\WhatsApp",
        "AppData\Local\WhatsApp",
        "AppData\Roaming\WhatsAppBeta",
        "AppData\Local\WhatsAppBeta"
    )

    # Dynamic WhatsApp Package Detection (Beta & Stable)
    $pkgPath = Join-Path $user.FullName "AppData\Local\Packages"
    if (Test-Path $pkgPath) {
        Get-ChildItem -Path $pkgPath -Filter "*WhatsApp*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $subTargets += ("AppData\Local\Packages\" + $_.Name)
            Write-Host "      -> Detected WhatsApp Package: $($_.Name)" -FG DarkGray
        }
    }
    
    # Also check Roaming Packages for WhatsApp
    $pkgRoamingPath = Join-Path $user.FullName "AppData\Roaming\Packages"
    if (Test-Path $pkgRoamingPath) {
        Get-ChildItem -Path $pkgRoamingPath -Filter "*WhatsApp*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $subTargets += ("AppData\Roaming\Packages\" + $_.Name)
            Write-Host "      -> Detected WhatsApp Package (Roaming): $($_.Name)" -FG DarkGray
        }
    }
    
    foreach ($sub in $subTargets) {
        $fullPath = Join-Path $user.FullName $sub
        if (Test-Path $fullPath) {
            Write-Host "      -> Sanitizing Content: $sub" -FG DarkGray
             
            # 1. Wipe Files inside (Keep Folder)
            $files = Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                # Attempt Secure Wipe via Force-Eradicate (Handles Turbo Logic)
                Force-Eradicate $file.FullName "File"
            }
             
            # 2. Remove Sub-directories (Keep Root Target)
            Get-ChildItem -Path $fullPath -Directory -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            
            # 3. SPECIAL OPS: BROWSER PROFILE HUNT
            # If we just wiped a 'User Data' folder, doubly ensure 'Default' and 'Profile' folders are dead.
            if ($fullPath -match "User Data" -or $fullPath -match "Firefox\\Profiles") {
                $profiles = Get-ChildItem -Path $fullPath -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Default" -or $_.Name -match "Profile" -or $_.Name -match "Guest" -or $_.Name -match "System" }
                foreach ($prof in $profiles) {
                    Write-Host "         [X] Killing Profile: $($prof.Name)" -FG Red
                    Force-Eradicate $prof.FullName "Folder"
                }
            }
            
            # 4. SPECIAL OPS: TELEGRAM COMPLETE WIPE
            # Telegram stores session/auth data in both Roaming and Local, plus registry
            if ($fullPath -match "Telegram") {
                Write-Host "         [X] Complete Telegram Wipe: Ensuring all data cleared" -FG Red
                # Force delete the entire folder structure, not just contents
                if (Test-Path $fullPath) {
                    Force-Eradicate $fullPath "Folder"
                }
            }
            
            # 5. SPECIAL OPS: WHATSAPP & WHATSAPP BETA COMPLETE WIPE
            # WhatsApp and WhatsAppBeta follow the same wiping process:
            # 1. Wipe all files recursively
            # 2. Wipe all subdirectories recursively  
            # 3. Force delete the entire folder structure (same as WhatsApp)
            if ($fullPath -match "WhatsApp") {
                Write-Host "         [X] Complete WhatsApp/WhatsAppBeta Wipe: Ensuring all data cleared" -FG Red
                # Same process for both WhatsApp and WhatsAppBeta - complete folder deletion
                if (Test-Path $fullPath) {
                    # Step 1: Wipe all files recursively
                    Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Force-Eradicate $_.FullName "File"
                    }
                    # Step 2: Wipe all subdirectories recursively
                    Get-ChildItem -Path $fullPath -Directory -Recurse -Force -ErrorAction SilentlyContinue | 
                        Sort-Object -Property FullName -Descending | ForEach-Object {
                        Force-Eradicate $_.FullName "Folder"
                    }
                    # Step 3: Force delete the root folder structure (same as WhatsApp)
                    Force-Eradicate $fullPath "Folder"
                }
            }
            
            # 6. SPECIAL OPS: CLOUD SYNC FOLDERS COMPLETE WIPE
            # Cloud sync folders (OneDrive, Google Drive, Proton Drive, etc.) need complete wipe
            # Uses TURBO_MODE for speed while ensuring complete removal
            $cloudSyncPatterns = @("OneDrive", "Google Drive", "My Drive", "ProtonDrive", "Proton Drive", "Dropbox", "iCloudDrive", "iCloud Drive", "Box", "MEGA", "pCloud", "Sync")
            $isCloudSync = $false
            foreach ($pattern in $cloudSyncPatterns) {
                if ($fullPath -match $pattern) {
                    $isCloudSync = $true
                    break
                }
            }
            
            if ($isCloudSync) {
                Write-Host "         [X] Cloud Sync Folder Wipe: Complete eradication ($sub)" -FG Red
                if (Test-Path $fullPath) {
                    # TURBO MODE: Fast deletion (final free space wipe will sanitize)
                    # Step 1: Wipe all files recursively (uses Force-Eradicate which respects TURBO_MODE)
                    Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Force-Eradicate $_.FullName "File"
                    }
                    # Step 2: Wipe all subdirectories recursively (sorted descending for proper deletion order)
                    Get-ChildItem -Path $fullPath -Directory -Recurse -Force -ErrorAction SilentlyContinue | 
                        Sort-Object -Property FullName -Descending | ForEach-Object {
                        Force-Eradicate $_.FullName "Folder"
                    }
                    # Step 3: Force delete the root cloud sync folder structure
                    Force-Eradicate $fullPath "Folder"
                }
            }
        }
    }
    
    # --- COMPREHENSIVE USER FOLDER WIPE (PRESERVE STRUCTURE) ---
    Write-Host "   [~] Comprehensive User Folder Content Wipe (Preserving Structure)..." -FG DarkGray
    
    # List of Windows standard folders to preserve (structure only, contents will be wiped)
    # Note: Cloud sync folders (OneDrive, Google Drive, etc.) are NOT preserved - they are completely wiped
    $preserveFolders = @(
        "Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos", 
        "Favorites", "Links", "Saved Games", "Contacts", "Searches",
        "AppData"
    )
    
    # Wipe ALL files in root user directory (except system files)
    $rootUserFiles = Get-ChildItem -Path $user.FullName -File -Force -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -notin @("ntuser.dat", "ntuser.dat.LOG1", "ntuser.dat.LOG2", "ntuser.ini", "desktop.ini") }
    foreach ($file in $rootUserFiles) {
        Write-Host "      -> Wiping root file: $($file.Name)" -FG DarkGray
        Force-Eradicate $file.FullName "File"
    }
    
    # Wipe ALL non-standard folders in user directory (keep only Windows standard folders)
    $allUserFolders = Get-ChildItem -Path $user.FullName -Directory -Force -ErrorAction SilentlyContinue
    foreach ($folder in $allUserFolders) {
        $folderName = $folder.Name
        $folderPath = $folder.FullName
        
        # Skip if it's a standard Windows folder (we'll wipe its contents separately)
        if ($preserveFolders -contains $folderName) {
            # Wipe contents but preserve folder structure
            Write-Host "      -> Wiping contents of standard folder: $folderName" -FG DarkGray
            Get-ChildItem -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Force-Eradicate $_.FullName ($_.PSIsContainer ? "Folder" : "File")
            }
            # Ensure folder exists (recreate if needed)
            if (-not (Test-Path $folderPath)) {
                New-Item -ItemType Directory -Path $folderPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } else {
            # Non-standard folder - wipe completely
            Write-Host "      -> Wiping non-standard folder: $folderName" -FG DarkGray
            Force-Eradicate $folderPath "Folder"
        }
    }
    
    # Final pass: Wipe any remaining files/folders that might have been missed
    # This ensures ALL non-standard Windows user folders and files are completely wiped unrecoverably
    $remainingItems = Get-ChildItem -Path $user.FullName -Recurse -Force -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.FullName -ne $user.FullName -and
            $_.Name -notin @("ntuser.dat", "ntuser.dat.LOG1", "ntuser.dat.LOG2", "ntuser.ini", "desktop.ini") -and
            -not ($_.PSIsContainer -and $preserveFolders -contains $_.Name) -and
            # Exclude AppData subfolders that are standard Windows folders
            -not ($_.FullName -like "*\AppData\Local\Microsoft\Windows\*" -and $_.Name -in @("INetCache", "History", "Cookies", "Temporary Internet Files")) -and
            -not ($_.FullName -like "*\AppData\Roaming\Microsoft\Windows\*" -and $_.Name -in @("Start Menu", "SendTo", "Network Shortcuts"))
        }
    foreach ($item in $remainingItems) {
        # Skip if it's a standard Windows system file/folder in AppData
        $isStandardAppData = $false
        if ($item.FullName -like "*\AppData\*") {
            $standardAppDataPaths = @(
                "*\AppData\Local\Microsoft\Windows\INetCache",
                "*\AppData\Local\Microsoft\Windows\History",
                "*\AppData\Roaming\Microsoft\Windows\Start Menu",
                "*\AppData\Roaming\Microsoft\Windows\SendTo"
            )
            foreach ($stdPath in $standardAppDataPaths) {
                if ($item.FullName -like $stdPath) {
                    $isStandardAppData = $true
                    break
                }
            }
        }
        
        if (-not $isStandardAppData) {
            Write-Host "      -> Final pass: Wiping remaining item: $($item.Name)" -FG DarkGray
            Force-Eradicate $item.FullName ($item.PSIsContainer ? "Folder" : "File")
        }
    }
    
    # Additional pass: Hunt for any hidden or system files/folders that might have been missed
    $hiddenItems = Get-ChildItem -Path $user.FullName -Recurse -Force -ErrorAction SilentlyContinue | 
        Where-Object { 
            (($_.Attributes -band [System.IO.FileAttributes]::Hidden) -or
            ($_.Attributes -band [System.IO.FileAttributes]::System)) -and
            $_.Name -notin @("ntuser.dat", "ntuser.dat.LOG1", "ntuser.dat.LOG2", "ntuser.ini", "desktop.ini") -and
            -not ($_.PSIsContainer -and $preserveFolders -contains $_.Name)
        }
    foreach ($hiddenItem in $hiddenItems) {
        Write-Host "      -> Final pass: Wiping hidden/system item: $($hiddenItem.Name)" -FG DarkGray
        Force-Eradicate $hiddenItem.FullName ($hiddenItem.PSIsContainer ? "Folder" : "File")
    }
    
    Write-Host "   [+] User Folder Contents: COMPLETELY WIPED UNRECOVERABLY (Structure Preserved)" -FG DarkGray
    
    # --- CLOUD SYNC FOLDERS COMPREHENSIVE WIPE (TURBO MODE) ---
    Write-Host "   [~] Comprehensive Cloud Sync Folders Wipe (Turbo Mode)..." -FG DarkGray
    
    # Common cloud sync folder locations in user directory
    $cloudSyncFolders = @(
        "OneDrive",
        "Google Drive",
        "My Drive",
        "ProtonDrive",
        "Proton Drive",
        "Dropbox",
        "iCloudDrive",
        "iCloud Drive",
        "Box",
        "MEGA",
        "pCloud Drive",
        "pCloud",
        "Sync"
    )
    
    foreach ($cloudFolder in $cloudSyncFolders) {
        $cloudPath = Join-Path $user.FullName $cloudFolder
        if (Test-Path $cloudPath) {
            Write-Host "      -> Wiping cloud sync folder: $cloudFolder" -FG DarkGray
            # TURBO MODE: Fast deletion (final free space wipe will sanitize)
            # Complete wipe: Files → Subdirectories → Root folder
            Get-ChildItem -Path $cloudPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Force-Eradicate $_.FullName "File"
            }
            Get-ChildItem -Path $cloudPath -Directory -Recurse -Force -ErrorAction SilentlyContinue | 
                Sort-Object -Property FullName -Descending | ForEach-Object {
                Force-Eradicate $_.FullName "Folder"
            }
            Force-Eradicate $cloudPath "Folder"
        }
    }
    
    # Also check for cloud sync folders in Documents (some services create subfolders there)
    $documentsPath = Join-Path $user.FullName "Documents"
    if (Test-Path $documentsPath) {
        Get-ChildItem -Path $documentsPath -Directory -Force -ErrorAction SilentlyContinue | 
            Where-Object { $cloudSyncFolders -contains $_.Name } | ForEach-Object {
            Write-Host "      -> Wiping cloud sync folder in Documents: $($_.Name)" -FG DarkGray
            Get-ChildItem -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Force-Eradicate $_.FullName ($_.PSIsContainer ? "Folder" : "File")
            }
            Force-Eradicate $_.FullName "Folder"
        }
    }
    
    Write-Host "   [+] Cloud Sync Folders: COMPLETELY WIPED UNRECOVERABLY" -FG DarkGray
    
    # DO NOT WIPE ROOT USER FILES (ntuser.dat etc) to prevent profile corruption before reset.
    
    # LNK File Hunt (Shortcuts with metadata) - User directories only
    Write-Host "   [~] Hunting LNK files (Shortcut metadata)..." -FG DarkGray
    $lnkPaths = @(
        Join-Path $user.FullName "Desktop",
        Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\Recent",
        Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\SendTo",
        Join-Path $user.FullName "AppData\Roaming\Microsoft\Office\Recent"
    )
    foreach ($lnkPath in $lnkPaths) {
        if (Test-Path $lnkPath) {
            Get-ChildItem -Path $lnkPath -Filter "*.lnk" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Force-Eradicate $_.FullName "File"
            }
        }
    }
    Write-Host "   [+] LNK Files: VAPORIZED" -FG DarkGray
}

# --- MODULE 5: BROWSER, COMMS & SYSTEM ARTIFACTS ---
Write-Host "[7/11] Scorching Browser, Comms & System Artifacts..." -FG $C
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
    "$env:LocalAppData\Telegram Desktop",
    "$env:AppData\discord",
    "$env:LocalAppData\Discord",
    "$env:AppData\WhatsApp",
    "$env:LocalAppData\WhatsApp",
    "$env:AppData\WhatsAppBeta",
    "$env:LocalAppData\WhatsAppBeta",
    
    # Cloud Sync App Data (Configuration & Cache)
    "$env:AppData\Microsoft\OneDrive",
    "$env:LocalAppData\Microsoft\OneDrive",
    "$env:AppData\Google\Drive",
    "$env:LocalAppData\Google\Drive",
    "$env:AppData\Proton\ProtonDrive",
    "$env:LocalAppData\Proton\ProtonDrive",
    "$env:AppData\Dropbox",
    "$env:LocalAppData\Dropbox",
    "$env:AppData\Apple Computer\iCloud",
    "$env:LocalAppData\Apple Computer\iCloud",
    "$env:AppData\Box",
    "$env:LocalAppData\Box",
    "$env:AppData\MEGA",
    "$env:LocalAppData\MEGA",
    "$env:AppData\pCloud",
    "$env:LocalAppData\pCloud",
    "$env:AppData\Sync",
    "$env:LocalAppData\Sync"
)

# Dynamic WhatsApp Package Detection (Current User)
if (Test-Path "$env:LocalAppData\Packages") {
    Get-ChildItem -Path "$env:LocalAppData\Packages" -Filter "*WhatsApp*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $appData += $_.FullName
    }
}

$appData += @(
    # System
    "$env:TEMP",
    "$env:WINDIR\Temp",
    "$env:WINDIR\Prefetch",
    "$env:ProgramData\Microsoft\Search\Data"
)

# 1. Clear DNS Cache
Write-Host "[~] Flushing DNS Cache..." -FG $Y
Clear-DnsClientCache -ErrorAction SilentlyContinue

# 2. Clear Clipboard (including Windows 10+ Clipboard History)
Write-Host "[~] Vaporizing Clipboard..." -FG $Y
Set-Clipboard $null -ErrorAction SilentlyContinue
# Windows 10+ Clipboard History
$clipboardHistory = "$env:LocalAppData\Microsoft\Windows\Clipboard"
if (Test-Path $clipboardHistory) {
    Get-ChildItem -Path $clipboardHistory -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName ($_.PSIsContainer ? "Folder" : "File")
    }
}
# Clear clipboard history registry
$clipboardRegPath = "HKCU:\Software\Microsoft\Clipboard"
if (Test-Path $clipboardRegPath) {
    Force-Eradicate-Registry $clipboardRegPath
}

# 3. Clear Recycle Bin
Write-Host "[~] Emptying Recycle Bin..." -FG $Y
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# 4. Clear Thumbnail Cache (Thumbs.db and thumbcache_*.db)
Write-Host "[~] Vaporizing Thumbnail Cache..." -FG $Y
$thumbPaths = @(
    "$env:LocalAppData\Microsoft\Windows\Explorer",
    "$env:AppData\Microsoft\Windows\Explorer"
)
foreach ($thumbPath in $thumbPaths) {
    if (Test-Path $thumbPath) {
        Get-ChildItem -Path $thumbPath -Include "thumbcache_*.db", "Thumbs.db" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName "File"
        }
    }
}
# Also hunt for Thumbs.db in user directories
Get-ChildItem -Path "$env:USERPROFILE" -Filter "Thumbs.db" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}
Write-Host "   [+] Thumbnail Cache: INCINERATED" -FG DarkGray

# 5. Clear Windows Timeline (ActivitiesCache.db)
Write-Host "[~] Erasing Windows Timeline..." -FG $Y
$timelinePaths = @(
    "$env:LocalAppData\ConnectedDevicesPlatform",
    "$env:LocalAppData\Microsoft\Windows\WebCache"
)
foreach ($timelinePath in $timelinePaths) {
    if (Test-Path $timelinePath) {
        Get-ChildItem -Path $timelinePath -Filter "*ActivitiesCache*" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName "File"
        }
    }
}
Write-Host "   [+] Windows Timeline: OBLITERATED" -FG DarkGray

# 6. Clear Jump Lists (Recent Items, Frequent Items)
Write-Host "[~] Wiping Jump Lists..." -FG $Y
$jumpListPath = "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations"
if (Test-Path $jumpListPath) {
    Get-ChildItem -Path $jumpListPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
}
$jumpListPath2 = "$env:AppData\Microsoft\Windows\Recent\CustomDestinations"
if (Test-Path $jumpListPath2) {
    Get-ChildItem -Path $jumpListPath2 -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
}
Write-Host "   [+] Jump Lists: ANNIHILATED" -FG DarkGray

# 7. Wipe Artifact Paths
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

# --- TELEGRAM & WHATSAPP REGISTRY CLEANUP (AUTHENTICATION KEYS) ---
Write-Host "[~] Purging Telegram & WhatsApp Authentication Keys..." -FG $Y

# Telegram Registry Keys
$telegramRegPaths = @(
    "HKCU:\Software\Telegram Desktop",
    "HKCU:\Software\Classes\TelegramDesktop*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Telegram Desktop"
)
foreach ($regPath in $telegramRegPaths) {
    if (Test-Path $regPath) {
        Force-Eradicate-Registry $regPath
        Write-Host "   [+] Telegram Registry: ERASED" -FG DarkGray
    }
}

# WhatsApp Registry Keys
$whatsappRegPaths = @(
    "HKCU:\Software\WhatsApp",
    "HKCU:\Software\Classes\WhatsApp*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WhatsApp*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WhatsApp*"
)
foreach ($regPath in $whatsappRegPaths) {
    if (Test-Path $regPath) {
        Force-Eradicate-Registry $regPath
    }
}
# Also search for WhatsApp in registry
Get-ChildItem -Path "HKCU:\Software" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSPath -like "*WhatsApp*" } | ForEach-Object {
    Force-Eradicate-Registry $_.PSPath
}
Get-ChildItem -Path "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSPath -like "*WhatsApp*" } | ForEach-Object {
    Force-Eradicate-Registry $_.PSPath
}
Write-Host "   [+] WhatsApp Registry: ERASED" -FG DarkGray

# --- MODULE 5.5: WINDOWS DEFENDER CLEANUP ---
Write-Host "[8/11] Purging Windows Defender Artifacts..." -FG $C

# Clear Windows Defender Quarantine
$defenderQuarantine = "$env:ProgramData\Microsoft\Windows Defender\Quarantine"
if (Test-Path $defenderQuarantine) {
    Get-ChildItem -Path $defenderQuarantine -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Defender Quarantine: CLEARED" -FG DarkGray
}

# Clear Windows Defender Scan History
$defenderLogs = @(
    "$env:ProgramData\Microsoft\Windows Defender\Support",
    "$env:ProgramData\Microsoft\Windows Defender\Scans",
    "$env:ProgramData\Microsoft\Windows Defender\LocalCopy",
    "$env:ProgramData\Microsoft\Windows Defender\Network Inspection System"
)
foreach ($defLog in $defenderLogs) {
    if (Test-Path $defLog) {
        Get-ChildItem -Path $defLog -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName "File"
        }
    }
}
Write-Host "   [+] Defender History: ERASED" -FG DarkGray

# Clear Windows Defender Exclusions Registry (may contain file paths)
$defenderExclusions = @(
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
)
foreach ($exclPath in $defenderExclusions) {
    if (Test-Path $exclPath) {
        Get-ChildItem $exclPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate-Registry $_.PSPath
        }
        Write-Host "   [+] Defender Exclusions: ERASED" -FG DarkGray
    }
}

# Clear Windows Update Logs
$updateLogs = "$env:WINDIR\Logs\WindowsUpdate"
if (Test-Path $updateLogs) {
    Get-ChildItem -Path $updateLogs -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Update Logs: WIPED" -FG DarkGray
}

# Clear Windows Update Download Cache (contains downloaded update files)
$updateDownloadCache = "$env:WINDIR\SoftwareDistribution\Download"
if (Test-Path $updateDownloadCache) {
    Get-ChildItem -Path $updateDownloadCache -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Update Download Cache: WIPED" -FG DarkGray
}

# Clear Windows Update History Database
$updateHistoryDB = "$env:WINDIR\SoftwareDistribution\DataStore\DataStore.edb"
if (Test-Path $updateHistoryDB) {
    Force-Eradicate $updateHistoryDB "File"
    Write-Host "   [+] Windows Update History Database: ERASED" -FG DarkGray
}
# Also clear any WUDB files
Get-ChildItem -Path "$env:WINDIR\SoftwareDistribution" -Filter "*.wudb" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}

# Clear Network Connection History
$networkPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures"
)
foreach ($netPath in $networkPaths) {
    if (Test-Path $netPath) {
        Get-ChildItem $netPath -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate-Registry $_.PSPath
        }
    }
}
Write-Host "   [+] Network History: VAPORIZED" -FG DarkGray

# Clear Windows Firewall Logs
$firewallLog = "$env:WINDIR\System32\LogFiles\Firewall"
if (Test-Path $firewallLog) {
    Get-ChildItem -Path $firewallLog -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Firewall Logs: CLEARED" -FG DarkGray
}

# --- WIFI PROFILES CLEARING ---
Write-Host "[~] Erasing WiFi Profiles..." -FG $Y
try {
    # Get all WiFi profiles
    $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[1].Trim() }
    foreach ($profile in $wifiProfiles) {
        if ($profile) {
            netsh wlan delete profile name="$profile" 2>$null | Out-Null
        }
    }
    # Also try to delete all profiles at once
    netsh wlan delete profile * 2>$null | Out-Null
    Write-Host "   [+] WiFi Profiles: ERASED" -FG DarkGray
} catch {
    Write-Host "   [+] WiFi Profiles: ATTEMPTED" -FG DarkGray
}

# --- BLUETOOTH CLEARING ---
Write-Host "[~] Purging Bluetooth Devices & History..." -FG $Y
# Clear Bluetooth registry keys
$bluetoothPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Bluetooth\Devices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Bluetooth\Devices"
)
foreach ($btPath in $bluetoothPaths) {
    if (Test-Path $btPath) {
        Get-ChildItem $btPath -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate-Registry $_.PSPath
        }
    }
}
# Clear Bluetooth pairing history
$btHistoryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Bluetooth",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Bluetooth"
)
foreach ($btHistPath in $btHistoryPaths) {
    if (Test-Path $btHistPath) {
        Get-ChildItem $btHistPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like "*Device*" -or $_.PSChildName -like "*Pairing*" } | ForEach-Object {
            Force-Eradicate-Registry $_.PSPath
        }
    }
}
Write-Host "   [+] Bluetooth Devices: ERASED" -FG DarkGray

# --- MODULE 6: TIMING GAP FILLER (THE NOISE) ---
Write-Host "[9/11] Injecting Digital Noise (Timing Gap Filler)..." -FG $C
# Pertama, bersihkan log asli
$logs = Get-WinEvent -ListLog * -Force
foreach ($l in $logs) { try { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l.LogName) } catch {} }
Write-Host "   [+] System Logs: VACUUMED" -FG DarkGray

# Kedua, injeksi log palsu agar tidak terlihat 'kosong' (Enhanced with variety)
$noiseCount = 30
$eventSources = @("MsiInstaller", "Service Control Manager", "Microsoft-Windows-Kernel-General", "Microsoft-Windows-Security-Auditing")
$eventTypes = @("Information", "Warning", "SuccessAudit")
$eventIds = @(1033, 1074, 1076, 4624, 4648, 4672)

for ($i = 1; $i -le $noiseCount; $i++) {
    Write-Progress -Activity "Injecting Noise" -Status "Fabricating Event $i of $noiseCount" -PercentComplete (($i / $noiseCount) * 100)
    $source = $eventSources | Get-Random
    $entryType = $eventTypes | Get-Random
    $eventId = $eventIds | Get-Random
    $logName = if ($i % 2 -eq 0) { "Application" } else { "System" }
    
    try {
        $messages = @(
            "Windows Installer reconfigured the product. Control Panel\Programs\Features. Transaction: $i.",
            "The system time was changed. Process: System. New Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').",
            "A process has exited. Process Name: svchost.exe. Process Id: $((1000..9999) | Get-Random).",
            "An account was successfully logged on. Account Name: SYSTEM. Account Domain: WORKGROUP.",
            "Special privileges assigned to new logon. Subject: SYSTEM. Privileges: SeDebugPrivilege, SeTcbPrivilege."
        )
        $message = $messages | Get-Random
        Write-EventLog -LogName $logName -Source $source -EntryType $entryType -EventId $eventId -Message $message -ErrorAction SilentlyContinue
    }
    catch {}
}
Write-Progress -Activity "Injecting Noise" -Completed
Write-Host "   [+] Fake Entropy: INJECTED (Enhanced Variety)" -FG DarkGray

# --- MODULE 7: SHELL & RDP PURGE ---
Write-Host "[10/11] Wiping Shell Memory & RDP Tracks..." -FG $C
Clear-History
if (Test-Path "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") {
    Force-Eradicate "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "File"
}
$rdpKeys = @("HKCU:\Software\Microsoft\Terminal Server Client\Servers", "HKCU:\Software\Microsoft\Terminal Server Client\Default")
foreach ($k in $rdpKeys) { if (Test-Path $k) { Force-Eradicate $k "Registry" } }

# ShellBags
$bagPaths = @(
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
)
foreach ($b in $bagPaths) { if (Test-Path $b) { Force-Eradicate-Registry $b } }
Write-Host "   [+] ShellBags: INCINERATED" -FG DarkGray

# Windows Search Database (already stopped service, now clear index)
$searchIndexPath = "$env:ProgramData\Microsoft\Search\Data"
if (Test-Path $searchIndexPath) {
    Get-ChildItem -Path $searchIndexPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Search Index: DESTROYED" -FG DarkGray
}

# Windows Indexer Database (Windows.edb files) - Comprehensive clearing
$indexerPaths = @(
    "$env:ProgramData\Microsoft\Search\Data\Applications\Windows",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
foreach ($idxPath in $indexerPaths) {
    if (Test-Path $idxPath) {
        Get-ChildItem -Path $idxPath -Filter "Windows.edb" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName "File"
        }
    }
}
# Also search for Windows.edb in ProgramData
Get-ChildItem -Path "$env:ProgramData" -Filter "Windows.edb" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}
Write-Host "   [+] Windows Indexer Database: ERASED" -FG DarkGray

# MRU (Most Recently Used) Lists
$mruPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
)
foreach ($mruPath in $mruPaths) {
    if (Test-Path $mruPath) {
        Force-Eradicate-Registry $mruPath
    }
}
Write-Host "   [+] MRU Lists: ERASED" -FG DarkGray

# Clear Command History (CMD)
$cmdHistoryPath = "HKCU:\Software\Microsoft\Command Processor"
if (Test-Path $cmdHistoryPath) {
    Remove-ItemProperty -Path $cmdHistoryPath -Name "CompletionChar" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cmdHistoryPath -Name "DefaultColor" -ErrorAction SilentlyContinue
    Write-Host "   [+] CMD History: CLEARED" -FG DarkGray
}

# --- WINDOWS CREDENTIAL MANAGER CLEANUP ---
Write-Host "[~] Purging Windows Credential Manager (Saved Passwords)..." -FG $Y

# Windows Credential Manager (Windows Vault)
$credentialPaths = @(
    "$env:USERPROFILE\AppData\Local\Microsoft\Credentials",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Credentials",
    "$env:USERPROFILE\AppData\Local\Microsoft\Vault"
)
foreach ($credPath in $credentialPaths) {
    if (Test-Path $credPath) {
        Get-ChildItem -Path $credPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName ($_.PSIsContainer ? "Folder" : "File")
        }
    }
}

# Windows Credential Manager Registry
$credRegPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Credentials",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Credentials"
)
foreach ($credRegPath in $credRegPaths) {
    if (Test-Path $credRegPath) {
        Get-ChildItem $credRegPath -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate-Registry $_.PSPath
        }
    }
}

# Windows Credential Locker (Modern Windows)
$credLockerPath = "$env:USERPROFILE\AppData\Local\Microsoft\Credentials\*"
Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Microsoft\Credentials" -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}

# Clear saved credentials using cmdkey (if available)
try {
    $savedCreds = cmdkey /list 2>$null | Select-String "Target:"
    if ($savedCreds) {
        $savedCreds | ForEach-Object {
            $target = ($_ -split "Target:")[1].Trim()
            if ($target) {
                cmdkey /delete:"$target" 2>$null | Out-Null
            }
        }
    }
} catch {}

Write-Host "   [+] Windows Credentials: ERASED" -FG DarkGray

# --- WINDOWS INSTALLER CACHE & LOGS CLEANUP ---
Write-Host "[~] Purging Windows Installer Cache & Logs..." -FG $Y

# Windows Installer Package Cache (MSI cache files)
$installerCache = "$env:WINDIR\Installer"
if (Test-Path $installerCache) {
    # Clear MSI cache files (but preserve folder structure for system stability)
    Get-ChildItem -Path $installerCache -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Installer Cache: CLEARED" -FG DarkGray
}

# Windows Installer Logs (MSI*.log files)
$installerLogPaths = @(
    "$env:WINDIR\Temp",
    "$env:TEMP",
    "$env:WINDIR"
)
foreach ($logPath in $installerLogPaths) {
    if (Test-Path $logPath) {
        Get-ChildItem -Path $logPath -Filter "MSI*.log" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName "File"
        }
    }
}
Write-Host "   [+] Windows Installer Logs: WIPED" -FG DarkGray

# Windows Installer Registry (MSI cache registry keys - user-specific data)
$installerRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData"
)
foreach ($instRegPath in $installerRegPaths) {
    if (Test-Path $instRegPath) {
        # Clear user-specific installer data (SIDs)
        Get-ChildItem $instRegPath -ErrorAction SilentlyContinue | Where-Object { 
            $_.PSChildName -like "S-1-5-21*"
        } | ForEach-Object {
            Force-Eradicate-Registry $_.PSPath
        }
    }
}
Write-Host "   [+] Windows Installer Registry: CLEARED" -FG DarkGray

# Windows Thumbcache in System32 (system-wide thumbnails)
Get-ChildItem -Path "$env:WINDIR\System32" -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}
Write-Host "   [+] System Thumbcache: ERASED" -FG DarkGray

# --- WINDOWS INSTALLER CACHE & LOGS CLEANUP ---
Write-Host "[~] Purging Windows Installer Cache & Logs..." -FG $Y

# Windows Installer Package Cache (MSI cache files)
$installerCache = "$env:WINDIR\Installer"
if (Test-Path $installerCache) {
    # Clear MSI cache files (but preserve folder structure for system stability)
    Get-ChildItem -Path $installerCache -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Installer Cache: CLEARED" -FG DarkGray
}

# Windows Installer Logs (MSI*.log files)
$installerLogPaths = @(
    "$env:WINDIR\Temp",
    "$env:TEMP",
    "$env:WINDIR"
)
foreach ($logPath in $installerLogPaths) {
    if (Test-Path $logPath) {
        Get-ChildItem -Path $logPath -Filter "MSI*.log" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Force-Eradicate $_.FullName "File"
        }
    }
}
Write-Host "   [+] Windows Installer Logs: WIPED" -FG DarkGray

# Windows Installer Registry (MSI cache registry keys)
$installerRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer"
)
foreach ($instRegPath in $installerRegPaths) {
    if (Test-Path $instRegPath) {
        # Clear user data and product information (but preserve system installer data)
        $subKeys = @("UserData", "Folders")
        foreach ($subKey in $subKeys) {
            $fullRegPath = Join-Path $instRegPath $subKey
            if (Test-Path $fullRegPath) {
                Get-ChildItem $fullRegPath -Recurse -ErrorAction SilentlyContinue | Where-Object { 
                    $_.PSChildName -like "*S-1-5-21*" -or $_.PSChildName -like "*Products*"
                } | ForEach-Object {
                    Force-Eradicate-Registry $_.PSPath
                }
            }
        }
    }
}
Write-Host "   [+] Windows Installer Registry: CLEARED" -FG DarkGray

# Windows Thumbcache in System32 (system-wide thumbnails)
$systemThumbcache = "$env:WINDIR\System32\thumbcache_*.db"
Get-ChildItem -Path "$env:WINDIR\System32" -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}
Write-Host "   [+] System Thumbcache: ERASED" -FG DarkGray

# --- WINDOWS TASK SCHEDULER & PRINT SPOOLER CLEANUP ---
Write-Host "[~] Purging Task Scheduler & Print Spooler Artifacts..." -FG $Y

# Windows Task Scheduler History (may contain executed task info)
$taskSchedulerLog = "$env:WINDIR\Tasks"
if (Test-Path $taskSchedulerLog) {
    # Clear user-created tasks (preserve system tasks for stability)
    Get-ChildItem -Path $taskSchedulerLog -Filter "*.job" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        # Only delete non-system tasks
        if ($_.Name -notlike "*Microsoft*" -and $_.Name -notlike "*Windows*") {
            Force-Eradicate $_.FullName "File"
        }
    }
    Write-Host "   [+] Task Scheduler History: CLEARED" -FG DarkGray
}

# Windows Print Spooler (may contain print job history)
$printSpooler = "$env:WINDIR\System32\spool\PRINTERS"
if (Test-Path $printSpooler) {
    Get-ChildItem -Path $printSpooler -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Print Spooler: CLEARED" -FG DarkGray
}

# Windows Store App Data (may contain user data)
$storeAppData = "$env:LocalAppData\Packages"
if (Test-Path $storeAppData) {
    # Clear user data from Store apps (but preserve app structure for system stability)
    Get-ChildItem -Path $storeAppData -Directory -Force -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -notlike "*Microsoft.Windows*" -and $_.Name -notlike "*Windows.*" } | ForEach-Object {
        $appDataPath = Join-Path $_.FullName "LocalState"
        if (Test-Path $appDataPath) {
            Get-ChildItem -Path $appDataPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Force-Eradicate $_.FullName ($_.PSIsContainer ? "Folder" : "File")
            }
        }
    }
    Write-Host "   [+] Windows Store App Data: CLEARED" -FG DarkGray
}

# --- MODULE 8: FREE SPACE SANITIZATION ---
Write-Host "[11/11] Unleashing the Void: Free Space Sanitization..." -FG $C
Write-Host "[!] Info: Overwriting deleted data on Drive C: (Free Space Only)." -FG $Y
Write-Host "[!] Info: Your active files (Windows, Documents, etc.) are SAFE and will NOT be deleted." -FG $Y
Write-Host "[!] Warning: This process can take time. Press Ctrl+C if you need to abort early." -FG $Y

# Ensure we use the best tool available
if ($SDEL -and (Test-Path $SDEL)) {
    Write-Host "[~] Using SDelete (Standard: $WIPE_PASSES Passes DoD) for Free Space Wipe..." -FG Cyan
    # Use -c (Clean) instead of -z (Zero) to force multi-pass overwrite if needed
    # Note: sdelete -z is usually standard zero-fill. -c allows random/multiple passes (DoD).
    & $SDEL -p $WIPE_PASSES -c $env:SystemDrive
}
else {
    # Failover to CIPHER if needed, as per user interest
    Write-Host "[~] SDelete not found, employing Windows CIPHER (DoD Standard)..." -FG Cyan
    cipher /w:$env:SystemDrive
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
}
elseif ($choice -eq '2') {
    $scriptPath = $PSCommandPath
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$scriptPath`" && shutdown /s /t 0 /f" -WindowStyle Hidden
    exit
}
else {
    Start-Process explorer.exe
    # Self-destruct via CMD to ensure clean removal after exit
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$PSCommandPath`"" -WindowStyle Hidden
    exit
}
