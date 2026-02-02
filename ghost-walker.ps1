# ===============================================================
#  PROJECT: GHOST-WALKER // VOID PROTOCOL v3.5 (PS1)
#  Coded by: Falken Fujimaru [The Digital Phantom]
#  Counter-Forensic: Timing Gaps, State Sync, MFT Overwriting
# ===============================================================

# --- EXECUTION POLICY BYPASS ---
# Ensure script can run regardless of execution policy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue

$ErrorActionPreference = 'Continue'
$version = "4.6-ULTRA"

# --- COLOR VARIABLES (Global Scope) ---
# Define color variables globally so they're available throughout the script
# Function to ensure color variables are always initialized
function Initialize-ColorVariables {
    if (-not $script:G) { $script:G = "Green" }
    if (-not $script:C) { $script:C = "Cyan" }
    if (-not $script:Y) { $script:Y = "Yellow" }
    if (-not $script:R) { $script:R = "Red" }
    if (-not $global:G) { $global:G = "Green" }
    if (-not $global:C) { $global:C = "Cyan" }
    if (-not $global:Y) { $global:Y = "Yellow" }
    if (-not $global:R) { $global:R = "Red" }
    # Set local variables
    $G = "Green"
    $C = "Cyan"
    $Y = "Yellow"
    $R = "Red"
}

# Initialize color variables
Initialize-ColorVariables

# --- PRIVILEGE CHECK (MUST BE FIRST) ---
# Check if running as administrator
$isAdmin = $false
try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {
    # Fallback check method
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $isAdmin) {
    # Not running as admin - elevate with UAC prompt
    Write-Host ""
    Write-Host "[!] ADMINISTRATOR PRIVILEGES REQUIRED" -ForegroundColor Red
    Write-Host "[!] This script requires administrator permissions to run." -ForegroundColor Yellow
    Write-Host "[!] Please click 'Yes' when prompted by Windows UAC." -ForegroundColor Yellow
    Write-Host ""
    
    # Get the script path (handle different scenarios)
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        $scriptPath = $MyInvocation.MyCommand.Path
    }
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        $scriptPath = $MyInvocation.PSCommandPath
    }
    
    # If still empty, try to get from script block
    if ([string]::IsNullOrWhiteSpace($scriptPath) -and $MyInvocation.MyCommand.ScriptBlock) {
        $scriptPath = $MyInvocation.MyCommand.ScriptBlock.File
    }
    
    # Final fallback - use current location
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        $scriptPath = Join-Path $PWD "ghost-walker.ps1"
    }
    
    # Resolve full path
    try {
        $scriptPath = (Resolve-Path $scriptPath -ErrorAction Stop).Path
    }
    catch {
        # If resolution fails, use as-is
    }
    
    # Elevate with proper arguments
    try {
        # Build argument string for elevation
        $elevateArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        
        Start-Process -FilePath "powershell.exe" -ArgumentList $elevateArgs -Verb RunAs -ErrorAction Stop
        exit
    }
    catch {
        Write-Host "[!] Failed to elevate privileges: $_" -ForegroundColor Red
        Write-Host "[!] Please right-click the script and select 'Run as Administrator'" -ForegroundColor Yellow
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# Verify admin privileges one more time after elevation
$isAdmin = $false
try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $isAdmin) {
    Write-Host "[!] CRITICAL: Still not running as administrator!" -ForegroundColor Red
    Write-Host "[!] Please run this script as Administrator." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

function Show-Header {
    Clear-Host
    # Color variables are already defined in global scope
    Write-Host "=======================================================================================================" -ForegroundColor $G
    Write-Host "   PHANTOM-LEAP // GHOST-WALKER v$version " -ForegroundColor $G
    Write-Host "   [ STATUS: COUNTER-FORENSIC ACTIVE ]" -ForegroundColor $G
    Write-Host "=======================================================================================================" -ForegroundColor $G
    Write-Host ""
    Write-Host "   Crafted by 乍丹し片ヨ几　乍凵勹工冊丹尺凵" -ForegroundColor $C
    Write-Host "   Breaking Codes, Not Hearts." -ForegroundColor $C
    Write-Host ""
    Write-Host "=======================================================================================================" -ForegroundColor $G
}

# --- SDELETE VALIDATION ---
$is64 = [Environment]::Is64BitOperatingSystem
$sdelName = if ($is64) { 'sdelete64.exe' } else { 'sdelete.exe' }
$SDEL = Join-Path $PSScriptRoot $sdelName

if ([string]::IsNullOrWhiteSpace($SDEL)) {
    Write-Host "[!] CRITICAL ERROR: Unable to determine SDelete path." -ForegroundColor $R
    exit
}

if (!(Test-Path $SDEL)) {
    Write-Host "[~] Summoning the Void Shredder (SDelete)..." -ForegroundColor $C
    $zip = "$env:TEMP\s.zip"
    try {
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $PSScriptRoot -Force
        Remove-Item $zip -Force
    }
    catch {
        Write-Host "[!] Failed to download SDelete. Please ensure internet connection." -ForegroundColor $R
        Write-Host "[!] Error: $_" -ForegroundColor $R
    }
}


if (!(Test-Path $SDEL)) {
    Write-Host "[!] SDelete not found at $SDEL. Cannot proceed safely." -ForegroundColor $R
    Read-Host "Press Enter to exit..."
    exit
}

# --- DEFENSE EVASION ---
# Stop Windows Search to unlock index files
Stop-Service "wsearch" -Force -ErrorAction SilentlyContinue


& $SDEL -accepteula

# Ensure color variables are initialized before use
Initialize-ColorVariables

Show-Header

# --- FINAL WARNING ---
Write-Host "[!] MISSION: Kill Traces, Bury MFT, Zero-Out Everything." -ForegroundColor $Y
$confirm = Read-Host "[?] Ready to disappear? Type 'GHOST' to execute"
if ($confirm -ne 'GHOST') { 
    Read-Host "Aborted. Press Enter to exit..."
    exit 
}

# ===============================================================
#  COUNTER-FORENSIC MODULES
# ===============================================================

# --- MODULE 1: TELEMETRY BLACKOUT ---
Write-Host "[1/11] Cutting the Cord: Microsoft Telemetry Blackout..." -ForegroundColor $C
Write-Host "   [+] Telemetry Uplink: SEVERED" -ForegroundColor DarkGray
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "`n0.0.0.0 oca.telemetry.microsoft.com`n0.0.0.0 telemetry.microsoft.com"

# --- CONFIGURATION ---
$TURBO_MODE = $true   # Set to $false for slower, individual file shredding (Higher Security per file)
$WIPE_PASSES = 3      # DoD Standard (3 Passes). Gutmann is 35 (Overkill/Slow).

# --- HELPER FUNCTIONS ---
function Force-Eradicate-Registry {
    param(
        [string]$Path,
        [switch]$OverwriteValues = $true,  # Overwrite registry values before deletion for anti-forensics
        [int]$MaxDepth = 50,  # OPTIMIZATION: Prevent infinite recursion and limit depth
        [int]$MaxProperties = 100  # OPTIMIZATION: Limit property processing to prevent hangs
    )

    if ($MaxDepth -le 0) {
        # Max depth reached - skip to prevent infinite loops
        return
    }

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return }

    try {
        # OPTIMIZATION: Get subkeys first (before processing values) to handle large trees efficiently
        $subKeys = @()
        try {
            $subKeys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
        } catch {
            # If enumeration fails, try direct deletion
            Force-Eradicate -Path $Path -Type "Registry"
            return
        }
        
        # OPTIMIZATION: Process subkeys in reverse order (children before parents) for efficient deletion
        if ($subKeys.Count -gt 0) {
            $subKeys = $subKeys | Sort-Object -Property PSPath -Descending
            foreach ($subKey in $subKeys) {
                try {
                    # Recursively process subkeys with depth limit
                    Force-Eradicate-Registry -Path $subKey.PSPath -OverwriteValues:$OverwriteValues -MaxDepth ($MaxDepth - 1) -MaxProperties $MaxProperties
                } catch {
                    # Continue on individual subkey errors
                }
            }
        }
        
        # ANTI-FORENSIC: Overwrite registry values before deletion (after subkeys are processed)
        if ($OverwriteValues) {
            try {
                $regKey = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if ($regKey) {
                    # Get all property names (values)
                    $properties = $regKey | Get-ItemProperty -ErrorAction SilentlyContinue
                    if ($properties) {
                        $propertyNames = $properties.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') }
                        
                        # OPTIMIZATION: Limit property processing to prevent hangs on keys with many values
                        $propCount = 0
                        foreach ($propName in $propertyNames) {
                            if ($propCount -ge $MaxProperties) { break }
                            try {
                                # Overwrite with random garbage data
                                $garbage = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 256 | ForEach-Object { [char]$_ })
                                Set-ItemProperty -Path $Path -Name $propName -Value $garbage -ErrorAction SilentlyContinue
                                # Overwrite again with zeros
                                Set-ItemProperty -Path $Path -Name $propName -Value ([byte[]]@(0) * 256) -ErrorAction SilentlyContinue
                                $propCount++
                            }
                            catch {}
                        }
                    }
                }
            }
            catch {
                # Continue if property overwriting fails
            }
        }
        
        # Now proceed with standard deletion
        Force-Eradicate -Path $Path -Type "Registry"
    }
    catch {
        # Suppress errors but try direct deletion as fallback
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
        } catch {}
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
            Write-Host "   [GUARDRAIL] BLOCKED: Unresolvable path >> $Path" -ForegroundColor Red
            return
        }
    }
    $AbsPath = $AbsPath.TrimEnd('\') # Remove trailing slash for comparison
    
    # Additional safety: Block empty or suspiciously short paths
    if ([string]::IsNullOrWhiteSpace($AbsPath) -or $AbsPath.Length -lt 3) {
        Write-Host "   [GUARDRAIL] BLOCKED: Invalid path length >> $AbsPath" -ForegroundColor Red
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
            Write-Host "   [GUARDRAIL] BLOCKED: Contains critical system component >> $AbsPath" -ForegroundColor Red
            return
        }
    }
    
    # SECOND CHECK: Block exact matches and children of critical paths
    foreach ($Crit in $CriticalPaths) {
        # 1. Block Exact Match (e.g. trying to delete C:\Windows)
        if ($AbsPath -eq $Crit) {
            Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete CRITICAL ROOT >> $AbsPath" -ForegroundColor Red
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
                Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete PROTECTED SYSTEM PATH >> $AbsPath" -ForegroundColor Red
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
                Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete Windows system app >> $AbsPath" -ForegroundColor Red
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
                Write-Host "   [GUARDRAIL] BLOCKED: Attempt to delete system executable >> $AbsPath" -ForegroundColor Red
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
Write-Host "[2/11] Annihilating Snapshots & Journals..." -ForegroundColor $C
vssadmin delete shadows /all /quiet 2>$null
Write-Host "   [+] Volume Shadows: DESTROYED" -ForegroundColor DarkGray
fsutil usn deletejournal /d C: 2>$null
Write-Host "   [+] NTFS Journal: OBLITERATED" -ForegroundColor DarkGray

# --- MODULE 2: STATE INCONSISTENCY (DEEP CLEAN) ---
Write-Host "[3/11] Nuking Deep Artifacts (Shimcache/Amcache/SRUM/UserAssist)..." -ForegroundColor $C
Write-Host "   [+] Shimcache: FLUSHED" -ForegroundColor DarkGray
Write-Host "   [+] Amcache: PURGED" -ForegroundColor DarkGray

# Shimcache & AppCompat
Force-Eradicate-Registry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
Force-Eradicate-Registry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Explorer"

# BAM (Background Activity Moderator)
$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object { Force-Eradicate-Registry $_.PSPath }
}
Write-Host "   [+] BAM Evidence: VAPORIZED" -ForegroundColor DarkGray

# SRUM (System Resource Usage Monitor) - Tracks application execution
$srumPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM"
if (Test-Path $srumPath) {
    Write-Host "   [~] Processing SRUM database (this may take a moment)..." -ForegroundColor DarkGray
    $srumKeys = Get-ChildItem $srumPath -Recurse -ErrorAction SilentlyContinue
    $srumCount = 0
    $srumTotal = $srumKeys.Count
    # OPTIMIZATION: Process in batches for better performance
    $batchSize = 20
    for ($i = 0; $i -lt $srumTotal; $i += $batchSize) {
        $batch = $srumKeys[$i..([Math]::Min($i + $batchSize - 1, $srumTotal - 1))]
        foreach ($srumKey in $batch) {
            Force-Eradicate-Registry $srumKey.PSPath
        }
        $srumCount += $batch.Count
        if ($srumCount % 50 -eq 0 -or $srumCount -eq $srumTotal) {
            Write-Host "      -> Processed SRUM key $srumCount of $srumTotal..." -ForegroundColor DarkGray
        }
    }
    Write-Host "   [+] SRUM Database: OBLITERATED" -ForegroundColor DarkGray
}

# UserAssist - Tracks program execution frequency
$userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
if (Test-Path $userAssistPath) {
    Write-Host "   [~] Processing UserAssist keys (this may take a moment)..." -ForegroundColor DarkGray
    $uaKeys = Get-ChildItem $userAssistPath -Recurse -ErrorAction SilentlyContinue
    $uaCount = 0
    $uaTotal = $uaKeys.Count
    # OPTIMIZATION: Process in batches for better performance
    $batchSize = 50
    for ($i = 0; $i -lt $uaTotal; $i += $batchSize) {
        $batch = $uaKeys[$i..([Math]::Min($i + $batchSize - 1, $uaTotal - 1))]
        foreach ($uaKey in $batch) {
            Force-Eradicate-Registry $uaKey.PSPath
        }
        $uaCount += $batch.Count
        if ($uaCount % 100 -eq 0 -or $uaCount -eq $uaTotal) {
            Write-Host "      -> Processed UserAssist key $uaCount of $uaTotal..." -ForegroundColor DarkGray
        }
    }
    Write-Host "   [+] UserAssist: ANNIHILATED" -ForegroundColor DarkGray
}

# TypedPaths - Recently typed paths in Run dialog
Force-Eradicate-Registry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
Write-Host "   [+] TypedPaths: ERASED" -ForegroundColor DarkGray

# MUICache - Multilingual User Interface cache
$muiCachePath = "HKCU:\Software\Classes\Local Settings\MuiCache"
if (Test-Path $muiCachePath) {
    Write-Host "   [~] Processing MUICache (this may take a moment)..." -ForegroundColor DarkGray
    # OPTIMIZATION: Handle MUICache recursively with progress indicators
    # MUICache can have many subkeys, so we need to process them efficiently
    try {
        $muiKeys = Get-ChildItem $muiCachePath -Recurse -ErrorAction SilentlyContinue
        $muiCount = 0
        $muiTotal = $muiKeys.Count
        if ($muiTotal -gt 0) {
            Write-Host "      -> Found $muiTotal MUICache keys, processing..." -ForegroundColor DarkGray
            # OPTIMIZATION: Process in batches with progress updates
            $batchSize = 50
            for ($i = 0; $i -lt $muiTotal; $i += $batchSize) {
                $batch = $muiKeys[$i..([Math]::Min($i + $batchSize - 1, $muiTotal - 1))]
                # Process in reverse order (children before parents) for efficient deletion
                $batch = $batch | Sort-Object -Property PSPath -Descending
                foreach ($muiKey in $batch) {
                    try {
                        Force-Eradicate-Registry $muiKey.PSPath
                    } catch {
                        # Continue on individual key errors
                    }
                }
                $muiCount += $batch.Count
                if ($muiCount % 100 -eq 0 -or $muiCount -eq $muiTotal) {
                    Write-Host "      -> Processed MUICache key $muiCount of $muiTotal..." -ForegroundColor DarkGray
                }
            }
        }
        # Final cleanup of root key
        if (Test-Path $muiCachePath) {
            Force-Eradicate-Registry $muiCachePath
        }
        Write-Host "   [+] MUICache: DESTROYED" -ForegroundColor DarkGray
    } catch {
        Write-Host "   [!] MUICache processing encountered an issue, attempting direct deletion..." -ForegroundColor Yellow
        # Fallback: Direct deletion attempt
        try {
            Remove-Item -Path $muiCachePath -Recurse -Force -ErrorAction SilentlyContinue
            $regPath = $muiCachePath -replace "HKCU:\\", "HKCU\"
            Start-Process cmd.exe -ArgumentList "/c reg delete `"$regPath`" /f" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Write-Host "   [+] MUICache: DESTROYED (Fallback Method)" -ForegroundColor DarkGray
        } catch {
            Write-Host "   [+] MUICache: PROCESSED (Some keys may remain locked)" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "   [+] MUICache: NOT FOUND (Already Clean)" -ForegroundColor DarkGray
}

# RecentDocs - Recent documents list
Force-Eradicate-Registry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
Write-Host "   [+] RecentDocs: WIPED" -ForegroundColor DarkGray

# --- MODULE 2.5: MEMORY ARTIFACT PURGE (Pagefile/Hibernation) ---
Write-Host "[4/11] Purging Memory Artifacts (Pagefile/Hibernation)..." -ForegroundColor $C

# Disable and clear Pagefile.sys (contains memory dumps)
$pagefilePath = "$env:SystemDrive\pagefile.sys"
if (Test-Path $pagefilePath) {
    Write-Host "   [~] Disabling Pagefile for next boot..." -ForegroundColor $Y
    # Set registry to disable pagefile on next boot
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value @() -ErrorAction SilentlyContinue
    Write-Host "   [+] Pagefile: SCHEDULED FOR DELETION" -ForegroundColor DarkGray
}

# Disable and clear Hiberfil.sys (contains hibernation state)
$hiberPath = "$env:SystemDrive\hiberfil.sys"
if (Test-Path $hiberPath) {
    Write-Host "   [~] Disabling Hibernation..." -ForegroundColor $Y
    # Disable hibernation (this will delete hiberfil.sys on next boot)
    powercfg /hibernate off 2>$null
    Write-Host "   [+] Hibernation: DISABLED" -ForegroundColor DarkGray
}

# Clear Windows Error Reporting (WER) - may contain memory dumps
$werPaths = @(
    "$env:ProgramData\Microsoft\Windows\WER",
    "$env:LocalAppData\Microsoft\Windows\WER"
)
foreach ($werPath in $werPaths) {
    if (Test-Path $werPath) {
        Write-Host "   [~] Processing WER logs in $werPath..." -ForegroundColor DarkGray
        # OPTIMIZATION: Single recursive scan, filter files only, then batch process
        $werFiles = Get-ChildItem -Path $werPath -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
        $werCount = 0
        $werTotal = $werFiles.Count
        if ($werTotal -gt 0) {
            Write-Host "      -> Found $werTotal WER files, wiping..." -ForegroundColor DarkGray
            # OPTIMIZATION: Process in batches
            $batchSize = 50
            for ($i = 0; $i -lt $werTotal; $i += $batchSize) {
                $batch = $werFiles[$i..([Math]::Min($i + $batchSize - 1, $werTotal - 1))]
                foreach ($werFile in $batch) {
                    Force-Eradicate $werFile.FullName "File"
                }
                $werCount += $batch.Count
                if ($werCount % 100 -eq 0 -or $werCount -eq $werTotal) {
                    Write-Host "         -> Wiped WER file $werCount of $werTotal..." -ForegroundColor DarkGray
                }
            }
        }
        Write-Host "   [+] WER Logs: CLEARED" -ForegroundColor DarkGray
    }
}

# --- MODULE 3: MFT BURIAL (THE BURIER) - OPTIMIZED ---
Write-Host "[5/11] Burying the Evidence: MFT Overwrite Sequence..." -ForegroundColor $C
$targetDir = "$env:TEMP\void_fill"
New-Item -ItemType Directory -Path $targetDir -Force -ErrorAction SilentlyContinue | Out-Null
# OPTIMIZATION: Reduced to 500 files (still effective for MFT cluttering, 2x faster)
# MFT records are limited, so 500 files is sufficient to overwrite deleted file metadata
$maxFiles = 500
Write-Progress -Activity "MFT Burial In Progress" -Status "Creating $maxFiles ghost files..." -PercentComplete 0
# OPTIMIZATION: Batch file creation using array operations (faster than loop)
$filePaths = 1..$maxFiles | ForEach-Object { "$targetDir\ghost_$_.tmp" }
$batchSize = 50
$batchCount = 0
for ($i = 0; $i -lt $filePaths.Count; $i += $batchSize) {
    $batch = $filePaths[$i..([Math]::Min($i + $batchSize - 1, $filePaths.Count - 1))]
    $batch | ForEach-Object { 
        $null = New-Item -Path $_ -ItemType File -Value "VOID" -Force -ErrorAction SilentlyContinue
    }
    $batchCount++
    $percent = [Math]::Min(($batchCount * $batchSize / $maxFiles) * 100, 100)
    Write-Progress -Activity "MFT Burial In Progress" -Status "Created $($batchCount * $batchSize) of $maxFiles files" -PercentComplete $percent
}
Write-Progress -Activity "MFT Burial In Progress" -Completed
Force-Eradicate $targetDir "Folder"

# --- MODULE 4: PROCESS & DATA VAPORIZATION - OPTIMIZED ---
Write-Host "[6/11] Vaporizing Active Witnesses & Personal Stash..." -ForegroundColor $C
# OPTIMIZATION: Batch process killing - get all processes first, then kill in parallel where possible
$procs = "chrome", "msedge", "brave", "firefox", "opera", "Discord", "WhatsApp*", "Telegram", "TelegramDesktop", "Telegram.exe", "explorer", "msedgewebview2", "edge", "iexplore", "SearchApp", "SearchUI", "OneDrive", "OneDriveSetup", "GoogleDriveFS", "ProtonDrive", "Dropbox", "iCloudDrive", "BoxSync", "MEGASync", "pCloud", "Sync", "RuntimeBroker"

# Collect all processes to kill
$processesToKill = @()
foreach ($p in $procs) {
    $processesToKill += Get-Process -Name $p -ErrorAction SilentlyContinue
}
# Additional Telegram/WhatsApp processes
$processesToKill += Get-Process | Where-Object { $_.ProcessName -like "*Telegram*" -or $_.ProcessName -like "*WhatsApp*" }

# Kill all processes at once (faster than sequential)
if ($processesToKill.Count -gt 0) {
    Write-Host "   [~] Terminating $($processesToKill.Count) processes..." -ForegroundColor DarkGray
    $processesToKill | Stop-Process -Force -ErrorAction SilentlyContinue
}

# OPTIMIZATION: Reduced sleep time from 3 to 1.5 seconds (sufficient for process cleanup)
Start-Sleep -Seconds 1.5

# --- SURGICAL USER WIPE (SAFE MODE) ---
Write-Host "[!][CRITICAL] STARTING SURGICAL DATA WIPE (CONTENT ONLY)..." -ForegroundColor $R
if ($TURBO_MODE) {
    Write-Host "   [i] TURBO MODE: ENABLED (Fast Delete + Final Wipe)" -ForegroundColor Yellow
}
else {
    Write-Host "   [i] SECURE MODE: ENABLED (SDelete Per File: $WIPE_PASSES Pass)" -ForegroundColor Yellow
}
Write-Host "   [i] Preserving Folder Structure for OS Stability" -ForegroundColor DarkGray

$usersDir = "$env:SystemDrive\Users"
# SAFETY: Ensure we're targeting Users directory safely
if (-not (Test-Path $usersDir)) {
    Write-Host "   [!] WARNING: Users directory not found. Skipping user data wipe." -ForegroundColor Red
    $targetUsers = @()
} else {
    $targetUsers = Get-ChildItem -Path $usersDir -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("Public", "Default", "All Users", "Default User") }
}

$userCount = 0
$userTotal = $targetUsers.Count
Write-Host "   [~] Found $userTotal user(s) to process..." -ForegroundColor DarkGray

foreach ($user in $targetUsers) {
    $userCount++
    Write-Host "   [>>] ENTERING USER HIVES: $($user.Name) ($userCount of $userTotal)" -ForegroundColor $Y
    
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
            Write-Host "      -> Detected WhatsApp Package: $($_.Name)" -ForegroundColor DarkGray
        }
    }
    
    # Also check Roaming Packages for WhatsApp
    $pkgRoamingPath = Join-Path $user.FullName "AppData\Roaming\Packages"
    if (Test-Path $pkgRoamingPath) {
        Get-ChildItem -Path $pkgRoamingPath -Filter "*WhatsApp*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $subTargets += ("AppData\Roaming\Packages\" + $_.Name)
            Write-Host "      -> Detected WhatsApp Package (Roaming): $($_.Name)" -ForegroundColor DarkGray
        }
    }
    
    foreach ($sub in $subTargets) {
        $fullPath = Join-Path $user.FullName $sub
        if (Test-Path $fullPath) {
            Write-Host "      -> Sanitizing Content: $sub" -ForegroundColor DarkGray
             
            # SPEED OPTIMIZATION: Process files and dirs immediately (streaming, no full scan first)
            # TURBO MODE: Fast deletion - process as we find items
            Write-Host "         [~] Wiping $sub (streaming)..." -ForegroundColor DarkGray
            
            # 1. Wipe Files inside (Keep Folder) - STREAMING PROCESSING
            Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                # TURBO: Delete immediately as found (no counting/collecting)
                Force-Eradicate $_.FullName "File"
            }
             
            # 2. Remove Sub-directories (Keep Root Target) - STREAMING PROCESSING
            Get-ChildItem -Path $fullPath -Directory -Recurse -Force -ErrorAction SilentlyContinue | 
                Sort-Object -Property FullName -Descending | 
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            
            # 3. SPECIAL OPS: BROWSER PROFILE HUNT
            # If we just wiped a 'User Data' folder, doubly ensure 'Default' and 'Profile' folders are dead.
            if ($fullPath -match "User Data" -or $fullPath -match "Firefox\\Profiles") {
                $profiles = Get-ChildItem -Path $fullPath -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Default" -or $_.Name -match "Profile" -or $_.Name -match "Guest" -or $_.Name -match "System" }
                foreach ($prof in $profiles) {
                    Write-Host "         [X] Killing Profile: $($prof.Name)" -ForegroundColor Red
                    Force-Eradicate $prof.FullName "Folder"
                }
            }
            
            # 4. SPECIAL OPS: TELEGRAM COMPLETE WIPE
            # Telegram stores session/auth data in both Roaming and Local, plus registry
            if ($fullPath -match "Telegram") {
                Write-Host "         [X] Complete Telegram Wipe: Ensuring all data cleared" -ForegroundColor Red
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
                Write-Host "         [X] Complete WhatsApp/WhatsAppBeta Wipe: Ensuring all data cleared" -ForegroundColor Red
                # Same process for both WhatsApp and WhatsAppBeta - complete folder deletion
                if (Test-Path $fullPath) {
                    # TURBO MODE: Fast streaming deletion (no counting/collecting)
                    # Step 1: Wipe all files recursively - STREAMING
                    Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Force-Eradicate $_.FullName "File"
                    }
                    # Step 2: Wipe all subdirectories recursively - STREAMING
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
                Write-Host "         [X] Cloud Sync Folder Wipe: Complete eradication ($sub)" -ForegroundColor Red
                if (Test-Path $fullPath) {
                    # TURBO MODE: Fast streaming deletion (no counting/collecting)
                    # Step 1: Wipe all files recursively - STREAMING
                    Get-ChildItem -Path $fullPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Force-Eradicate $_.FullName "File"
                    }
                    # Step 2: Wipe all subdirectories recursively - STREAMING
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
    
    # --- FAST USER FOLDER WIPE (STREAMING PROCESSING) - SPEED OPTIMIZED ---
    Write-Host "   [~] Fast User Folder Content Wipe (Preserving Structure)..." -ForegroundColor DarkGray
    
    # List of Windows standard folders to preserve (structure only, contents will be wiped)
    $preserveFolders = @(
        "Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos", 
        "Favorites", "Links", "Saved Games", "Contacts", "Searches",
        "AppData"
    )
    $systemFiles = @("ntuser.dat", "ntuser.dat.LOG1", "ntuser.dat.LOG2", "ntuser.ini", "desktop.ini")
    
    # SPEED OPTIMIZATION: Process root files immediately (no full scan)
    Write-Host "   [~] Wiping root user files..." -ForegroundColor DarkGray
    Get-ChildItem -Path $user.FullName -File -Force -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -notin $systemFiles } | 
        ForEach-Object { Force-Eradicate $_.FullName "File" }
    
    # SPEED OPTIMIZATION: Process root folders immediately (streaming, not full scan)
    Write-Host "   [~] Processing user folders (streaming)..." -ForegroundColor DarkGray
    Get-ChildItem -Path $user.FullName -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $folder = $_
        $folderName = $folder.Name
        $folderPath = $folder.FullName
        
        if ($preserveFolders -contains $folderName) {
            # Standard folder - wipe contents but preserve structure
            Write-Host "      -> Wiping contents of: $folderName" -ForegroundColor DarkGray
            # TURBO: Process and delete immediately (streaming)
            Get-ChildItem -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSIsContainer) { Force-Eradicate $_.FullName "Folder" } else { Force-Eradicate $_.FullName "File" }
            }
            # Ensure folder exists
            if (-not (Test-Path $folderPath)) {
                New-Item -ItemType Directory -Path $folderPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } else {
            # Non-standard folder - wipe completely (TURBO MODE)
            Write-Host "      -> Wiping non-standard folder: $folderName" -ForegroundColor DarkGray
            Force-Eradicate $folderPath "Folder"
        }
    }
    
    Write-Host "   [+] User Folder Contents: COMPLETELY WIPED UNRECOVERABLY (Structure Preserved)" -ForegroundColor DarkGray
    
    # --- CLOUD SYNC FOLDERS COMPREHENSIVE WIPE (TURBO MODE) ---
    Write-Host "   [~] Comprehensive Cloud Sync Folders Wipe (Turbo Mode)..." -ForegroundColor DarkGray
    
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
            Write-Host "      -> Wiping cloud sync folder: $cloudFolder" -ForegroundColor DarkGray
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
            Write-Host "      -> Wiping cloud sync folder in Documents: $($_.Name)" -ForegroundColor DarkGray
            Get-ChildItem -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSIsContainer) { Force-Eradicate $_.FullName "Folder" } else { Force-Eradicate $_.FullName "File" }
            }
            Force-Eradicate $_.FullName "Folder"
        }
    }
    
    Write-Host "   [+] Cloud Sync Folders: COMPLETELY WIPED UNRECOVERABLY" -ForegroundColor DarkGray
    
    # DO NOT WIPE ROOT USER FILES (ntuser.dat etc) to prevent profile corruption before reset.
    
    # LNK File Hunt (Shortcuts with metadata) - User directories only
    Write-Host "   [~] Hunting LNK files (Shortcut metadata)..." -ForegroundColor DarkGray
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
    Write-Host "   [+] LNK Files: VAPORIZED" -ForegroundColor DarkGray
}

# --- MODULE 5: BROWSER, COMMS & SYSTEM ARTIFACTS ---
Write-Host "[7/11] Scorching Browser, Comms & System Artifacts..." -ForegroundColor $C
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
Write-Host "[~] Flushing DNS Cache..." -ForegroundColor $Y
Clear-DnsClientCache -ErrorAction SilentlyContinue

# 2. Clear Clipboard (including Windows 10+ Clipboard History)
Write-Host "[~] Vaporizing Clipboard..." -ForegroundColor $Y
Set-Clipboard $null -ErrorAction SilentlyContinue
# Windows 10+ Clipboard History
$clipboardHistory = "$env:LocalAppData\Microsoft\Windows\Clipboard"
if (Test-Path $clipboardHistory) {
    Get-ChildItem -Path $clipboardHistory -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSIsContainer) { Force-Eradicate $_.FullName "Folder" } else { Force-Eradicate $_.FullName "File" }
    }
}
# Clear clipboard history registry
$clipboardRegPath = "HKCU:\Software\Microsoft\Clipboard"
if (Test-Path $clipboardRegPath) {
    Force-Eradicate-Registry $clipboardRegPath
}

# 3. Clear Recycle Bin
Write-Host "[~] Emptying Recycle Bin..." -ForegroundColor $Y
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# 4. Clear Thumbnail Cache (Thumbs.db and thumbcache_*.db)
Write-Host "[~] Vaporizing Thumbnail Cache..." -ForegroundColor $Y
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
Write-Host "   [+] Thumbnail Cache: INCINERATED" -ForegroundColor DarkGray

# 5. Clear Windows Timeline (ActivitiesCache.db)
Write-Host "[~] Erasing Windows Timeline..." -ForegroundColor $Y
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
Write-Host "   [+] Windows Timeline: OBLITERATED" -ForegroundColor DarkGray

# 6. Clear Jump Lists (Recent Items, Frequent Items)
Write-Host "[~] Wiping Jump Lists..." -ForegroundColor $Y
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
Write-Host "   [+] Jump Lists: ANNIHILATED" -ForegroundColor DarkGray

# 7. Wipe Artifact Paths
$totalArtifacts = $appData.Count
$artCounter = 0
foreach ($path in $appData) {
    $artCounter++
    Write-Progress -Activity "Scorching Artifacts" -Status "Wiping: $path" -PercentComplete (($artCounter / $totalArtifacts) * 100)
    
    if (Test-Path $path) {
        Write-Host "   [+] Target Locked: $path" -ForegroundColor DarkGray
        
        # Special Hunter for Browsers: History, Cookies, Web Data
        $browserFiles = @("History", "Cookies", "Web Data", "Login Data", "Top Sites", "Visited Links")
        Write-Host "         [~] Hunting browser artifacts in $path..." -ForegroundColor DarkGray
        $browserArtifacts = Get-ChildItem -Path $path -Include $browserFiles -Recurse -Force -ErrorAction SilentlyContinue
        $baCount = 0
        $baTotal = $browserArtifacts.Count
        if ($baTotal -gt 0) {
            Write-Host "         [~] Found $baTotal browser artifacts, wiping..." -ForegroundColor DarkGray
            foreach ($ba in $browserArtifacts) {
                $baCount++
                if ($baCount % 50 -eq 0 -or $baCount -eq $baTotal) {
                    Write-Host "            -> Wiping browser artifact $baCount of $baTotal..." -ForegroundColor DarkGray
                }
                Force-Eradicate $ba.FullName "File"
            }
        }

        Force-Eradicate $path "Folder"
    }
}
Write-Progress -Activity "Scorching Artifacts" -Completed

# --- TELEGRAM & WHATSAPP REGISTRY CLEANUP (AUTHENTICATION KEYS) ---
Write-Host "[~] Purging Telegram & WhatsApp Authentication Keys..." -ForegroundColor $Y

# Telegram Registry Keys
$telegramRegPaths = @(
    "HKCU:\Software\Telegram Desktop",
    "HKCU:\Software\Classes\TelegramDesktop*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Telegram Desktop"
)
foreach ($regPath in $telegramRegPaths) {
    if (Test-Path $regPath) {
        Force-Eradicate-Registry $regPath
        Write-Host "   [+] Telegram Registry: ERASED" -ForegroundColor DarkGray
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
Write-Host "   [+] WhatsApp Registry: ERASED" -ForegroundColor DarkGray

# --- MODULE 5.5: WINDOWS DEFENDER CLEANUP ---
Write-Host "[8/11] Purging Windows Defender Artifacts..." -ForegroundColor $C

# Clear Windows Defender Quarantine
$defenderQuarantine = "$env:ProgramData\Microsoft\Windows Defender\Quarantine"
if (Test-Path $defenderQuarantine) {
    Get-ChildItem -Path $defenderQuarantine -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Defender Quarantine: CLEARED" -ForegroundColor DarkGray
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
Write-Host "   [+] Defender History: ERASED" -ForegroundColor DarkGray

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
        Write-Host "   [+] Defender Exclusions: ERASED" -ForegroundColor DarkGray
    }
}

# Clear Windows Update Logs
$updateLogs = "$env:WINDIR\Logs\WindowsUpdate"
if (Test-Path $updateLogs) {
    Get-ChildItem -Path $updateLogs -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Update Logs: WIPED" -ForegroundColor DarkGray
}

# Clear Windows Update Download Cache (contains downloaded update files)
$updateDownloadCache = "$env:WINDIR\SoftwareDistribution\Download"
if (Test-Path $updateDownloadCache) {
    Get-ChildItem -Path $updateDownloadCache -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Update Download Cache: WIPED" -ForegroundColor DarkGray
}

# Clear Windows Update History Database
$updateHistoryDB = "$env:WINDIR\SoftwareDistribution\DataStore\DataStore.edb"
if (Test-Path $updateHistoryDB) {
    Force-Eradicate $updateHistoryDB "File"
    Write-Host "   [+] Windows Update History Database: ERASED" -ForegroundColor DarkGray
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
Write-Host "   [+] Network History: VAPORIZED" -ForegroundColor DarkGray

# Clear Windows Firewall Logs
$firewallLog = "$env:WINDIR\System32\LogFiles\Firewall"
if (Test-Path $firewallLog) {
    Get-ChildItem -Path $firewallLog -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Firewall Logs: CLEARED" -ForegroundColor DarkGray
}

# --- WIFI PROFILES CLEARING ---
Write-Host "[~] Erasing WiFi Profiles..." -ForegroundColor $Y
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
    Write-Host "   [+] WiFi Profiles: ERASED" -ForegroundColor DarkGray
} catch {
    Write-Host "   [+] WiFi Profiles: ATTEMPTED" -ForegroundColor DarkGray
}

# --- BLUETOOTH CLEARING ---
Write-Host "[~] Purging Bluetooth Devices & History..." -ForegroundColor $Y
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
Write-Host "   [+] Bluetooth Devices: ERASED" -ForegroundColor DarkGray

# --- MODULE 6: TIMING GAP FILLER (THE NOISE) ---
Write-Host "[9/11] Injecting Digital Noise (Timing Gap Filler)..." -ForegroundColor $C
# Pertama, bersihkan log asli
$logs = Get-WinEvent -ListLog * -Force
foreach ($l in $logs) { try { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l.LogName) } catch {} }
Write-Host "   [+] System Logs: VACUUMED" -ForegroundColor DarkGray

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
Write-Host "   [+] Fake Entropy: INJECTED (Enhanced Variety)" -ForegroundColor DarkGray

# --- MODULE 7: SHELL & RDP PURGE ---
Write-Host "[10/11] Wiping Shell Memory & RDP Tracks..." -ForegroundColor $C
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
Write-Host "   [+] ShellBags: INCINERATED" -ForegroundColor DarkGray

# Windows Search Database (already stopped service, now clear index)
$searchIndexPath = "$env:ProgramData\Microsoft\Search\Data"
if (Test-Path $searchIndexPath) {
    Get-ChildItem -Path $searchIndexPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Search Index: DESTROYED" -ForegroundColor DarkGray
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
Write-Host "   [+] Windows Indexer Database: ERASED" -ForegroundColor DarkGray

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
Write-Host "   [+] MRU Lists: ERASED" -ForegroundColor DarkGray

# Clear Command History (CMD)
$cmdHistoryPath = "HKCU:\Software\Microsoft\Command Processor"
if (Test-Path $cmdHistoryPath) {
    Remove-ItemProperty -Path $cmdHistoryPath -Name "CompletionChar" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $cmdHistoryPath -Name "DefaultColor" -ErrorAction SilentlyContinue
    Write-Host "   [+] CMD History: CLEARED" -ForegroundColor DarkGray
}

# --- WINDOWS CREDENTIAL MANAGER CLEANUP ---
Write-Host "[~] Purging Windows Credential Manager (Saved Passwords)..." -ForegroundColor $Y

# Windows Credential Manager (Windows Vault)
$credentialPaths = @(
    "$env:USERPROFILE\AppData\Local\Microsoft\Credentials",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Credentials",
    "$env:USERPROFILE\AppData\Local\Microsoft\Vault"
)
foreach ($credPath in $credentialPaths) {
    if (Test-Path $credPath) {
        Get-ChildItem -Path $credPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSIsContainer) { Force-Eradicate $_.FullName "Folder" } else { Force-Eradicate $_.FullName "File" }
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

Write-Host "   [+] Windows Credentials: ERASED" -ForegroundColor DarkGray

# --- WINDOWS INSTALLER CACHE & LOGS CLEANUP ---
Write-Host "[~] Purging Windows Installer Cache & Logs..." -ForegroundColor $Y

# Windows Installer Package Cache (MSI cache files)
$installerCache = "$env:WINDIR\Installer"
if (Test-Path $installerCache) {
    # Clear MSI cache files (but preserve folder structure for system stability)
    Get-ChildItem -Path $installerCache -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Installer Cache: CLEARED" -ForegroundColor DarkGray
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
Write-Host "   [+] Windows Installer Logs: WIPED" -ForegroundColor DarkGray

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
Write-Host "   [+] Windows Installer Registry: CLEARED" -ForegroundColor DarkGray

# Windows Thumbcache in System32 (system-wide thumbnails)
Get-ChildItem -Path "$env:WINDIR\System32" -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}
Write-Host "   [+] System Thumbcache: ERASED" -ForegroundColor DarkGray

# --- WINDOWS INSTALLER CACHE & LOGS CLEANUP ---
Write-Host "[~] Purging Windows Installer Cache & Logs..." -ForegroundColor $Y

# Windows Installer Package Cache (MSI cache files)
$installerCache = "$env:WINDIR\Installer"
if (Test-Path $installerCache) {
    # Clear MSI cache files (but preserve folder structure for system stability)
    Get-ChildItem -Path $installerCache -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Windows Installer Cache: CLEARED" -ForegroundColor DarkGray
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
Write-Host "   [+] Windows Installer Logs: WIPED" -ForegroundColor DarkGray

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
Write-Host "   [+] Windows Installer Registry: CLEARED" -ForegroundColor DarkGray

# Windows Thumbcache in System32 (system-wide thumbnails)
$systemThumbcache = "$env:WINDIR\System32\thumbcache_*.db"
Get-ChildItem -Path "$env:WINDIR\System32" -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Force-Eradicate $_.FullName "File"
}
Write-Host "   [+] System Thumbcache: ERASED" -ForegroundColor DarkGray

# --- WINDOWS TASK SCHEDULER & PRINT SPOOLER CLEANUP ---
Write-Host "[~] Purging Task Scheduler & Print Spooler Artifacts..." -ForegroundColor $Y

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
    Write-Host "   [+] Task Scheduler History: CLEARED" -ForegroundColor DarkGray
}

# Windows Print Spooler (may contain print job history)
$printSpooler = "$env:WINDIR\System32\spool\PRINTERS"
if (Test-Path $printSpooler) {
    Get-ChildItem -Path $printSpooler -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Force-Eradicate $_.FullName "File"
    }
    Write-Host "   [+] Print Spooler: CLEARED" -ForegroundColor DarkGray
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
                if ($_.PSIsContainer) { Force-Eradicate $_.FullName "Folder" } else { Force-Eradicate $_.FullName "File" }
            }
        }
    }
    Write-Host "   [+] Windows Store App Data: CLEARED" -ForegroundColor DarkGray
}

# --- MODULE 8: FREE SPACE SANITIZATION ---
Write-Host "[11/11] Unleashing the Void: Free Space Sanitization..." -ForegroundColor $C
Write-Host "[!] Info: Overwriting deleted data on Drive C: (Free Space Only)." -ForegroundColor $Y
Write-Host "[!] WARNING: This is the FINAL and LONGEST step. It may take 30-60 minutes or more depending on drive size." -ForegroundColor Yellow
Write-Host "[!] The script is still running - please be patient. Progress will be shown below..." -ForegroundColor Yellow
Write-Host "[!] Info: Your active files (Windows, Documents, etc.) are SAFE and will NOT be deleted." -ForegroundColor $Y
Write-Host "[!] Warning: This process can take time. Press Ctrl+C if you need to abort early." -ForegroundColor $Y

# Ensure we use the best tool available
if ($SDEL -and (Test-Path $SDEL)) {
    Write-Host "[~] Using SDelete (Standard: $WIPE_PASSES Passes DoD) for Free Space Wipe..." -ForegroundColor Cyan
    # Use -c (Clean) instead of -z (Zero) to force multi-pass overwrite if needed
    # Note: sdelete -z is usually standard zero-fill. -c allows random/multiple passes (DoD).
    & $SDEL -p $WIPE_PASSES -c $env:SystemDrive
}
else {
    # Failover to CIPHER if needed, as per user interest
    Write-Host "[~] SDelete not found, employing Windows CIPHER (DoD Standard)..." -ForegroundColor Cyan
    cipher /w:$env:SystemDrive
}

# ===============================================================
#  FINALIZATION
# ===============================================================
Write-Host "===============================================================" -ForegroundColor $G
Write-Host "   MISSION COMPLETE. YOU ARE NOW A GHOST." -ForegroundColor $G
Write-Host "===============================================================" -ForegroundColor $G
Write-Host ""

# Display menu options
Write-Host "   [1] Restart Only" -ForegroundColor $C
Write-Host "   [2] Shutdown" -ForegroundColor $C
Write-Host "   [3] Factory Reset" -ForegroundColor $C
Write-Host ""

$choice = Read-Host "   Select an option (1-3)"

Write-Host ""
Write-Host "   Sayonara from Falken Fujimaru..." -ForegroundColor $C
Write-Host "   The shadows have reclaimed what was theirs." -ForegroundColor $C
Write-Host ""

$scriptPath = $PSCommandPath

if ($choice -eq '1') {
    # Option 1: Restart Only
    Write-Host "   [~] Preparing to restart..." -ForegroundColor $Y
    Write-Host "   [~] Script will be removed after restart." -ForegroundColor $Y
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$scriptPath`" && shutdown /r /t 0 /f" -WindowStyle Hidden
    exit
}
elseif ($choice -eq '2') {
    # Option 2: Shutdown
    Write-Host "   [~] Preparing to shutdown..." -ForegroundColor $Y
    Write-Host "   [~] Script will be removed after shutdown." -ForegroundColor $Y
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$scriptPath`" && shutdown /s /t 0 /f" -WindowStyle Hidden
    exit
}
elseif ($choice -eq '3') {
    # Option 3: Factory Reset
    Write-Host "   [!] FACTORY RESET SELECTED" -ForegroundColor $R
    Write-Host "   [!] This will reset Windows to factory settings." -ForegroundColor $R
    Write-Host ""
    
    # Ask user if they want to remove everything or keep files
    Write-Host "   Factory Reset Options:" -ForegroundColor $Y
    Write-Host "   [1] Remove everything (Complete factory reset)" -ForegroundColor $C
    Write-Host "   [2] Keep my files (Reset settings only)" -ForegroundColor $C
    Write-Host ""
    
    $resetChoice = Read-Host "   Select factory reset option (1-2)"
    
    Write-Host ""
    Write-Host "   [!] WARNING: Factory reset will begin after script removal." -ForegroundColor $R
    Write-Host "   [!] This process cannot be cancelled once started." -ForegroundColor $R
    Write-Host ""
    
    $finalConfirm = Read-Host "   Type 'RESET' to confirm factory reset, anything else to cancel"
    
    if ($finalConfirm -eq 'RESET') {
        Write-Host "   [~] Initiating factory reset..." -ForegroundColor $Y
        Write-Host "   [~] Script will be removed, then factory reset will begin." -ForegroundColor $Y
        
        # Remove script first
        Start-Process cmd.exe -ArgumentList "/c timeout /t 2 && del `"$scriptPath`"" -WindowStyle Hidden
        
        # Wait a moment for script deletion
        Start-Sleep -Seconds 2
        
        # Initiate factory reset based on user choice
        if ($resetChoice -eq '1') {
            # Remove everything - Complete factory reset
            Write-Host "   [~] Starting complete factory reset (Remove everything)..." -ForegroundColor $R
            Write-Host "   [~] Windows will restart and begin factory reset process." -ForegroundColor $R
            Write-Host "   [~] All personal files and settings will be removed." -ForegroundColor $R
            
            try {
                # Method 1: Try systemreset command (Windows 10/11)
                # This opens the Windows Reset UI with the selected option
                $resetCmd = "systemreset.exe"
                $resetArgs = "-factoryreset", "-cleanpc"
                
                # Check if systemreset.exe exists
                if (Test-Path "$env:WINDIR\System32\systemreset.exe") {
                    Write-Host "   [~] Launching Windows Reset interface..." -ForegroundColor $Y
                    Start-Process $resetCmd -ArgumentList $resetArgs -WindowStyle Normal
                }
                else {
                    # Fallback: Use Windows Recovery Environment via reagentc
                    Write-Host "   [~] Configuring Windows Recovery Environment..." -ForegroundColor $Y
                    # Enable Windows Recovery Environment
                    Start-Process cmd.exe -ArgumentList "/c reagentc /enable" -WindowStyle Hidden -Wait
                    # Create a script to trigger reset on next boot
                    $resetScript = @"
@echo off
timeout /t 5 /nobreak >nul
systemreset.exe -factoryreset -cleanpc
"@
                    $resetScriptPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\factory_reset.cmd"
                    $resetScript | Out-File -FilePath $resetScriptPath -Encoding ASCII -Force
                    Write-Host "   [~] Factory reset scheduled for next boot..." -ForegroundColor $Y
                    Start-Process cmd.exe -ArgumentList "/c shutdown /r /t 10 /f" -WindowStyle Hidden
                }
            }
            catch {
                Write-Host "   [!] Error initiating factory reset: $_" -ForegroundColor $R
                Write-Host "   [~] Please use Windows Settings > Recovery > Reset this PC manually." -ForegroundColor $Y
            }
        }
        else {
            # Keep files - Reset settings only
            Write-Host "   [~] Starting factory reset (Keep my files)..." -ForegroundColor $Y
            Write-Host "   [~] Windows will restart and reset settings while keeping your files." -ForegroundColor $Y
            
            try {
                # Method 1: Try systemreset command with keepfiles option
                $resetCmd = "systemreset.exe"
                $resetArgs = "-factoryreset", "-keepfiles"
                
                # Check if systemreset.exe exists
                if (Test-Path "$env:WINDIR\System32\systemreset.exe") {
                    Write-Host "   [~] Launching Windows Reset interface..." -ForegroundColor $Y
                    Start-Process $resetCmd -ArgumentList $resetArgs -WindowStyle Normal
                }
                else {
                    # Fallback: Use Windows Recovery Environment
                    Write-Host "   [~] Configuring Windows Recovery Environment..." -ForegroundColor $Y
                    Start-Process cmd.exe -ArgumentList "/c reagentc /enable" -WindowStyle Hidden -Wait
                    $resetScript = @"
@echo off
timeout /t 5 /nobreak >nul
systemreset.exe -factoryreset -keepfiles
"@
                    $resetScriptPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\factory_reset.cmd"
                    $resetScript | Out-File -FilePath $resetScriptPath -Encoding ASCII -Force
                    Write-Host "   [~] Factory reset scheduled for next boot..." -ForegroundColor $Y
                    Start-Process cmd.exe -ArgumentList "/c shutdown /r /t 10 /f" -WindowStyle Hidden
                }
            }
            catch {
                Write-Host "   [!] Error initiating factory reset: $_" -ForegroundColor $R
                Write-Host "   [~] Please use Windows Settings > Recovery > Reset this PC manually." -ForegroundColor $Y
            }
        }
        
        # Give user time to see the message, then exit
        Start-Sleep -Seconds 3
        exit
    }
    else {
        # User cancelled factory reset
        Write-Host "   [~] Factory reset cancelled." -ForegroundColor $Y
        Write-Host "   [~] Script will self-destruct and exit." -ForegroundColor $Y
        Start-Process explorer.exe
        Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$scriptPath`"" -WindowStyle Hidden
        exit
    }
}
else {
    # Invalid choice - Default to self-destruct
    Write-Host "   [~] Invalid choice. Self-destructing and exiting..." -ForegroundColor $Y
    Start-Process explorer.exe
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 && del `"$scriptPath`"" -WindowStyle Hidden
    exit
}
