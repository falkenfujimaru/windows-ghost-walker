# Ghost Walker v4.6-ULTRA // Technical Audit & Architecture Analysis

**Date**: 2026-02-02 (Updated)
**Version**: 4.6-ULTRA
**Status**: ENHANCED (Advanced Anti-Forensics + Hardened Safety)

---

## 1. System Overview
Ghost Walker is a counter-forensic script designed to securely eradicate user artifacts from a Windows environment while maintaining system stability.  
**Latest Upgrades (v4.6-ULTRA)**:
-   **Enhanced Anti-Forensics**: Added 20+ new forensic artifact targets
-   **Registry Overwriting**: Implemented value overwriting before deletion
-   **Memory Artifact Purge**: Pagefile.sys and Hiberfil.sys clearing
-   **Comprehensive User Folder Wipe**: Complete content removal while preserving structure
-   **Multi-Layer Safety Guardrails**: 6-layer protection system
-   **Telegram/WhatsApp Complete Wipe**: Enhanced clearing with registry cleanup
-   **WiFi/Bluetooth Clearing**: Network and device history removal

---

## 2. Implemented Features Analysis

| Feature | Status | Implementation Details |
| :--- | :--- | :--- |
| **Turbo Mode** | **ACTIVE** | Configured via `$TURBO_MODE = $true`. Uses `Remove-Item` for instant deletion of files, relying on Module 11 for cryptographic sanitization. |
| **Safety Guardrails** | **ENHANCED** | 6-layer protection system blocking: `C:\`, `C:\Windows`, `C:\Program Files`, `C:\Users` (root), System32, SysWOW64, WinSxS, Boot, Config, and more. |
| **Registry Overwriting** | **NEW** | `Force-Eradicate-Registry` function overwrites registry values with random data + zeros before deletion. |
| **Memory Artifacts** | **NEW** | Clears Pagefile.sys (scheduled), Hiberfil.sys (disabled), and Windows Error Reporting logs. |
| **WhatsApp Cleaning** | **ENHANCED** | Comprehensive clearing of WhatsApp, WhatsApp Beta, and WhatsApp Store packages. Includes registry cleanup. |
| **Telegram Cleaning** | **ENHANCED** | Complete wipe of Roaming + Local AppData, plus registry authentication keys. |
| **User Folder Wipe** | **NEW** | Comprehensive wipe of all user folder contents while preserving Windows standard folder structure. |
| **WiFi Profiles** | **NEW** | Uses `netsh wlan delete profile` to remove all saved WiFi networks. |
| **Bluetooth Clearing** | **NEW** | Clears Bluetooth device registry keys and pairing history. |
| **Free Space Wipe** | **ACTIVE** | Primary Method: `sdelete -p 3 -c`. Fallback: `cipher /w:C`. Ensures data from "Fast Delete" is unrecoverable. |
| **Browser Wipe** | **ACTIVE** | Targeted removal of History, Cookies, Web Data, and entire User Data folders for major browsers (Chrome, Edge, Brave, Firefox, Opera). |

---

## 3. Security & Safety Mechanisms (Deep Dive)

### A. Turbo Security Model
Instead of spending hours overwriting 50,000+ small cache files (classic SDelete approach), the script now:
1.  **Vaporizes** file entries immediately (Logical Delete).
2.  **Sanitizes** the entire free space of the drive at the end.
    -   *Result*: Deleted data is overwritten with zeros/random data.
    -   *Benefit*: Reduces runtime from Hours -> Minutes.

### B. Multi-Layer Anti-Brick Guardrails (6-Layer Protection System)

#### Layer 1: Path Validation
- Validates path resolution before any operation
- Blocks unresolvable or suspiciously short paths (< 3 characters)
- Prevents empty/null path operations

#### Layer 2: Critical Substring Detection
Blocks paths containing critical Windows components:
- `\System32\`, `\SysWOW64\`, `\WinSxS\`, `\Boot\`, `\Config\`
- `\Program Files\Windows`, `\Program Files (x86)\Windows`
- `\Program Files\Common Files\Microsoft Shared`

#### Layer 3: Critical Path Protection
Expanded critical paths list (13 protected paths):
- `C:\`, `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`
- `C:\Users` (root), `C:\Windows\System32`, `C:\Windows\SysWOW64`
- `C:\Windows\System`, `C:\ProgramData`, `C:\Windows\WinSxS`
- `C:\Windows\Boot`, `C:\Windows\Config`, `C:\Windows\Logs`
- `C:\Windows\SoftwareDistribution`

#### Layer 4: Program Files Protection
- Blocks deletion of Windows, Microsoft, and Common Files folders in Program Files
- Prevents accidental deletion of system applications

#### Layer 5: Critical File Type Protection
- Blocks deletion of `.dll`, `.sys`, `.exe` files in system locations
- Only applies to files in Windows/Program Files directories

#### Layer 6: Exception-Based Safe Deletion
- Safe exceptions: `C:\Windows\Temp`, `C:\Windows\Prefetch`
- Allows clearing logs: `C:\Windows\Logs\CBS`, `C:\Windows\Logs\DISM`

**Protection Logic**:
```powershell
# Multi-layer checks before any deletion
1. Path validation → 2. Substring blocking → 3. Critical path blocking
→ 4. Program Files protection → 5. File type protection → 6. Exception handling
```

### C. Registry Overwriting (Anti-Forensics)
**NEW in v4.6**: `Force-Eradicate-Registry` function:
1. Reads all registry values in a key
2. Overwrites each value with random garbage data (256 chars)
3. Overwrites again with zeros (256 bytes)
4. Recursively processes subkeys
5. Then deletes the key

**Result**: Makes forensic recovery of deleted registry data extremely difficult.

### D. Fallback Redundancy
-   **Wiping**: If `sdelete.exe` is missing/corrupt, the script automatically switches to Windows native `cipher.exe`.
-   **Deletion**: If PowerShell `Remove-Item` fails (locked file), it falls back to CMD `del /f /q` or `rmdir /s /q`.
-   **Process Killing**: Multiple process name variants + wildcard search for Telegram/WhatsApp.

---

## 4. Module Architecture (11 Modules)

### Module 1: Telemetry Blackout
- Disables Windows Telemetry
- Blocks telemetry domains in hosts file

### Module 1.5: Shadow Copy & Journal Purge
- Deletes all Volume Shadow Copies (`vssadmin delete shadows /all`)
- Deletes NTFS USN Journal (`fsutil usn deletejournal`)

### Module 2: State Inconsistency (Deep Registry Clean)
**ENHANCED**: Now includes:
- Shimcache (AppCompatCache)
- Amcache
- BAM (Background Activity Moderator)
- **SRUM** (System Resource Usage Monitor) - NEW
- **UserAssist** (Program execution frequency) - NEW
- **TypedPaths** (Run dialog history) - NEW
- **MUICache** (Multilingual UI cache) - NEW
- **RecentDocs** (Recent documents list) - NEW

All use `Force-Eradicate-Registry` for overwriting before deletion.

### Module 2.5: Memory Artifact Purge (NEW)
- **Pagefile.sys**: Scheduled for deletion on next boot (registry change)
- **Hiberfil.sys**: Hibernation disabled (`powercfg /hibernate off`)
- **Windows Error Reporting (WER)**: Clears memory dump logs

### Module 3: MFT Burial
- Creates 1000 temporary files to overwrite MFT records
- Deletes the void_fill directory

### Module 4: Process & Data Vaporization
**ENHANCED**:
- Stops processes: Chrome, Edge, Brave, Firefox, Opera, Discord, WhatsApp*, Telegram, TelegramDesktop, Telegram.exe
- Wildcard process search for any Telegram/WhatsApp variant
- **Comprehensive User Folder Wipe** (NEW):
  - Wipes ALL files in root user directory (except system files: ntuser.dat, etc.)
  - Wipes ALL non-standard folders
  - Preserves Windows standard folder structure (Desktop, Documents, Downloads, etc.)
  - Wipes contents of standard folders while preserving structure
  - Final pass to catch any remaining items

### Module 5: Browser, Comms & System Artifacts
**ENHANCED**: Now includes:
- Browser data (Chrome, Edge, Brave, Firefox, Opera)
- **Thumbnail Cache** (Thumbs.db, thumbcache_*.db) - NEW
- **Windows Timeline** (ActivitiesCache.db) - NEW
- **Jump Lists** (Recent/Frequent items) - NEW
- **LNK Files** (Shortcut metadata) - NEW
- DNS Cache, Clipboard, Recycle Bin

### Module 5.5: Windows Defender & Network Cleanup (NEW)
- Windows Defender Quarantine clearing
- Windows Defender scan history
- Windows Update logs
- Network connection history (registry)
- Windows Firewall logs

### Module 5.6: Telegram & WhatsApp Registry Cleanup (NEW)
- **Telegram Registry Keys**:
  - `HKCU:\Software\Telegram Desktop`
  - `HKCU:\Software\Classes\TelegramDesktop*`
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Telegram Desktop`
- **WhatsApp Registry Keys**:
  - `HKCU:\Software\WhatsApp`
  - `HKCU:\Software\Classes\WhatsApp*`
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WhatsApp*`
  - `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WhatsApp*`
  - Recursive search through HKCU and HKLM for any WhatsApp-related keys

### Module 5.7: WiFi & Bluetooth Clearing (NEW)
- **WiFi Profiles**: Uses `netsh wlan delete profile` to remove all saved networks
- **Bluetooth**: Clears device registry keys and pairing history:
  - `HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices`
  - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Bluetooth\Devices`
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Bluetooth\Devices`

### Module 6: Timing Gap Filler (Noise Injection)
**ENHANCED**:
- Clears all Windows Event Logs
- Injects 30 fake events (increased from 20)
- Multiple event sources: MsiInstaller, Service Control Manager, Kernel, Security
- Multiple event types: Information, Warning, SuccessAudit
- Multiple event IDs for variety
- More realistic fake log entries

### Module 7: Shell & RDP Purge
**ENHANCED**: Now includes:
- PowerShell history
- RDP connection history
- ShellBags
- **Windows Search Database** - NEW
- **MRU Lists** (Most Recently Used) - NEW
- **CMD History** - NEW

### Module 8: Free Space Sanitization
- Primary: `sdelete -p 3 -c` (3 passes, DoD standard)
- Fallback: `cipher /w:C` (Windows native)

---

## 5. Enhanced Features (v4.6-ULTRA)

### A. Comprehensive User Folder Wipe
**ENHANCED** (v4.6-ULTRA Update): Complete content removal while preserving structure:
- Wipes ALL files in root user directory (except: ntuser.dat, ntuser.dat.LOG1, ntuser.dat.LOG2, ntuser.ini, desktop.ini)
- Wipes ALL non-standard folders completely (any folder not in Windows standard list)
- Preserves Windows standard folders: Desktop, Documents, Downloads, Pictures, Music, Videos, Favorites, Links, Saved Games, Contacts, Searches, AppData, OneDrive
- Wipes contents of standard folders while preserving folder structure
- **Multi-Pass Wiping Process**:
  1. First pass: Wipe root files (except system files)
  2. Second pass: Wipe non-standard folders completely, wipe contents of standard folders
  3. Third pass: Catch any remaining files/folders that might have been missed
  4. Fourth pass: Hunt for hidden/system files and folders
- **Enhanced Coverage**: 
  - Excludes standard Windows AppData subfolders (INetCache, History, Start Menu, SendTo)
  - Targets hidden and system attributes files/folders
  - Ensures ALL non-default/non-basic Windows user folders and files are wiped
- **Result**: User folder structure remains intact, ALL contents are completely wiped unrecoverably

### B. Telegram Complete Wipe
**ENHANCED**:
- Process killing: Multiple variants (Telegram, TelegramDesktop, Telegram.exe) + wildcard search
- Data paths: Both `AppData\Roaming\Telegram Desktop` AND `AppData\Local\Telegram Desktop`
- Registry cleanup: Authentication keys removed
- Complete folder deletion (not just contents)

### C. WhatsApp & WhatsApp Beta Complete Wipe
**ENHANCED** (v4.6-ULTRA Update):
- Process killing: WhatsApp* wildcard + wildcard search (covers both WhatsApp and WhatsAppBeta)
- Data paths: 
  - `AppData\Roaming\WhatsApp`, `AppData\Local\WhatsApp`
  - `AppData\Roaming\WhatsAppBeta`, `AppData\Local\WhatsAppBeta` (same structure as WhatsApp)
- Package detection: Both Local and Roaming Packages folders (covers all WhatsApp variants)
- **Unified Wiping Process**: WhatsAppBeta follows the exact same 3-step process as WhatsApp:
  1. Wipe all files recursively
  2. Wipe all subdirectories recursively
  3. Force delete the entire folder structure
- Registry cleanup: Comprehensive registry key removal (HKCU + HKLM + recursive search)
- **Result**: Both WhatsApp and WhatsAppBeta are completely wiped using identical methodology

### D. Safety Improvements
- Fixed hardcoded `C:\Users` → now uses `$env:SystemDrive\Users`
- Path existence check before user enumeration
- Enhanced error handling for path resolution failures
- Multiple validation layers before any deletion operation

---

## 6. Anti-Forensic Targets (Complete List)

### Registry Artifacts
- Shimcache, Amcache, BAM, SRUM, UserAssist, TypedPaths, MUICache, RecentDocs
- ShellBags, MRU Lists, RDP history, CMD history
- Telegram authentication keys, WhatsApp registry keys
- Network connection history, Bluetooth device registry

### File System Artifacts
- Browser data (Chrome, Edge, Brave, Firefox, Opera)
- Telegram data (Roaming + Local)
- WhatsApp data (Roaming + Local + Beta + Packages)
- Thumbnail cache, Windows Timeline, Jump Lists, LNK files
- Windows Search database, Event Logs (with noise injection)
- Windows Defender quarantine/history, Windows Update logs
- Windows Error Reporting logs
- User folder contents (comprehensive wipe)

### Memory Artifacts
- Pagefile.sys (scheduled for deletion)
- Hiberfil.sys (hibernation disabled)
- Windows Error Reporting dumps

### Network Artifacts
- WiFi profiles (all saved networks)
- Network connection history (registry)
- Windows Firewall logs
- DNS cache

### Bluetooth Artifacts
- Paired device registry keys
- Bluetooth pairing history

---

## 7. Safety Guarantees

### Protected Paths (Never Deleted)
- `C:\` (root)
- `C:\Windows` and all critical subdirectories
- `C:\Program Files` and `C:\Program Files (x86)`
- `C:\Users` (root - only contents of user folders are wiped)
- System32, SysWOW64, WinSxS, Boot, Config
- ProgramData (system-wide app data)

### Preserved User Files
- `ntuser.dat` (user registry hive)
- `ntuser.dat.LOG1`, `ntuser.dat.LOG2` (registry logs)
- `ntuser.ini`, `desktop.ini` (system configuration files)

### Preserved Folder Structure
- Windows standard user folders (Desktop, Documents, Downloads, etc.)
- Folder structure remains intact for OS stability
- Only contents are wiped, not the folders themselves

---

## 8. Performance & Reliability

### Turbo Mode Benefits
- **Before**: Hours (individual file SDelete overwriting)
- **After**: Minutes (logical delete + free space wipe)
- **Security**: Maintained via final free space sanitization

### Reliability
- Multiple fallback mechanisms (PowerShell → CMD → SDelete → Cipher)
- Process killing with multiple name variants
- Comprehensive error handling
- Path validation before operations

---

## 9. Future Considerations

### Potential Enhancements
- **Registry Wipe**: Already implemented (v4.6) ✓
- **Event Log Noise**: Already enhanced (v4.6) ✓
- **Memory Artifacts**: Already implemented (v4.6) ✓
- **Pagefile Clearing**: Already implemented (v4.6) ✓
- **Advanced MFT Manipulation**: Could increase file count for more thorough MFT burial
- **Registry Hive Defragmentation**: Could defragment registry hives after cleaning

---

## 10. Version History

### v4.6-ULTRA (Current - Updated)
- Enhanced anti-forensics (20+ new targets)
- Registry overwriting before deletion
- Memory artifact purge (Pagefile/Hibernation)
- Comprehensive user folder wipe (multi-pass with hidden/system file hunting)
- Multi-layer safety guardrails (6 layers)
- Telegram/WhatsApp complete wipe with registry cleanup
- **WhatsAppBeta unified wiping process** (follows same 3-step process as WhatsApp)
- **Enhanced non-standard user folder/file wiping** (4-pass process ensures complete removal)
- WiFi/Bluetooth clearing
- Enhanced noise injection

### v4.5-ULTRA (Previous)
- Turbo Mode implementation
- Basic safety guardrails
- Dynamic WhatsApp detection

---

*Authorized by: Falken Fujimaru*  
*Last Updated: 2026-02-02*
