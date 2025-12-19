$ErrorActionPreference = 'SilentlyContinue'
$arch64 = [Environment]::Is64BitOperatingSystem
$sdelName = if ($arch64) { 'sdelete64.exe' } else { 'sdelete.exe' }
$SDEL = Join-Path $PSScriptRoot $sdelName
if (!(Test-Path $SDEL)) {
  Write-Host "[>] SDelete not found. Fetching from Sysinternals..."
  try {
    $zip = Join-Path $env:TEMP 'SDelete.zip'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $PSScriptRoot -Force
  } catch {}
  if (!(Test-Path $SDEL)) {
    if (Test-Path (Join-Path $PSScriptRoot 'sdelete64.exe')) { $SDEL = Join-Path $PSScriptRoot 'sdelete64.exe' }
    elseif (Test-Path (Join-Path $PSScriptRoot 'sdelete.exe')) { $SDEL = Join-Path $PSScriptRoot 'sdelete.exe' }
  }
  if (!(Test-Path $SDEL)) {
    Write-Host "[!] Error: The shredder (sdelete.exe) is missing and download failed from Sysinternals"
    Write-Host "[!] Operation aborted. Check your network or place SDelete next to this script."
    exit 1
  }
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Host "[!] Access Denied. I need God-Mode permissions to go Ghost."
  Write-Host "[>] Relaunching with elevated clearance..."
  Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  exit
}
Start-Process -FilePath $SDEL -ArgumentList "-accepteula" -NoNewWindow -Wait
$host.UI.RawUI.WindowTitle = "GHOST-WALKER // FF VOID PROTOCOL"
Write-Host "=============================================================="
Write-Host "  GHOST-WALKER : THE ULTIMATE TRACE VAPORIZER"
Write-Host "  System Coded by 乍丹し片ヨ几　乍凵勹工冊丹尺凵 — [PRIVATE LICENSE]"
Write-Host "=============================================================="
Write-Host ""
Write-Host "[!] WARNING: You are about to enter Stealth Mode."
Write-Host "[!] Everything you've done on this box will be NUKED."
Write-Host "[>] Booting the Void Engine... Time to vanish."
Write-Host "[>] Flatlining active witnesses (apps) to unlock data vaults..."
"chrome","msedge","brave","firefox","opera","Discord","DiscordCanary","DiscordPTB","WhatsApp","Telegram","explorer" | ForEach-Object { Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue }
function WipePath($path,$startMsg,$endMsg){ if(Test-Path $path){ Write-Host $startMsg; & $SDEL -p 3 -s -q $path; Write-Host $endMsg } }
Write-Host "[>] Zeroing out the personal vaults. No history, no mystery."
WipePath "$env:USERPROFILE\Downloads\*" ">>> Nuking Downloads... shredding every byte." ">>> Downloads folder: VAPORIZED."
WipePath "$env:USERPROFILE\Documents\*" ">>> Sanitizing Documents... leave no trace." ">>> Documents folder: GHOSTED."
WipePath "$env:USERPROFILE\Pictures\*" ">>> Obliterating Media archives..." ">>> Pictures folder: PURGED."
WipePath "$env:USERPROFILE\Videos\*" ">>> Cleaning Video tracks... going dark." ">>> Videos folder: PURGED."
Write-Host "[>] Memory Wipe: Browsers and Comms are going offline."
Write-Host "[>] Choose your Purge Mode: [A]ll-Out / [S]elect / [N]one"
$mode = Read-Host
if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'N' } else { $mode = $mode.Substring(0,1).ToUpper() }
$DO_CHROME=$false;$DO_EDGE=$false;$DO_BRAVE=$false;$DO_FIREFOX=$false;$DO_OPERA=$false;$DO_DISCORD=$false;$DO_WHATSAPP=$false;$DO_TELEGRAM=$false
if ($mode -eq 'A') {
  $DO_CHROME=$true;$DO_EDGE=$true;$DO_BRAVE=$true;$DO_FIREFOX=$true;$DO_OPERA=$true;$DO_DISCORD=$true;$DO_WHATSAPP=$true;$DO_TELEGRAM=$true
} elseif ($mode -eq 'S') {
  function Ask($q){ $r = Read-Host $q; if ([string]::IsNullOrWhiteSpace($r)) { return $false } else { return $r.Trim().ToUpper().StartsWith('Y') } }
  if (Ask "[?] Nuke Chrome? [Y/N]") { $DO_CHROME=$true }
  if (Ask "[?] Nuke Edge? [Y/N]") { $DO_EDGE=$true }
  if (Ask "[?] Nuke Brave? [Y/N]") { $DO_BRAVE=$true }
  if (Ask "[?] Nuke Firefox? [Y/N]") { $DO_FIREFOX=$true }
  if (Ask "[?] Nuke Opera? [Y/N]") { $DO_OPERA=$true }
  if (Ask "[?] Nuke Discord (all variants)? [Y/N]") { $DO_DISCORD=$true }
  if (Ask "[?] Nuke WhatsApp? [Y/N]") { $DO_WHATSAPP=$true }
  if (Ask "[?] Nuke Telegram? [Y/N]") { $DO_TELEGRAM=$true }
}
if ($DO_CHROME -and (Test-Path "$env:LocalAppData\Google\Chrome\User Data\")) { Write-Host ">>> Chrome shadows: Vaporizing..."; & $SDEL -p 3 -s -q "$env:LocalAppData\Google\Chrome\User Data\*"; Write-Host ">>> Chrome cache: VAPORIZED." }
if ($DO_EDGE -and (Test-Path "$env:LocalAppData\Microsoft\Edge\User Data\")) { Write-Host ">>> Edge fingerprints: Shredding..."; & $SDEL -p 3 -s -q "$env:LocalAppData\Microsoft\Edge\User Data\*"; Write-Host ">>> Edge cache: VAPORIZED." }
if ($DO_BRAVE -and (Test-Path "$env:LocalAppData\BraveSoftware\Brave-Browser\User Data\")) { Write-Host ">>> Brave profiles: Obliterating..."; & $SDEL -p 3 -s -q "$env:LocalAppData\BraveSoftware\Brave-Browser\User Data\*"; Write-Host ">>> Brave cache: VAPORIZED." }
if ($DO_FIREFOX -and (Test-Path "$env:AppData\Mozilla\Firefox\Profiles\")) { Write-Host ">>> Firefox profiles: Erasing..."; & $SDEL -p 3 -s -q "$env:AppData\Mozilla\Firefox\Profiles\*"; Write-Host ">>> Firefox profiles: VAPORIZED." }
if ($DO_FIREFOX -and (Test-Path "$env:LocalAppData\Mozilla\Firefox\Profiles\")) { Write-Host ">>> Firefox local profiles: Erasing..."; & $SDEL -p 3 -s -q "$env:LocalAppData\Mozilla\Firefox\Profiles\*"; Write-Host ">>> Firefox local profiles: VAPORIZED." }
if ($DO_FIREFOX -and (Test-Path "$env:AppData\Mozilla\Firefox\Crash Reports\")) { Write-Host ">>> Firefox crash reports: Erasing..."; & $SDEL -p 3 -s -q "$env:AppData\Mozilla\Firefox\Crash Reports\*"; Write-Host ">>> Firefox crash reports: VAPORIZED." }
if ($DO_OPERA -and (Test-Path "$env:AppData\Opera Software\Opera Stable\")) { Write-Host ">>> Opera cache: Erasing..."; & $SDEL -p 3 -s -q "$env:AppData\Opera Software\Opera Stable\*"; Write-Host ">>> Opera cache: VAPORIZED." }
if ($DO_OPERA -and (Test-Path "$env:LocalAppData\Opera Software\Opera Stable\")) { Write-Host ">>> Opera local cache: Erasing..."; & $SDEL -p 3 -s -q "$env:LocalAppData\Opera Software\Opera Stable\*"; Write-Host ">>> Opera local cache: VAPORIZED." }
if ($DO_DISCORD -and (Test-Path "$env:AppData\discord\")) { Write-Host ">>> Discord cache: Erasing..."; & $SDEL -p 3 -s -q "$env:AppData\discord\*"; Write-Host ">>> Discord cache: VAPORIZED." }
if ($DO_DISCORD -and (Test-Path "$env:AppData\discordcanary\")) { Write-Host ">>> Discord Canary cache: Erasing..."; & $SDEL -p 3 -s -q "$env:AppData\discordcanary\*"; Write-Host ">>> Discord Canary cache: VAPORIZED." }
if ($DO_DISCORD -and (Test-Path "$env:AppData\discordptb\")) { Write-Host ">>> Discord PTB cache: Erasing..."; & $SDEL -p 3 -s -q "$env:AppData\discordptb\*"; Write-Host ">>> Discord PTB cache: VAPORIZED." }
if ($DO_DISCORD -and (Test-Path "$env:LocalAppData\Discord\")) { Write-Host ">>> Discord local cache: Erasing..."; & $SDEL -p 3 -s -q "$env:LocalAppData\Discord\*"; Write-Host ">>> Discord local cache: VAPORIZED." }
if ($DO_TELEGRAM -and (Test-Path "$env:AppData\Telegram Desktop\")) { Write-Host ">>> Telegram session: Deleted from reality."; & $SDEL -p 3 -s -q "$env:AppData\Telegram Desktop\*"; Write-Host ">>> Telegram session: VAPORIZED." }
if ($DO_WHATSAPP -and (Test-Path "$env:LocalAppData\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\")) { Write-Host ">>> WhatsApp Desktop: Erasing..."; & $SDEL -p 3 -s -q "$env:LocalAppData\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\*"; Write-Host ">>> WhatsApp Desktop: VAPORIZED." }
if ($DO_WHATSAPP -and (Test-Path "$env:AppData\WhatsApp\")) { Write-Host ">>> WhatsApp Roaming: Erasing..."; & $SDEL -p 3 -s -q "$env:AppData\WhatsApp\*"; Write-Host ">>> WhatsApp Roaming: VAPORIZED." }
Write-Host "[>] Timeline Eraser: Flattening the Event Logs."
$logs = & wevtutil.exe el
foreach($log in $logs){ if([string]::IsNullOrWhiteSpace($log)){continue}; Write-Host ">>> Reality check: Cleaning log $log"; & wevtutil.exe cl "$log"; Write-Host ">>> Event log $log: FLATTENED." }
Write-Host "[>] Digital Breadcrumbs: Deleting the Registry echoes."
if (Test-Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist") { Remove-Item "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" -Recurse -Force; Write-Host ">>> UserAssist: DELETED" }
if (Test-Path "Registry::HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU") { Remove-Item "Registry::HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" -Recurse -Force; Write-Host ">>> Shell BagMRU: DELETED" }
if (Test-Path "Registry::HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags") { Remove-Item "Registry::HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" -Recurse -Force; Write-Host ">>> Shell Bags: DELETED" }
if (Test-Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") { Remove-Item "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Recurse -Force; Write-Host ">>> RunMRU: DELETED" }
if (Test-Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths") { Remove-Item "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Recurse -Force; Write-Host ">>> TypedPaths: DELETED" }
if (Test-Path "Registry::HKCU\Software\Microsoft\Terminal Server Client\Servers") { Remove-Item "Registry::HKCU\Software\Microsoft\Terminal Server Client\Servers" -Recurse -Force; Write-Host ">>> RDP Servers: DELETED" }
if (Test-Path "Registry::HKCU\Software\Microsoft\Terminal Server Client\Default") { Remove-Item "Registry::HKCU\Software\Microsoft\Terminal Server Client\Default" -Recurse -Force; Write-Host ">>> RDP Default: DELETED" }
if (Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Terminal Server Client" -Name "UsernameHint" -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Terminal Server Client" -Name "UsernameHint" -Force; Write-Host ">>> RDP Hints: DELETED" }
if (Test-Path "$env:USERPROFILE\Documents\Default.rdp") { Write-Host ">>> RDP file (Documents\Default.rdp): Erasing..."; Start-Process cmd -ArgumentList "/c attrib -s -h `"$env:USERPROFILE\Documents\Default.rdp`"" -NoNewWindow -Wait; & $SDEL -p 3 -q "$env:USERPROFILE\Documents\Default.rdp"; Write-Host ">>> RDP file (Documents\Default.rdp): VAPORIZED." }
if (Test-Path "$env:USERPROFILE\Default.rdp") { Write-Host ">>> RDP file (Default.rdp): Erasing..."; Start-Process cmd -ArgumentList "/c attrib -s -h `"$env:USERPROFILE\Default.rdp`"" -NoNewWindow -Wait; & $SDEL -p 3 -q "$env:USERPROFILE\Default.rdp"; Write-Host ">>> RDP file (Default.rdp): VAPORIZED." }
if (Test-Path "$env:LocalAppData\Microsoft\Terminal Server Client\Cache\") { Write-Host ">>> RDP bitmap cache: Erasing..."; & $SDEL -p 3 -s -q "$env:LocalAppData\Microsoft\Terminal Server Client\Cache\*"; Write-Host ">>> RDP bitmap cache: VAPORIZED." }
Write-Host ">>> Removing stored RDP credentials..."
$cmdkeyList = & cmdkey /list
foreach($line in $cmdkeyList){ $m=[regex]::Match($line,'TERMSRV\/[^\s]+'); if($m.Success){ & cmdkey /delete:$($m.Value) | Out-Null; Write-Host ">>> RDP credentials $($m.Value): DELETED." } }
if (Test-Path "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\1b4dd67f29cb1962.automaticDestinations-ms") { & $SDEL -p 3 -q "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\1b4dd67f29cb1962.automaticDestinations-ms" }
Write-Host "[>] Shell Silence: Muting the command echoes."
if (Test-Path "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") { & $SDEL -p 3 -q "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" }
Write-Host "[>] Shortcut Purge: Burning the Recent Files and Thumbnails."
if (Test-Path "$env:AppData\Microsoft\Windows\Recent\") { Write-Host ">>> Recent files: Erasing..."; & $SDEL -p 3 -q "$env:AppData\Microsoft\Windows\Recent\*"; Write-Host ">>> Recent files: VAPORIZED." }
if (Test-Path "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\") { Write-Host ">>> JumpLists (AutomaticDestinations): Erasing..."; & $SDEL -p 3 -q "$env:AppData\Microsoft\Windows\Recent\AutomaticDestinations\*"; Write-Host ">>> JumpLists (AutomaticDestinations): VAPORIZED." }
if (Test-Path "$env:AppData\Microsoft\Windows\Recent\CustomDestinations\") { Write-Host ">>> JumpLists (CustomDestinations): Erasing..."; & $SDEL -p 3 -q "$env:AppData\Microsoft\Windows\Recent\CustomDestinations\*"; Write-Host ">>> JumpLists (CustomDestinations): VAPORIZED." }
if (Get-ChildItem "$env:LocalAppData\Microsoft\Windows\Explorer" -Filter "thumbcache_*.db" -ErrorAction SilentlyContinue) { Write-Host ">>> Thumbnail caches: Erasing..."; & $SDEL -p 3 -q "$env:LocalAppData\Microsoft\Windows\Explorer\thumbcache_*.db"; Write-Host ">>> Thumbnail caches: VAPORIZED." }
Write-Host "[>] System Flush: Draining the Temp and Error reports."
if (Test-Path "$env:TEMP\") { Write-Host ">>> Temp folder: Erasing..."; & $SDEL -p 1 -q "$env:TEMP\*"; Write-Host ">>> Temp folder: VAPORIZED." }
if (Test-Path "$env:SystemRoot\Temp\") { Write-Host ">>> Windows Temp: Erasing..."; & $SDEL -p 1 -q "$env:SystemRoot\Temp\*"; Write-Host ">>> Windows Temp: VAPORIZED." }
if (Test-Path "$env:LocalAppData\Microsoft\Windows\WER\") { Write-Host ">>> WER (Local): Erasing..."; & $SDEL -p 1 -q "$env:LocalAppData\Microsoft\Windows\WER\*"; Write-Host ">>> WER (Local): VAPORIZED." }
if (Test-Path "$env:ProgramData\Microsoft\Windows\WER\") { Write-Host ">>> WER (ProgramData): Erasing..."; & $SDEL -p 1 -q "$env:ProgramData\Microsoft\Windows\WER\*"; Write-Host ">>> WER (ProgramData): VAPORIZED." }
if (Test-Path "$env:SystemRoot\Prefetch\") { Write-Host ">>> Prefetch: Erasing..."; & $SDEL -p 1 -q "$env:SystemRoot\Prefetch\*"; Write-Host ">>> Prefetch: VAPORIZED." }
if (Test-Path "$env:SystemRoot\SoftwareDistribution\Download\") { Write-Host ">>> Windows Update downloads: Erasing..."; & $SDEL -p 1 -q "$env:SystemRoot\SoftwareDistribution\Download\*"; Write-Host ">>> Windows Update downloads: VAPORIZED." }
if (Test-Path "$env:SystemRoot\Logs\CBS\") { Write-Host ">>> CBS logs: Erasing..."; & $SDEL -p 1 -q "$env:SystemRoot\Logs\CBS\*"; Write-Host ">>> CBS logs: VAPORIZED." }
if (Test-Path "$env:SystemRoot\Logs\WindowsUpdate\") { Write-Host ">>> Windows Update logs: Erasing..."; & $SDEL -p 1 -q "$env:SystemRoot\Logs\WindowsUpdate\*"; Write-Host ">>> Windows Update logs: VAPORIZED." }
if (Test-Path "$env:ProgramData\USOShared\Logs\") { Write-Host ">>> USOShared logs: Erasing..."; & $SDEL -p 1 -q "$env:ProgramData\USOShared\Logs\*"; Write-Host ">>> USOShared logs: VAPORIZED." }
Write-Host ">>> RDP Registry MRU: Purging..."
if (Test-Path "Registry::HKCU\Software\Microsoft\Terminal Server Client\Default") { Remove-Item "Registry::HKCU\Software\Microsoft\Terminal Server Client\Default" -Recurse -Force }
if (Test-Path "Registry::HKCU\Software\Microsoft\Terminal Server Client\Servers") { Remove-Item "Registry::HKCU\Software\Microsoft\Terminal Server Client\Servers" -Recurse -Force }
New-Item -Path "Registry::HKCU\Software\Microsoft\Terminal Server Client\Servers" -Force | Out-Null
New-Item -Path "Registry::HKCU\Software\Microsoft\Terminal Server Client\Default" -Force | Out-Null
Write-Host "[>] Final Pockets: Emptying the Bin and Clipboard."
Set-Clipboard -Value ""
if (Test-Path "$env:LocalAppData\Microsoft\Windows\Clipboard\") { Write-Host ">>> Clipboard history: Erasing..."; & $SDEL -p 1 -q "$env:LocalAppData\Microsoft\Windows\Clipboard\*"; Write-Host ">>> Clipboard history: VAPORIZED." }
if (Test-Path "$env:SystemDrive\$Recycle.Bin") { Write-Host ">>> Recycle Bin: Erasing..."; & $SDEL -p 3 -s -q "$env:SystemDrive\$Recycle.Bin"; Write-Host ">>> Recycle Bin: VAPORIZED." }
Write-Host "[>] Void Filling: Overwriting free space on $env:SystemDrive (Sanitize Mode)"
& $SDEL -z $env:SystemDrive
$fixed = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.Name -ne ("$env:SystemDrive" + "\") }
if ($fixed.Count -gt 0) {
  $list = ($fixed | ForEach-Object { $_.Name.TrimEnd('\') }) -join ' '
  Write-Host "[>] Fixed non-system drives detected: $list"
  Write-Host "[>] Choose free-space wipe: [A]ll / [S]elect / [N]one"
  $fs = Read-Host
  if ([string]::IsNullOrWhiteSpace($fs)) { $fs = 'N' } else { $fs = $fs.Substring(0,1).ToUpper() }
  if ($fs -eq 'A') {
    foreach($d in $fixed){ $dn = $d.Name.TrimEnd('\'); Write-Host ">>> Free space $dn: Erasing..."; & $SDEL -z $dn; Write-Host ">>> Free space $dn: SANITIZED." }
  } elseif ($fs -eq 'S') {
    foreach($d in $fixed){ $dn = $d.Name.TrimEnd('\'); $ans = Read-Host "[>] Overwrite free space on $dn ? [Y/N]"; if([string]::IsNullOrWhiteSpace($ans) -or ($ans.Trim().ToUpper().StartsWith('N'))){ Write-Host ">>> Free space $dn: SKIPPED." } else { Write-Host ">>> Free space $dn: Erasing..."; & $SDEL -z $dn; Write-Host ">>> Free space $dn: SANITIZED." } }
  } else {
    Write-Host ">>> Non-system drive free-space wipe: SKIPPED."
  }
}
Start-Process explorer.exe
Write-Host ""
Write-Host "=============================================================="
Write-Host " OPERATION COMPLETE — SYSTEM IS NOW STERILE."
Write-Host " Your forensic footprint has been vaporized into the void."
Write-Host " Logs: DEAD. Session: DEAD. History: DEAD."
Write-Host "=============================================================="
Write-Host ""
Write-Host "[1] Full Reboot (Clear RAM Shadows)"
Write-Host "[2] Hard Shutdown (Ghost Out)"
Write-Host "[3] Stealth Exit (Self-Destruct Script)"
Write-Host ""
$opt = Read-Host
if ([string]::IsNullOrWhiteSpace($opt)) { $opt = '3' } else { $opt = $opt.Substring(0,1) }
switch ($opt) {
  '1' { Write-Host "[>] Initializing System Reset... Fade to black."; Start-Process -WindowStyle Hidden -FilePath powershell -ArgumentList "Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath '$PSCommandPath' -Force"; Restart-Computer -Force }
  '2' { Write-Host "[>] Initializing Hard Shutdown... Going dark."; Start-Process -WindowStyle Hidden -FilePath powershell -ArgumentList "Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath '$PSCommandPath' -Force"; Stop-Computer -Force }
  default { Write-Host "[>] Shredding Ghost-Walker script... Bye."; Start-Process -WindowStyle Hidden -FilePath powershell -ArgumentList "Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath '$PSCommandPath' -Force"; exit }
}
