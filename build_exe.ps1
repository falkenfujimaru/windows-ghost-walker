$sourcePs1 = "ghost-walker.ps1"
$outputExe = "dist\ghost-walker.exe"
$iconPath = "icon.ico" # Optional, if we had one

if (!(Test-Path "dist")) { New-Item -ItemType Directory -Path "dist" | Out-Null }

$scriptContent = Get-Content $sourcePs1 -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
$base64Script = [Convert]::ToBase64String($bytes)

$csharpCode = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

class GhostWalker
{
    static void Main(string[] args)
    {
        string base64Script = "$base64Script";
        string scriptContent = Encoding.UTF8.GetString(Convert.FromBase64String(base64Script));
        string tempPath = Path.Combine(Path.GetTempPath(), "ghost_walker_" + Guid.NewGuid().ToString() + ".ps1");

        try
        {
            File.WriteAllText(tempPath, scriptContent);

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + tempPath + "\"";
            psi.UseShellExecute = false;
            
            Process p = Process.Start(psi);
            p.WaitForExit();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            Console.ReadKey();
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }
}
"@

$csharpFile = "ghost-walker.cs"
Set-Content -Path $csharpFile -Value $csharpCode

$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if (!(Test-Path $csc)) {
    Write-Host "Error: C# Compiler (csc.exe) not found at $csc" -ForegroundColor Red
    exit 1
}

Write-Host "Compiling $outputExe ..."
$compileArgs = "/target:exe", "/out:$outputExe", "/platform:anycpu", "$csharpFile"
Start-Process -FilePath $csc -ArgumentList $compileArgs -NoNewWindow -Wait

if (Test-Path $outputExe) {
    Write-Host "Success! EXE created at: $outputExe" -ForegroundColor Green
    Remove-Item $csharpFile
} else {
    Write-Host "Compilation failed." -ForegroundColor Red
}
