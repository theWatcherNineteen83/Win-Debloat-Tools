Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Get-TempScriptFolder.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Request-FileDownload.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-ItemVerified.psm1"

# One-time malware scan using Microsoft Safety Scanner (MSERT).
# MSERT is a portable, free, on-demand scanner from Microsoft. It is NOT a
# real-time antivirus and does not replace Windows Defender. Definitions are
# frozen at download time and expire after 10 days — always re-download before each scan.
# Detailed results are written by MSERT to: %SYSTEMROOT%\debug\msert.log

function Invoke-SecurityScanner() {
    [CmdletBinding()]
    param (
        [Switch] $DetectionOnly
    )

    # MSERT has separate 32-bit and 64-bit downloads
    $Is64Bit = [Environment]::Is64BitOperatingSystem
    If ($Is64Bit) {
        $MSERTUri = "https://go.microsoft.com/fwlink/?LinkId=212732" # 64-bit
        $ArchLabel = "64-bit"
    } Else {
        $MSERTUri = "https://go.microsoft.com/fwlink/?LinkId=212733" # 32-bit
        $ArchLabel = "32-bit"
    }

    Write-Title "Microsoft Safety Scanner (MSERT) — One-Time Malware Scan"
    Write-Status -Types "@" -Status "Downloading MSERT ($ArchLabel)..."
    [String] $MSERTOutput = (Request-FileDownload -FileURI $MSERTUri -ExtendFolder "msert" -OutputFile "msert.exe")

    If ($DetectionOnly) {
        # Quiet full scan WITHOUT auto-clean (detection only)
        Write-Status -Types "?" -Status "Running MSERT full scan (quiet, detection-only)..." -Warning
        Write-DebugLog "MSERT scan start (detection-only): /f /q"
        $Process = Start-Process -FilePath "$MSERTOutput" -ArgumentList "/f", "/q" -Wait -PassThru
    } Else {
        # Quiet full scan with auto-clean (MSERT removes detected malware by default)
        Write-Status -Types "+" -Status "Running MSERT full scan (quiet, auto-clean). This can take a long time..."
        Write-DebugLog "MSERT scan start (auto-clean): /f:y /q"
        $Process = Start-Process -FilePath "$MSERTOutput" -ArgumentList "/f:y", "/q" -Wait -PassThru
    }

    $ExitCode = $Process.ExitCode
    Write-Status -Types "@" -Status "MSERT finished with exit code $ExitCode"
    Write-DebugLog "MSERT exit code: $ExitCode"

    Write-Status -Types "?" -Status "Detailed results are in: %SYSTEMROOT%\debug\msert.log" -Warning
    Write-Status -Types "?" -Status "Exit code 0 = no threats found. Any other code: check msert.log for detections/errors." -Warning

    # Clean up the downloaded executable (msert.log remains in %SYSTEMROOT%\debug)
    Remove-ItemVerified (Split-Path -Path $MSERTOutput) -Force -Recurse
}

Invoke-SecurityScanner # [MANUAL] Run a one-time full malware scan with Microsoft Safety Scanner
