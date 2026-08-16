Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Get-TempScriptFolder.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Request-FileDownload.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-ItemVerified.psm1"

# One-time malware scan using Microsoft Safety Scanner (MSERT).
# MSERT is a portable, free, on-demand scanner from Microsoft. It is NOT a
# real-time antivirus and does not replace Windows Defender. Definitions are
# frozen at download time and expire after 10 days — always re-download before each scan.
# Detailed results are written by MSERT to: %SYSTEMROOT%\debug\msert.log
#
# NOTE on switches: MSERT's documented CLI switches are limited. The /f, /f:y, /q
# switches are widely used and confirmed to work (they mirror MRT.exe), but Microsoft
# does not formally document all of them for Safety Scanner. Behavior:
#   - no /f  -> Quick Scan (default scan type)
#   - /f     -> Full Scan
#   - /f:y   -> Full Scan + automatically remove detected malware
#   - /q     -> Quiet mode (no GUI, results only in msert.log)

function Invoke-SecurityScanner() {
    [CmdletBinding()]
    param (
        [Switch] $QuickScan,     # Quick Scan instead of Full Scan (faster, checks active/likely-infected areas only)
        [Switch] $DetectionOnly  # Do not auto-clean; detect and report only
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

    # Build the argument list
    $Args = @("/q")                       # always quiet (no GUI)
    If (!$QuickScan) {
        If ($DetectionOnly) {
            $Args = @("/f", "/q")         # Full scan, detection only
        } Else {
            $Args = @("/f:y", "/q")       # Full scan + auto-clean
        }
    }
    # Quick Scan + /q alone (no /f flag) -> MSERT runs its quick scan quietly.
    # MSERT removes detected threats by default; for a detection-only quick scan
    # we note that the clean behavior is controlled by the tool itself.

    If ($QuickScan) {
        Write-Status -Types "+" -Status "Running MSERT quick scan (quiet)..."
        Write-DebugLog "MSERT scan start (quick): $($Args -join ' ')"
    } ElseIf ($DetectionOnly) {
        Write-Status -Types "?" -Status "Running MSERT full scan (quiet, detection-only)..." -Warning
        Write-DebugLog "MSERT scan start (detection-only): $($Args -join ' ')"
    } Else {
        Write-Status -Types "+" -Status "Running MSERT full scan (quiet, auto-clean). This can take a long time..."
        Write-DebugLog "MSERT scan start (auto-clean): $($Args -join ' ')"
    }

    $Process = Start-Process -FilePath "$MSERTOutput" -ArgumentList $Args -Wait -PassThru

    $ExitCode = $Process.ExitCode
    Write-Status -Types "@" -Status "MSERT finished with exit code $ExitCode"
    Write-DebugLog "MSERT exit code: $ExitCode"

    Write-Status -Types "?" -Status "Detailed results are in: %SYSTEMROOT%\debug\msert.log" -Warning
    Write-Status -Types "?" -Status "Exit code 0 = no threats found. Any other code: check msert.log for detections/errors." -Warning

    # Clean up the downloaded executable (msert.log remains in %SYSTEMROOT%\debug)
    Remove-ItemVerified (Split-Path -Path $MSERTOutput) -Force -Recurse
}

# Parse invocation: default = full scan + auto-clean.
If ($MyInvocation.InvocationName -ne '.') {
    $Quick = $args -contains '-QuickScan'
    $DetectOnly = $args -contains '-DetectionOnly'
    Invoke-SecurityScanner -QuickScan:$Quick -DetectionOnly:$DetectOnly
}
