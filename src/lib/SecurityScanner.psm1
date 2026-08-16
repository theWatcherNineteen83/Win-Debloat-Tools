Import-Module -DisableNameChecking "$PSScriptRoot\Get-TempScriptFolder.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\Request-FileDownload.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\debloat-helper\Remove-ItemVerified.psm1"

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

function Get-ThirdPartyAntivirus() {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param ()

    # SecurityCenter2 (WMI) lists registered antivirus products. Filter out Defender
    # so we only warn about third-party AV (Norton, Avast, McAfee, ESET, ...).
    Try {
        $Products = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
    } Catch {
        Write-Verbose "SecurityCenter2 not available: $($_.Exception.Message)"
        return $null
    }

    If (-not $Products) { return $null }

    $ThirdParty = @()
    ForEach ($Product in $Products) {
        $Name = $Product.displayName
        If ($Name -notmatch 'Windows Defender|Microsoft Defender') {
            # Best-effort active-state decode: productState high byte 0x10/0x11 = ON, 0x00 = OFF
            $StateHex = ([uint32]$Product.productState).ToString('X6')
            $Active = $StateHex.Substring(0, 2) -in @('10', '11')
            $ThirdParty += [PSCustomObject]@{
                Name   = $Name
                Active = $Active
            }
        }
    }

    return $ThirdParty
}

function Invoke-SecurityScanner() {
    [CmdletBinding()]
    param (
        [Switch] $QuickScan,     # Quick Scan instead of Full Scan (faster, checks active/likely-infected areas only)
        [Switch] $DetectionOnly  # Do not auto-clean; detect and report only
    )

    # Warn if a third-party antivirus (Norton, Avast, McAfee, ...) is present.
    $ThirdPartyAV = Get-ThirdPartyAntivirus
    If ($ThirdPartyAV) {
        Write-Title "Third-Party Antivirus Detected"
        ForEach ($AV in $ThirdPartyAV) {
            $StateLabel = If ($AV.Active) { "active" } Else { "installed (possibly inactive)" }
            Write-Status -Types "!", "AV" -Status "Detected: $($AV.Name) ($StateLabel)" -Warning
        }
        Write-Status -Types "?", "AV" -Status "MSERT is on-demand only and does NOT conflict with your antivirus." -Warning
        Write-Status -Types "?", "AV" -Status "If MSERT is blocked or cannot remove a threat: temporarily disable your AV's real-time protection, re-run the scan, then re-enable it." -Warning
        Write-Status -Types "?", "AV" -Status "For stubborn infections, repeat the scan in Windows Safe Mode." -Warning
        Write-DebugLog "Third-party AV detected: $(($ThirdPartyAV | ForEach-Object Name) -join ', ')"
    }

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
