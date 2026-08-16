Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\SecurityScanner.psm1" -Force

Invoke-SecurityScanner -QuickScan # [MANUAL] Run a one-time QUICK malware scan with Microsoft Safety Scanner
