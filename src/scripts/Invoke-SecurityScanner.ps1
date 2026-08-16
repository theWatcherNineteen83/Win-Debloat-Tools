Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\SecurityScanner.psm1" -Force

Invoke-SecurityScanner # [MANUAL] Run a one-time FULL malware scan (auto-clean) with Microsoft Safety Scanner
