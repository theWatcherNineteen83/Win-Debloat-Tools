# Quick Scan variant of the Microsoft Safety Scanner (MSERT) one-time scan.
# Thin wrapper: dot-sources the full scanner script (function definition only,
# no auto-run due to the $MyInvocation guard) and runs it in Quick Scan mode.
# Quick Scan checks only the active/likely-infected areas — much faster than
# a full scan, good as a first pass. Results: %SYSTEMROOT%\debug\msert.log

. "$PSScriptRoot\Invoke-SecurityScanner.ps1"
Invoke-SecurityScanner -QuickScan
