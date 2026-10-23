$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$packagePath = Join-Path $sourceRoot 'package.json'
$bridgePath = Join-Path $PSScriptRoot 'xbox-failover-bridge.mjs'
$targetRoot = Join-Path $env:USERPROFILE '.dsh\profiles\desktop\node_modules\dsh-plugin-antigravity-quota'

if (-not (Test-Path $packagePath)) { throw "Package metadata not found: $packagePath" }
$pkg = Get-Content $packagePath -Raw | ConvertFrom-Json
if ($pkg.version -ne '1.5.1') { throw "Expected package version 1.5.1, found $($pkg.version). Nothing was copied." }
if (-not (Test-Path $bridgePath)) { throw "Bridge file not found: $bridgePath" }
if ((Get-Content $bridgePath -Raw) -notmatch 'dsh-antigravity-unified-connect-v7') { throw 'Expected bridge build marker missing. Nothing was copied.' }
if (-not (Test-Path $targetRoot)) { throw "Active profile plugin directory not found: $targetRoot. Nothing was copied." }

# DSH should be closed first. Stop only the bridge launched from this exact active-profile
# plugin path and the cli-proxy-api executable installed in that same folder, so files are not locked.
$processesToStop = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $isCliProxy = $_.Name -ieq 'cli-proxy-api.exe' -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)
    $isThisBridge = $_.CommandLine -and $_.CommandLine -match '(?i)xbox-failover-bridge\.mjs' -and $_.CommandLine.IndexOf($targetRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    $isCliProxy -or $isThisBridge
})
foreach ($process in $processesToStop) {
    Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 700
$lockedProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    ($_.Name -ieq 'cli-proxy-api.exe' -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) -or
    ($_.CommandLine -and $_.CommandLine -match '(?i)xbox-failover-bridge\.mjs' -and $_.CommandLine.IndexOf($targetRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
})
if ($lockedProcesses.Count -gt 0) { throw 'The active-profile bridge or cli-proxy-api is still running. Close DSH and retry; no files were copied.' }

$backupRoot = "$targetRoot.backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item -LiteralPath $targetRoot -Destination $backupRoot -Recurse
Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $targetRoot -Recurse -Force

$installedPackage = Get-Content (Join-Path $targetRoot 'package.json') -Raw | ConvertFrom-Json
$installedBridge = Get-Content (Join-Path $targetRoot 'bin\xbox-failover-bridge.mjs') -Raw
if ($installedPackage.version -ne '1.5.1' -or $installedBridge -notmatch 'dsh-antigravity-unified-connect-v7' -or $installedBridge -notmatch '/geohide-eu-doh-probe') {
    throw "Post-copy verification failed. Backup preserved at: $backupRoot"
}

Write-Output 'Active profile plugin updated to version 1.5.1.'
Write-Output ("Backup: {0}" -f $backupRoot)

Write-Output 'Auto starts with GeoHide EU Smart DNS, then GeoHide US and the configured fallback DoH resolvers. GeoHide SNI gateways, Xbox, Karing and ag_dns remain outside Auto; route-health history was left unchanged.'
Write-Output 'No OAuth tokens, passwords, raw auth JSON, or account identifiers were copied, read, or printed by this installer.' 
