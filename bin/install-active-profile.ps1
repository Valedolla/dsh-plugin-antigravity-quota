$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$packagePath = Join-Path $sourceRoot 'package.json'
$bridgePath = Join-Path $PSScriptRoot 'xbox-failover-bridge.mjs'
$targetRoot = Join-Path $env:USERPROFILE '.dsh\profiles\desktop\node_modules\dsh-plugin-antigravity-quota'

if (-not (Test-Path $packagePath)) { throw "Package metadata not found: $packagePath" }
$pkg = Get-Content $packagePath -Raw | ConvertFrom-Json
$expectedVersion = $pkg.version
if (-not $expectedVersion) { throw "Unable to read version from $packagePath" }
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

$backupDir = Join-Path $env:LOCALAPPDATA 'AGUnlocker\backups'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$backupRoot = Join-Path $backupDir "dsh-plugin-antigravity-quota.backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item -LiteralPath $targetRoot -Destination $backupRoot -Recurse -Force

# Clean copy: exclude git metadata, tests, and temporary backup artifacts
$excludeItems = @('.git', 'tests', '*.bak*', '*.backup-*', '*.clean-bak*', 'node_modules')
$sourceItems = Get-ChildItem -Path $sourceRoot | Where-Object {
    $name = $_.Name
    $skip = $false
    foreach ($pat in $excludeItems) {
        if ($name -like $pat) { $skip = $true; break }
    }
    -not $skip
}

foreach ($item in $sourceItems) {
    Copy-Item -Path $item.FullName -Destination $targetRoot -Recurse -Force
}

$installedPackage = Get-Content (Join-Path $targetRoot 'package.json') -Raw | ConvertFrom-Json
$installedBridge = Get-Content (Join-Path $targetRoot 'bin\xbox-failover-bridge.mjs') -Raw
if ($installedPackage.version -ne $expectedVersion -or $installedBridge -notmatch 'dsh-antigravity-unified-connect-v7' -or $installedBridge -notmatch '/geohide-eu-doh-probe') {
    throw "Post-copy verification failed. Backup preserved at: $backupRoot"
}

Write-Output "Active profile plugin updated to version $expectedVersion."
Write-Output ("Backup: {0}" -f $backupRoot)

Write-Output 'Auto starts with GeoHide EU Smart DNS, then GeoHide US and configured fallback DoH resolvers.'
Write-Output 'No OAuth tokens, passwords, raw auth JSON, or account identifiers were copied, read, or printed by this installer.'
