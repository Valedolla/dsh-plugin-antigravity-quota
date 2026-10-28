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

$profileRoot = Join-Path $env:USERPROFILE '.dsh\profiles\desktop'
$profilePkgPath = Join-Path $profileRoot 'package.json'
if (-not (Test-Path $profilePkgPath)) {
    throw "DSH desktop profile not found at: $profileRoot. Launch DSH at least once before installing."
}

# DSH should be closed first. Stop active bridge and cli-proxy-api if already installed
if (Test-Path $targetRoot) {
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

    # Backup outside node_modules with retention of last 3 backups
    $backupDir = Join-Path $env:LOCALAPPDATA 'AGUnlocker\backups'
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $backupRoot = Join-Path $backupDir "dsh-plugin-antigravity-quota.backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item -LiteralPath $targetRoot -Destination $backupRoot -Recurse -Force

    Get-ChildItem -Path $backupDir -Directory -Filter 'dsh-plugin-antigravity-quota.backup-*' |
        Sort-Object CreationTime -Descending |
        Select-Object -Skip 3 |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
} else {
    New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
}

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

# Remove Zone.Identifier (Mark-of-the-Web) from browser-downloaded files to prevent SmartScreen blocking
Get-ChildItem -Path $targetRoot -Recurse -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue

# Automatically register plugin in ~/.dsh/profiles/desktop/package.json without UTF-8 BOM
$profilePkg = Get-Content $profilePkgPath -Raw | ConvertFrom-Json
if (-not $profilePkg.dependencies) {
    $profilePkg | Add-Member -NotePropertyName 'dependencies' -NotePropertyValue ([PSCustomObject]@{})
}
$profilePkg.dependencies | Add-Member -NotePropertyName 'dsh-plugin-antigravity-quota' -NotePropertyValue "^$expectedVersion" -Force

if (-not $profilePkg.dsh) {
    $profilePkg | Add-Member -NotePropertyName 'dsh' -NotePropertyValue ([PSCustomObject]@{})
}
if (-not $profilePkg.dsh.profile) {
    $profilePkg.dsh | Add-Member -NotePropertyName 'profile' -NotePropertyValue ([PSCustomObject]@{})
}
$bundles = @()
if ($profilePkg.dsh.profile.bundles) { $bundles = @($profilePkg.dsh.profile.bundles) }
if ($bundles -notcontains 'dsh-plugin-antigravity-quota') {
    $bundles += 'dsh-plugin-antigravity-quota'
    $profilePkg.dsh.profile | Add-Member -NotePropertyName 'bundles' -NotePropertyValue $bundles -Force
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($profilePkgPath, ($profilePkg | ConvertTo-Json -Depth 10), $utf8NoBom)

$installedPackage = Get-Content (Join-Path $targetRoot 'package.json') -Raw | ConvertFrom-Json
$installedBridge = Get-Content (Join-Path $targetRoot 'bin\xbox-failover-bridge.mjs') -Raw
if ($installedPackage.version -ne $expectedVersion -or $installedBridge -notmatch 'dsh-antigravity-unified-connect-v7' -or $installedBridge -notmatch '/geohide-eu-doh-probe') {
    throw "Post-copy verification failed. Backup preserved at: $backupRoot"
}

Write-Output "Plugin successfully installed to active DSH profile (version $expectedVersion)."
if ($backupRoot) { Write-Output ("Backup created: {0}" -f $backupRoot) }
Write-Output "Profile package.json verified and registered."
