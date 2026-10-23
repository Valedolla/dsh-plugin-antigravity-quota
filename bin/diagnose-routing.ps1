$ErrorActionPreference = 'Continue'
$expectedProxyUrl = 'http://127.0.0.1:53130'
$configPath = Join-Path $PSScriptRoot 'config.yaml'
$homePath = [Environment]::GetFolderPath('UserProfile')
$authDir = Join-Path $homePath '.cli-proxy-api'
$vaultDir = Join-Path (Join-Path $homePath '.dsh') 'antigravity-vault'

function Get-SafeProxyUrl([object]$value) {
    if (-not ($value -is [string]) -or [string]::IsNullOrWhiteSpace($value)) { return '(not set)' }
    try {
        $uri = [uri]$value
        if (-not $uri.IsAbsoluteUri -or @('http', 'https') -notcontains $uri.Scheme) { return '(invalid or unsupported URL)' }
        return ('{0}://{1}:{2}' -f $uri.Scheme, $uri.Host, $uri.Port)
    } catch { return '(invalid URL)' }
}

Write-Output '=== Antigravity routing diagnostics (secrets are not printed) ==='
$configProxyUrl = '(not found)'
$configWriteTime = $null
try {
    $configItem = Get-Item $configPath -ErrorAction Stop
    $configWriteTime = $configItem.LastWriteTime
    $configText = Get-Content $configPath -Raw -ErrorAction Stop
    $configMatch = [regex]::Match($configText, '(?m)^\s*proxy-url\s*:\s*"?([^"\r\n#]+)')
    if ($configMatch.Success) { $configProxyUrl = Get-SafeProxyUrl $configMatch.Groups[1].Value.Trim() }
} catch {}
Write-Output ("config.yaml proxy-url: {0}" -f $configProxyUrl)
Write-Output ("Expected proxy-url: {0}" -f $expectedProxyUrl)

$activeEmail = $null
try {
    $statePath = Join-Path $vaultDir 'active-account.json'
    if (Test-Path $statePath) { $activeEmail = (Get-Content $statePath -Raw | ConvertFrom-Json).activeEmail }
} catch {}
$activeAuthProxyUrl = '(active auth not found)'
$authFiles = @(Get-ChildItem -Path $authDir -Filter 'antigravity-*.json' -File -ErrorAction SilentlyContinue)
foreach ($file in $authFiles) {
    try {
        $authData = Get-Content $file.FullName -Raw | ConvertFrom-Json
        if (-not $activeEmail -or $authData.email -eq $activeEmail) {
            $activeAuthProxyUrl = Get-SafeProxyUrl $authData.proxy_url
            if ($activeEmail) { break }
        }
    } catch {}
}
Write-Output ("Active auth proxy_url: {0}" -f $activeAuthProxyUrl)
$filesMatch = $configProxyUrl -eq $expectedProxyUrl -and $activeAuthProxyUrl -eq $expectedProxyUrl
Write-Output ("Config/auth URL alignment: {0}" -f $(if ($filesMatch) { 'OK' } else { 'MISMATCH' }))

$listeners = @()
try {
    $ports = @(53129, 53130, 8317)
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $ports -contains [int]$_.LocalPort } | ForEach-Object {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $_.OwningProcess) -ErrorAction SilentlyContinue
        $start = $null
        if ($proc.CreationDate) { $start = [datetime]$proc.CreationDate }
        [PSCustomObject]@{
            Port = [int]$_.LocalPort
            PID = [int]$_.OwningProcess
            Process = [string]$proc.Name
            BridgeScript = ([string]$proc.CommandLine -match '(?i)xbox-failover-bridge\.mjs')
            CliProxy = ([string]$proc.Name -ieq 'cli-proxy-api.exe')
            StartTime = $start
        }
    })
} catch { Write-Output 'Listener inspection: FAILED (Get-NetTCPConnection/Get-CimInstance unavailable or access denied)' }
foreach ($port in @(53130, 53129, 8317)) {
    $found = @($listeners | Where-Object { $_.Port -eq $port })
    if (-not $found.Count) {
        Write-Output ("Listener {0}: none" -f $port)
    } else {
        foreach ($listener in $found) {
            Write-Output ("Listener {0}: PID {1}, process={2}, bridge-script={3}, cli-proxy-api={4}" -f $port, $listener.PID, $listener.Process, $listener.BridgeScript, $listener.CliProxy)
            if ($port -eq 8317 -and $listener.CliProxy -and $configWriteTime) {
                Write-Output ("cli-proxy-api started after config.yaml mtime: {0}" -f ($listener.StartTime -ge $configWriteTime))
            }
        }
    }
}

try {
    $bridge = Invoke-RestMethod -Uri 'http://127.0.0.1:53130/status' -TimeoutSec 2
    Write-Output ("Bridge build: {0}; port: {1}; route preference: {2}" -f $bridge.bridgeBuildId, $bridge.port, $bridge.routePreference)
    if ($bridge.autoRouteIds) { Write-Output ("Auto routes in order: {0}; GeoHide SNI #1-#3/Xbox/Karing/ag_dns excluded from Auto" -f (@($bridge.autoRouteIds) -join ', ')) }
    Write-Output ("Last transport: route={0}; kind={1}; effect={2}; at={3}" -f $bridge.lastTransportRoute.id, $bridge.lastTransportRoute.kind, $bridge.lastTransportRoute.routingEffect, $bridge.lastTransportRoute.at)
    if ($bridge.lastApiResult) {
        Write-Output ("Last API check: stage={0}; ok={1}; status={2}; at={3}" -f $bridge.lastApiResult.stage, $bridge.lastApiResult.ok, $bridge.lastApiResult.shortStatus, $bridge.lastApiResult.at)
    } else {
        Write-Output 'Last API check: none'
    }
    if ($bridge.lastDiagnosticConnect) {
        Write-Output ("Last diagnostic CONNECT: target={0}; header-received={1}; stage={2}; route-id={3}; route-kind={4}; at={5}" -f $bridge.lastDiagnosticConnect.target, $bridge.lastDiagnosticConnect.diagnosticHeaderReceived, $bridge.lastDiagnosticConnect.stage, $bridge.lastDiagnosticConnect.routeId, $bridge.lastDiagnosticConnect.routeKind, $bridge.lastDiagnosticConnect.at)
        if ($bridge.lastDiagnosticConnect.error) {
            Write-Output ("Diagnostic CONNECT detail: {0}" -f ([string]$bridge.lastDiagnosticConnect.error -replace '[\r\n]+', ' '))
        }
    } else {
        Write-Output 'Last diagnostic CONNECT: none recorded by the active bridge build'
    }
    if ($bridge.lastTransportRoute.kind -eq 'resolver') {
        Write-Output 'WARNING: active transport is ordinary DoH/DNS-only; it does not change the egress IP.'
    }
    if ($bridge.lastTransportRoute.kind -eq 'smart-resolver') {
        Write-Output 'INFO: active transport is GeoHide Smart DNS; run the region-specific non-generative probe to check DNS proxy answers and TLS/SNI.'
    }
    $karingPortReachable = Test-NetConnection -ComputerName '127.0.0.1' -Port 3066 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    Write-Output ("Karing full-proxy listener 127.0.0.1:3066: {0}" -f $(if ($karingPortReachable) { 'reachable' } else { 'not listening' }))
    if ($bridge.temporarilyFailedRouteIds -and @($bridge.temporarilyFailedRouteIds).Count -gt 0) {
        Write-Output ("Auto temporarily excludes routes after TLS failures: {0}" -f (@($bridge.temporarilyFailedRouteIds) -join ', '))
    }
    if ($bridge.bridgeBuildId -ne 'dsh-antigravity-unified-connect-v7') {
        Write-Output 'WARNING: an old or unrelated bridge build owns port 53130.'
    }
} catch {
    Write-Output 'Bridge status: FAILED or port 53130 is not the current unified bridge.'
}

$mainBridge = @($listeners | Where-Object { $_.Port -eq 53130 -and $_.BridgeScript -eq $true })
$compatBridge = @($listeners | Where-Object { $_.Port -eq 53129 -and $_.BridgeScript -eq $true })
if ($mainBridge.Count -gt 0 -and $compatBridge.Count -gt 0 -and $mainBridge[0].PID -eq $compatBridge[0].PID) {
    Write-Output '53129/53130 ownership: OK, same bridge process (compatibility listener).'
} else {
    Write-Output '53129/53130 ownership: NOT CONFIRMED as the same bridge process.'
}
Write-Output 'No OAuth tokens, passwords, raw auth JSON, process command lines, or account identifiers were printed.'
