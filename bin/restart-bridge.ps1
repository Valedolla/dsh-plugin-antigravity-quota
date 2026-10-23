$ErrorActionPreference = 'Stop'
$ports = @(53130, 53129)
$bridgePattern = '(?i)xbox-failover-bridge\.mjs'

foreach ($port in $ports) {
    $connections = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    foreach ($connection in $connections) {
        $processId = [int]$connection.OwningProcess
        if ($processId -le 4) { continue }
        $processInfo = Get-CimInstance Win32_Process -Filter ("ProcessId = $processId") -ErrorAction SilentlyContinue
        if ([string]$processInfo.CommandLine -match $bridgePattern) {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        }
    }
}

Start-Sleep -Milliseconds 500
$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) { throw 'node.exe was not found in PATH.' }
$bridgeScript = Join-Path $PSScriptRoot 'xbox-failover-bridge.mjs'
if (-not (Test-Path $bridgeScript)) { throw "Bridge script not found: $bridgeScript" }
Start-Process -FilePath $node.Source -ArgumentList ('"' + $bridgeScript + '"') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden

$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 150
    try {
        $status = Invoke-RestMethod -Uri 'http://127.0.0.1:53130/status' -TimeoutSec 1
        if ($status.ok -eq $true -and $status.port -eq 53130 -and $status.bridgeBuildId -eq 'dsh-antigravity-unified-connect-v7') {
            $ready = $true
            break
        }
    } catch {}
}
if (-not $ready) { throw 'Unified bridge did not become ready on port 53130. An unrelated process may own the port.' }
Write-Output 'Unified Antigravity bridge is ready on 127.0.0.1:53130.'
