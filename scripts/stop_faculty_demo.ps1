$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pidFile = Join-Path $root '.data/faculty-demo/processes.json'
if (-not (Test-Path -LiteralPath $pidFile)) {
    Write-Output 'No faculty demo process record found.'
    exit 0
}

$record = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
$entries = @($record.api, $record.ui)
foreach ($entry in $entries) {
    $process = Get-Process -Id ([int]$entry.pid) -ErrorAction SilentlyContinue
    $recordedStart = [DateTime]::Parse([string]$entry.started).ToUniversalTime()
    if ($process -and [Math]::Abs(($process.StartTime.ToUniversalTime() - $recordedStart).TotalSeconds) -lt 2) {
        Stop-Process -Id $process.Id -Force
    }
}

# Start-Process can return a short-lived wrapper on some Windows installations.
# Clean up only listeners whose command lines match this demo's exact programs
# and recorded ports; never stop an unrelated service on the same port.
foreach ($port in @([int]$record.api_port, [int]$record.ui_port)) {
    $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($socket in $listener) {
        $candidate = Get-CimInstance Win32_Process -Filter "ProcessId=$($socket.OwningProcess)" -ErrorAction SilentlyContinue
        $line = [string]$candidate.CommandLine
        $matchesDemo = (($port -eq [int]$record.api_port -and $line -match 'uvicorn dashboard_api\.main:app' -and $line -match "--port $port") -or
                        ($port -eq [int]$record.ui_port -and $line -match 'vite\.js' -and $line -match "--port $port"))
        if ($matchesDemo) {
            Stop-Process -Id $socket.OwningProcess -Force
        }
    }
}
Remove-Item -LiteralPath $pidFile
Write-Output 'Faculty demo processes stopped.'
