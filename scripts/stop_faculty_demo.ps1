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
    # ConvertFrom-Json may already turn ISO timestamps into DateTime values.
    # Stringifying those values first uses the current culture and can fail to parse.
    $recordedStart = if ($entry.started -is [DateTime]) {
        $entry.started.ToUniversalTime()
    } else {
        [DateTime]::Parse([string]$entry.started, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
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
if ($record.etw_broker) {
    $tokenPath = Join-Path $root '.data/faculty-demo/etw-broker-token'
    if (Test-Path -LiteralPath $tokenPath) {
        $token = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
        $url = "http://127.0.0.1:$([int]$record.etw_broker.port)/shutdown"
        try {
            Invoke-RestMethod -Uri $url -Method Post -Headers @{'X-AgentSentinel-Token' = $token} -ContentType 'application/json' -Body '{}' -TimeoutSec 5 | Out-Null
            Remove-Item -LiteralPath $tokenPath
            Write-Output 'Elevated ETW broker stopped.'
        } catch {
            Write-Warning 'ETW broker did not confirm shutdown; token file retained for recovery.'
        }
    }
}
Remove-Item -LiteralPath $pidFile
Write-Output 'Faculty demo processes stopped.'
