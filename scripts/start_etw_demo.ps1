param(
    [ValidateRange(1024, 65535)][int]$ApiPort = 8010,
    [ValidateRange(1024, 65535)][int]$UiPort = 5180,
    [ValidateRange(1024, 65535)][int]$EtwPort = 8011
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$data = Join-Path $root '.data/faculty-demo'
$recordPath = Join-Path $data 'processes.json'
$tokenPath = Join-Path $data 'etw-broker-token'
if (Test-Path -LiteralPath $recordPath) {
    throw 'A demo process record exists. Run scripts/stop_faculty_demo.ps1 first.'
}
if (Get-NetTCPConnection -LocalPort $EtwPort -State Listen -ErrorAction SilentlyContinue) {
    throw "ETW broker port $EtwPort is in use."
}
New-Item -ItemType Directory -Force -Path $data | Out-Null
$bytes = [byte[]]::new(32)
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($bytes) } finally { $random.Dispose() }
$token = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
[System.IO.File]::WriteAllText($tokenPath, $token, [System.Text.Encoding]::ASCII)
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $tokenPath /inheritance:r /grant:r "*${userSid}:(R)" '*S-1-5-32-544:(F)' '*S-1-5-18:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $tokenPath
    throw 'Could not restrict the ETW broker token file ACL.'
}
$python = (Get-Command python.exe -ErrorAction Stop).Source
$broker = $null
$brokerReady = $false
$brokerUrl = "http://127.0.0.1:$EtwPort"
$previousUrl = $env:AGENTSENTINEL_ETW_BROKER_URL
$previousToken = $env:AGENTSENTINEL_ETW_BROKER_TOKEN
try {
    # Only this narrow broker receives elevation. The API and UI remain ordinary user processes.
    $broker = Start-Process -FilePath $python -ArgumentList @('-m', 'agent_runtime.windows_etw_broker', '--port', "$EtwPort") -WorkingDirectory $root -WindowStyle Hidden -Verb RunAs -PassThru
    for ($attempt = 0; $attempt -lt 25; $attempt++) {
        if ($broker.HasExited) { throw 'Elevated ETW broker exited during startup.' }
        try {
            $health = Invoke-RestMethod -Uri "$brokerUrl/health" -Headers @{'X-AgentSentinel-Token' = $token} -TimeoutSec 2
            if ($health.ready -eq $true) { $brokerReady = $true; break }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $brokerReady) { throw 'Elevated ETW broker did not become ready.' }
    $env:AGENTSENTINEL_ETW_BROKER_URL = $brokerUrl
    $env:AGENTSENTINEL_ETW_BROKER_TOKEN = $token
    & (Join-Path $PSScriptRoot 'start_faculty_demo.ps1') -ApiPort $ApiPort -UiPort $UiPort
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $recordPath)) {
        throw 'Faculty demo did not start after ETW broker readiness.'
    }
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    $record | Add-Member -NotePropertyName etw_broker -NotePropertyValue @{ port = $EtwPort; pid = $broker.Id; started = $broker.StartTime.ToUniversalTime().ToString('o') }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $recordPath -Encoding utf8
    Write-Output "Elevated ETW broker ready on loopback port $EtwPort; API and UI remain unelevated."
} catch {
    if (Test-Path -LiteralPath $recordPath) { & (Join-Path $PSScriptRoot 'stop_faculty_demo.ps1') }
    $brokerStopped = $null -eq $broker -or $broker.HasExited
    if (-not $brokerStopped) {
        try {
            Invoke-RestMethod -Uri "$brokerUrl/shutdown" -Method Post -Headers @{'X-AgentSentinel-Token' = $token} -ContentType 'application/json' -Body '{}' -TimeoutSec 3 | Out-Null
            $brokerStopped = $true
        } catch { Write-Warning 'ETW broker could not confirm shutdown; token file retained for recovery.' }
    }
    if ($brokerStopped -and (Test-Path -LiteralPath $tokenPath)) { Remove-Item -LiteralPath $tokenPath }
    throw
} finally {
    $env:AGENTSENTINEL_ETW_BROKER_URL = $previousUrl
    $env:AGENTSENTINEL_ETW_BROKER_TOKEN = $previousToken
}
