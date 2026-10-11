param(
    [ValidateRange(1024, 65535)][int]$ApiPort = 8008,
    [ValidateRange(1024, 65535)][int]$UiPort = 5178
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$data = Join-Path $root '.data/faculty-demo'
$temp = Join-Path $root '.data/tmp'
$frontend = Join-Path $root 'frontend'
$vite = Join-Path $frontend 'node_modules/vite/bin/vite.js'
$pidFile = Join-Path $data 'processes.json'

if (Test-Path -LiteralPath $pidFile) {
    throw "A faculty demo is already recorded. Run scripts/stop_faculty_demo.ps1 first."
}
if (-not (Test-Path -LiteralPath $vite)) {
    throw 'Frontend dependencies are missing. Run npm ci in frontend first.'
}
if (Get-NetTCPConnection -LocalPort $ApiPort, $UiPort -State Listen -ErrorAction SilentlyContinue) {
    throw 'A faculty demo port is already in use. Stop the prior demo or choose different ports.'
}
New-Item -ItemType Directory -Force -Path $data, $temp | Out-Null
$python = (Get-Command python.exe -ErrorAction Stop).Source
$node = (Get-Command node.exe -ErrorAction Stop).Source
$env:TEMP = $temp
$env:TMP = $temp
$env:AGENTSENTINEL_UI_ORIGIN = "http://127.0.0.1:$UiPort"
$env:VITE_API_BASE_URL = "http://127.0.0.1:$ApiPort"
& $python -c 'from agent_runtime.local_key import load_gemini_key; load_gemini_key()'
if ($LASTEXITCODE -ne 0) {
    throw 'The locally stored Gemini key could not be opened. The demo was not started.'
}

$api = $null
$ui = $null
try {
    $api = Start-Process -FilePath $python -ArgumentList @('-m', 'uvicorn', 'dashboard_api.main:app', '--host', '127.0.0.1', '--port', "$ApiPort") -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $data 'api.stdout.log') -RedirectStandardError (Join-Path $data 'api.stderr.log') -PassThru
    $ui = Start-Process -FilePath $node -ArgumentList @('node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', "$UiPort", '--strictPort') -WorkingDirectory $frontend -WindowStyle Hidden -RedirectStandardOutput (Join-Path $data 'ui.stdout.log') -RedirectStandardError (Join-Path $data 'ui.stderr.log') -PassThru

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($api.HasExited -or $ui.HasExited) {
            throw 'A demo process exited before readiness. Inspect .data/faculty-demo/*.stderr.log.'
        }
        try {
            $status = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/api/runtime/provider-status" -TimeoutSec 2
            $page = Invoke-WebRequest -Uri "http://127.0.0.1:$UiPort/gateway" -TimeoutSec 2
            if ($page.StatusCode -eq 200) { $ready = $true; break }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $ready) {
        throw "The API or UI did not become ready. Inspect .data/faculty-demo/*.stderr.log."
    }

    [pscustomobject]@{
        api = @{ pid = $api.Id; started = $api.StartTime.ToUniversalTime().ToString('o') }
        ui = @{ pid = $ui.Id; started = $ui.StartTime.ToUniversalTime().ToString('o') }
        api_port = $ApiPort
        ui_port = $UiPort
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $pidFile -Encoding utf8

    Write-Output "Faculty demo: http://127.0.0.1:$UiPort/gateway"
    Write-Output "Gemini key configured: $($status.gemini_key_configured); SDK installed: $($status.gemini_sdk_installed)"
    Write-Output 'Stop with ./scripts/stop_faculty_demo.ps1'
} catch {
    if ($ui) { Stop-Process -Id $ui.Id -Force -ErrorAction SilentlyContinue }
    if ($api) { Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue }
    throw
}
