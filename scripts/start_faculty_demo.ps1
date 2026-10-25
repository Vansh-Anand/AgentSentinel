param(
    [ValidateRange(1024, 65535)][int]$ApiPort = 8010,
    [ValidateRange(1024, 65535)][int]$UiPort = 5180
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$data = Join-Path $root '.data/faculty-demo'
$temp = Join-Path $root '.data/tmp'
$frontend = Join-Path $root 'frontend'
$vite = Join-Path $frontend 'node_modules/vite/bin/vite.js'
$pidFile = Join-Path $data 'processes.json'

if (Test-Path -LiteralPath $pidFile) {
    $old = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
    $live = @($old.api, $old.ui) | Where-Object {
        $entry = $_
        $process = Get-Process -Id ([int]$entry.pid) -ErrorAction SilentlyContinue
        if (-not $process) { return $false }
        $recorded = if ($entry.started -is [DateTime]) { $entry.started.ToUniversalTime() }
            else { [DateTime]::Parse([string]$entry.started, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
        [Math]::Abs(($process.StartTime.ToUniversalTime() - $recorded).TotalSeconds) -lt 2
    }
    if ($live.Count -gt 0) {
        throw "A faculty demo is already running. Run scripts/stop_faculty_demo.ps1 first."
    }
    Remove-Item -LiteralPath $pidFile
    Write-Output 'Removed a stale faculty demo process record.'
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
$env:AGENTSENTINEL_WINDOWS_JOB_REQUIRED = '1'
$env:AGENTSENTINEL_NATIVE_L3_REQUIRED = '0'
$env:AGENTSENTINEL_TPM_REQUIRED = '0'
$env:VITE_API_BASE_URL = "http://127.0.0.1:$ApiPort"
$api = $null
$ui = $null
try {
    $api = Start-Process -FilePath $python -ArgumentList @('-m', 'uvicorn', 'dashboard_api.main:app', '--host', '127.0.0.1', '--port', "$ApiPort") -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $data 'api.stdout.log') -RedirectStandardError (Join-Path $data 'api.stderr.log') -PassThru
    $ui = Start-Process -FilePath $node -ArgumentList @('node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', "$UiPort", '--strictPort') -WorkingDirectory $frontend -WindowStyle Hidden -RedirectStandardOutput (Join-Path $data 'ui.stdout.log') -RedirectStandardError (Join-Path $data 'ui.stderr.log') -PassThru

    $ready = $false
    $lastReadinessError = ''
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($api.HasExited -or $ui.HasExited) {
            throw 'A demo process exited before readiness. Inspect .data/faculty-demo/*.stderr.log.'
        }
        try {
            # Readiness must not depend on the optional model provider probe.
            # Ollama or a cloud SDK may be slow even when the API is serving.
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/api/health" -TimeoutSec 2
            $page = Invoke-WebRequest -Uri "http://127.0.0.1:$UiPort/lab" -TimeoutSec 2
            if ($page.StatusCode -eq 200) { $ready = $true; break }
        } catch {
            $lastReadinessError = $_.Exception.Message
            Start-Sleep -Seconds 1
        }
    }
    if (-not $ready) {
        throw "The API or UI did not become ready: $lastReadinessError. Inspect .data/faculty-demo/*.stderr.log."
    }

    $lab = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/api/lab/capabilities" -TimeoutSec 5
    if (-not $lab.integrity.valid) { throw "Approved source baseline is invalid: $($lab.integrity.reason)" }
    if (-not $lab.windows_job.required -or -not $lab.windows_job.available) {
        throw "Windows Job Object execution is unavailable: $($lab.windows_job.reason)"
    }

    $status = $null
    try {
        $status = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/api/runtime/provider-status" -TimeoutSec 3
    } catch {
        Write-Output 'Provider readiness probe timed out; check System Status in the app.'
    }

    [pscustomobject]@{
        api = @{ pid = $api.Id; started = $api.StartTime.ToUniversalTime().ToString('o') }
        ui = @{ pid = $ui.Id; started = $ui.StartTime.ToUniversalTime().ToString('o') }
        api_port = $ApiPort
        ui_port = $UiPort
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $pidFile -Encoding utf8

    Write-Output "Faculty demo: http://127.0.0.1:$UiPort/lab"
    if ($status) {
        Write-Output "Gemini key configured: $($status.gemini_key_configured); SDK installed: $($status.gemini_sdk_installed)"
        Write-Output "Ollama local model ready: $($status.ollama_available) ($($status.ollama_model))"
    }
    Write-Output 'Stop with ./scripts/stop_faculty_demo.ps1'
} catch {
    if ($ui) { Stop-Process -Id $ui.Id -Force -ErrorAction SilentlyContinue }
    if ($api) { Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue }
    throw
}
