param(
    [ValidateRange(2, 200)][int]$Limit = 50,
    [ValidateRange(1024, 65535)][int]$EtwPort = 8011,
    [ValidatePattern('^[A-Za-z0-9_.-]+\.json$')][string]$Output = 'portable_lab_eval_etw_broker.json'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tokenPath = Join-Path $root '.data/faculty-demo/etw-broker-token'
if (-not (Test-Path -LiteralPath $tokenPath)) {
    throw 'Start the local ETW demo first with scripts/start_etw_demo.ps1.'
}
$token = [System.IO.File]::ReadAllText($tokenPath).Trim()
$brokerUrl = "http://127.0.0.1:$EtwPort"
$health = Invoke-RestMethod -Uri "$brokerUrl/health" -Headers @{'X-AgentSentinel-Token' = $token} -TimeoutSec 3
if ($health.ready -ne $true) { throw 'ETW broker is not ready.' }

$priorJob = $env:AGENTSENTINEL_WINDOWS_JOB_REQUIRED
$priorUrl = $env:AGENTSENTINEL_ETW_BROKER_URL
$priorToken = $env:AGENTSENTINEL_ETW_BROKER_TOKEN
try {
    $env:AGENTSENTINEL_WINDOWS_JOB_REQUIRED = '1'
    $env:AGENTSENTINEL_ETW_BROKER_URL = $brokerUrl
    $env:AGENTSENTINEL_ETW_BROKER_TOKEN = $token
    & python (Join-Path $root 'scripts/evaluate_portable_lab.py') --limit $Limit --output $Output
    if ($LASTEXITCODE -ne 0) { throw 'Fixture evaluation failed.' }
    $reportPath = Join-Path $root "benchmarks/results/$Output"
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $authorized = [math]::Floor($Limit / 2)
    if ($report.windows_job_runs -ne $authorized -or
        $report.etw_process_correlated_runs -ne $authorized -or
        $report.denied_executors_invoked -ne 0 -or
        $report.provider_or_runtime_errors -ne 0) {
        throw 'The evaluation did not reach the required Job/ETW coverage. Inspect the report before citing it.'
    }
    Write-Output "Verified $authorized authorized Job workers and ETW starts; denied executor count is zero."
} finally {
    if ($null -eq $priorJob) { Remove-Item Env:AGENTSENTINEL_WINDOWS_JOB_REQUIRED -ErrorAction SilentlyContinue }
    else { $env:AGENTSENTINEL_WINDOWS_JOB_REQUIRED = $priorJob }
    if ($null -eq $priorUrl) { Remove-Item Env:AGENTSENTINEL_ETW_BROKER_URL -ErrorAction SilentlyContinue }
    else { $env:AGENTSENTINEL_ETW_BROKER_URL = $priorUrl }
    if ($null -eq $priorToken) { Remove-Item Env:AGENTSENTINEL_ETW_BROKER_TOKEN -ErrorAction SilentlyContinue }
    else { $env:AGENTSENTINEL_ETW_BROKER_TOKEN = $priorToken }
}
