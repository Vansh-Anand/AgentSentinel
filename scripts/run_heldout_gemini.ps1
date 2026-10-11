param(
    [ValidateRange(1, 25)][int]$PerCategory = 25,
    [ValidateRange(1, 5)][int]$Repeats = 1,
    [ValidateRange(0, 120)][double]$DelaySeconds = 12,
    [string]$Output = '.data/model-eval/gemini-full-v4.json',
    [string]$RetryErrorsFrom = '',
    [ValidateRange(0, 1000)][int]$MaxNewCalls = 0
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$keyPath = Join-Path $projectRoot '.data/secrets/gemini-key.dpapi'
if (-not (Test-Path -LiteralPath $keyPath)) {
    throw 'No local DPAPI key file found. Store a rotated Gemini key in .data/secrets first.'
}

Push-Location $projectRoot
$secretPointer = [IntPtr]::Zero
$evaluationExitCode = 1
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
try {
    $taskTemp = Join-Path $projectRoot '.data/tmp'
    New-Item -ItemType Directory -Force -Path $taskTemp | Out-Null
    $env:TEMP = $taskTemp
    $env:TMP = $taskTemp
    $encrypted = Get-Content -LiteralPath $keyPath -Raw | ConvertTo-SecureString
    $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($encrypted)
    $env:GEMINI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)
    $evalArgs = @(
        '-m', 'benchmarks.model_eval', '--provider', 'gemini',
        '--corpus', 'model_cases_v2.json', '--per-category', "$PerCategory",
        '--repeats', "$Repeats", '--delay-seconds', "$DelaySeconds",
        '--output', $Output
    )
    if ($RetryErrorsFrom) {
        $evalArgs += @('--retry-errors-from', $RetryErrorsFrom)
    }
    if ($MaxNewCalls) {
        $evalArgs += @('--max-new-calls', "$MaxNewCalls")
    }
    & python @evalArgs
    $evaluationExitCode = $LASTEXITCODE
}
finally {
    Remove-Item Env:GEMINI_API_KEY -ErrorAction SilentlyContinue
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    if ($secretPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
    }
    Pop-Location
}
exit $evaluationExitCode
