param([switch]$CheckRunning)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$verificationTemp = Join-Path $projectRoot '.data/tmp'
New-Item -ItemType Directory -Force -Path $verificationTemp | Out-Null
$priorTemp = $env:TEMP
$priorTmp = $env:TMP
try {
    # Windows restricted processes need a writable, project-local temporary directory.
    $env:TEMP = $verificationTemp
    $env:TMP = $verificationTemp
    Push-Location $projectRoot
    try {
        python -m unittest discover -s tests/gateway -q
        if ($LASTEXITCODE -ne 0) { throw 'Gateway regression failed.' }
        python -m unittest discover -s tests/runtime -p 'test_secure_lab*.py' -q
        if ($LASTEXITCODE -ne 0) { throw 'Lab/API regression failed.' }
        python -m unittest discover -s tests/runtime -p 'test_dispatch_boundary.py' -q
        if ($LASTEXITCODE -ne 0) { throw 'Dispatch-boundary regression failed.' }
        python -m unittest discover -s tests/runtime -p 'test_workspace_documents.py' -q
        if ($LASTEXITCODE -ne 0) { throw 'Document-workspace regression failed.' }
        python -m unittest discover -s tests/runtime -p 'test_windows_l3.py' -q
        if ($LASTEXITCODE -ne 0) { throw 'Windows execution/observation regression failed.' }
        Push-Location (Join-Path $projectRoot 'frontend')
        try {
            npm.cmd test -- --maxWorkers=2
            if ($LASTEXITCODE -ne 0) { throw 'Frontend regression failed.' }
            npm.cmd run build
            if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
        } finally { Pop-Location }
        if ($CheckRunning) {
            $record = Get-Content -LiteralPath (Join-Path $projectRoot '.data/faculty-demo/processes.json') -Raw | ConvertFrom-Json
            Invoke-RestMethod -Uri "http://127.0.0.1:$($record.api_port)/api/health" -TimeoutSec 5 | Out-Null
            $page = Invoke-WebRequest -Uri "http://127.0.0.1:$($record.ui_port)/lab" -TimeoutSec 5
            if ($page.StatusCode -ne 200) { throw 'Chat page is not ready.' }
        }
        Write-Output 'PASS: gateway, lab/API, dispatch-boundary, frontend tests and production build. Browser interaction remains a separate manual gate.'
    } finally { Pop-Location }
} finally {
    $env:TEMP = $priorTemp
    $env:TMP = $priorTmp
}
