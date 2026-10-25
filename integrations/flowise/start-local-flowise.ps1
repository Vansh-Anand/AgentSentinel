param([int]$Port = 3000)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$runtime = Join-Path $root '.data\flowise-release-runtime'
$flowise = Join-Path $root '.data\flowise-release\node_modules\flowise\bin\run'
if (-not (Test-Path -LiteralPath $flowise)) { throw 'Install Flowise 3.1.4 first' }
& (Join-Path $PSScriptRoot 'install-native-node.ps1') | Out-Host
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$node = (Get-Command node.exe -ErrorAction Stop).Source
$env:HOST = '127.0.0.1'
$env:PORT = [string]$Port
$env:DATABASE_TYPE = 'sqlite'
$env:DATABASE_PATH = $runtime
$env:SECRETKEY_PATH = $runtime
$env:LOG_PATH = $runtime
$env:AGENTSENTINEL_FLOWISE_GATEWAY_URL = 'http://127.0.0.1:8010'
$process = Start-Process -FilePath $node -ArgumentList ('"' + $flowise + '" start') -WorkingDirectory $root `
  -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtime 'flowise.stdout.log') `
  -RedirectStandardError (Join-Path $runtime 'flowise.stderr.log') -PassThru
Write-Output "Flowise PID=$($process.Id) URL=http://127.0.0.1:$Port"
