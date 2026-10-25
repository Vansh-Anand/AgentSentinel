param([string]$FlowiseRoot = (Join-Path $PSScriptRoot '..\..\.data\flowise-release'))
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $FlowiseRoot).Path
$package = Join-Path $resolved 'node_modules\flowise\package.json'
if (-not (Test-Path -LiteralPath $package)) { throw 'Flowise installation not found' }
$version = (Get-Content -LiteralPath $package -Raw | ConvertFrom-Json).version
if ($version -ne '3.1.4') { throw "Expected Flowise 3.1.4; found $version" }
$target = Join-Path $resolved 'node_modules\flowise-components\dist\nodes\tools\AgentSentinelGateway'
New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'native-node\AgentSentinelGateway.js') -Destination (Join-Path $target 'AgentSentinelGateway.js') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'native-node\gateway.svg') -Destination (Join-Path $target 'gateway.svg') -Force
Write-Output "Installed pinned-loopback AgentSentinel Gateway node for Flowise $version"
