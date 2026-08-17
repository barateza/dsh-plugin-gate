# One-shot npm publish for dsh-plugin-gate. Token is read from the local
# secrets file ($DSH_HOME/secrets/npm-token.txt) or $env:NPM_TOKEN — never
# pasted into chat. Temporary .npmrc is deleted afterwards.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) -Parent
if (-not $env:DSH_NODE_DIR) { $env:DSH_NODE_DIR = 'C:\Users\l''x\.workbuddy\binaries\node\versions\22.22.2' }
$node = Join-Path $env:DSH_NODE_DIR 'node.exe'
$npmCli = Join-Path $env:DSH_NODE_DIR 'node_modules\npm\bin\npm-cli.js'
$secrets = Join-Path $env:DSH_HOME 'secrets\npm-token.txt'
$token = $env:NPM_TOKEN
if (-not $token -and (Test-Path $secrets)) { $token = (Get-Content $secrets -Raw).Trim() }
if (-not $token) { throw 'npm token missing: set NPM_TOKEN or create $DSH_HOME/secrets/npm-token.txt' }
Push-Location $root
$npmrc = Join-Path $root '.npmrc'
try {
  Set-Content -Path $npmrc -Value ("//registry.npmjs.org/:_authToken=" + $token) -Encoding ascii
  & $node $npmCli publish --ignore-scripts --cache (Join-Path $root '.npm-cache') 2>&1
  if ($LASTEXITCODE -ne 0) { throw "npm publish failed (exit $LASTEXITCODE)" }
  Write-Host 'published — check https://www.npmjs.com/package/dsh-plugin-gate'
} finally {
  Remove-Item -Force $npmrc -ErrorAction SilentlyContinue
  Pop-Location
}
