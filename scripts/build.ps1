# Validation build on an x64 Windows host — native x86_64-pc-windows-gnu
# target. Uses rustup's bundled mingw; no system mingw-w64 needed.

$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $PSScriptRoot
Set-Location $Here

$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
if (-not (Test-Path $cargo)) { throw ("cargo.exe not at " + $cargo + " - install rustup first") }

Write-Host "=== Build config ==="
& $cargo --version
Write-Host "cwd: $(Get-Location)"
Write-Host ""

& $cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit $LASTEXITCODE" }

$Exe = "target\x86_64-pc-windows-gnu\release\darkcrypt-rs.exe"
if (-not (Test-Path $Exe)) { throw "$Exe not produced" }

New-Item -ItemType Directory -Path "artifacts" -Force | Out-Null
Copy-Item $Exe "artifacts\darkcrypt-rs.exe" -Force

$final = Get-Item "artifacts\darkcrypt-rs.exe"
$hash = (Get-FileHash $final.FullName -Algorithm SHA256).Hash

Write-Host ""
Write-Host "==================== BUILD OK ===================="
Write-Host ("Artifact : " + $final.FullName)
Write-Host ("Size     : " + $final.Length + " bytes")
Write-Host ("SHA256   : " + $hash)
Write-Host "=================================================="
