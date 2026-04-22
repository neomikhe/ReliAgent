# fetch_model.ps1 — Windows counterpart of fetch_model.sh.
#
# Downloads a canonical model artifact listed in MODEL_SHA256.txt,
# verifies its SHA-256, and drops it under vendor\models\.
#
# Usage:
#     scripts\fetch_model.ps1                                    # default quant
#     scripts\fetch_model.ps1 qwen2.5-7b-instruct-q5_k_m.gguf
#     scripts\fetch_model.ps1 -List
#
# Environment:
#     RELI_MODEL_MIRROR         Override base URL.
#     RELI_ACCEPT_MODEL_LICENSE Set to 1 to skip the interactive prompt.
#
# Exit codes (match fetch_model.sh):
#   0 ok, 1 generic, 2 unknown name, 3 download, 4 hash, 5 licence.

param(
    [string]$Name = 'qwen2.5-7b-instruct-q4_k_m.gguf',
    [switch]$List
)

$ErrorActionPreference = 'Stop'

$Root     = Resolve-Path (Join-Path $PSScriptRoot '..')
$Manifest = Join-Path $Root 'MODEL_SHA256.txt'
$Models   = Join-Path $Root 'vendor\models'

$Mirror = $env:RELI_MODEL_MIRROR
if (-not $Mirror) {
    $Mirror = 'https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main'
}

# --- Parse manifest ------------------------------------------------------
if (-not (Test-Path $Manifest)) {
    Write-Error "[fetch_model] manifest not found: $Manifest"
    exit 1
}

$ShaByName = @{}
$LicByName = @{}
Get-Content $Manifest | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#')) { return }
    $parts = -split $line
    if ($parts.Length -lt 4) { return }
    $ShaByName[$parts[1]] = $parts[0]
    $LicByName[$parts[1]] = $parts[3]
}

if ($List) {
    $ShaByName.Keys | Sort-Object | ForEach-Object { Write-Output $_ }
    exit 0
}

if (-not $ShaByName.ContainsKey($Name)) {
    Write-Error "[fetch_model] unknown artifact: $Name"
    Write-Host   "[fetch_model] known artifacts:"
    $ShaByName.Keys | Sort-Object | ForEach-Object { Write-Host "  $_" }
    exit 2
}

$ShaExpected = $ShaByName[$Name]
$LicenseUrl  = $LicByName[$Name]

# --- Licence gate --------------------------------------------------------
Write-Host "[fetch_model] artifact:  $Name"
Write-Host "[fetch_model] licence:   $LicenseUrl"
Write-Host "[fetch_model] Qwen2.5 is NOT Apache-2.0. You must accept Qwen's own terms."

if ($env:RELI_ACCEPT_MODEL_LICENSE -ne '1') {
    $reply = Read-Host "[fetch_model] type YES to accept the licence and continue"
    if ($reply -ne 'YES') {
        Write-Error "[fetch_model] licence not accepted; aborting."
        exit 5
    }
}

# --- Download (resumable) ------------------------------------------------
New-Item -ItemType Directory -Force -Path $Models | Out-Null
$Target = Join-Path $Models $Name
$Url    = "$Mirror/$Name"

Write-Host "[fetch_model] url=$Url"
try {
    Invoke-WebRequest -Uri $Url -OutFile $Target -Resume -TimeoutSec 900
}
catch {
    Write-Error "[fetch_model] download failed: $_"
    exit 3
}

# --- Verify --------------------------------------------------------------
if ($ShaExpected -like 'REPLACE_WITH_SHA256*') {
    Write-Warning "[fetch_model] placeholder SHA-256 for $Name"
    Write-Warning "[fetch_model] MODEL_SHA256.txt must be updated before release."
    exit 4
}

$ShaActual = (Get-FileHash -Path $Target -Algorithm SHA256).Hash.ToLower()
if ($ShaActual -ne $ShaExpected) {
    Write-Error "[fetch_model] SHA-256 mismatch"
    Write-Error "  expected: $ShaExpected"
    Write-Error "  actual:   $ShaActual"
    Write-Error "[fetch_model] keeping partial file at $Target for retry."
    exit 4
}

Write-Host "[fetch_model] ok: $Target"
Write-Host "[fetch_model] sha256 verified: $ShaActual"
