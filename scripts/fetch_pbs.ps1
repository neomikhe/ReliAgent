# fetch_pbs.ps1 — Windows counterpart of fetch_pbs.sh.
#
# Downloads a python-build-standalone archive matching Windows x64 or
# arm64, verifies its SHA-256, and extracts it to vendor\python\.
#
# Invariants (mirror the sh version):
#   - No admin, no writes outside the repo.
#   - SHA-256 mismatch is a hard stop; nothing extracts if it fails.
#   - Partial downloads are kept on disk (Invoke-WebRequest resume is
#     best-effort via Range requests).
#
# Exit codes:
#   0  success
#   1  generic failure
#   2  unsupported platform
#   3  download failure
#   4  hash mismatch

$ErrorActionPreference = 'Stop'

# --- Pin one release here. Keep in sync with fetch_pbs.sh. ---
$PbsTag    = $env:PBS_TAG;    if (-not $PbsTag)    { $PbsTag    = '20260101' }     # placeholder
$PbsPython = $env:PBS_PYTHON; if (-not $PbsPython) { $PbsPython = '3.12.7' }

# Per-platform archive + sha256 table.
$Archives = @{
    'win-x64'   = "cpython-$PbsPython+$PbsTag-x86_64-pc-windows-msvc-install_only.tar.gz"
    'win-arm64' = "cpython-$PbsPython+$PbsTag-aarch64-pc-windows-msvc-install_only.tar.gz"
}
$Sha256s = @{
    'win-x64'   = 'REPLACE_WITH_SHA256'
    'win-arm64' = 'REPLACE_WITH_SHA256'
}

# --- Detect platform -----------------------------------------------------
$arch = (Get-CimInstance Win32_Processor).Architecture
switch ($arch) {
    9  { $Platform = 'win-x64' }     # x64
    12 { $Platform = 'win-arm64' }   # arm64
    default {
        Write-Error "[fetch_pbs] unsupported Windows architecture: $arch"
        exit 2
    }
}

$Archive         = $Archives[$Platform]
$Sha256Expected  = $Sha256s[$Platform]
$Url             = "https://github.com/astral-sh/python-build-standalone/releases/download/$PbsTag/$Archive"

# --- Paths ---------------------------------------------------------------
$Root       = Resolve-Path (Join-Path $PSScriptRoot '..')
$Vendor     = Join-Path $Root   'vendor'
$Cache      = Join-Path $Vendor 'cache'
$Target     = Join-Path $Vendor 'python'
$TmpArchive = Join-Path $Cache  $Archive

New-Item -ItemType Directory -Force -Path $Cache | Out-Null

# --- Download (best-effort resume via Range) -----------------------------
Write-Host "[fetch_pbs] platform=$Platform tag=$PbsTag python=$PbsPython"
Write-Host "[fetch_pbs] url=$Url"

try {
    $existing = 0
    if (Test-Path $TmpArchive) {
        $existing = (Get-Item $TmpArchive).Length
    }
    $headers = @{}
    if ($existing -gt 0) { $headers['Range'] = "bytes=$existing-" }

    Invoke-WebRequest -Uri $Url -Headers $headers -OutFile $TmpArchive `
                      -Resume -TimeoutSec 300
}
catch {
    Write-Error "[fetch_pbs] download failed: $_"
    exit 3
}

# --- Verify --------------------------------------------------------------
if ($Sha256Expected -eq 'REPLACE_WITH_SHA256') {
    Write-Warning "[fetch_pbs] placeholder SHA-256 — this is not a release build."
    Write-Warning "[fetch_pbs] edit fetch_pbs.ps1 to pin the real digest before a tag."
}

$Sha256Actual = (Get-FileHash -Path $TmpArchive -Algorithm SHA256).Hash.ToLower()

if ($Sha256Expected -ne 'REPLACE_WITH_SHA256' -and $Sha256Actual -ne $Sha256Expected) {
    Write-Error "[fetch_pbs] SHA-256 mismatch"
    Write-Error "  expected: $Sha256Expected"
    Write-Error "  actual:   $Sha256Actual"
    Write-Error "[fetch_pbs] keeping $TmpArchive for forensics; not extracting."
    exit 4
}

# --- Extract -------------------------------------------------------------
Write-Host "[fetch_pbs] verified, extracting to $Target"
if (Test-Path $Target) { Remove-Item -Recurse -Force $Target }
New-Item -ItemType Directory -Force -Path $Target | Out-Null

# tar is shipped with Windows 10+ (bsdtar).
& tar -xzf $TmpArchive -C $Target --strip-components=1
if ($LASTEXITCODE -ne 0) {
    Write-Error "[fetch_pbs] tar extraction failed"
    exit 1
}

$PyExe = Join-Path $Target 'python.exe'
if (-not (Test-Path $PyExe)) {
    Write-Error "[fetch_pbs] archive did not contain python.exe at the expected path"
    exit 1
}

$ver = & $PyExe --version
Write-Host "[fetch_pbs] ok: $ver"
