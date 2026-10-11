[CmdletBinding()]
param([Parameter(Mandatory)][string]$ArchivePath)

$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'install-nsis.ps1'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw 'No repository NSIS verifier protects archive extraction.'
}
$directory = Join-Path ([IO.Path]::GetTempPath()) ('picocrypt-nsis-controls-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $directory
try {
    # Appending bytes preserves the usable ZIP; extraction would accept it if
    # the repository trust anchor were removed or checked after extraction.
    $tampered = Join-Path $directory 'tampered.zip'
    Copy-Item -LiteralPath $ArchivePath -Destination $tampered
    $stream = [IO.File]::Open($tampered, [IO.FileMode]::Append)
    try { $stream.WriteByte(0x42) } finally { $stream.Dispose() }
    $rejected = Join-Path $directory 'rejected'
    $compiler = $null
    try {
        $compiler = & $installer -ArchivePath $tampered -DestinationPath $rejected
        throw 'Tampered NSIS archive was accepted.'
    } catch {
        if ($_.Exception.Message -notlike 'Checksum mismatch for NSIS archive:*') { throw }
    }
    if ($null -ne $compiler -or (Test-Path -LiteralPath $rejected)) {
        throw 'Tampered NSIS archive exposed a compiler or extracted files.'
    }

    # A valid ZIP must not merge with stale or injected compiler dependencies.
    $existing = Join-Path $directory 'existing'
    $null = New-Item -ItemType Directory -Path $existing
    try {
        $null = & $installer -ArchivePath $ArchivePath -DestinationPath $existing
        throw 'NSIS archive was merged into an existing destination.'
    } catch {
        if ($_.Exception.Message -notlike 'NSIS destination already exists:*') { throw }
    }
    if (@(Get-ChildItem -LiteralPath $existing -Force).Count -ne 0) {
        throw 'Existing NSIS destination was modified.'
    }

    $verified = Join-Path $directory 'verified'
    $compiler = & $installer -ArchivePath $ArchivePath -DestinationPath $verified
    $expected = Join-Path (Join-Path $verified 'nsis-3.13') 'makensis.exe'
    if ($compiler -ne $expected -or -not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
        throw 'Verified NSIS archive did not produce the expected portable compiler.'
    }
    if ((Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash -ne '4ec390d0f96f9728507fbc2f4e91311dd90bfc6c8ddfe2159357b3651ae151c0') {
        throw 'Portable compiler bytes differ from the reviewed upstream archive.'
    }
    if ($IsWindows) {
        $version = & $compiler -VERSION
        if ($LASTEXITCODE -ne 0 -or $version -ne 'v3.13') {
            throw "Verified NSIS compiler version failed: $version (exit $LASTEXITCODE)."
        }
    }
    Write-Output 'NSIS archive controls passed: tampered bytes rejected before extraction, original archive accepted.'
} finally {
    Remove-Item -LiteralPath $directory -Recurse -Force
}
