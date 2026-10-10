[CmdletBinding()]
param(
    [string]$ArchivePath,
    [string]$DestinationPath = (Join-Path $env:RUNNER_TEMP 'nsis-portable')
)

$ErrorActionPreference = 'Stop'
# Reviewed upstream ZIP: https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/
$expectedHash = 'ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8'
if (-not $ArchivePath) {
    $ArchivePath = Join-Path $env:RUNNER_TEMP 'nsis-3.13.zip'
    curl.exe `
        --fail `
        --location `
        --silent `
        --show-error `
        --retry 3 `
        --retry-all-errors `
        --retry-delay 2 `
        --connect-timeout 30 `
        --max-time 300 `
        --retry-max-time 600 `
        --remove-on-error `
        --output $ArchivePath `
        https://downloads.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13.zip
    if ($LASTEXITCODE -ne 0) {
        throw "NSIS download failed with exit code $LASTEXITCODE"
    }
}
$actualHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    throw "Checksum mismatch for NSIS archive: expected $expectedHash, got $actualHash"
}
if (Test-Path -LiteralPath $DestinationPath) {
    throw "NSIS destination already exists: $DestinationPath"
}
Expand-Archive -LiteralPath $ArchivePath -DestinationPath $DestinationPath
$compiler = Join-Path $DestinationPath 'nsis-3.13/makensis.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw 'Verified NSIS archive is missing the portable compiler.'
}
(Resolve-Path -LiteralPath $compiler).Path
