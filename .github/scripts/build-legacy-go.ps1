param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'The legacy Go toolchain must be built on Windows' }
if (Test-Path -LiteralPath $OutputRoot) { throw "Refusing to reuse an existing toolchain directory: $OutputRoot" }

$manifestPathResolved = (Resolve-Path -LiteralPath $ManifestPath).Path
$manifestDirectory = Split-Path -Parent $manifestPathResolved
$manifest = Get-Content -LiteralPath $manifestPathResolved -Raw | ConvertFrom-Json
if ($manifest.version -cne 'go1.27.2') { throw 'Unsupported legacy Go source version' }
if ($manifest.source.url -cne 'https://go.dev/dl/go1.27.2.src.tar.gz' -or
    $manifest.bootstrap_windows_amd64.url -cne 'https://go.dev/dl/go1.27.2.windows-amd64.zip') {
    throw 'Only the approved official Go source and bootstrap URLs are allowed'
}
if ($manifest.vendor_commit -cne '2f6cdc24e8e5c029eafebe42fcbe966cc0589f97') { throw 'Unexpected compatibility patch source commit' }
$expectedPatchNumbers = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15)
if ($manifest.patches.Count -ne $expectedPatchNumbers.Count) { throw 'Incomplete compatibility patch catalog' }
for ($index = 0; $index -lt $expectedPatchNumbers.Count; $index++) {
    $patch = $manifest.patches[$index]
    $number = $expectedPatchNumbers[$index]
    $prefix = '{0:D4}' -f $number
    if ($patch.path -cnotmatch "^$prefix-[a-z0-9-]+\.patch$" -or $patch.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Invalid compatibility patch name, order, or checksum'
    }
    if ($number -eq 10 -or $number -eq 13) {
        if ($patch.local -cne ('patches/' + $patch.path)) { throw 'Invalid local compatibility patch path' }
    } else {
        $expectedUrl = "https://raw.githubusercontent.com/thongtech/go-legacy-win7/$($manifest.vendor_commit)/patches/$($patch.path)"
        if (($patch.PSObject.Properties.Name -contains 'local') -or $patch.url -cne $expectedUrl) {
            throw 'Compatibility patches must use the approved immutable vendor URL'
        }
    }
}
New-Item -ItemType Directory -Path $OutputRoot | Out-Null
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path

function Get-VerifiedSource {
    param([string]$Url, [string]$Hash, [string]$Destination)
    if ($Url -cnotmatch '^https://' -or $Hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid pinned source URL or checksum' }
    curl.exe --fail --location --proto '=https' --proto-redir '=https' --silent --show-error --retry 3 --retry-all-errors `
        --connect-timeout 30 --max-time 300 --retry-max-time 600 --remove-on-error `
        --output $Destination $Url
    if ($LASTEXITCODE -ne 0) { throw "Source download failed: $Url" }
    $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Hash) { throw "Source checksum mismatch: $Destination" }
}

$bootstrapArchive = Join-Path $OutputRoot 'bootstrap.zip'
$sourceArchive = Join-Path $OutputRoot 'source.tar.gz'
Get-VerifiedSource $manifest.bootstrap_windows_amd64.url $manifest.bootstrap_windows_amd64.sha256 $bootstrapArchive
Get-VerifiedSource $manifest.source.url $manifest.source.sha256 $sourceArchive
$bootstrapRoot = Join-Path $OutputRoot 'bootstrap'
Expand-Archive -LiteralPath $bootstrapArchive -DestinationPath $bootstrapRoot
& tar.exe -xzf $sourceArchive -C $OutputRoot
if ($LASTEXITCODE -ne 0) { throw 'Go source extraction failed' }
$goRoot = Join-Path $OutputRoot 'go'
if ((Get-Content -LiteralPath (Join-Path $goRoot 'VERSION') -First 1).Trim() -ne $manifest.version) {
    throw 'Go source VERSION does not match the approved release'
}

$patchDirectory = Join-Path $OutputRoot 'patches'
New-Item -ItemType Directory -Path $patchDirectory | Out-Null
foreach ($patch in $manifest.patches) {
    $destination = Join-Path $patchDirectory $patch.path
    if ($patch.PSObject.Properties.Name -contains 'local') {
        $localPath = [IO.Path]::GetFullPath((Join-Path $manifestDirectory $patch.local))
        $catalogPrefix = $manifestDirectory.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $localPath.StartsWith($catalogPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Local compatibility patch escapes its catalog directory'
        }
        Copy-Item -LiteralPath $localPath -Destination $destination
        $actual = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $patch.sha256) { throw "Local compatibility patch checksum mismatch: $($patch.path)" }
    } else {
        Get-VerifiedSource $patch.url $patch.sha256 $destination
    }
    & git -C $goRoot apply --check -- $destination
    if ($LASTEXITCODE -ne 0) { throw "Compatibility patch does not apply: $($patch.path)" }
    & git -C $goRoot apply -- $destination
    if ($LASTEXITCODE -ne 0) { throw "Compatibility patch failed: $($patch.path)" }
}

$environmentNames = @('GOROOT', 'GOROOT_BOOTSTRAP', 'GOTOOLCHAIN', 'CGO_ENABLED', 'GOOS', 'GOARCH', 'GOHOSTOS', 'GOHOSTARCH', 'GOAMD64', 'GOEXPERIMENT')
$savedEnvironment = @{}
foreach ($name in $environmentNames) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location (Join-Path $goRoot 'src')
try {
    $env:GOROOT = $null
    $env:GOROOT_BOOTSTRAP = Join-Path $bootstrapRoot 'go'
    $env:GOTOOLCHAIN = 'local'
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOHOSTOS = 'windows'
    $env:GOHOSTARCH = 'amd64'
    $env:GOAMD64 = 'v1'
    $env:GOEXPERIMENT = ''
    $bootstrapGo = Join-Path $env:GOROOT_BOOTSTRAP 'bin/go.exe'
    $version = (& $bootstrapGo env GOVERSION).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -ne $manifest.version) { throw 'Unexpected Go bootstrap compiler' }
    & cmd.exe /d /c make.bat
    if ($LASTEXITCODE -ne 0) { throw 'Legacy Go source build failed' }
    $goExecutable = Join-Path $goRoot 'bin/go.exe'
    $version = (& $goExecutable env GOVERSION).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -ne $manifest.version) { throw 'Unexpected legacy Go compiler version' }
    $actualRoot = (& $goExecutable env GOROOT).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualRoot -ne $goRoot) { throw 'Unexpected legacy Go compiler root' }
    $buildEnvironment = & $goExecutable env -json GOOS GOARCH GOHOSTOS GOHOSTARCH GOAMD64 GOEXPERIMENT GOTOOLCHAIN
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect legacy compiler build settings' }
    $buildEnvironment = $buildEnvironment | ConvertFrom-Json
    if ($buildEnvironment.GOOS -ne 'windows' -or $buildEnvironment.GOARCH -ne 'amd64' -or
        $buildEnvironment.GOHOSTOS -ne 'windows' -or $buildEnvironment.GOHOSTARCH -ne 'amd64' -or
        $buildEnvironment.GOAMD64 -ne 'v1' -or $buildEnvironment.GOEXPERIMENT -ne '' -or
        $buildEnvironment.GOTOOLCHAIN -ne 'local') { throw 'Unexpected legacy compiler build settings' }
    & (Join-Path $PSScriptRoot 'assert-windows-legacy-pe.ps1') -Path $goExecutable
    & $goExecutable version
    if ($LASTEXITCODE -ne 0) { throw 'Legacy Go compiler could not execute' }
} finally {
    Pop-Location
    foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}
