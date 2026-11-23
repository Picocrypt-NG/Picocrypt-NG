$ErrorActionPreference = 'Stop'

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$src = Join-Path $repo 'src'
$resourceDirectory = Join-Path $repo 'dist/windows'
$mingw = 'C:\mingw64\bin'
$resourceCompiler = Join-Path $mingw 'windres.exe'
$gcc = Join-Path $mingw 'gcc.exe'
$binutilsVersion = '2.46.0.20260210'
$reportedBinutils = & $resourceCompiler --version
if ($LASTEXITCODE -ne 0 -or -not ($reportedBinutils -match "^GNU windres \(GNU Binutils\) $([regex]::Escape($binutilsVersion))$")) {
    throw "Expected GNU windres $binutilsVersion from $mingw"
}
$gccVersion = & $gcc -dumpfullversion
if ($LASTEXITCODE -ne 0 -or $gccVersion -ne '15.2.0') {
    throw "Expected GCC 15.2.0 from $mingw"
}
$llvm = Join-Path $env:ProgramFiles 'LLVM/bin'
$resourceReader = Join-Path $llvm 'llvm-readobj.exe'
$llvmVersion = '20.1.8'
$reportedVersion = & $resourceReader --version
if ($LASTEXITCODE -ne 0 -or -not ($reportedVersion -match "^\s*LLVM version $([regex]::Escape($llvmVersion))(\s|$)")) {
    throw "Expected LLVM $llvmVersion from $llvm"
}

$go = (Get-Command go -CommandType Application | Select-Object -First 1).Source
$object = Join-Path $src 'cmd/picocrypt/gui_windows_amd64.syso'
$output = Join-Path $src 'Picocrypt-NG-gui.exe'
if (Test-Path -LiteralPath $object) {
    throw "GUI resource object already exists at $object"
}
$scratch = [IO.Directory]::CreateTempSubdirectory('picocrypt-windows-resources-').FullName
$ownedObject = $false
try {
    $compiledObject = Join-Path $scratch 'resources.syso'
    Push-Location $resourceDirectory
    try {
        & $resourceCompiler --input gui_resources.rc --output $compiledObject --output-format=coff --target=pe-x86-64 `
            --preprocessor "$gcc -E -xc -DRC_INVOKED"
        if ($LASTEXITCODE -ne 0) { throw "windres failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
    [IO.File]::Move($compiledObject, $object)
    $ownedObject = $true

    Push-Location $src
    try {
        & $go build -v -tags migrated_fynedo -ldflags '-s -w -H=windowsgui -extldflags=-static' -o $output ./cmd/picocrypt
        if ($LASTEXITCODE -ne 0) { throw "Windows GUI build failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }

    $actualResources = & $resourceReader --coff-resources $output
    if ($LASTEXITCODE -ne 0) { throw "Could not read the GUI PE resources ($LASTEXITCODE)" }
    foreach ($pattern in @(
        '^\s*Type: GROUP_ICON \(ID 14\) \[$',
        '^\s*Name: MAINICON \[$',
        '^\s*Name: A \[$',
        '^\s*Type: MANIFEST \(ID 24\) \[$',
        '^\s*Type: VERSIONINFO \(ID 16\) \[$'
    )) {
        if (-not ($actualResources -cmatch $pattern)) {
            throw "Missing expected PE resource ($pattern)"
        }
    }
    $expectedVersion = (Get-Content -LiteralPath (Join-Path $repo 'VERSION') -Raw).Trim()
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($output)
    if ($version.FileVersion -cne $expectedVersion -or $version.ProductName -cne 'Picocrypt NG') {
        throw "Unexpected PE version metadata: $($version.ProductName) $($version.FileVersion)"
    }
    Write-Host "Verified Windows GUI PE resources from GNU windres $binutilsVersion using LLVM $llvmVersion"
} finally {
    if ($ownedObject) {
        Remove-Item -LiteralPath $object -Force
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
