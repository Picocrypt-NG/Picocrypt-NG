param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Stop'
$stream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
$reader = [IO.BinaryReader]::new($stream)
try {
    if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { throw "Missing DOS header: $Path" }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadUInt32()
    if ($peOffset -gt $stream.Length - 88) { throw "Invalid PE header offset: $Path" }
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw "Expected AMD64 PE: $Path" }
    $stream.Position = $peOffset + 24
    if ($reader.ReadUInt16() -ne 0x20B) { throw "Expected PE32+ optional header: $Path" }
    $stream.Position = $peOffset + 64
    if ($reader.ReadUInt16() -ne 6 -or $reader.ReadUInt16() -ne 1) { throw "Expected Windows 6.1 OS target: $Path" }
    $stream.Position = $peOffset + 72
    if ($reader.ReadUInt16() -ne 6 -or $reader.ReadUInt16() -ne 1) { throw "Expected Windows 6.1 subsystem target: $Path" }
} finally {
    $reader.Dispose()
}
Write-Output "Verified AMD64 PE Windows 6.1 target: $Path"
