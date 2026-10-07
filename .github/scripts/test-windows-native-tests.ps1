$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Native launcher controls require Windows.' }
$launcher = Join-Path $PSScriptRoot 'run-windows-native-tests.ps1'
$directory = Join-Path $env:RUNNER_TEMP ('picocrypt-launcher-controls-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $directory
$originalPath = $env:PATH
try {
    # Tooling controls only: the real launcher still proves account/job facts.
    $fakeGo = Join-Path $directory 'go.cmd'
    $env:PATH = $directory + ';' + $originalPath
    "@echo off`r`nexit /b 7" | Set-Content -LiteralPath $fakeGo -Encoding ascii
    & $launcher -GoExecutable $fakeGo -GoArguments @('exit-control') -TimeoutSeconds 120
    if ($LASTEXITCODE -ne 7) { throw "Launcher hid child exit 7: received $LASTEXITCODE." }

    $identityPath = Join-Path $directory 'descendant.json'
    $workload = Join-Path $directory 'bounded-descendant.ps1'
    @'
param([string]$IdentityPath)
$self = [Diagnostics.Process]::GetCurrentProcess()
@{ ProcessId = $PID; CreationTicks = $self.StartTime.ToUniversalTime().Ticks } |
    ConvertTo-Json | Set-Content -LiteralPath ($IdentityPath + '.tmp') -Encoding utf8
Move-Item -LiteralPath ($IdentityPath + '.tmp') -Destination $IdentityPath
Start-Sleep -Seconds 90
'@ | Set-Content -LiteralPath $workload -Encoding utf8
    $powerShell = Join-Path $PSHOME 'pwsh.exe'
    ('@echo off' + "`r`n" + '"{0}" -NoLogo -NoProfile -NonInteractive -File "{1}" -IdentityPath "{2}"' -f $powerShell, $workload, $identityPath) |
        Set-Content -LiteralPath $fakeGo -Encoding ascii
    try {
        & $launcher -GoExecutable $fakeGo -GoArguments @('timeout-control') -TimeoutSeconds 30
        throw 'Launcher accepted a workload that must time out.'
    } catch {
        if ($_.Exception.Message -ne 'Native Windows tests exceeded 30 seconds.') { throw }
    }
    if (-not (Test-Path -LiteralPath $identityPath)) { throw 'Timeout control never started its real descendant.' }
    $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    $cleanupTimer = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $descendant = $null
        $stillRunning = $false
        try {
            $descendant = [Diagnostics.Process]::GetProcessById([int]$identity.ProcessId)
            $stillRunning = -not $descendant.HasExited -and
                $descendant.StartTime.ToUniversalTime().Ticks -eq $identity.CreationTicks
        } catch [ArgumentException] {
            # The captured PID no longer exists. A reused PID also fails the
            # creation-time match and is never a cleanup target here.
        } finally {
            if ($null -ne $descendant) { $descendant.Dispose() }
        }
        if (-not $stillRunning) { break }
        if ($cleanupTimer.Elapsed.TotalSeconds -ge 10) { throw 'Launcher timeout left its captured descendant running.' }
        Start-Sleep -Milliseconds 100
    }
    Write-Output "Timeout control confirmed descendant PID $($identity.ProcessId), creation ticks $($identity.CreationTicks), is no longer running."
    Write-Output 'Native launcher tooling controls passed: child exit 7 and timeout descendant cleanup.'
} finally {
    $env:PATH = $originalPath
    Remove-Item -LiteralPath $directory -Recurse -Force
}
exit 0
