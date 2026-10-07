[CmdletBinding()]
param(
    [string]$GoExecutable,
    [string[]]$GoArguments,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 2700,
    [string]$ChildConfig
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows) { throw 'Native Windows tests require Windows.' }

if ($ChildConfig) {
    $configuration = Get-Content -LiteralPath $ChildConfig -Raw | ConvertFrom-Json
    $childExit = 1
    try {
        & {
            # Keep the returned PID alive until the parent pins and verifies
            # its creation time; a recycled PID must never become a kill target.
            $self = [Diagnostics.Process]::GetCurrentProcess()
            $readyTemporary = $configuration.Ready + '.tmp'
            @{ ProcessId = $PID; CreationTicks = $self.StartTime.ToUniversalTime().Ticks } |
                ConvertTo-Json | Set-Content -LiteralPath $readyTemporary -Encoding utf8
            Move-Item -LiteralPath $readyTemporary -Destination $configuration.Ready
            $startupTimer = [Diagnostics.Stopwatch]::StartNew()
            while (-not (Test-Path -LiteralPath $configuration.Acknowledgement)) {
                if ($startupTimer.Elapsed.TotalSeconds -ge 30) { throw 'Native test parent did not acknowledge ownership.' }
                Start-Sleep -Milliseconds 100
            }
            if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $configuration.UserSid) {
                throw 'Native test process did not retain the runner account.'
            }
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NativeTestJob {
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsProcessInJob(IntPtr process, IntPtr job,
        [MarshalAs(UnmanagedType.Bool)] out bool inJob);
}
'@
            $inJob = $true
            if (-not [NativeTestJob]::IsProcessInJob([IntPtr](-1), [IntPtr]::Zero, [ref]$inJob) -or $inJob) {
                throw 'Native test process remains in a Job Object or membership is unknown; refusing tests.'
            }
            if ((Get-Command go -CommandType Application | Select-Object -First 1).Source -ne $configuration.GoExecutable) {
                throw 'Native test process did not retain the selected Go executable.'
            }
            Write-Output 'Windows native CI: same runner account and outside-job execution verified.'
            Set-Location -LiteralPath $configuration.WorkingDirectory
            $arguments = [string[]]$configuration.GoArguments
            & $configuration.GoExecutable @arguments
            $script:childExit = $LASTEXITCODE
        } *> $configuration.Log
    } catch {
        $_ | Out-String | Add-Content -LiteralPath $configuration.Log
    }
    exit $childExit
}

if (-not $GoExecutable -or -not $GoArguments -or -not $env:RUNNER_TEMP -or -not $env:RUNNER_TRACKING_ID) {
    throw 'Native test launch requires Go arguments and the normal Actions runner tracking environment.'
}
$GoExecutable = (Resolve-Path -LiteralPath $GoExecutable).Path
$workingDirectory = (Resolve-Path (Join-Path $PSScriptRoot '../../src')).Path
$stateDirectory = Join-Path $env:RUNNER_TEMP ('picocrypt-native-tests-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $stateDirectory
$configPath = Join-Path $stateDirectory 'config.json'
$logPath = Join-Path $stateDirectory 'tests.log'
$acknowledgement = Join-Path $stateDirectory 'owned'
$readyPath = Join-Path $stateDirectory 'ready.json'
@{
    GoExecutable = $GoExecutable
    GoArguments = $GoArguments
    WorkingDirectory = $workingDirectory
    UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Acknowledgement = $acknowledgement
    Ready = $readyPath
    Log = $logPath
} | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding utf8

# Pass build/runtime facts only. Never inherit token/credential variables from
# the Actions step. RUNNER_TRACKING_ID preserves normal runner orphan cleanup.
$environment = foreach ($name in @(
    'PATH', 'PATHEXT', 'SystemRoot', 'SystemDrive', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'USERPROFILE',
    'HOMEDRIVE', 'HOMEPATH', 'LOCALAPPDATA', 'APPDATA', 'ProgramData',
    'ProgramFiles', 'ProgramFiles(x86)', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE',
    'GOTOOLCHAIN', 'GOROOT', 'GOPATH', 'GOCACHE', 'GOMODCACHE', 'GOFLAGS',
    'GOOS', 'GOARCH', 'GOAMD64', 'CGO_ENABLED', 'CC', 'CXX', 'CGO_CFLAGS',
    'CGO_CPPFLAGS', 'CGO_CXXFLAGS', 'CGO_LDFLAGS', 'GOMAXPROCS', 'GOMEMLIMIT',
    'PICOCRYPT_RUN_CLI_INTEGRATION', 'RUNNER_TRACKING_ID'
)) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ($null -ne $value) { "$name=$value" }
}
$process = $null
$reader = $null
$exitCode = 1
try {
    # Win32_Process.Create avoids the caller's job; the documented breakaway
    # flag must also be permitted by the WMI provider's job. No limits change.
    # https://learn.microsoft.com/windows/win32/cimwin32prov/create-method-in-class-win32-process
    $startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{
        CreateFlags = [uint32]0x01000400 # CREATE_BREAKAWAY_FROM_JOB | CREATE_UNICODE_ENVIRONMENT
        EnvironmentVariables = [string[]]$environment
    }
    $powerShell = Join-Path $PSHOME 'pwsh.exe'
    $commandLine = '"{0}" -NoLogo -NoProfile -NonInteractive -File "{1}" -ChildConfig "{2}"' -f $powerShell, $PSCommandPath, $configPath
    $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -OperationTimeoutSec 30 -Arguments @{
        CommandLine = $commandLine
        CurrentDirectory = $workingDirectory
        ProcessStartupInformation = $startup
    }
    if ($created.ReturnValue -ne 0) {
        throw "Windows refused native test process creation (WMI status $($created.ReturnValue)); job policy remains unchanged."
    }
    $startupTimer = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $readyPath)) {
        if ($startupTimer.Elapsed.TotalSeconds -ge 20) { throw 'Native test process did not complete startup.' }
        Start-Sleep -Milliseconds 100
    }
    $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
    $candidate = [Diagnostics.Process]::GetProcessById([int]$created.ProcessId)
    $null = $candidate.SafeHandle
    if ($ready.ProcessId -ne $created.ProcessId -or $candidate.StartTime.ToUniversalTime().Ticks -ne $ready.CreationTicks) {
        $candidate.Dispose()
        throw 'Native test process identity changed before ownership was established.'
    }
    $process = $candidate
    $null = New-Item -ItemType File -Path $acknowledgement
    $testTimer = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ($null -eq $reader -and (Test-Path -LiteralPath $logPath)) {
            $stream = [IO.File]::Open($logPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = [IO.StreamReader]::new($stream)
        }
        if ($null -ne $reader) {
            while ($null -ne ($line = $reader.ReadLine())) { Write-Output $line }
        }
        if ($process.HasExited) { break }
        if ($testTimer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw "Native Windows tests exceeded $TimeoutSeconds seconds." }
        Start-Sleep -Milliseconds 250
    } while ($true)
    $process.WaitForExit()
    $exitCode = $process.ExitCode
} finally {
    if ($null -ne $process) {
        if (-not $process.HasExited) {
            $process.Kill($true)
            if (-not $process.WaitForExit(10000)) { throw 'Native test process tree did not terminate.' }
        }
        $process.Dispose()
    }
    if ($null -ne $reader) {
        while ($null -ne ($line = $reader.ReadLine())) { Write-Output $line }
        $reader.Dispose()
    } elseif (Test-Path -LiteralPath $logPath) {
        Get-Content -LiteralPath $logPath
    }
    Remove-Item -LiteralPath $stateDirectory -Recurse -Force
}
exit $exitCode
