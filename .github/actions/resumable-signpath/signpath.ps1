[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('inspect', 'record', 'retrieve')]
    [string]$Operation
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = 'Picocrypt-NG/Picocrypt-NG'
$organization = 'd6e78672-6bae-47d3-b2b8-fa464705b34e'
$policy = 'release-signing'
$phaseFiles = @{
    'windows-binaries' = @('Picocrypt-NG-cli.exe', 'Picocrypt-NG-portable.exe')
    'windows-uninstaller' = @('Uninstall.exe')
    'windows-installer' = @('Picocrypt-NG-Setup.exe')
    'windows-legacy-cli' = @('Picocrypt-NG-cli-Legacy.exe')
}
$phase = $env:SIGNPATH_PHASE
if (!$phase -or !$phaseFiles.ContainsKey($phase) -or $env:GITHUB_REPOSITORY -cne $repository -or
    $env:GITHUB_WORKFLOW_REF -cne "$repository/.github/workflows/release.yml@refs/heads/main" -or
    $env:GITHUB_REF -cne 'refs/heads/main' -or $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
    $env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$' -or $env:GITHUB_WORKFLOW_SHA -cne $env:GITHUB_SHA -or
    $env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]*$' -or $env:GITHUB_RUN_ATTEMPT -notmatch '^[1-9][0-9]*$' -or
    $env:SIGNPATH_PROJECT_SLUG -notmatch '^[A-Za-z0-9_-]+$') {
    throw 'Unexpected SignPath continuation authority'
}

$window = $env:SIGNPATH_APPROVAL_WINDOW_HOURS
if (!$window) { $window = '12' }
if ($window -notmatch '^(?:[1-9]|1[0-9]|2[0-4])$') {
    throw 'SIGNPATH_APPROVAL_WINDOW_HOURS must be an integer from 1 to 24'
}

$prefix = "signpath-$phase"
$unsignedName = "$prefix-unsigned"
$requestName = "$prefix-request"
$signedName = "$prefix-completed"
$checkpointDir = Join-Path $env:RUNNER_TEMP "$prefix-request"
$checkpointFile = Join-Path $checkpointDir 'request.json'
$apiBase = "https://app.signpath.io/Api/v1/$organization"

function Set-ActionOutput([string]$Name, [string]$Value) {
    "$Name=$Value" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
}

function Get-GitHubData([string]$Path) {
    $data = & gh api --method GET $Path
    if ($LASTEXITCODE -ne 0) { throw 'Cannot verify GitHub continuation metadata' }
    return (ConvertFrom-Json -InputObject ($data -join [Environment]::NewLine) -AsHashtable)
}

function Get-PhaseArtifact([string]$Name) {
    $listing = Get-GitHubData "repos/$repository/actions/runs/$env:GITHUB_RUN_ID/artifacts?name=$Name"
    if ($listing.total_count -eq 0 -and @($listing.artifacts).Count -eq 0) { return $null }
    if ($listing.total_count -ne 1 -or @($listing.artifacts).Count -ne 1) {
        throw "Ambiguous SignPath continuation artifact $Name"
    }
    $id = [string]$listing.artifacts[0].id
    if ($id -notmatch '^[1-9][0-9]*$') { throw "Invalid artifact ID for $Name" }
    $artifact = Get-GitHubData "repos/$repository/actions/artifacts/$id"
    if ([string]$artifact.id -cne $id -or $artifact.name -cne $Name -or
        $artifact.digest -cnotmatch '^sha256:[0-9a-f]{64}$' -or $artifact.expired -ne $false -or
        [string]$artifact.workflow_run.id -cne $env:GITHUB_RUN_ID -or
        $artifact.workflow_run.head_sha -cne $env:GITHUB_SHA -or $artifact.workflow_run.head_branch -cne 'main') {
        throw "Invalid authority for SignPath continuation artifact $Name"
    }
    return $artifact
}

function Assert-Checkpoint($Checkpoint) {
    if ($Checkpoint.schema -ne 1 -or $Checkpoint.repository -cne $repository -or
        $Checkpoint.source_sha -cne $env:GITHUB_SHA -or [string]$Checkpoint.run_id -cne $env:GITHUB_RUN_ID -or
        [string]$Checkpoint.attempt -notmatch '^[1-9][0-9]*$' -or
        [long]$Checkpoint.attempt -gt [long]$env:GITHUB_RUN_ATTEMPT -or
        $Checkpoint.phase -cne $phase -or $Checkpoint.project -cne $env:SIGNPATH_PROJECT_SLUG -or
        $Checkpoint.policy -cne $policy -or
        $Checkpoint.request_id -cnotmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or
        [string]$Checkpoint.input_id -notmatch '^[1-9][0-9]*$' -or
        $Checkpoint.input_digest -cnotmatch '^sha256:[0-9a-f]{64}$' -or
        [string]$Checkpoint.expires_at -notmatch '^[1-9][0-9]*$') {
        throw 'Invalid SignPath request receipt'
    }
}

function Get-RequestData([string]$Id, [switch]$StatusOnly) {
    if ([string]::IsNullOrWhiteSpace($env:SIGNPATH_API_TOKEN)) { throw 'Missing SignPath API token' }
    $url = "$apiBase/SigningRequests/$Id"
    if ($StatusOnly) { $url += '/Status' }
    $request = @{
        Uri = $url
        Headers = @{ Authorization = "Bearer $env:SIGNPATH_API_TOKEN" }
        MaximumRedirection = 0
        TimeoutSec = 30
    }
    return (Invoke-RestMethod @request)
}

function Assert-RequestOrigin($Request, [string]$ProducingAttempt) {
    $repoURI = [uri]$Request.origin.repositoryData.url
    $buildURI = [uri]$Request.origin.buildData.url
    $runPath = "/$repository/actions/runs/$env:GITHUB_RUN_ID"
    $attemptPath = "$runPath/attempts/$ProducingAttempt"
    $buildPath = $buildURI.AbsolutePath.TrimEnd('/')
    if ($Request.projectSlug -cne $env:SIGNPATH_PROJECT_SLUG -or
        $Request.signingPolicySlug -cne $policy -or $Request.artifactConfigurationSlug -cne $phase -or
        $Request.origin.repositoryData.commitId -cne $env:GITHUB_SHA -or
        $Request.origin.repositoryData.branchName -cnotin @('main', 'refs/heads/main') -or
        $repoURI.Scheme -cne 'https' -or $repoURI.Host -cne 'github.com' -or
        $repoURI.AbsolutePath.TrimEnd('/') -cnotin @("/$repository", "/$repository.git") -or
        $buildURI.Scheme -cne 'https' -or $buildURI.Host -cne 'github.com' -or
        ($buildPath -cne $attemptPath -and $buildPath -cnotmatch ('^' + [regex]::Escape($runPath) + '(/job/[0-9]+)?$'))) {
        throw 'SignPath request origin or policy differs from the authorized signing phase'
    }
}

function Get-SignedPayload([string]$Id) {
    $directory = $env:SIGNPATH_OUTPUT_PATH
    if (Test-Path -LiteralPath $directory) { throw 'SignPath output path already exists' }
    $archivePath = Join-Path $env:RUNNER_TEMP "$prefix-signed.zip"
    $download = @{
        Uri = "$apiBase/SigningRequests/$Id/SignedArtifact"
        Headers = @{ Authorization = "Bearer $env:SIGNPATH_API_TOKEN" }
        OutFile = $archivePath
        MaximumRedirection = 0
        TimeoutSec = 120
    }
    Invoke-WebRequest @download
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $expected = $phaseFiles[$phase]
        $names = @($archive.Entries | ForEach-Object FullName)
        if ($names.Count -ne $expected.Count -or (Compare-Object $expected $names -CaseSensitive)) {
            throw 'Unexpected SignPath signed payload files'
        }
        New-Item -ItemType Directory -Path $directory | Out-Null
        foreach ($entry in $archive.Entries) {
            if ($entry.Length -le 0 -or $entry.Length -gt 128MB) { throw 'Invalid signed file size' }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $directory $entry.FullName))
        }
    } finally {
        $archive.Dispose()
        Remove-Item -LiteralPath $archivePath -Force
    }
}

switch ($Operation) {
    'inspect' {
        $run = Get-GitHubData "repos/$repository/actions/runs/$env:GITHUB_RUN_ID"
        if ($run.head_sha -cne $env:GITHUB_SHA -or $run.head_branch -cne 'main' -or
            $run.path -cne '.github/workflows/release.yml' -or $run.event -cne 'workflow_dispatch' -or
            [DateTimeOffset]::UtcNow -gt ([DateTimeOffset]$run.created_at).AddDays(7)) {
            throw 'Unauthorized or expired GitHub signing run'
        }
        $unsigned = Get-PhaseArtifact $unsignedName
        $request = Get-PhaseArtifact $requestName
        $signed = Get-PhaseArtifact $signedName
        if ($null -eq $request) {
            if ($null -ne $unsigned -or $null -ne $signed) {
                throw 'Signing intent exists without its request receipt. Inspect SignPath before starting another submission.'
            }
            Set-ActionOutput 'submit' 'true'
        } else {
            if ($null -eq $unsigned) { throw 'Signing request has lost its original unsigned input' }
            Set-ActionOutput 'submit' 'false'
            Set-ActionOutput 'input-id' ([string]$unsigned.id)
            Set-ActionOutput 'input-digest' $unsigned.digest
            Set-ActionOutput 'request-artifact-id' ([string]$request.id)
            if ($null -ne $signed) {
                Set-ActionOutput 'signed-artifact-id' ([string]$signed.id)
            }
        }
    }
    'record' {
        # These are the outputs of the upload and submit steps in this job.
        # Save the receipt immediately; later runs reread their GitHub metadata.
        $checkpoint = @{
            schema = 1
            repository = $repository
            source_sha = $env:GITHUB_SHA
            run_id = $env:GITHUB_RUN_ID
            attempt = $env:GITHUB_RUN_ATTEMPT
            phase = $phase
            project = $env:SIGNPATH_PROJECT_SLUG
            policy = $policy
            request_id = $env:SIGNPATH_REQUEST_ID
            input_id = $env:SIGNPATH_INPUT_ID
            input_digest = "sha256:$env:SIGNPATH_INPUT_DIGEST"
            expires_at = [DateTimeOffset]::UtcNow.AddHours([int]$window).ToUnixTimeSeconds()
        }
        Assert-Checkpoint $checkpoint
        New-Item -ItemType Directory -Path $checkpointDir | Out-Null
        $checkpoint | ConvertTo-Json -Compress | Set-Content -LiteralPath $checkpointFile -Encoding utf8
    }
    'retrieve' {
        $checkpoint = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $checkpointFile -Raw) -AsHashtable
        Assert-Checkpoint $checkpoint
        if ([string]$checkpoint.input_id -cne $env:SIGNPATH_INPUT_ID -or
            $checkpoint.input_digest -cne $env:SIGNPATH_INPUT_DIGEST) {
            throw 'SignPath receipt does not match the immutable original input'
        }
        $alreadyDownloaded = $env:SIGNPATH_COMPLETED_ARTIFACT_ID -match '^[1-9][0-9]*$'
        if (!$alreadyDownloaded -and [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -gt $checkpoint.expires_at) {
            throw 'SignPath approval window expired'
        }

        # Keep the originating job token available while SignPath retrieves its input.
        $id = $checkpoint.request_id
        $status = $null
        $attempts = if ($checkpoint.attempt -ceq $env:GITHUB_RUN_ATTEMPT) { 12 } else { 1 }
        for ($attempt = 0; $attempt -lt $attempts; $attempt++) {
            $status = Get-RequestData $id -StatusOnly
            if ($status.signingRequestId -ine $id) { throw 'SignPath status returned a different request ID' }
            if ($status.workflowStatus -cnotin @('Submitted', 'RetrievingArtifact')) { break }
            if ($attempt -lt $attempts - 1) { Start-Sleep -Seconds 5 }
        }
        if ($status.workflowStatus -cin @('Submitted', 'RetrievingArtifact')) {
            throw 'SignPath did not retrieve the unsigned artifact before the submission job ended'
        }
        $request = Get-RequestData $id
        Assert-RequestOrigin $request $checkpoint.attempt

        if ($request.status -ceq 'Completed' -and $request.workflowStatus -ceq 'Completed' -and $request.isFinalStatus -eq $true) {
            if (!$alreadyDownloaded) {
                Get-SignedPayload $id
                Set-ActionOutput 'downloaded' 'true'
            }
            return
        }
        if ($alreadyDownloaded -or $request.isFinalStatus -ne $false -or
            $request.workflowStatus -cnotin @('WaitingForApproval', 'QueuedForMalwareScanning', 'ScanningForMalware', 'QueuedForProcessing', 'Processing')) {
            throw 'SignPath returned an unsuccessful or unexpected signing result'
        }
        @(
            "SignPath is waiting for $phase."
            "Request: https://app.signpath.io/Web/$organization/SigningRequests/$id"
            "Continue with **Re-run failed jobs** in this run."
            "Resume by $([DateTimeOffset]::FromUnixTimeSeconds($checkpoint.expires_at).ToString('u'))."
        ) | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
        throw 'SignPath request is pending. Continue this run after approval.'
    }
}
