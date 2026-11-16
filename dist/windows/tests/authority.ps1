[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][string]$NsisArchive,
    [switch]$Interactive,
    [switch]$OnlyInteractive,
    [switch]$OnlyHeldWriter
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Native Windows is required; Wine is not an ACL test lane.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run in an elevated Windows PowerShell 7 session.'
}
$id = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$app = "Picocrypt-NG-Authority-$id"
$root = "C:\pcng-authority-$id"
$default = Join-Path $env:ProgramW6432 $app
$users = @()
$credentials = @()
$junctions = @()
$aliasDrive = $null
$setup = $null
$passed = 0

function Protect-Directory([string]$Path) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Grant-Access([string]$Path, [string]$Sid, [string]$Rights) {
    & icacls.exe $Path /grant "*$($Sid):$Rights" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for $Path" }
}
function Run-User([int]$Principal, [string]$Code) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('$ErrorActionPreference="Stop"; ' + $Code))
    $process = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $credentials[$Principal] -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand',$encoded -Wait -PassThru -WindowStyle Hidden
    return $process.ExitCode
}
function Assert-Blocked([string]$Path) {
    foreach ($principal in 0, 1) {
        $quoted = $Path.Replace("'", "''")
        $rc = Run-User $principal "try { [IO.File]::WriteAllText('$quoted', 'REPLACED'); exit 41 } catch [UnauthorizedAccessException] { exit 0 }"
        if ($rc -ne 0) { throw "Principal $principal can modify $Path (rc=$rc)" }
        $rc = Run-User $principal "try { [IO.File]::Delete('$quoted'); exit 41 } catch [UnauthorizedAccessException] { exit 0 }"
        if ($rc -ne 0) { throw "Principal $principal can delete $Path (rc=$rc)" }
        $rc = Run-User $principal "try { [IO.File]::Move('$quoted', '$quoted.moved'); exit 41 } catch [UnauthorizedAccessException] { exit 0 }"
        if ($rc -ne 0) { throw "Principal $principal can rename $Path (rc=$rc)" }
    }
}
function Snapshot {
    $registry = @("HKLM:\Software\$app", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$app", "HKLM:\Software\Classes\$app.pcv", "HKLM:\Software\Classes\.$app")
    return (@($registry | ForEach-Object { if (Test-Path $_) { & reg.exe query ($_.Replace('HKLM:', 'HKLM')) /s } else { "ABSENT $_" } }) + @(
        (Get-Item 'HKLM:\Software\RegisteredApplications').GetValue($app, '<absent>')
        foreach ($path in @((Join-Path ([Environment]::GetFolderPath('Desktop')) "$app.lnk"), (Join-Path ([Environment]::GetFolderPath('Programs')) $app))) {
            if (Test-Path -LiteralPath $path) { "SHORTCUT $path" } else { "ABSENT $path" }
        }
    )) -join "`n"
}
function Shared-Hash([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]7)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($hash.ComputeHash($stream)) } finally { $hash.Dispose(); $stream.Dispose() }
}
function Destination-Snapshot([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '<absent>' }
    $entries = @(Get-Item -LiteralPath $Path) + @(Get-ChildItem -LiteralPath $Path -Force | Sort-Object Name)
    return @($entries | ForEach-Object {
        [ordered]@{
            Name = $_.Name
            Attributes = [int]$_.Attributes
            Modified = $_.LastWriteTimeUtc.Ticks
            ACL = (Get-Acl -LiteralPath $_.FullName).Sddl
            Hash = if (-not $_.PSIsContainer -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Shared-Hash $_.FullName } else { $null }
        }
    }) | ConvertTo-Json -Depth 4 -Compress
}
function Clear-InstallRecord {
    foreach ($view in [Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64) {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try { $hive.DeleteSubKeyTree("Software\$app", $false) } finally { $hive.Dispose() }
    }
}
function Install([string]$Destination, [switch]$Stored, [switch]$Default) {
    $arguments = '/S'
    if (-not $Stored -and -not $Default) { $arguments += " /D=$Destination" }
    return (Start-Process -FilePath $setup -ArgumentList $arguments -PassThru -Wait).ExitCode
}
function Install-Interactive([string]$Destination) {
    if (-not ('PcngInstallerWindow' -as [type])) {
        Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class PcngInstallerWindow {
    public delegate bool EnumProc(IntPtr h, IntPtr p);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr p);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc f, IntPtr p);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr h, uint command);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder b, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder b, int n);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, string l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] static extern IntPtr ReadMessage(IntPtr h, uint m, IntPtr w, StringBuilder l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
    public static string Text(IntPtr h) { var b=new StringBuilder(512); GetWindowText(h,b,b.Capacity); return b.ToString(); }
    static IntPtr OkButton(IntPtr h) {
        foreach(int id in new[]{1,2}) { var button=GetDlgItem(h,id); if(Text(button).Replace("&","")=="OK") return button; }
        return IntPtr.Zero;
    }
    public static IntPtr Window(uint pid, bool ok) {
        IntPtr found=IntPtr.Zero;
        EnumWindows((h,p)=>{ uint actual; GetWindowThreadProcessId(h,out actual);
            if(actual==pid && IsWindowVisible(h) && (ok ? OkButton(h)!=IntPtr.Zero :
                GetDlgItem(h,1)!=IntPtr.Zero && GetWindow(h,4)==IntPtr.Zero)) { found=h; return false; } return true; }, IntPtr.Zero);
        return found;
    }
    static IntPtr DirectoryEdit(IntPtr h) {
        IntPtr edit=IntPtr.Zero;
        EnumChildWindows(h,(c,p)=>{ var b=new StringBuilder(64); GetClassName(c,b,b.Capacity);
            if(IsWindowVisible(c) && b.ToString()=="Edit") { edit=c; return false; } return true; },IntPtr.Zero);
        return edit;
    }
    public static bool SetDirectory(IntPtr h,string path) {
        IntPtr edit=DirectoryEdit(h);
        if(edit==IntPtr.Zero) return false; SendMessage(edit,0x000C,IntPtr.Zero,path); return true;
    }
    public static string Directory(IntPtr h) { var b=new StringBuilder(1024); ReadMessage(DirectoryEdit(h),0x000D,(IntPtr)b.Capacity,b); return b.ToString(); }
    public static bool Browse(IntPtr h) {
        IntPtr button=IntPtr.Zero;
        EnumChildWindows(h,(c,p)=>{ if(IsWindowVisible(c) && Text(c).Replace("&","").StartsWith("Browse")) { button=c; return false; } return true; },IntPtr.Zero);
        return button!=IntPtr.Zero && PostMessage(button,0x00F5,IntPtr.Zero,IntPtr.Zero);
    }
    public static void Click(IntPtr h) { SendMessage(GetDlgItem(h,1),0x00F5,IntPtr.Zero,null); }
    public static void DismissPopup(IntPtr h) { SendMessage(OkButton(h),0x00F5,IntPtr.Zero,null); }
    public static void Cancel(IntPtr h) { SendMessage(GetDlgItem(h,2),0x00F5,IntPtr.Zero,null); }
}
'@
    }
    $process = Start-Process -FilePath $setup -PassThru
    try {
        $page = 0
        $refusal = $false
        $lastState = ''
        $browsing = $false
        $browsed = $false
        $until = [DateTime]::UtcNow.AddSeconds(40)
        while (-not $process.HasExited -and [DateTime]::UtcNow -lt $until) {
            $popup = [PcngInstallerWindow]::Window($process.Id, $true)
            if ($popup -ne [IntPtr]::Zero) {
                Write-Host "UI popup=$([PcngInstallerWindow]::Text($popup)); page=$page; browsing=$browsing; browsed=$browsed"
                if ($browsing) {
                    $browsed = $true
                    $browsing = $false
                } else { $refusal = $true }
                [PcngInstallerWindow]::DismissPopup($popup)
            } else {
                $window = [PcngInstallerWindow]::Window($process.Id, $false)
                if ($window -ne [IntPtr]::Zero) {
                    $button = [PcngInstallerWindow]::Text([PcngInstallerWindow]::GetDlgItem($window, 1)).Replace('&', '')
                    $state = "$page|$button|$refusal"
                    if ($state -ne $lastState) { Write-Host "UI $state"; $lastState = $state }
                    if ($page -lt 3 -and ($button -like '*Next*' -or $button -like '*Agree*')) {
                        [PcngInstallerWindow]::Click($window)
                        $page++
                    } elseif ($page -eq 3 -and $button -like '*Install*') {
                        if (-not $browsed) {
                            if (-not [PcngInstallerWindow]::SetDirectory($window, $root)) { throw 'Directory page Edit not found before Browse' }
                            if (-not [PcngInstallerWindow]::Browse($window)) { throw 'Directory Browse control not found' }
                            $browsing = $true
                        } elseif (-not $browsing) {
                            $selected = [PcngInstallerWindow]::Directory($window).TrimEnd('\')
                            if ($selected -ne (Join-Path $root $app)) { throw "Browse did not preserve application-name suffix: $selected" }
                            Write-Host 'UI Browse preserves application-name suffix'
                            if (-not [PcngInstallerWindow]::SetDirectory($window, $Destination)) { throw 'Directory page Edit not found' }
                            [PcngInstallerWindow]::Click($window)
                            $page++
                        }
                    } elseif ($refusal) { [PcngInstallerWindow]::Cancel($window) }
                }
            }
            Start-Sleep -Milliseconds 200
            $process.Refresh()
        }
        if (-not $process.HasExited) { throw "Interactive installer did not finish (state=$lastState)" }
        if (-not $refusal -or $page -ne 4) { throw "Interactive test did not reach directory selection and protected-destination refusal (page=$page; refusal=$refusal; browsing=$browsing; browsed=$browsed; rc=$($process.ExitCode))" }
        return $process.ExitCode
    } finally {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
        $process.Dispose()
    }
}
function Assert-Refused([string]$Name, [string]$Destination, [switch]$Stored, [switch]$InteractiveCase) {
    if ($Stored) {
        foreach ($view in [Microsoft.Win32.RegistryView]::Registry64) {
            $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            try {
                $key = $hive.CreateSubKey("Software\$app")
                try { $key.SetValue('InstallDir', $Destination) } finally { $key.Dispose() }
            } finally { $hive.Dispose() }
        }
    }
    $beforeRegistry = Snapshot
    $before = Destination-Snapshot $Destination
    $rc = if ($InteractiveCase) { Install-Interactive $Destination } else { Install $Destination -Stored:$Stored }
    if ($rc -eq 0) { throw "$Name accepted an unsafe destination" }
    if ((Snapshot) -ne $beforeRegistry) { throw "$Name changed registration/shortcuts before refusal" }
    if ((Destination-Snapshot $Destination) -ne $before) { throw "$Name modified destination bytes, ACLs or metadata before refusal" }
    $script:passed++
    Write-Output "PASS $Name refusal, no payload/registry/shortcut effects (rc=$rc)"
}

function Test-HeldWriter {
    $directory = Join-Path $root 'held-writer'
    $signals = Join-Path $root 'writer-signals'
    Protect-Directory $directory
    Protect-Directory $signals
    Grant-Access $signals $users[0].SID.Value '(OI)(CI)(M)'
    $payload = Join-Path $directory 'Uninstall.exe'
    Set-Content $payload 'ORIGINAL' -NoNewline -Encoding ascii
    $safeACL = Get-Acl $payload
    Grant-Access $payload $users[0].SID.Value '(M)'
    $code = @'
$ErrorActionPreference='Stop'
$stream=[IO.File]::Open('__PAYLOAD__',[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]7)
try {
    Set-Content '__SIGNALS__\ready' 'OPEN'
    $until=[DateTime]::UtcNow.AddSeconds(30)
    while(-not (Test-Path '__SIGNALS__\probe')) {
        if([DateTime]::UtcNow -gt $until) { throw 'Held writer probe timed out' }
        Start-Sleep -Milliseconds 50
    }
    $stream.WriteByte(0x58)
    $stream.Flush()
    Set-Content '__SIGNALS__\proved' 'WROTE'
    while(-not (Test-Path '__SIGNALS__\release')) {
        if([DateTime]::UtcNow -gt $until) { throw 'Held writer release timed out' }
        Start-Sleep -Milliseconds 50
    }
} finally { $stream.Dispose() }
'@
    $code = $code.Replace('__PAYLOAD__', $payload).Replace('__SIGNALS__', $signals)
    $workerPath = Join-Path $root 'held-writer.ps1'
    Set-Content $workerPath $code -Encoding utf8
    $bootstrap = ". ([scriptblock]::Create([IO.File]::ReadAllText('$workerPath')))"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    $errorsPath = Join-Path $signals 'stderr.txt'
    $writer = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $credentials[0] -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand',$encoded -PassThru -WindowStyle Hidden -RedirectStandardError $errorsPath
    $acquired = $false
    try {
        for ($i = 0; $i -lt 100 -and -not (Test-Path (Join-Path $signals 'ready')) -and -not $writer.HasExited; $i++) { Start-Sleep -Milliseconds 50 }
        if (-not (Test-Path (Join-Path $signals 'ready'))) { throw "Standard principal did not acquire the writable-handle fixture: $(Get-Content $errorsPath -Raw)" }
        $acquired = $true
        Set-Acl $payload $safeACL
        Set-Content (Join-Path $signals 'probe') 'WRITE'
        for ($i = 0; $i -lt 100 -and -not (Test-Path (Join-Path $signals 'proved')) -and -not $writer.HasExited; $i++) { Start-Sleep -Milliseconds 50 }
        $expected = [Security.Cryptography.SHA256]::Create()
        try { $expectedHash = [Convert]::ToHexString($expected.ComputeHash([Text.Encoding]::ASCII.GetBytes('XRIGINAL'))) } finally { $expected.Dispose() }
        if (-not (Test-Path (Join-Path $signals 'proved')) -or (Shared-Hash $payload) -ne $expectedHash) { throw 'Historical data-write handle did not modify the restored-ACL file' }
        Write-Output 'PASS native held-writer oracle: standard principal retained data-write capability after ACL restoration'
        Assert-Refused 'pre-existing standard-user writable uninstaller handle' $directory
    } finally {
        Set-Content (Join-Path $signals 'release') 'CLOSE'
        if (-not $writer.WaitForExit(10000)) { Stop-Process -Id $writer.Id -Force; throw 'Held writer did not exit' }
        if ($acquired -and $writer.ExitCode -ne 0) { throw "Historical data-write handle oracle failed after ACL restoration: $(Get-Content $errorsPath -Raw)" }
        $writer.Dispose()
    }
}

try {
    Protect-Directory $root
    Protect-Directory (Join-Path $root 'fixture\dist\windows')
    Protect-Directory (Join-Path $root 'fixture\src')
    Protect-Directory (Join-Path $root 'fixture\images')
    foreach ($index in 0, 1) {
        $name = "pcng$index$id"
        $password = ConvertTo-SecureString ('Pcng!' + [Guid]::NewGuid().ToString('N') + '4') -AsPlainText -Force
        $user = New-LocalUser -Name $name -Password $password -AccountNeverExpires -Description "Picocrypt NG ACL test $id"
        $users += $user
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $user
        $credentials += [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    }
    Write-Output "NATIVE fixture=$root; principals=$($users.SID.Value -join ',')"
    $compiler = & (Join-Path $Repository '.github\scripts\install-nsis.ps1') -ArchivePath $NsisArchive -DestinationPath (Join-Path $root 'nsis')
    $fixture = Join-Path $root 'fixture'
    Copy-Item (Join-Path $Repository 'LICENSE') $fixture
    Copy-Item (Join-Path $Repository 'images\key.ico') (Join-Path $fixture 'images')
    Copy-Item (Join-Path $Repository 'images\pcv-icon.ico') (Join-Path $fixture 'images')
    foreach ($helper in Get-ChildItem -LiteralPath (Join-Path $Repository 'dist\windows') -Filter '*.nsh' -File -Force) {
        Copy-Item -LiteralPath $helper.FullName -Destination (Join-Path $fixture 'dist\windows') -Force
    }
    # Only the fixture's application namespace changes. The real installer
    # instructions, pages and security implementation are compiled unchanged.
    $source = Get-Content (Join-Path $Repository 'dist\windows\installer.nsi') -Raw
    if ($source.Contains('install-authority.nsh') -and -not (Test-Path -LiteralPath (Join-Path $fixture 'dist\windows\install-authority.nsh'))) {
        throw 'Required installer authority include was not copied into the native fixture.'
    }
    foreach ($literal in @('!define APPNAME     "Picocrypt-NG"', '!define PROGID      "PicocryptNG.pcv"')) {
        if (-not $source.Contains($literal)) { throw "Missing fixture namespace anchor: $literal" }
    }
    $source = $source.Replace('!define APPNAME     "Picocrypt-NG"', "!define APPNAME     `"$app`"")
    $source = $source.Replace('!define PROGID      "PicocryptNG.pcv"', "!define PROGID      `"$app.pcv`"")
    $source = $source.Replace('Software\Classes\.pcv', "Software\Classes\.$app").Replace('".pcv"', "`".$app`"")
    $scriptPath = Join-Path $fixture 'dist\windows\installer.nsi'
    Set-Content -LiteralPath $scriptPath -Value $source -Encoding utf8
    $version = (Get-Content (Join-Path $Repository 'VERSION') -Raw).Trim()
    foreach ($marker in 'PCNG_V1', 'PCNG_V2') {
        Set-Content (Join-Path $fixture 'src\Picocrypt-NG-portable.exe') $marker -NoNewline -Encoding ascii
        Set-Content (Join-Path $fixture 'src\Picocrypt-NG-cli.exe') "CLI-$marker" -NoNewline -Encoding ascii
        $mode = @()
        if ($marker -eq 'PCNG_V2') { $mode += '/DEXPORT_UNINST' }
        & $compiler /WX /V4 "/DVERSION=$version" @mode $scriptPath
        if ($LASTEXITCODE -ne 0) { throw "NSIS compile failed ($LASTEXITCODE)" }
        if ($marker -eq 'PCNG_V2') {
            & $compiler /WX /V4 "/DVERSION=$version" /DIMPORT_UNINST $scriptPath
            if ($LASTEXITCODE -ne 0) { throw "NSIS uninstaller import compile failed ($LASTEXITCODE)" }
        }
        Copy-Item (Join-Path $fixture 'dist\windows\Picocrypt-NG-Setup.exe') (Join-Path $root "$marker.exe")
    }
    $setup = Join-Path $root 'PCNG_V1.exe'
    if ($OnlyHeldWriter) { Test-HeldWriter; Write-Output 'NATIVE PARTIAL PASS: held-writer lane only'; return }
    $leaf = Join-Path $root 'user-writable'
    Protect-Directory $leaf
    Grant-Access $leaf $users[0].SID.Value '(OI)(CI)(M)'
    if ((Run-User 0 "[IO.File]::WriteAllText('$leaf\attacker-proof', 'owned')") -ne 0) { throw 'Writable leaf oracle invalid' }
    Assert-Refused 'per-user writable leaf /D' $leaf
    if ($OnlyInteractive) {
        Assert-Refused 'interactive directory selection' $leaf -InteractiveCase
        Write-Output 'NATIVE PARTIAL PASS: interactive lane only'
        return
    }
    Test-HeldWriter

    $owner = Join-Path $root 'user-owned'
    Protect-Directory $owner
    $acl = Get-Acl $owner
    $acl.SetOwner($users[0].SID)
    Set-Acl $owner $acl
    Assert-Refused 'untrusted owner' $owner

    foreach ($rights in '(DC)', '(WDAC)', '(WO)', '(WA)', '(WD)') {
        $path = Join-Path $root ('privilege-' + $rights.Trim('(', ')'))
        Protect-Directory $path
        Grant-Access $path $users[0].SID.Value $rights
        Assert-Refused "per-user directory $rights" $path
        Protect-Directory (Join-Path $path 'child')
        Assert-Refused "per-user ancestor $rights" (Join-Path $path 'child')
    }
    $ancestor = Join-Path $root 'mutable-ancestor'
    Protect-Directory $ancestor
    Grant-Access $ancestor $users[0].SID.Value '(OI)(CI)(M)'
    Protect-Directory (Join-Path $ancestor 'protected-leaf')
    Assert-Refused 'mutable ancestor existing leaf' (Join-Path $ancestor 'protected-leaf')
    Assert-Refused 'mutable ancestor missing leaf' (Join-Path $ancestor 'missing')
    Assert-Refused 'stored unsafe InstallDir' $leaf -Stored

    $inherit = Join-Path $root 'inherit-only'
    Protect-Directory $inherit
    Grant-Access $inherit $users[0].SID.Value '(OI)(IO)(M)'
    Assert-Refused 'inherit-only file mutation' $inherit

    foreach ($name in 'Picocrypt-NG.exe', 'Picocrypt-NG-cli.exe', 'Uninstall.exe', 'pcv-icon.ico', 'Picocrypt-NG-portable.exe') {
        $path = Join-Path $root ('file-' + $name)
        Protect-Directory $path
        Set-Content (Join-Path $path $name) 'ORIGINAL' -NoNewline
        Grant-Access (Join-Path $path $name) $users[0].SID.Value '(M)'
        Assert-Refused "existing mutable $name" $path
    }
    $target = Join-Path $root 'junction-target'
    foreach ($rights in '(D)', '(AD)') {
        $path = Join-Path $root ('file-only-' + $rights.Trim('(', ')'))
        Protect-Directory $path
        Set-Content (Join-Path $path 'Picocrypt-NG.exe') 'ORIGINAL' -NoNewline
        Grant-Access (Join-Path $path 'Picocrypt-NG.exe') $users[0].SID.Value $rights
        Assert-Refused "existing payload $rights only" $path
    }
    Protect-Directory $target
    foreach ($name in 'junction-leaf', 'junction-ancestor') {
        $link = Join-Path $root $name
        $null = New-Item -ItemType Junction -Path $link -Target $target
        $junctions += $link
        $destination = if ($name -eq 'junction-leaf') { $link } else { Join-Path $link 'child' }
        Assert-Refused $name $destination
    }

    $hardlink = Join-Path $root 'hardlink'
    Protect-Directory $hardlink
    Set-Content (Join-Path $root 'hardlink-original') 'HARDLINK' -NoNewline
    $null = New-Item -ItemType HardLink -Path (Join-Path $hardlink 'Picocrypt-NG.exe') -Target (Join-Path $root 'hardlink-original')
    Assert-Refused 'existing hardlinked payload' $hardlink
    $aliasTarget = Join-Path $root 'alias-target'
    Protect-Directory $aliasTarget
    foreach ($letter in 'Z', 'Y', 'X', 'W') {
        if (-not (Get-PSDrive -Name $letter -ErrorAction SilentlyContinue)) { $aliasDrive = $letter + ':'; break }
    }
    if (-not $aliasDrive) { throw 'No free synthetic SUBST drive letter available' }
    & subst.exe $aliasDrive $aliasTarget
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic SUBST fixture failed' }
    Assert-Refused 'DOS-device SUBST alias' ($aliasDrive + '\child')
    $callback = Join-Path $root 'callback-ace'
    Protect-Directory $callback
    $acl = Get-Acl $callback
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    $ace = [Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None, [Security.AccessControl.AceQualifier]::AccessAllowed, 0x1200a9, $users[0].SID, $true, [byte[]]@())
    $raw.DiscretionaryAcl.InsertAce($raw.DiscretionaryAcl.Count, $ace)
    $binary = [byte[]]::new($raw.BinaryLength)
    $raw.GetBinaryForm($binary, 0)
    $acl.SetSecurityDescriptorBinaryForm($binary)
    Set-Acl $callback $acl
    Assert-Refused 'unsupported callback allow ACE' $callback
    $existing = Join-Path $root 'safe-existing-custom'
    Protect-Directory $existing
    Grant-Access $existing 'S-1-3-0' '(OI)(CI)(IO)(F)'
    $existingACL = (Get-Acl $existing).Sddl
    foreach ($destination in $default, (Join-Path $root 'safe-custom'), $existing) {
        Clear-InstallRecord
        if ($destination -ne $default) {
            $null = New-Item "HKLM:\Software\$app" -Force
            Set-ItemProperty "HKLM:\Software\$app" InstallDir $leaf
        }
        $setup = Join-Path $root 'PCNG_V1.exe'
        $rc = Install $destination -Default:($destination -eq $default)
        if ($rc -ne 0) { throw "Protected positive failed: $destination ($rc)" }
        if ($destination -eq $existing -and (Get-Acl $existing).Sddl -ne $existingACL) { throw 'Existing custom ACL was rewritten' }
        foreach ($name in 'Picocrypt-NG.exe', 'Picocrypt-NG-cli.exe', 'Uninstall.exe') { Assert-Blocked (Join-Path $destination $name) }
        if ((Get-Content (Join-Path $destination 'Picocrypt-NG.exe') -Raw) -ne 'PCNG_V1') { throw 'Clean install payload mismatch' }
        Set-Content (Join-Path $destination 'Picocrypt-NG-portable.exe') 'ORPHAN' -NoNewline
        $setup = Join-Path $root 'PCNG_V2.exe'
        if ((Install $destination -Stored) -ne 0) { throw 'Protected stored-directory upgrade failed' }
        if ((Get-Content (Join-Path $destination 'Picocrypt-NG.exe') -Raw) -ne 'PCNG_V2') { throw 'Upgrade did not replace payload' }
        if (Test-Path (Join-Path $destination 'Picocrypt-NG-portable.exe')) { throw 'Upgrade left orphan' }
        Copy-Item "$env:WINDIR\System32\ping.exe" (Join-Path $destination 'Picocrypt-NG.exe') -Force
        $running = Start-Process (Join-Path $destination 'Picocrypt-NG.exe') -ArgumentList '-n 600 127.0.0.1' -WindowStyle Hidden -PassThru
        try {
            Start-Sleep -Milliseconds 500
            $before = (Get-FileHash (Join-Path $destination 'Picocrypt-NG.exe')).Hash
            if ((Install $destination) -eq 0) { throw 'Running executable was silently accepted' }
            if ($running.HasExited -or (Get-FileHash (Join-Path $destination 'Picocrypt-NG.exe')).Hash -ne $before) { throw 'Running instance was killed or changed' }
        } finally { if (-not $running.HasExited) { Stop-Process -Id $running.Id -Force; $running.WaitForExit() }; $running.Dispose() }
        if ((Install $destination) -ne 0) { throw 'Upgrade after closing running instance failed' }
        $command = (Get-Item "HKLM:\Software\Classes\$app.pcv\shell\open\command").GetValue('')
        if ($command -ne "`"$destination\Picocrypt-NG.exe`" `"%1`"") { throw 'Association points outside protected destination' }
        $uninstaller = Join-Path $destination 'Uninstall.exe'
        $safeACL = Get-Acl $uninstaller
        Grant-Access $uninstaller $users[0].SID.Value '(M)'
        $beforeRegistry = Snapshot
        $beforeDestination = Destination-Snapshot $destination
        $rc = (Start-Process $uninstaller -ArgumentList "/S _?=$destination" -Wait -PassThru).ExitCode
        if ($rc -eq 0 -or (Snapshot) -ne $beforeRegistry -or (Destination-Snapshot $destination) -ne $beforeDestination) { throw "Unsafe uninstaller destination was not refused without effects (rc=$rc)" }
        Set-Acl $uninstaller $safeACL
        $rc = (Start-Process (Join-Path $destination 'Uninstall.exe') -ArgumentList '/S' -Wait -PassThru).ExitCode
        if ($rc -ne 0) { throw "Uninstall failed ($rc)" }
        for ($i = 0; $i -lt 40 -and (Test-Path $destination); $i++) { Start-Sleep -Milliseconds 100 }
        if (Test-Path $destination) { throw 'Uninstall left installed files' }
        if (Test-Path "HKLM:\Software\Classes\$app.pcv") { throw 'Uninstall left association' }
        $passed++
        Write-Output "PASS protected install/upgrade/cross-principal denial/association/uninstall: $destination"
    }
    if ($Interactive) { Assert-Refused 'interactive directory selection' $leaf -InteractiveCase }
    if (-not $Interactive) { Write-Output 'NOT RUN: interactive directory selection; use -Interactive in an interactive desktop session.' }
    Write-Output "NATIVE PASS $passed scenarios; principals=$($users.SID.Value -join ','); identity=$($identity.Name); Windows=$([Environment]::OSVersion.Version)"
} finally {
    foreach ($link in $junctions) { if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link) } }
    if ($aliasDrive) { & subst.exe $aliasDrive /d }
    foreach ($user in $users) {
        Get-CimInstance Win32_UserProfile -Filter "SID='$($user.SID.Value)'" | Remove-CimInstance
        Remove-LocalUser -SID $user.SID -ErrorAction Continue
    }
    foreach ($view in [Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64) {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            foreach ($key in @("Software\$app", "Software\Microsoft\Windows\CurrentVersion\Uninstall\$app", "Software\Classes\$app.pcv", "Software\Classes\.$app")) { $hive.DeleteSubKeyTree($key, $false) }
            $key = $hive.OpenSubKey('Software\RegisteredApplications', $true)
            if ($key) { try { $key.DeleteValue($app, $false) } finally { $key.Dispose() } }
        } finally { $hive.Dispose() }
    }
    foreach ($path in @((Join-Path ([Environment]::GetFolderPath('Desktop')) "$app.lnk"), (Join-Path ([Environment]::GetFolderPath('Programs')) $app), $default, $root)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}
