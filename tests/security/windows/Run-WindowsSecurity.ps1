#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Python, [Parameter(Mandatory)][string]$Root,
      [ValidatePattern('^[a-f0-9]{32}$')][string]$RunId = ([Guid]::NewGuid().ToString('N')),
      [switch]$CleanupOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
$Root = [IO.Path]::GetFullPath($Root)
$Python = [IO.Path]::GetFullPath($Python)
if (-not $IsWindows) { throw 'Native Windows security tier requires Windows' }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'Required prepared Python executable is unavailable' }
$runId = $RunId
$state = [IO.Path]::GetFullPath((Join-Path (Join-Path $Root '.scratch') "security-windows-$runId"))
if ($CleanupOnly) {
    $ownedVhd = Join-Path $state 'scratch.vhdx'
    if (Test-Path -LiteralPath $ownedVhd -PathType Leaf) {
        if ((Get-Item -LiteralPath $ownedVhd -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Owned cleanup disk is a reparse point' }
        $disk = Get-VHD -Path $ownedVhd -ErrorAction Stop
        if ($disk.Attached) { Dismount-VHD -Path $ownedVhd -ErrorAction Stop }
    }
    if (Test-Path -LiteralPath $state) { Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction Stop }
    [Console]::Out.WriteLine('WINDOWS_OWNED_STATE_CLEANED')
    exit 0
}
$null = New-Item -ItemType Directory -Path $state
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$logDir = Join-Path $Root '.scratch/security-logs'
$null = New-Item -ItemType Directory -Path $logDir -Force
$logName = 'Run-WindowsSecurity_' + [DateTime]::UtcNow.ToString('yyyy-MM-dd_HH-mm-ss') + '_UTC.log'
$logPath = Join-Path $logDir $logName
if (Test-Path -LiteralPath $logPath) { $logPath = Join-Path $logDir ($logName + '.' + $runId) }
$log = $null
try { $log = [IO.StreamWriter]::new([IO.FileStream]::new($logPath, [IO.FileMode]::CreateNew), $utf8) }
catch { [Console]::Error.WriteLine('Security logging initialization failed'); throw }
function Write-RunLog([string]$Level, [string]$Message) {
    $log.WriteLine('[' + [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + " UTC] [$Level] [WINDOWS-SECURITY] $Message")
    $log.Flush()
    # Content-free phase activity lets the independent outer owner enforce its idle deadline.
    [Console]::Out.WriteLine("WINDOWS_SECURITY_PROGRESS level=$Level")
}
function Checked-Native([string]$Executable, [string[]]$Arguments) {
    $resolved = [string](Get-Command $Executable -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    Write-RunLog INFO ('trusted setup command=' + [IO.Path]::GetFileName($resolved))
    $text = [ScientificSecurity.TrustedSetup]::Run($resolved, $Arguments, $state)
    return @($text -split "`r?`n" | Where-Object { $_ -ne '' })
}
function Set-OwnedAccess([string]$Path, [bool]$Writable, [bool]$Directory) {
    # Label the owned empty scratch root before denying the owner's WRITE_OWNER.
    if ($Writable) { $null = Checked-Native (Join-Path $env:SystemRoot 'System32/icacls.exe') @($Path, '/setintegritylevel', '(OI)(CI)L') }
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    $prop = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $deny = [Security.AccessControl.AccessControlType]::Deny
    # OWNER RIGHTS removes the implicit owner WRITE_DAC bypass on newly created files.
    foreach ($identity in @($package, [Security.Principal.SecurityIdentifier]::new('S-1-3-4'))) {
        $rights = [Security.AccessControl.FileSystemRights]'ChangePermissions,TakeOwnership'
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, $rights, $inherit, $prop, $deny))
    }
    foreach ($identity in @([Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, $prop, $allow))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, $prop, $allow))
    $rights = if ($Writable) { [Security.AccessControl.FileSystemRights]::Modify } else { [Security.AccessControl.FileSystemRights]::ReadAndExecute }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($package, $rights, $inherit, $prop, $allow))
    if (-not $Writable) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($package, [Security.AccessControl.FileSystemRights]::Write, $inherit, $prop, $deny))
    }
    $acl.SetOwner($user)
    # Set-Acl forces all descriptor sections; persist only our changed Access/Owner
    # sections so the previously established mandatory integrity label survives.
    if ($Directory) {
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path), $acl)
    }
    else {
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $acl)
    }
}
function Assert-SourcePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared copy source or ancestor is a reparse point' }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }; $current = $parent
    }
}
function Assert-SourceTree([string]$Path) {
    Assert-SourcePath $Path
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $relative = [IO.Path]::GetRelativePath($Path, $item.FullName)
            $diagnostic = @{ phase='runtime-copy'; root=[IO.Path]::GetFullPath($Path); relative=$relative;
                             attributes=[int]$item.Attributes; item_type=$item.GetType().Name } | ConvertTo-Json -Compress
            [Console]::Error.WriteLine($diagnostic)
            throw 'Prepared runtime copy source contains a reparse point'
        }
    }
}
function Protect-Tree([string]$Path) {
    $completed = 0
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Prepared target/runtime unexpectedly contains a reparse point' }
        Set-OwnedAccess $item.FullName $false $item.PSIsContainer
        $completed++
        if ($completed % 500 -eq 0) { Write-RunLog INFO "readonly ACL preparation items=$completed" }
    }
    Set-OwnedAccess $Path $false $true
}
$vhd = Join-Path $state 'scratch.vhdx'
$mounted = $false
$mountPath = Join-Path $state 'scratch'
$tcp4 = $null; $tcp6 = $null; $udp4 = $null; $udp6 = $null
$result = $null; $failure = $null
try {
    Write-RunLog INFO "start run=$runId native_runtime=3.11 root=$Root"
    foreach ($name in @('New-VHD','Mount-VHD','Dismount-VHD','Initialize-Disk','New-Partition','Format-Volume')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "Required native control unavailable: $name" }
    }
    # The workflow's outer owned command bounds this compiler bootstrap. Subsequent
    # native setup commands use the suspended Job-owned runner loaded here.
    Add-Type -Path @((Join-Path $PSScriptRoot 'Native.cs'), (Join-Path $PSScriptRoot 'Capture.cs'), (Join-Path $PSScriptRoot 'TrustedSetup.cs'), (Join-Path $PSScriptRoot 'Sandbox.cs'), (Join-Path $PSScriptRoot 'QuotaSid.cs'), (Join-Path $PSScriptRoot 'TokenPolicy.cs'))
    $gitCandidates = @(Get-Command git -CommandType Application -ErrorAction Stop)
    [Console]::Out.WriteLine("WINDOWS_SETUP_RESOLUTION command=git candidates=$($gitCandidates.Count) type=$($gitCandidates.GetType().FullName)")
    $gitExecutable = [string]($gitCandidates | Select-Object -First 1).Source
    $mixedCwd = $state.Replace('\', '/')
    $nativeVersion = [ScientificSecurity.TrustedSetup]::Run($gitExecutable, @('--version'), $state)
    $mixedVersion = [ScientificSecurity.TrustedSetup]::Run($gitExecutable, @('--version'), $mixedCwd)
    if ($nativeVersion -notmatch '^git version ' -or $mixedVersion -ne $nativeVersion) { throw 'Trusted setup normalized-CWD regression failed' }
    Write-RunLog INFO 'trusted setup native and mixed-separator CWD controls passed'
    $moniker = 'Scientific.Security.' + $runId
    $package = [Security.Principal.SecurityIdentifier]::new([ScientificSecurity.Sandbox]::PackageSid($moniker))
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $userName = $user.Translate([Security.Principal.NTAccount]).Value
    $target = Join-Path $state 'target'
    $runtime = Join-Path $state 'python'
    $psRuntime = Join-Path $state 'powershell'
    $null = New-Item -ItemType Directory -Path $target, $runtime, $psRuntime, $mountPath
    # Only tracked source is copied; private/local/generated files never enter the child view.
    $paths = Checked-Native 'git' @('-C', $Root, '-c', 'core.quotepath=false', 'ls-files')
    foreach ($relative in $paths) {
        if ($relative -match '(^|/)(\.ai|\.agents|\.claude|\.specify|specs|graphify-out|\.codebase-memory)(/|$)' -or
            $relative -match '(^|/)(secrets\.md|explain-AI\.md|\.ignoreme|\.env[^/]*|CLAUDE\.md|AGENTS\.md)$') { continue }
        $source = Join-Path $Root $relative
        $destination = Join-Path $target $relative
        $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force
        Assert-SourcePath $source
        Copy-Item -LiteralPath $source -Destination $destination
    }
    # Newly authored files may be unstaged during a controlled CI checkout; copy only this fixed trusted set.
    foreach ($relative in @('tests/security/windows/KernelProbe.py','tests/security/windows_probe.py')) {
        $destination = Join-Path $target $relative
        $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force
        Assert-SourcePath (Join-Path $Root $relative)
        Copy-Item -LiteralPath (Join-Path $Root $relative) -Destination $destination -Force
    }
    $framework = Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319'
    $csc = Join-Path $framework 'csc.exe'
    $windowsBase = Join-Path $framework 'WPF/WindowsBase.dll'
    if (-not (Test-Path -LiteralPath $csc) -or -not (Test-Path -LiteralPath $windowsBase)) { throw 'Existing .NET Framework WindowsBase consumer is unavailable' }
    $consumerExe = Join-Path $target 'tests/security/windows/OpcConsumer.exe'
    $null = Checked-Native $csc @('/nologo','/target:exe',('/out:' + $consumerExe),('/reference:' + $windowsBase), (Join-Path $PSScriptRoot 'OpcConsumer.cs'))
    $pythonHome = [IO.Path]::GetDirectoryName($Python)
    if (Test-Path -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($pythonHome)) 'pyvenv.cfg')) { throw 'Pass the prepared base Python, not a relocated virtual environment launcher' }
    if (-not (Test-Path -LiteralPath (Join-Path $pythonHome 'Lib'))) { throw 'Prepared Python base runtime has no Lib directory' }
    # The hosted toolcache also contains a python3.exe alias that is not copied.
    # Validate the exact immutable copy plan, never dereference or exempt a selected link.
    $pythonLeaves = @((Join-Path $pythonHome 'python.exe')) + @(
        Get-ChildItem -LiteralPath $pythonHome -File -Force |
            Where-Object { $_.Extension -in @('.dll','.zip','._pth') } |
            ForEach-Object { $_.FullName }
    )
    $pythonTrees = @((Join-Path $pythonHome 'DLLs'), (Join-Path $pythonHome 'Lib'))
    foreach ($selected in $pythonLeaves) { Assert-SourcePath $selected }
    foreach ($selected in $pythonTrees) { Assert-SourceTree $selected }
    $pwsh = [string](Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    Assert-SourceTree ([IO.Path]::GetDirectoryName($pwsh))
    Copy-Item -LiteralPath $pythonLeaves -Destination $runtime
    Copy-Item -LiteralPath $pythonTrees -Destination $runtime -Recurse
    Copy-Item -Path (Join-Path ([IO.Path]::GetDirectoryName($pwsh)) '*') -Destination $psRuntime -Recurse
    $childPython = Join-Path $runtime 'python.exe'
    $childPowerShell = Join-Path $psRuntime 'pwsh.exe'
    $chromium = $env:REVAYAT_CHROMIUM
    if (-not $chromium) {
        foreach ($candidate in @('C:/Program Files/Microsoft/Edge/Application/msedge.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe','C:/Program Files/Google/Chrome/Application/chrome.exe')) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $chromium = $candidate; break }
        }
    }
    if (-not $chromium -or -not (Test-Path -LiteralPath $chromium -PathType Leaf)) { throw 'Existing real Chromium prerequisite is unavailable' }
    # Adapter checks a genuine prepared executable, not a synthetic tool stub; refusal must precede rendering.
    $browserDir = Join-Path $target 'tools/native-browser'
    $null = New-Item -ItemType Directory -Path $browserDir
    Assert-SourcePath $chromium
    Copy-Item -LiteralPath $chromium -Destination (Join-Path $browserDir 'chromium.exe')
    $chromium = Join-Path $browserDir 'chromium.exe'
    Write-RunLog INFO 'protecting target tree'
    Protect-Tree $target
    Write-RunLog INFO 'protecting prepared Python runtime'
    Protect-Tree $runtime
    Write-RunLog INFO 'protecting prepared PowerShell runtime'
    Protect-Tree $psRuntime
    [IO.File]::WriteAllText((Join-Path $state 'host-canary'), 'dummy parent-only control', $utf8)
    $parentAcl = Get-Acl -LiteralPath $state
    $parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($package, [Security.AccessControl.FileSystemRights]::ReadAndExecute, [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $state -AclObject $parentAcl
    Write-RunLog INFO 'readonly target and runtime prepared; no profile or capabilities granted'
    $null = New-VHD -Path $vhd -SizeBytes 128MB -Fixed
    $disk = Mount-VHD -Path $vhd -PassThru | Get-Disk
    $mounted = $true
    if ($disk.Count -ne 1 -or $disk.PartitionStyle -ne 'RAW') { throw 'Owned new virtual disk identity is ambiguous' }
    $partition = $disk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter
    $null = $partition | Format-Volume -FileSystem NTFS -Confirm:$false -Force
    $ownedDisk = Get-VHD -Path $vhd -ErrorAction Stop
    $ownedVolume = $partition | Get-Volume
    if ($ownedDisk.VhdType -ne 'Fixed' -or $ownedDisk.Size -ne 134217728 -or
        $ownedDisk.DiskNumber -ne $disk.Number -or $disk.Size -ne 134217728 -or
        $ownedVolume.FileSystem -ne 'NTFS' -or $ownedVolume.Size -le 0 -or $ownedVolume.Size -gt 134217728) {
        throw 'Owned fixed virtual-disk physical capacity or volume identity differs'
    }
    Write-RunLog INFO 'fixed virtual-disk physical capacity readback passed bytes=134217728'
    # A directory volume mount is itself a junction ancestor and would invalidate ordinary controls.
    $mountPath = "$($partition.DriveLetter):\"
    $volume = $mountPath
    $fsutil = Join-Path $env:SystemRoot 'System32/fsutil.exe'
    $quota = New-Object -ComObject 'Microsoft.DiskQuota.1'
    $quota.Initialize($volume, $true)
    $quota.DefaultQuotaThreshold = 16777216
    $quota.DefaultQuotaLimit = 16777216
    $null = Checked-Native $fsutil @('quota','modify', $volume, '16777216', '16777216', $userName)
    [ScientificSecurity.QuotaSid]::SetPackageEntry($volume, $package.Value)
    $null = Checked-Native $fsutil @('quota','enforce', $volume)
    $null = Checked-Native $fsutil @('quota','query', $volume)
    Set-OwnedAccess $mountPath $true $true
    foreach ($relative in @('home','home/cache','temp','junction-target')) { $null = New-Item -ItemType Directory -Path (Join-Path $mountPath $relative) }
    $null = New-Item -ItemType Junction -Path (Join-Path $mountPath 'prepared-junction') -Target (Join-Path $mountPath 'junction-target')
    # The suspended child's TokenOwner is forced to TokenUser; trusted preflight compares
    # its actual new-file owner to that user SID before accepting quota denial.
    $tcp4 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $tcp4.Start()
    $tcpPort = $tcp4.LocalEndpoint.Port
    $tcp6 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, $tcpPort); $tcp6.Server.DualMode = $false; $tcp6.Start()
    $udp4 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork); $udp4.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $udpPort = $udp4.Client.LocalEndPoint.Port
    $udp6 = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6); $udp6.Client.DualMode = $false; $udp6.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::IPv6Loopback, $udpPort))
    $env:SCIENTIFIC_AMBIENT_CANARY = 'dummy-never-forwarded'
    Write-RunLog INFO 'trusted kernel preflight starts before reviewed-code import'
    $preflightText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $true, $tcpPort, $udpPort)
    $preflight = $preflightText | ConvertFrom-Json
    if ($preflight.status -ne 'passed' -or $preflight.phase -ne 'preflight') { throw 'Trusted preflight did not return its required success observation' }
    $wall = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $true, $tcpPort, $udpPort, $true)
    if ($wall -ne 'WALL_TREE_TERMINATED') { throw 'Native wall/process-tree negative control was not proved' }
    Write-RunLog INFO 'all required native controls observed including wall-tree cleanup; reviewed regressions admitted'
    $regressionText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $false, 0, 0)
    $observations = @($regressionText -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    $consumer = @($observations | Where-Object { $_.phase -eq 'consumer' })
    $regression = @($observations | Where-Object { $_.phase -eq 'native-regressions' })
    if ($consumer.Count -ne 1 -or $consumer[0].status -ne 'passed' -or $regression.Count -ne 1 -or $regression[0].passed.Count -ne 4) { throw 'Required native regression/consumer evidence is incomplete' }
    $regression = $regression[0]
    $result = @{ status='passed'; preflight=$preflight; consumer=$consumer[0]; regressions=$regression; cleanup='pending'; run=$runId }
}
catch {
    $failure = $_
    $cause = $_.Exception
    while ($cause) {
        $detail = 'failed type=' + $cause.GetType().Name + ' message=' + $cause.Message
        if ($cause -is [ComponentModel.Win32Exception]) { $detail += ' native_error=' + $cause.NativeErrorCode }
        Write-RunLog ERROR $detail
        [Console]::Error.WriteLine($detail)
        $cause = $cause.InnerException
    }
}
finally {
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        foreach ($listener in @($tcp4,$tcp6)) {
            try { if ($listener) { $listener.Stop() } } catch { $cleanupErrors.Add('listener close failed'); if (-not $failure) { $failure = $_ } }
        }
        foreach ($socket in @($udp4,$udp6)) {
            try { if ($socket) { $socket.Dispose() } } catch { $cleanupErrors.Add('socket close failed'); if (-not $failure) { $failure = $_ } }
        }
        Remove-Item Env:SCIENTIFIC_AMBIENT_CANARY -ErrorAction SilentlyContinue
        try {
            if (Get-Variable quota -ErrorAction SilentlyContinue) {
                if ($quota) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($quota) }
            }
        }
        catch { $cleanupErrors.Add('quota COM release failed'); if (-not $failure) { $failure = $_ } }
    }
    finally {
        try {
            if ($mounted) { Dismount-VHD -Path $vhd -ErrorAction Stop; $mounted = $false }
            # Retain the log; remove only this run's detached disposable state.
            Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction Stop
        }
        catch { $cleanupErrors.Add('owned virtual-disk/state cleanup failed'); if (-not $failure) { $failure = $_ } }
        finally {
            try {
                if ($cleanupErrors.Count -eq 0) { Write-RunLog INFO 'cleanup complete owned_jobs=0 own_virtualdisk_detached=true' }
                else { Write-RunLog ERROR ($cleanupErrors -join '; ') }
            }
            catch { if (-not $failure) { $failure = $_ } }
            finally { try { $log.Dispose() } catch { if (-not $failure) { $failure = $_ } } }
        }
    }
}
if ($failure) { [Console]::Error.WriteLine($failure.Exception.Message); exit 1 }
$result.cleanup = 'complete'
$result | ConvertTo-Json -Depth 8 -Compress
