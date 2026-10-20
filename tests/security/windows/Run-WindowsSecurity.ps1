#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Python, [Parameter(Mandatory)][string]$Root,
      [ValidatePattern('^[a-f0-9]{32}$')][string]$RunId = ([Guid]::NewGuid().ToString('N')),
      [switch]$CleanupOnly, [switch]$OuterOwnerReaped)
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
    Add-Type -Path @((Join-Path $PSScriptRoot 'Native.cs'), (Join-Path $PSScriptRoot 'RegistryContext.cs'), (Join-Path $PSScriptRoot 'LpacQuery.cs'), (Join-Path $PSScriptRoot 'RegistrySeal.cs'), (Join-Path $PSScriptRoot 'LoaderSnaps.cs'), (Join-Path $PSScriptRoot 'Profile.cs'), (Join-Path $PSScriptRoot 'RegistryPolicyLease.cs'))
    [ScientificSecurity.RegistryPolicyLease]::CleanupOwned(
        [Action]{ [ScientificSecurity.RegistryPolicyLease]::Recover($runId, $state, $OuterOwnerReaped.IsPresent) },
        [Action]{ [ScientificSecurity.LoaderSnaps]::Cleanup($runId, $state) },
        [Action]{ [ScientificSecurity.Profile]::DeleteOwned('Scientific.Security.' + $runId, (Join-Path $state 'profile.receipt')) },
        [Action]{
            $ownedVhd = Join-Path $state 'scratch.vhdx'
            if (Test-Path -LiteralPath $ownedVhd -PathType Leaf) {
                if ((Get-Item -LiteralPath $ownedVhd -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Owned cleanup disk is a reparse point' }
                $disk = Get-VHD -Path $ownedVhd -ErrorAction Stop
                if ($disk.Attached) { Dismount-VHD -Path $ownedVhd -ErrorAction Stop }
            }
        },
        [Action]{ if (Test-Path -LiteralPath $state) { Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction Stop } })
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
    $existingOwner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    $acl.SetOwner($user)
    $aclDiagnostic = @{ phase='owned-acl'; relative=[IO.Path]::GetRelativePath($state, [IO.Path]::GetFullPath($Path));
                       writable=$Writable; directory=$Directory; owner_matches_user=($existingOwner -eq $user.Value);
                       attributes=[int](Get-Item -LiteralPath $Path -Force).Attributes } | ConvertTo-Json -Compress
    # Preserve bounded output: only a failed operation emits its pre-captured metadata.
    try {
        if (-not $Writable) {
            # Reuse the provider's scoped restore-privilege handling for copied RO trees.
            # These entries have no scratch MIC label to preserve; an absent label is Medium.
            Set-Acl -LiteralPath $Path -AclObject $acl
        }
        elseif ($Directory) {
            # Persist Access/Owner only on the newly labeled empty scratch root.
            [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path), $acl)
        }
        else {
            [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $acl)
        }
    }
    catch { [Console]::Error.WriteLine($aclDiagnostic); throw }
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
function Write-PreparationProgress(
    [ValidateSet('leaf-plan','leaf-check','python-dlls','python-lib','powershell-tree','copy-python-leaves','copy-python-trees','copy-powershell')][string]$Phase,
    [ValidateSet('before','validated','copied','after')][string]$State,
    [ValidateRange(0,2147483647)][int]$Count = 0) {
    Write-RunLog INFO "runtime preparation phase=$Phase state=$State count=$Count"
    [Console]::Out.WriteLine("WINDOWS_RUNTIME_PREPARATION phase=$Phase state=$State count=$Count")
    [Console]::Out.Flush()
}
function Measure-RuntimeCopy {
    param([string]$Phase, [Parameter(ValueFromPipeline)]$Item)
    begin { $completed = 0 }
    process {
        if ($Item -is [IO.FileInfo]) {
            $completed++
            if ($completed % 256 -eq 0) { Write-PreparationProgress $Phase 'copied' $completed }
        }
    }
    end { Write-PreparationProgress $Phase 'after' $completed }
}
function Assert-SourceTree([string]$Path, [string]$Phase) {
    Write-PreparationProgress $Phase 'before'
    Assert-SourcePath $Path
    $completed = 0
    Get-ChildItem -LiteralPath $Path -Recurse -Force | ForEach-Object {
        if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Prepared runtime copy source contains a reparse point'
        }
        $completed++
        if ($completed % 256 -eq 0) { Write-PreparationProgress $Phase 'validated' $completed }
    }
    Write-PreparationProgress $Phase 'after' $completed
}
function Protect-Tree([string]$Path) {
    $completed = 0
    # Parent denies propagate to existing children, so complete descendants before parents.
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Recurse -Force | Sort-Object { $_.FullName.Length } -Descending)) {
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
$result = $null; $failure = $null; $profileOwned = $false; $moniker = 'Scientific.Security.' + $runId
try {
    Write-RunLog INFO "start run=$runId native_runtime=3.11 root=$Root"
    foreach ($name in @('New-VHD','Mount-VHD','Dismount-VHD','Initialize-Disk','New-Partition','Format-Volume')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "Required native control unavailable: $name" }
    }
    # The workflow's outer owned command bounds this compiler bootstrap. Subsequent
    # native setup commands use the suspended Job-owned runner loaded here.
    Add-Type -Path @((Join-Path $PSScriptRoot 'Native.cs'), (Join-Path $PSScriptRoot 'Capture.cs'), (Join-Path $PSScriptRoot 'TrustedSetup.cs'), (Join-Path $PSScriptRoot 'Sandbox.cs'), (Join-Path $PSScriptRoot 'QuotaSid.cs'), (Join-Path $PSScriptRoot 'TokenPolicy.cs'), (Join-Path $PSScriptRoot 'TokenDefaultMetadata.cs'), (Join-Path $PSScriptRoot 'Profile.cs'), (Join-Path $PSScriptRoot 'RegistryContext.cs'), (Join-Path $PSScriptRoot 'LpacQuery.cs'), (Join-Path $PSScriptRoot 'RegistrySeal.cs'), (Join-Path $PSScriptRoot 'LoaderSnaps.cs'), (Join-Path $PSScriptRoot 'OwnedToken.cs'), (Join-Path $PSScriptRoot 'StartupAccess.cs'), (Join-Path $PSScriptRoot 'StartupImageAccess.cs'), (Join-Path $PSScriptRoot 'KernelImageImports.cs'), (Join-Path $PSScriptRoot 'OwnProcessAccess.cs'), (Join-Path $PSScriptRoot 'LoaderTrace.cs'), (Join-Path $PSScriptRoot 'KernelImage.cs'), (Join-Path $PSScriptRoot 'KernelImageIdentity.cs'), (Join-Path $PSScriptRoot 'KernelImageStatic.cs'), (Join-Path $PSScriptRoot 'KernelImageObservation.cs'), (Join-Path $PSScriptRoot 'KernelImageCheckpoint.cs'), (Join-Path $PSScriptRoot 'StaticKernelInspection.cs'), (Join-Path $PSScriptRoot 'HardwareTrace.cs'), (Join-Path $PSScriptRoot 'DebugContext.cs'), (Join-Path $PSScriptRoot 'DebugControl.cs'), (Join-Path $PSScriptRoot 'NativeFixture.cs'), (Join-Path $PSScriptRoot 'PythonStartupFixture.cs'), (Join-Path $PSScriptRoot 'KernelImageManifest.cs'), (Join-Path $PSScriptRoot 'StartupActivationAccess.cs'), (Join-Path $PSScriptRoot 'StartupRegistryAccess.cs'), (Join-Path $PSScriptRoot 'RegistryPolicyLease.cs'), (Join-Path $PSScriptRoot 'RegistryCausalComparison.cs'), (Join-Path $PSScriptRoot 'ManualActivationComparison.cs'), (Join-Path $PSScriptRoot 'StartupActivationEvents.cs'), (Join-Path $PSScriptRoot 'ActivationAssemblyAccess.cs'), (Join-Path $PSScriptRoot 'StartupTokenAccess.cs'), (Join-Path $PSScriptRoot 'ChildActivationFixture.cs'), (Join-Path $PSScriptRoot 'KernelImageChildActivation.cs'), (Join-Path $PSScriptRoot 'KernelImageDefaultActivation.cs'), (Join-Path $PSScriptRoot 'DefaultActivationFixture.cs'), (Join-Path $PSScriptRoot 'SelfActivationFixture.cs'), (Join-Path $PSScriptRoot 'KernelImageSelfActivation.cs'), (Join-Path $PSScriptRoot 'ModuleActivationFixture.cs'), (Join-Path $PSScriptRoot 'KernelImageModuleActivation.cs'), (Join-Path $PSScriptRoot 'KernelImageModuleCallback.cs'), (Join-Path $PSScriptRoot 'ModuleCallbackTrace.cs'), (Join-Path $PSScriptRoot 'KernelImageActivationWorker.cs'), (Join-Path $PSScriptRoot 'KernelImageActivationBoundary.cs'), (Join-Path $PSScriptRoot 'ActivationBoundaryTrace.cs'), (Join-Path $PSScriptRoot 'ExplicitEntryTrace.cs'), (Join-Path $PSScriptRoot 'LoaderEntryTrace.cs'), (Join-Path $PSScriptRoot 'ExplicitEntryComparison.cs'), (Join-Path $PSScriptRoot 'AutomaticResourceTrace.cs'), (Join-Path $PSScriptRoot 'AutomaticResourceValidation.cs'), (Join-Path $PSScriptRoot 'LoaderResourceTrace.cs'), (Join-Path $PSScriptRoot 'AutomaticResourceComparison.cs'))
    [ScientificSecurity.Profile]::CheckSealComparison()
    [ScientificSecurity.Profile]::CheckRegistryMasks()
    [ScientificSecurity.LoaderSnaps]::CheckValidation()
    [ScientificSecurity.TokenDefaultMetadata]::CheckValidation()
    [ScientificSecurity.KernelImage]::CheckValidation()
    [ScientificSecurity.KernelImage]::CheckCheckpointValidation()
    [ScientificSecurity.KernelImage]::CheckImportValidation()
    [ScientificSecurity.KernelImage]::CheckManifestValidation()
    [ScientificSecurity.KernelImage]::CheckActivationWorkerValidation()
    [ScientificSecurity.StartupActivationAccess]::CheckValidation()
    [ScientificSecurity.StartupRegistryAccess]::CheckValidation()
    [ScientificSecurity.RegistryPolicyLease]::CheckValidation()
    [ScientificSecurity.RegistryCausalComparison]::CheckValidation()
    [ScientificSecurity.ManualActivationComparison]::CheckValidation()
    [ScientificSecurity.AutomaticResourceComparison]::CheckValidation()
    [ScientificSecurity.StartupActivationEvents]::CheckValidation()
    [ScientificSecurity.ActivationAssemblyAccess]::CheckValidation($state)
    [ScientificSecurity.StartupTokenAccess]::CheckValidation()
    [ScientificSecurity.ChildActivationFixture]::CheckValidation($state)
    [ScientificSecurity.KernelImage]::CheckDefaultActivationValidation()
    [ScientificSecurity.DefaultActivationFixture]::CheckValidation($state)
    [ScientificSecurity.SelfActivationFixture]::CheckValidation($state)
    [ScientificSecurity.SelfActivationFixture]::CheckSourceValidation($PSScriptRoot)
    [ScientificSecurity.KernelImage]::CheckModuleActivationValidation()
    [ScientificSecurity.ModuleActivationFixture]::CheckValidation($state)
    [ScientificSecurity.ActivationBoundaryTrace]::CheckValidation()
    [ScientificSecurity.ActivationBoundaryTrace]::CheckModuleCallbackValidation()
    [ScientificSecurity.StartupImageAccess]::CheckValidation()
    [ScientificSecurity.TrustedSetup]::CheckValidation()
    [ScientificSecurity.StaticKernelInspection]::CheckValidation()
    [ScientificSecurity.HardwareTrace]::CheckValidation()
    [ScientificSecurity.DebugControl]::CheckValidation()
    Write-RunLog INFO 'managed strict seal-comparison positive and negative controls passed'
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
    $profileOwned = $true
    $profileFolder = [ScientificSecurity.Profile]::CreateSealed($moniker, $package.Value, (Join-Path $state 'profile.receipt'))
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
    Write-PreparationProgress 'leaf-plan' 'before'
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
    Write-PreparationProgress 'leaf-plan' 'after' $pythonLeaves.Count
    Write-PreparationProgress 'leaf-check' 'before'
    foreach ($selected in $pythonLeaves) { Assert-SourcePath $selected }
    Write-PreparationProgress 'leaf-check' 'after' $pythonLeaves.Count
    Assert-SourceTree $pythonTrees[0] 'python-dlls'
    Assert-SourceTree $pythonTrees[1] 'python-lib'
    $pwsh = [string](Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    Assert-SourceTree ([IO.Path]::GetDirectoryName($pwsh)) 'powershell-tree'
    Write-PreparationProgress 'copy-python-leaves' 'before'
    Copy-Item -LiteralPath $pythonLeaves -Destination $runtime -PassThru | Measure-RuntimeCopy 'copy-python-leaves'
    Write-PreparationProgress 'copy-python-trees' 'before'
    Copy-Item -LiteralPath $pythonTrees -Destination $runtime -Recurse -PassThru | Measure-RuntimeCopy 'copy-python-trees'
    Write-PreparationProgress 'copy-powershell' 'before'
    Copy-Item -Path (Join-Path ([IO.Path]::GetDirectoryName($pwsh)) '*') -Destination $psRuntime -Recurse -PassThru | Measure-RuntimeCopy 'copy-powershell'
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
    [ScientificSecurity.NativeFixture]::Build($PSScriptRoot, $runtime, $state)
    [ScientificSecurity.NativeFixture]::BuildDebugControlFixed($runtime, $state)
    [ScientificSecurity.PythonStartupFixture]::CheckValidation($state)
    [ScientificSecurity.PythonStartupFixture]::Prepare($runId, $state)
    [ScientificSecurity.ChildActivationFixture]::Build($PSScriptRoot, $childPython, $state)
    [ScientificSecurity.DefaultActivationFixture]::Build($childPython, $state)
    [ScientificSecurity.ModuleActivationFixture]::Build($PSScriptRoot, $childPython, $state)
    [ScientificSecurity.SelfActivationFixture]::Build($PSScriptRoot, $childPython, $state)
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
    Write-RunLog INFO 'fixed same-run static KernelBase entrypoint inspection starts; never execution or cause proof'
    [ScientificSecurity.StaticKernelInspection]::RunFixed($state)
    Write-RunLog INFO 'fixed same-run candidate activation-worker static inspection starts; never runtime host or cause proof'
    [ScientificSecurity.StaticKernelInspection]::RunActivationWorker($state)
    Write-RunLog INFO 'single fixed trusted-host debugger control starts; never normalization or admission proof'
    [ScientificSecurity.DebugControl]::RunFixed($runId, $state)
    Write-RunLog INFO 'fixed own-image activation host positive starts; never LPAC or Python equivalence'
    [ScientificSecurity.SelfActivationFixture]::RunHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunEntryHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunResourceHost($childPython)
    Write-RunLog INFO 'fixed no-CRT native startup differential starts; never an admission control'
    $diagnosticFailure = $null
    try {
        [ScientificSecurity.LoaderSnaps]::Enable($runId, $state, (Join-Path (Split-Path $childPython) 'startup-native.exe'))
        $nativeDiagnostic = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $true, $true)
        Write-RunLog INFO $nativeDiagnostic
    }
    catch { $diagnosticFailure = $_.Exception; throw }
    finally { [ScientificSecurity.LoaderSnaps]::Cleanup($runId, $state, $diagnosticFailure) }
    [ScientificSecurity.LoaderSnaps]::RequireClean($runId, $state)
    [Console]::Out.WriteLine('WINDOWS_INTERNAL_OBSERVATION site=KernelBaseEarlierByteCompare rva=0x000BD243 checkpoint_rva=0x0039B8F8 checkpoint_bytes=2 raw_checkpoint_captured=True observation_scope=attach_window site_consumed=True outer_pair=True restored=True sandbox_process_job_handle_cleanup=True global_cleanup=pending qualified_window=True cause_claimed=False abi_claimed=False')
    Write-RunLog INFO 'separate bounded trusted pass-code loader trace starts; never an admission control'
    $loaderDiagnostic = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $true)
    Write-RunLog INFO $loaderDiagnostic
    Write-RunLog INFO 'fixed byte-identical Python clone loader snaps starts; rename and debug perturbation remain noncausal'
    $diagnosticFailure = $null
    $cloneLease = [ScientificSecurity.PythonStartupFixture]::Hold($runId, $state)
    try {
        [ScientificSecurity.LoaderSnaps]::EnablePython($runId, $state)
        $cloneDiagnostic = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $true, $false, $true)
        Write-RunLog INFO $cloneDiagnostic
    }
    catch { $diagnosticFailure = $_.Exception; throw }
    finally { [ScientificSecurity.LoaderSnaps]::Cleanup($runId, $state, $diagnosticFailure, $cloneLease) }
    [ScientificSecurity.LoaderSnaps]::RequireClean($runId, $state)
    Write-RunLog INFO 'fixed nonreserved manual activation comparison starts; no target admission or Python causality'
    [ScientificSecurity.ManualActivationComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)
    Write-RunLog INFO 'fixed automatic resource observation then unchanged entry and explicit ID2 comparisons; none admits target code'
    [ScientificSecurity.AutomaticResourceComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)
    Write-RunLog INFO 'reversible fixed registry causal comparison starts; no target admission under intervention'
    $originalAdmissionExit = [ScientificSecurity.RegistryCausalComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)
    Write-RunLog INFO 'fixed child-process activation comparison starts; never Python causality or admission'
    $activationText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $false, $false, $false, $true)
    [Console]::Out.WriteLine([ScientificSecurity.ChildActivationFixture]::RequireResult($activationText))
    [Console]::Out.Flush()
    Write-RunLog INFO 'fixed activation caller-site trace starts; dynamic target and Python cause remain unverified'
    $tracedActivationText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $false, $false, $false, $false, $true)
    [Console]::Out.WriteLine([ScientificSecurity.ChildActivationFixture]::CompareTraceResult($activationText, $tracedActivationText))
    [Console]::Out.Flush()
    Write-RunLog INFO 'trusted undebugged kernel preflight starts before reviewed-code import'
    $preflightText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort)
    [ScientificSecurity.RegistryCausalComparison]::RequireAdmission($originalAdmissionExit)
    $preflight = $preflightText | ConvertFrom-Json
    if ($preflight.status -ne 'passed' -or $preflight.phase -ne 'preflight') { throw 'Trusted preflight did not return its required success observation' }
    $wall = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $true)
    if ($wall -ne 'WALL_TREE_TERMINATED') { throw 'Native wall/process-tree negative control was not proved' }
    Write-RunLog INFO 'all required native controls observed including wall-tree cleanup; reviewed regressions admitted'
    $regressionText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $false, 0, 0)
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
    if ('ScientificSecurity.RegistryCausalComparison' -as [type]) {
        $cause = [ScientificSecurity.RegistryCausalComparison]::PreserveCallbackFailure($cause)
        $failure = [Management.Automation.ErrorRecord]::new($cause, 'WindowsSecurityFailure', [Management.Automation.ErrorCategory]::NotSpecified, $null)
    }
    $staticReport = if ('ScientificSecurity.StaticKernelInspection' -as [type]) {
        [ScientificSecurity.StaticKernelInspection]::ActivationFailureReport($cause)
    } else { $null }
    if ($null -ne $staticReport) {
        foreach ($line in $staticReport.Split([char]10)) {
            try { Write-RunLog ERROR $line }
            catch { [ScientificSecurity.StaticKernelInspection]::RetainActivationReportingFailure($cause, $_.Exception) }
            try { [Console]::Error.WriteLine($line) }
            catch { [ScientificSecurity.StaticKernelInspection]::RetainActivationReportingFailure($cause, $_.Exception) }
        }
    }
    else {
        while ($cause) {
            $detail = 'failed type=' + $cause.GetType().Name + ' message=' + $cause.Message
            if ($cause -is [ComponentModel.Win32Exception]) { $detail += ' native_error=' + $cause.NativeErrorCode }
            Write-RunLog ERROR $detail
            [Console]::Error.WriteLine($detail)
            $cause = $cause.InnerException
        }
    }
}
finally {
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $registryRestored = $true
    try {
        if ('ScientificSecurity.RegistryPolicyLease' -as [type]) {
            try { [ScientificSecurity.RegistryPolicyLease]::Recover($runId, $state) }
            catch { $registryRestored = $false; $cleanupErrors.Add('fixed registry-policy recovery failed'); if (-not $failure) { $failure = $_ } }
        }
        if ('ScientificSecurity.LoaderSnaps' -as [type]) {
            try { [ScientificSecurity.LoaderSnaps]::Cleanup($runId, $state) }
            catch { $cleanupErrors.Add('owned loader-snaps cleanup failed'); if (-not $failure) { $failure = $_ } }
        }
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
            if ($profileOwned -and $registryRestored) { [ScientificSecurity.Profile]::DeleteOwned($moniker, (Join-Path $state 'profile.receipt')); $profileOwned = $false }
        }
        catch { $cleanupErrors.Add('owned profile cleanup failed'); if (-not $failure) { $failure = $_ } }
        finally {
        try {
            if ($mounted) { Dismount-VHD -Path $vhd -ErrorAction Stop; $mounted = $false }
            # Retain the log; remove only this run's detached disposable state.
            if ($registryRestored -and -not $profileOwned -and -not (Test-Path -LiteralPath (Join-Path $state 'registry-policy.receipt')) -and
                -not (Test-Path -LiteralPath (Join-Path $state 'loader-snaps.receipt')) -and
                -not (Test-Path -LiteralPath (Join-Path $state 'loader-snaps-python.receipt'))) {
                Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction Stop
            }
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
}
if ($failure) { [Console]::Error.WriteLine($failure.Exception.Message); exit 1 }
$result.cleanup = 'complete'
$result | ConvertTo-Json -Depth 8 -Compress
