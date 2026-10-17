# Pure controller-function checks; never launches the security entry point.
param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Work)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/security/windows/Run-WindowsSecurity.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Controller parse failed' }
$names = @('Assert-SourcePath', 'Assert-SourceTree', 'Write-PreparationProgress', 'Measure-RuntimeCopy')
foreach ($name in $names) {
    $function = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false))
    if ($function.Count -ne 1) { throw "Missing unique controller function: $name" }
    . ([scriptblock]::Create($function[0].Extent.Text))
}
$script:events = [Collections.Generic.List[string]]::new()
function Write-RunLog([string]$Level, [string]$Message) { $script:events.Add($Message) }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$source = Join-Path $Work 'source فارسی'
$destination = Join-Path $Work 'destination'
$null = New-Item -ItemType Directory -Path $source, $destination, (Join-Path $source 'empty'), (Join-Path $source 'nested')
[IO.File]::WriteAllText((Join-Path $source 'nested/a[1].txt'), 'fixture فارسی', [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $source '.hidden'), 'hidden fixture', [Text.UTF8Encoding]::new($false))
[IO.File]::SetAttributes((Join-Path $source '.hidden'), [IO.FileAttributes]::Hidden)
Assert-SourceTree $source 'python-lib'
Require ($script:events[-1] -eq 'runtime preparation phase=python-lib state=after count=4') 'Validation missed nested, empty or hidden entries'
$script:events.Clear()
Write-PreparationProgress 'copy-python-trees' 'before'
Copy-Item -LiteralPath $source -Destination $destination -Recurse -PassThru |
    Measure-RuntimeCopy 'copy-python-trees'
Require ($script:events[-1] -eq 'runtime preparation phase=copy-python-trees state=after count=2') 'Copy counted directories or missed files'
Require ([IO.File]::ReadAllText((Join-Path $destination 'source فارسی/nested/a[1].txt'), [Text.Encoding]::UTF8) -eq 'fixture فارسی') 'Copy layout or UTF-8 bytes changed'
Require (Test-Path -LiteralPath (Join-Path $destination 'source فارسی/empty') -PathType Container) 'Empty directory was omitted'
$script:events.Clear()
1..257 | ForEach-Object { [IO.FileInfo]::new((Join-Path $Work 'not-executed.txt')) } |
    Measure-RuntimeCopy 'copy-python-leaves'
Require ($script:events.Count -eq 2 -and $script:events[0] -eq 'runtime preparation phase=copy-python-leaves state=copied count=256' -and
    $script:events[1] -eq 'runtime preparation phase=copy-python-leaves state=after count=257') 'Copy progress is not tied to completed-item thresholds'
foreach ($bad in @(@('private/path', 'before', 0), @('python-lib', 'secret', 0), @('python-lib', 'after', -1))) {
    $refused = $false
    try { Write-PreparationProgress $bad[0] $bad[1] $bad[2] } catch { $refused = $true }
    Require $refused 'Progress accepted unqualified metadata'
}
# A producer must stop at the first rejected item, not finish before checking it.
function Get-ChildItem {
    [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint; FullName = (Join-Path $source 'link') }
    throw 'producer advanced after rejected reparse point'
}
$refused = $false
try { Assert-SourceTree $source 'python-lib' }
catch { $refused = $_.Exception.Message -eq 'Prepared runtime copy source contains a reparse point' }
Require $refused 'Source validation eagerly drained or failed to reject a reparse point'
function Get-ChildItem { throw 'fixed enumeration failure' }
$refused = $false
try { Assert-SourceTree $source 'python-lib' } catch { $refused = $_.Exception.Message -eq 'fixed enumeration failure' }
Require $refused 'Enumeration failure was swallowed'
[Console]::Out.WriteLine('RUNTIME_PREPARATION_FUNCTIONS_OK native_methods_invoked=false')
