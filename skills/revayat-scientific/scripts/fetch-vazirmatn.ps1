#Requires -Version 5.1
# Shared validated font/license/provenance delivery. Keep this wrapper ASCII.
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Destination = 'fonts',
    [string]$Version = $(if ($env:VAZIRMATN_VERSION) { $env:VAZIRMATN_VERSION } else { '33.003' })
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }
try {
    $python = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $python) { $python = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $python) { throw 'Python 3.10+ is required' }
    $PSNativeCommandUseErrorActionPreference = $false
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = $null
    & $python.Source -B (Join-Path $PSScriptRoot 'font-fetch.py') $Destination --version $Version
    if ($null -eq $LASTEXITCODE) { exit 127 }
    exit $LASTEXITCODE
}
catch {
    [Console]::Error.WriteLine(('fetch-vazirmatn: ' + $_.Exception.Message))
    exit 2
}
