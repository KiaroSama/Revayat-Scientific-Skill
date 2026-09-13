#Requires -Version 5.1
<#
.SYNOPSIS
    Put Vazirmatn Regular + Bold (Western digits) into a fonts directory
    for @font-face embedding. Windows counterpart of fetch-vazirmatn.sh.

.DESCRIPTION
    Never the UI-FD / Farsi-digits cut, which draws Eastern Arabic digits.
    Reuses an installed system face or a previous download before hitting
    the network, so an offline machine with the font already present still
    works. Vazirmatn is SIL Open Font License 1.1; keep the licence file
    beside the TTFs when you ship the HTML.

    Only the resulting font paths go to stdout; progress goes to stderr.

.PARAMETER Destination
    Directory to place the TTFs in. Defaults to .\fonts.

.PARAMETER Version
    Vazirmatn release to download when no local copy is found.

.EXAMPLE
    .\fetch-vazirmatn.ps1 fonts

.NOTES
    Runs on Windows PowerShell 5.1 and on PowerShell 7.x. Windows only:
    under pwsh on Linux or macOS it stops and points at fetch-vazirmatn.sh.

    Keep this file pure ASCII: 5.1 decodes a BOM-less .ps1 with the system
    ANSI code page, where a UTF-8 em dash becomes a curly quote that
    terminates a string and breaks the parse.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Destination = 'fonts',

    [string]$Version = $(if ($env:VAZIRMATN_VERSION) { $env:VAZIRMATN_VERSION } else { '33.003' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }

# PowerShell 5.1 still negotiates TLS 1.0 by default; GitHub refuses it.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
}
catch { }

$Want = @('Vazirmatn-Regular.ttf', 'Vazirmatn-Bold.ttf')
$Cache = Join-Path $env:LOCALAPPDATA 'fa-fonts'
$Url = "https://github.com/rastikerdar/vazirmatn/releases/download/v$Version/vazirmatn-v$Version.zip"

# Registry font names are space-separated ("Vazirmatn UI FD Bold
# (TrueType)"), so match FD as a whole token rather than as "UI-FD".
$FdPattern = '(?i)(^|[\s_-])(UI[\s_-]?)?FD([\s_-]|$|\s*\()|Farsi.*Digit'
# Vazirmatn ships SemiBold, ExtraBold and Black; none of them is Bold.
$BoldPattern = '(?i)(^|[\s_-])bold([\s_-]|$|\s*\()'
$OtherWeights = '(?i)semi|extra|ultra|demi|thin|light|medium|black|italic'

function Write-Log {
    param([string]$Message)
    [Console]::Error.WriteLine("fetch-vazirmatn: $Message")
}

function Test-Windows {
    # 5.1 is Windows-only and has no $IsWindows; 7.x defines it everywhere.
    if (Test-Path 'variable:IsWindows') { return [bool]$IsWindows }
    return $true
}

if (-not (Test-Windows)) {
    Write-Log 'this script reads the Windows font registry.'
    Write-Log 'On Linux or macOS run the POSIX twin instead:'
    Write-Log '  scripts/fetch-vazirmatn.sh [dest-dir]'
    exit 2
}

function Test-HaveAll {
    param([string]$Directory)
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return $false }
    foreach ($f in $Want) {
        $p = Join-Path $Directory $f
        $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
        if (-not $item -or $item.Length -eq 0) { return $false }
    }
    return $true
}

function Write-Report {
    foreach ($f in $Want) { Write-Output (Join-Path $Destination $f) }
}

function Find-InstalledVazirmatn {
    # Windows keeps installed faces in the font registry; the value is a
    # bare filename for machine fonts and a full path for per-user ones.
    $sources = @(
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'
           Dir = (Join-Path $env:WINDIR 'Fonts') },
        @{ Key = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'
           Dir = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts') }
    )
    $found = @{}
    foreach ($s in $sources) {
        if (-not (Test-Path -LiteralPath $s.Key)) { continue }
        $props = Get-ItemProperty -LiteralPath $s.Key
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if ($p.Name -notmatch '(?i)vazirmatn') { continue }
            # Reject the Farsi-digit cut outright.
            if ($p.Name -match $FdPattern) { continue }
            $value = [string]$p.Value
            if ([IO.Path]::IsPathRooted($value)) { $path = $value }
            else { $path = Join-Path $s.Dir $value }
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            if ($p.Name -match $BoldPattern -and $p.Name -notmatch $OtherWeights) {
                if (-not $found.ContainsKey('Bold')) { $found['Bold'] = $path }
            }
            elseif ($p.Name -notmatch $BoldPattern -and $p.Name -notmatch $OtherWeights) {
                if (-not $found.ContainsKey('Regular')) { $found['Regular'] = $path }
            }
        }
    }
    return $found
}

# --- main -------------------------------------------------------------

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
New-Item -ItemType Directory -Path $Cache -Force | Out-Null

# 0. Already in place.
if (Test-HaveAll $Destination) {
    Write-Log "already present in $Destination"
    Write-Report
    exit 0
}

# 1. A previous download.
if (Test-HaveAll $Cache) {
    Write-Log "using cache $Cache"
    foreach ($f in $Want) {
        Copy-Item -LiteralPath (Join-Path $Cache $f) -Destination (Join-Path $Destination $f) -Force
    }
    Write-Report
    exit 0
}

# 2. An installed system copy - no network needed.
$installed = Find-InstalledVazirmatn
if ($installed.ContainsKey('Regular')) {
    Write-Log 'copying the installed face'
    Copy-Item -LiteralPath $installed['Regular'] `
        -Destination (Join-Path $Destination 'Vazirmatn-Regular.ttf') -Force
    if ($installed.ContainsKey('Bold')) {
        Copy-Item -LiteralPath $installed['Bold'] `
            -Destination (Join-Path $Destination 'Vazirmatn-Bold.ttf') -Force
    }
    else {
        Copy-Item -LiteralPath $installed['Regular'] `
            -Destination (Join-Path $Destination 'Vazirmatn-Bold.ttf') -Force
    }
    foreach ($f in $Want) {
        Copy-Item -LiteralPath (Join-Path $Destination $f) `
            -Destination (Join-Path $Cache $f) -Force -ErrorAction SilentlyContinue
    }
    Write-Report
    exit 0
}

# 3. Download.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('fa-font-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    Write-Log "downloading v$Version"
    $zip = Join-Path $tmp 'v.zip'
    try {
        Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing -TimeoutSec 60
    }
    catch {
        Write-Log "download failed: $Url"
        Write-Log "  $($_.Exception.Message)"
        Write-Log 'fall back to any installed fa face, or install Vazirmatn'
        Write-Log '  from https://github.com/rastikerdar/vazirmatn/releases'
        exit 1
    }

    Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
    foreach ($f in $Want) {
        $src = Get-ChildItem -LiteralPath $tmp -Recurse -Filter $f -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $src) {
            Write-Log "missing $f in archive; the release layout may have changed"
            exit 1
        }
        Copy-Item -LiteralPath $src.FullName -Destination (Join-Path $Destination $f) -Force
        Copy-Item -LiteralPath $src.FullName -Destination (Join-Path $Cache $f) -Force -ErrorAction SilentlyContinue
    }

    Write-Log 'sha256'
    foreach ($f in $Want) {
        $h = Get-FileHash -LiteralPath (Join-Path $Destination $f) -Algorithm SHA256
        [Console]::Error.WriteLine("$($h.Hash.ToLowerInvariant())  $f")
    }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Report
exit 0
