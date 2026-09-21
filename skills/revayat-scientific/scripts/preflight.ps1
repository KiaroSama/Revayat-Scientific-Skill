#Requires -Version 5.1
<#
.SYNOPSIS
    Report which PDF engines, fonts, and extraction tools exist on this
    machine and what to install for the missing ones. Windows counterpart
    of preflight.sh. Run before planning a build.

.DESCRIPTION
    The report goes to stdout, like preflight.sh, so it can be captured or
    piped.

.PARAMETER RequireTex
    Exit 1 when local Linux Docker/Podman, the prepared toolchain image or
    same-interpreter PyMuPDF prerequisites are unavailable. No native fallback.

.EXAMPLE
    .\preflight.ps1

.EXAMPLE
    .\preflight.ps1 -RequireTex

.NOTES
    Runs on Windows PowerShell 5.1 and on PowerShell 7.x. Windows only:
    under pwsh on Linux or macOS it stops and points at preflight.sh.

    Keep this file pure ASCII: 5.1 decodes a BOM-less .ps1 with the system
    ANSI code page, where a UTF-8 em dash becomes a curly quote that
    terminates a string and breaks the parse.
#>
[CmdletBinding()]
param(
    [switch]$RequireTex
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }

function Write-Ok {
    param([string]$Name, [string]$Note = '')
    Write-Output ('  yes   {0,-22} {1}' -f $Name, $Note)
}

function Write-No {
    param([string]$Name, [string]$Note = '')
    Write-Output ('  NO    {0,-22} {1}' -f $Name, $Note)
}

function Get-Tool {
    # -First 1 is load-bearing: several pythons on PATH (3.13, 3.11, the
    # WindowsApps stub) make Get-Command return an array, and $cmd.Source
    # would then be an array of paths that the call operator cannot run.
    # Get-Command yields them in PATH order, so the first is the one a bare
    # name would have resolved to anyway.
    param([string]$Name)
    $cmd = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

function Invoke-Tool {
    # See the long note in build-pdf.ps1. Both assignments are
    # function-scoped and revert on return.
    #
    # 5.1: 2>&1 routes native stderr through WriteError, which under
    # $ErrorActionPreference='Stop' throws on the first line. A missing
    # Python module prints a traceback on stderr, so probing without this
    # would abort the whole report on a perfectly ordinary machine.
    #
    # $PSNativeCommandUseErrorActionPreference (7.3+) makes a non-zero exit
    # code throw as well. It ships $false, but a profile or CI runner can
    # set it, and this whole script is built on probing exit codes - so opt
    # out explicitly. On 5.1 the variable is simply unused.
    #
    # $Exe must be a resolved path from Get-Tool, never a bare name: the
    # call operator prefers an alias, function or cmdlet over the
    # executable, and those leave $LASTEXITCODE stale.
    param([string]$Exe, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    # Clear the sentinel first. If the executable never launches, nothing
    # updates $LASTEXITCODE and a stale or unset value would read as a clean
    # exit - which would report a missing Python module as installed.
    $global:LASTEXITCODE = $null
    $out = $null
    try { $out = & $Exe @Arguments 2>&1 }
    catch { $out = $_.Exception.Message }
    if ($null -eq $LASTEXITCODE) { $code = 127 } else { $code = $LASTEXITCODE }
    return [pscustomobject]@{ ExitCode = $code; Output = $out }
}

function Test-Windows {
    # 5.1 is Windows-only and has no $IsWindows; 7.x defines it everywhere.
    if (Test-Path 'variable:IsWindows') { return [bool]$IsWindows }
    return $true
}

if (-not (Test-Windows)) {
    [Console]::Error.WriteLine('preflight: this script reads Windows registry fonts and Program Files.')
    [Console]::Error.WriteLine('preflight: On Linux or macOS run the POSIX twin instead:')
    [Console]::Error.WriteLine('preflight:   scripts/preflight.sh')
    exit 2
}

function Get-Python {
    foreach ($n in 'python', 'python3') {
        $p = Get-Tool $n
        if ($p) { return $p }
    }
    return $null
}

function Test-PyModule {
    param([string]$Python, [string]$Module)
    if (-not $Python) { return $false }
    $r = Invoke-Tool $Python @('-c', "import $Module")
    return ($r.ExitCode -eq 0)
}

function Test-PythonCode {
    param([string]$Python, [string]$Code)
    if (-not $Python) { return $false }
    return ((Invoke-Tool $Python @('-c', $Code)).ExitCode -eq 0)
}

function Find-Browser {
    if ($env:REVAYAT_CHROMIUM) {
        if (Test-Path -LiteralPath $env:REVAYAT_CHROMIUM -PathType Leaf) { return $env:REVAYAT_CHROMIUM }
        return $null
    }
    foreach ($name in 'msedge', 'chrome', 'chromium') {
        $p = Get-Tool $name
        if ($p) { return $p }
    }
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA) |
        Where-Object { $_ }
    $relative = @(
        'Microsoft\Edge\Application\msedge.exe',
        'Google\Chrome\Application\chrome.exe',
        'Chromium\Application\chrome.exe'
    )
    foreach ($rel in $relative) {
        foreach ($root in $roots) {
            $candidate = Join-Path $root $rel
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    return $null
}

function Get-InstalledFontFamily {
    # Windows has no fc-list. Read the font registry, which covers both
    # machine-wide (C:\Windows\Fonts) and per-user installs.
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts',
        'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'
    )
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($key in $keys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $props = Get-ItemProperty -LiteralPath $key
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $names.Add($p.Name)
        }
    }
    return $names
}

$tex = $false
$browser = $false
$weasy = $false
$faFont = $false

$python = Get-Python

Write-Output 'PDF engines'
if ($python -and (Invoke-Tool $python @((Join-Path $PSScriptRoot 'tex-container.py'), '--probe')).ExitCode -eq 0 -and (Test-PyModule $python 'pymupdf')) {
    Write-Ok 'isolated XeLaTeX' 'local Linux runtime/image and PyMuPDF available; no document rendered'
    $tex = $true
}
else { Write-No 'isolated XeLaTeX' 'set up Docker/Podman and assets/Dockerfile.tex; no native fallback' }

$browserPath = Find-Browser
if ($browserPath -and (Test-PythonCode $python 'from playwright.sync_api import sync_playwright; import pymupdf')) {
    Write-Ok 'Chromium candidate' 'executable and same-Python Playwright/PyMuPDF available; not launched'
    $browser = $true
}
else {
    Write-No 'Chromium candidate' 'needs valid REVAYAT_CHROMIUM/PATH browser and same-Python Playwright/PyMuPDF'
}

$weasyProbe = @'
import re
from importlib.metadata import version
from weasyprint import HTML
from weasyprint.urls import URLFetcher, URLFetcherResponse, FatalURLFetchingError
import pymupdf
v = version('weasyprint')
raise SystemExit(0 if re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', v) and int(v.split('.')[0]) >= 68 else 1)
'@
if (Test-PythonCode $python $weasyProbe) {
    Write-Ok 'WeasyPrint candidate' 'same-Python stable 68+ and restricted-fetcher APIs import; not rendered'
    $weasy = $true
    Write-Output '        Keep whole English/number clusters inside one dir="ltr" span.'
}
else {
    Write-No 'WeasyPrint candidate' 'needs same-Python stable 68+, URLFetcher APIs, native libraries and PyMuPDF'
}

Write-Output ''
Write-Output 'Fonts'
# The Farsi-digit cut must never be selected: it draws Eastern Arabic
# digits. Registry names are space-separated ("Vazirmatn UI FD Bold
# (TrueType)"), so match FD as a whole token, not as "UI-FD".
$fdPattern = '(?i)(^|[\s_-])(UI[\s_-]?)?FD([\s_-]|$|\s*\()|Farsi.*Digit'
$families = Get-InstalledFontFamily
$faCandidates = $families | Where-Object {
    $_ -match '(?i)vazir|iran|nazli|behdad|shabnam|sahel|samim|estedad|noto\s*(naskh|kufi)|arabic|tahoma|segoe\s*ui'
}
if ($faCandidates) {
    $shown = ($faCandidates | Sort-Object -Unique | Select-Object -First 8) -join ', '
    Write-Ok 'host font candidates' $shown
    $faFont = $true
    $vazir = $faCandidates | Where-Object { $_ -match '(?i)vazirmatn' -and $_ -notmatch $fdPattern }
    if ($vazir) {
        Write-Ok 'Vazirmatn' 'registry entry only; actual rendering/embedding still requires verification'
    }
    else {
        Write-No 'Vazirmatn' 'run scripts\fetch-vazirmatn.ps1 fonts'
    }
    if ($faCandidates | Where-Object { $_ -match $fdPattern }) {
        Write-Output '        warn: a Farsi-digit cut is installed; never select it'
    }
}
else {
    Write-No 'fa-capable face' 'run scripts\fetch-vazirmatn.ps1 fonts'
}

Write-Output ''
Write-Output 'Source extraction and verification'
foreach ($t in 'pdftotext', 'pdfimages', 'pdftoppm', 'pdfinfo', 'pdffonts') {
    if (Get-Tool $t) { Write-Ok $t } else { Write-No $t 'part of poppler' }
}
foreach ($t in 'curl', 'tar', 'git') {
    if (Get-Tool $t) { Write-Ok $t } else { Write-No $t }
}
if ($python) {
    Write-Ok 'python' "required by scripts\check-fa.py ($python)"
}
else {
    Write-No 'python' 'check-fa.py will not run'
}
if (Test-PyModule $python 'PIL.Image') {
    Write-Ok 'Pillow' 'scripts\prepare-figures.py'
}
else {
    Write-No 'Pillow' 'image inspection/preparation requires the skill requirements'
}
foreach ($module in 'docx', 'playwright') {
    if (Test-PyModule $python $module) { Write-Ok $module 'built-in document helpers' }
    else { Write-No $module 'install the skill requirements' }
}
if (Test-PyModule $python 'pymupdf') {
    Write-Ok 'PyMuPDF' 'scripts\crop-source-figures.py'
}
else {
    Write-No 'PyMuPDF' 'cannot crop PDF artwork; pip install pymupdf'
}

Write-Output ''
Write-Output 'Verdict'
Write-Output '  Discovery only: no document, browser launch, font usage or extraction quality was verified.'
if ($tex) {
    Write-Output '  TeX candidate: isolated XeLaTeX; run the actual build and -Verify.'
}
elseif ($browser) {
    Write-Output '  HTML candidate: Chromium through the restricted renderer; verify layout and extraction.'
}
elseif ($weasy) {
    Write-Output '  no TeX and no browser: build .html with WeasyPrint, and keep'
    Write-Output '  every English cluster in a single dir="ltr" isolate'
}
else {
    Write-Output '  No configured engine has the required prerequisites; resolve the missing items.'
}
if (-not $faFont) { Write-Output '  Host Persian font discovery found no candidate; container/job-local fonts are separate.' }
Write-Output '  HTML/local fonts: deliver real static Regular/Bold files, OFL.txt and provenance beside the source.'
Write-Output '  -Verify requires pdfinfo, pdffonts, pdftoppm and same-Python PyMuPDF; missing tools fail.'

if (-not $tex) {
    Write-Output '  TeX setup: build assets/Dockerfile.tex as revayat-scientific-tex:1'
    Write-Output '  The helper never installs a runtime or pulls an image automatically.'
}
if (-not (Get-Tool 'pdftoppm')) {
    Write-Output ''
    Write-Output 'Install poppler for extraction and -Verify rasterisation:'
    Write-Output '  winget install oschwartz10612.Poppler'
    Write-Output '  (or: scoop install poppler)'
}

if ($RequireTex -and -not $tex) { exit 1 }
exit 0
