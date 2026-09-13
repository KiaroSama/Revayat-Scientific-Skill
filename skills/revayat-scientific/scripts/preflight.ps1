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
    Exit 1 when XeLaTeX + xepersian is not usable, so a caller can gate on
    the preferred engine.

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
    foreach ($n in 'python', 'python3', 'py') {
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

function Find-Browser {
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
$xelatex = Get-Tool 'xelatex'
if ($xelatex) {
    $xepersianMissing = $false
    $kpse = Get-Tool 'kpsewhich'
    if ($kpse) {
        # Exit code alone is not enough: MiKTeX's kpsewhich can exit 0 while
        # printing nothing for a package the basic install does not carry.
        # Require an actual path back.
        $r = Invoke-Tool $kpse @('xepersian.sty')
        $hit = $r.Output | Where-Object { "$_" -match 'xepersian\.sty' }
        if ($r.ExitCode -ne 0 -or -not $hit) { $xepersianMissing = $true }
    }
    if ($xepersianMissing) {
        Write-No 'xepersian.sty' 'xelatex is present but the Persian package is not'
    }
    else {
        $v = Invoke-Tool $xelatex @('--version')
        $ver = "$($v.Output | Select-Object -First 1)"
        Write-Ok 'xelatex + xepersian' $ver
        $tex = $true

        # MiKTeX installs missing packages on the fly and, by default, asks
        # first with a modal dialog. That is fine for a human at a keyboard
        # and fatal for an unattended or agent-driven build, which simply
        # hangs on an invisible window. AutoInstall: 1 = yes, 0 = no,
        # anything else (2) = ask.
        if ($ver -match '(?i)miktex') {
            $initexmf = Get-Tool 'initexmf'
            if ($initexmf) {
                $a = Invoke-Tool $initexmf @('--show-config-value=[MPM]AutoInstall')
                $auto = "$($a.Output | Select-Object -First 1)".Trim()
                if ($auto -eq '1') {
                    Write-Ok 'MiKTeX auto-install' 'missing packages install without prompting'
                }
                else {
                    Write-No 'MiKTeX auto-install' "set to '$auto'; a build will stop on a dialog"
                    Write-Output '        fix: initexmf --set-config-value "[MPM]AutoInstall=1"'
                }
            }
        }
    }
}
else {
    Write-No 'xelatex' 'preferred engine unavailable'
}
if (Get-Tool 'latexmk') { Write-Ok 'latexmk' 'used for reruns and bibliography' }

$browserPath = Find-Browser
if ($browserPath) {
    Write-Ok ([IO.Path]::GetFileName($browserPath)) 'HTML print fallback'
    $browser = $true
}
else {
    Write-No 'edge/chrome' 'no browser print fallback'
}

if ((Get-Tool 'weasyprint') -or (Test-PyModule $python 'weasyprint')) {
    Write-Ok 'weasyprint' 'HTML print fallback'
    $weasy = $true
    Write-Output '        note: ignores unicode-bidi: isolate - rely on dir="ltr"'
    Write-Output '        attributes and keep every cluster in one isolate'
}
else {
    Write-No 'weasyprint' 'py -m venv .venv; .venv\Scripts\pip install weasyprint'
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
    Write-Ok 'fa-capable faces' $shown
    $faFont = $true
    $vazir = $faCandidates | Where-Object { $_ -match '(?i)vazirmatn' -and $_ -notmatch $fdPattern }
    if ($vazir) {
        Write-Ok 'Vazirmatn' 'preferred text face'
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
elseif ((Get-Tool 'magick') -or (Get-Tool 'convert')) {
    Write-Ok 'ImageMagick' 'scripts\prepare-figures.py fallback'
}
else {
    Write-No 'Pillow/ImageMagick' 'figures cannot be flattened; pip install pillow'
}
if (Test-PyModule $python 'pymupdf') {
    Write-Ok 'PyMuPDF' 'scripts\crop-source-figures.py'
}
else {
    Write-No 'PyMuPDF' 'cannot crop PDF artwork; pip install pymupdf'
}

Write-Output ''
Write-Output 'Verdict'
if ($tex) {
    Write-Output '  build .tex with XeLaTeX - best print RTL'
}
elseif ($browser) {
    Write-Output '  no TeX: build .html with Edge/Chrome (display RTL; copy-paste may reverse)'
}
elseif ($weasy) {
    Write-Output '  no TeX and no browser: build .html with WeasyPrint, and keep'
    Write-Output '  every English cluster in a single dir="ltr" isolate'
}
else {
    Write-Output '  no engine can produce a PDF - stop and tell the user'
}
if (-not $faFont) { Write-Output '  fetch a Persian font before building' }

if (-not $tex) {
    Write-Output ''
    Write-Output 'Install the preferred engine (Windows):'
    Write-Output '  winget install MiKTeX.MiKTeX'
    Write-Output '  then let MiKTeX install xepersian on first use, or:'
    Write-Output '  mpm --install=xepersian --install=bidi'
}
if (-not (Get-Tool 'pdftoppm')) {
    Write-Output ''
    Write-Output 'Install poppler for extraction and -Verify rasterisation:'
    Write-Output '  winget install oschwartz10612.Poppler'
    Write-Output '  (or: scoop install poppler)'
}

if ($RequireTex -and -not $tex) { exit 1 }
exit 0
