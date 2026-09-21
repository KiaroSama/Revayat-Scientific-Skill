#Requires -Version 5.1
<#
.SYNOPSIS
    Compile a Persian print document and copy the PDF to
    $HOME\Documents\books. Windows counterpart of build-pdf.sh.

.DESCRIPTION
    Engine order for .tex: isolated XeLaTeX through Docker/Podman. For .html:
    a Chromium browser (Edge, then Chrome), then WeasyPrint. A *missing*
    engine falls back; a *failing* engine does not - it reports the error
    and stops, so a broken build is never quietly downgraded.

    Only the destination path is written to stdout; every diagnostic goes
    to stderr, so `$pdf = .\build-pdf.ps1 doc.tex slug` captures the path.

.PARAMETER Path
    The .tex or .html source to compile.

.PARAMETER Slug
    Filesystem-safe stem for the output PDF. Defaults to the source stem.

.PARAMETER Verify
    Report page count and embedded fonts, and rasterise sample pages to
    PNG. Judge RTL from those images, never from pdftotext.

.PARAMETER Engine
    Force one engine: tex, chromium, or weasyprint.

.EXAMPLE
    .\build-pdf.ps1 doc.tex my-slug -Verify

.EXAMPLE
    .\build-pdf.ps1 doc.html my-slug -Engine chromium -Verify

.NOTES
    Runs on Windows PowerShell 5.1 and on PowerShell 7.x. Windows only:
    under pwsh on Linux or macOS it stops and points at build-pdf.sh.

    This file is deliberately pure ASCII: 5.1 decodes a BOM-less .ps1 with
    the system ANSI code page, where a UTF-8 em dash turns into a curly
    quote that terminates a string and breaks the parse. Keep it ASCII-only.

    The Python helpers in this directory (check-fa.py, prepare-figures.py,
    crop-source-figures.py, extract-pdf-pages.py) are cross-platform
    already - run them with `python scripts\check-fa.py ...`.
#>
[CmdletBinding()]
param(
    # Not [Mandatory]: a mandatory parameter prompts before the platform
    # guard below can run, so `pwsh ./build-pdf.ps1` on Linux would hang on
    # a prompt instead of pointing at build-pdf.sh.
    [Parameter(Position = 0)]
    [string]$Path,

    [Parameter(Position = 1)]
    [string]$Slug,

    [switch]$Verify,

    [ValidateSet('tex', 'chromium', 'weasyprint')]
    [string]$Engine,

    [ValidateSet('system-docs', 'journal')]
    [string]$Level = 'system-docs',

    [string]$Terms,

    [string]$Manifest,

    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Persian filenames and TeX log lines are UTF-8; do not let the console
# code page mangle them.
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }

function Write-Log {
    param([string]$Message)
    [Console]::Error.WriteLine("build-pdf: $Message")
}

function Test-Windows {
    # 5.1 is Windows-only and has no $IsWindows; 7.x defines it on every
    # platform. Test-Path keeps StrictMode from throwing on 5.1.
    if (Test-Path 'variable:IsWindows') { return [bool]$IsWindows }
    return $true
}

if (-not (Test-Windows)) {
    Write-Log 'this script drives Windows tooling (registry fonts, Edge, local containers).'
    Write-Log 'On Linux or macOS run the POSIX twin instead:'
    Write-Log '  scripts/build-pdf.sh <file.tex|file.html> <slug> --verify'
    exit 2
}

if (-not $Path) {
    Write-Log 'usage: build-pdf.ps1 <file.tex|file.html> [slug] [-Verify]'
    Write-Log '                     [-Engine tex|chromium|weasyprint]'
    exit 2
}

function Get-Tool {
    # Resolve an executable on PATH; $null when absent. Filtering on
    # Application keeps $LASTEXITCODE meaningful after the call.
    #
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
    # Run a *console* executable, capture merged stdout+stderr, return the
    # exit code. The bounded Python renderer owns GUI-subsystem browsers.
    #
    # $Exe must be a resolved path from Get-Tool, never a bare name: the call
    # operator runs full command discovery, which prefers an alias, function
    # or cmdlet over the executable, and those leave $LASTEXITCODE stale.
    #
    # Both assignments below are function-scoped, so they shadow the caller's
    # values and revert on return - no finally needed.
    #
    # 5.1: 2>&1 on a native command wraps each stderr line in an ErrorRecord
    # and emits it through WriteError, which honours $ErrorActionPreference.
    # Under 'Stop' the first stderr line throws - and headless Chromium,
    # latexmk -silent, and a failing `python -c import` all write to stderr
    # on paths this function must treat as ordinary results. (7.2+ exempted
    # redirected native stderr from $ErrorActionPreference, so this trap is
    # 5.1-only, but the twins have to serve both.)
    #
    # $PSNativeCommandUseErrorActionPreference (7.3+) makes a non-zero *exit
    # code* raise NativeCommandExitException, which honours
    # $ErrorActionPreference too. It ships $false, but a profile or a CI
    # runner can set it, so opt out explicitly: this function reports exit
    # codes on purpose - kpsewhich 1 means "package not installed", not
    # "abort". On 5.1 the variable is simply unused.
    param([string]$Exe, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    # Clear the sentinel first. If the executable never launches, nothing
    # updates $LASTEXITCODE, and a stale or unset value would read as a
    # clean exit - turning a failed build into a reported success.
    $global:LASTEXITCODE = $null
    $out = $null
    try { $out = & $Exe @Arguments 2>&1 }
    catch { $out = $_.Exception.Message }
    if ($null -eq $LASTEXITCODE) { $code = 127 } else { $code = $LASTEXITCODE }
    return [pscustomobject]@{ ExitCode = $code; Output = $out }
}

function Write-ToolOutput {
    param($Output)
    if ($null -eq $Output) { return }
    $Output | ForEach-Object { [Console]::Error.WriteLine($_) }
}

function Write-ToolFailure {
    # A tool that fails silently still has to be reportable: without the
    # exit code there is nothing to act on, and "build failed" alone is not
    # a diagnosis.
    param([string]$What, $Result)
    Write-Log "$What failed with exit code $($Result.ExitCode)"
    if ($null -eq $Result.Output -or @($Result.Output).Count -eq 0) {
        Write-Log '  (the tool printed nothing on stdout or stderr)'
    }
    else {
        Write-ToolOutput $Result.Output
    }
}

function Test-XeLaTeX {
    $interpreter = Get-Tool 'python'
    if (-not $interpreter) { $interpreter = Get-Tool 'python3' }
    if (-not $interpreter) { return $false }
    $result = Invoke-Tool $interpreter @((Join-Path $PSScriptRoot 'tex-container.py'), '--probe')
    return ($result.ExitCode -eq 0)
}

function Find-Chromium {
    if ($env:REVAYAT_CHROMIUM) {
        if (Test-Path -LiteralPath $env:REVAYAT_CHROMIUM -PathType Leaf) { return $env:REVAYAT_CHROMIUM }
        return $null
    }
    # Edge ships with Windows and is the same Chromium engine, so it is the
    # first choice here; Chrome and a bare chromium build follow.
    foreach ($name in 'msedge', 'chrome', 'chromium') {
        $p = Get-Tool $name
        if ($p) { return $p }
    }
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:LOCALAPPDATA
    ) | Where-Object { $_ }
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

function Invoke-TexBuild {
    param([string]$SourceName, [string]$Stem, [string]$Destination)
    $result = Invoke-Tool $python @((Join-Path $PSScriptRoot 'tex-container.py'), $srcItem.FullName, $Destination)
    Write-ToolOutput $result.Output
    if ($result.ExitCode -ne 0) { return 2 }
    return 0
}

function Test-PdfStructure {
    # A PDF that exists is not a PDF that is complete. XeLaTeX can exit 0
    # while the xdvipdfmx driver dies, leaving a truncated file with a valid
    # header and no trailer - poppler then reports "Couldn't find trailer
    # dictionary" and the page count is unknown.
    param([string]$Pdf)
    $item = Get-Item -LiteralPath $Pdf -ErrorAction SilentlyContinue
    if (-not $item -or $item.Length -lt 100) { return $false }
    # Read through the item's full path. The .NET file APIs resolve a
    # relative path against [Environment]::CurrentDirectory, which
    # Push-Location does not touch - and the TeX build calls this with a
    # bare "<stem>.pdf" from inside the pushed source directory.
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    $head = [Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min(8, $bytes.Length))
    if ($head -notlike '%PDF-*') { return $false }
    $tailLen = [Math]::Min(2048, $bytes.Length)
    $tail = [Text.Encoding]::ASCII.GetString($bytes, $bytes.Length - $tailLen, $tailLen)
    return $tail.Contains('%%EOF')
}

function Invoke-HtmlBuild {
    param([string]$Html, [string]$Destination)
    $arguments = @((Join-Path $PSScriptRoot 'render-html.py'), $Html, $Destination, '--engine', $Engine)
    if ($Engine -eq 'chromium') {
        $browser = Find-Chromium
        if (-not $browser) { Write-Log 'selected Chromium became unavailable'; return 2 }
        $arguments += @('--browser', $browser)
    }
    $result = Invoke-Tool $python $arguments
    Write-ToolOutput $result.Output
    if ($result.ExitCode -ne 0) { return 2 }
    return 0
}

. (Join-Path $PSScriptRoot 'verify-pdf.ps1')

# --- main -------------------------------------------------------------

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Log "not a file: $Path"
    exit 1
}

$srcItem = Get-Item -LiteralPath $Path
$srcDir = $srcItem.DirectoryName
$srcName = $srcItem.Name
$srcStem = [IO.Path]::GetFileNameWithoutExtension($srcName)
$ext = $srcItem.Extension.TrimStart('.').ToLowerInvariant()
if (-not $Slug) { $Slug = $srcStem }
if ($Slug -in @('.', '..') -or $Slug.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
    Write-Log 'slug must be a filename, without directory separators'
    exit 2
}

$destDir = $OutputDirectory
if (-not $destDir) { $destDir = Join-Path $HOME 'Documents\books' }
$destDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($destDir)
$dest = Join-Path $destDir "$Slug.pdf"
$localPdf = Join-Path $srcDir "$srcStem.pdf"
if ([IO.Path]::GetFullPath($dest) -eq [IO.Path]::GetFullPath($localPdf)) {
    Write-Log 'output destination must differ from the working PDF; use -OutputDirectory'
    exit 2
}
if (-not $Terms) { $Terms = Join-Path $srcDir 'terms.tsv' }
if (-not $Manifest) { $Manifest = Join-Path $srcDir 'manifest.txt' }
$python = Get-Tool 'python'
if (-not $python) { $python = Get-Tool 'python3' }
if (-not $python) { Write-Log 'python is required for the strict lint gate'; exit 1 }
foreach ($sidecar in @($Terms, $Manifest)) {
    if (-not (Test-Path -LiteralPath $sidecar -PathType Leaf)) {
        Write-Log "missing required terms.tsv or manifest.txt: $sidecar"
        exit 1
    }
}
$available = @()
if (Test-XeLaTeX) { $available += 'tex' }
if ((Find-Chromium) -and (Invoke-Tool $python @('-c', 'import playwright.sync_api, pymupdf')).ExitCode -eq 0) { $available += 'chromium' }
if ((Invoke-Tool $python @('-c', 'from weasyprint import HTML; from weasyprint.urls import URLFetcher, URLFetcherResponse, FatalURLFetchingError; import pymupdf')).ExitCode -eq 0) { $available += 'weasyprint' }
$requestedEngine = if ($Engine) { $Engine } else { 'auto' }
$r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'build-support.py'), 'select',
    $srcItem.FullName, '--engine', $requestedEngine, '--available', ($available -join ','))
if ($r.ExitCode -ne 0) { Write-ToolOutput $r.Output; exit 1 }
$plan = (($r.Output | ForEach-Object { "$_" }) -join "`n") | ConvertFrom-Json
$srcItem = Get-Item -LiteralPath $plan.source
$srcName = $srcItem.Name
$ext = $srcItem.Extension.TrimStart('.').ToLowerInvariant()
$Engine = $plan.engine
$r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'build-support.py'), 'destination',
    $dest, $srcItem.FullName, $localPdf)
if ($r.ExitCode -ne 0) { Write-ToolOutput $r.Output; exit 1 }
$r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'check-fa.py'), $srcItem.FullName,
    '--level', $Level, '--terms', $Terms, '--manifest', $Manifest, '--strict')
Write-ToolOutput $r.Output
if ($r.ExitCode -ne 0) { Write-Log 'lint failed; destination was not changed'; exit 1 }
$r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'build-support.py'), 'assets', $srcItem.FullName)
Write-ToolOutput $r.Output
if ($r.ExitCode -ne 0) { Write-Log 'figure check failed'; exit 1 }

$rc = 1
Push-Location -LiteralPath $srcDir
try {
    switch ($ext) {
        'tex' {
            $rc = Invoke-TexBuild $srcName $srcStem $localPdf
            if ($rc -ne 0) {
                Write-Log 'selected TeX engine failed or became unavailable; no fallback after source checks'
                exit 1
            }
        }
        { $_ -in 'html', 'htm' } {
            $rc = Invoke-HtmlBuild $srcName $localPdf
        }
        default {
            Write-Log "expected .tex or .html, got: $srcName"
            exit 2
        }
    }

    if ($rc -ne 0) {
        Write-Log 'build failed'
        exit 1
    }

    # Verification that cannot fail the build is decoration. If -Verify was
    # asked for and it fails, do not print the destination path as though
    # the document were usable.
    if ($Verify -and -not (Test-OutputPdf $localPdf $srcDir $Slug)) {
        Write-Log 'verification failed; this PDF is not usable'
        exit 1
    }
}
finally {
    Pop-Location
}

if (-not (Test-PdfStructure $localPdf)) { Write-Log 'build produced an invalid PDF'; exit 1 }
$r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'build-support.py'), 'publish', $localPdf, $dest)
if ($r.ExitCode -ne 0) { Write-ToolOutput $r.Output; Write-Log 'delivery failed; previous destination was preserved'; exit 1 }
Write-Output $dest
exit 0
