#Requires -Version 5.1
<#
.SYNOPSIS
    Compile a Persian print document and copy the PDF to
    $HOME\Documents\books. Windows counterpart of build-pdf.sh.

.DESCRIPTION
    Engine order for .tex: XeLaTeX (via latexmk when present). For .html:
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
    Write-Log 'this script drives Windows tooling (registry fonts, Edge, MiKTeX).'
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
    # exit code. A GUI-subsystem executable needs Invoke-Browser instead -
    # see the note there.
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

function Invoke-Browser {
    # Same contract as Invoke-Tool, but for a GUI-subsystem executable.
    #
    # PowerShell only waits for *console* applications. msedge.exe and
    # chrome.exe are GUI binaries, so `& $browser --print-to-pdf ...`
    # returns the instant the process is launched: nothing is captured,
    # nothing writes $LASTEXITCODE, and the check for the finished PDF runs
    # while the browser is still starting. Invoke-Tool reads that unset
    # exit code as its "never launched" sentinel and reports 127, which is
    # why the HTML path failed on every Windows machine that has Edge.
    #
    # Start-Process -Wait is the form that actually blocks on a GUI
    # process. It hands the arguments over as one joined string instead of
    # an argv array, so anything holding a space - every path under
    # "Program Files", every slug with a space in it - has to be quoted
    # here; the call operator did that itself.
    param([string]$Exe, [string[]]$Arguments)
    $stem = Join-Path ([IO.Path]::GetTempPath()) ('fa-run-' + [Guid]::NewGuid().ToString('N'))
    $outFile = "$stem.out"
    $errFile = "$stem.err"
    $quoted = @($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    })
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $quoted -Wait -PassThru `
            -WindowStyle Hidden -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $lines = @()
        foreach ($f in @($outFile, $errFile)) {
            if (Test-Path -LiteralPath $f) {
                $lines += @(Get-Content -LiteralPath $f -Encoding UTF8 -ErrorAction SilentlyContinue)
            }
        }
        return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $lines }
    }
    catch {
        # Could not start at all: report it the way Invoke-Tool would.
        return [pscustomobject]@{ ExitCode = 127; Output = @($_.Exception.Message) }
    }
    finally {
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
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
    if (-not (Get-Tool 'xelatex')) { return $false }
    # xepersian is the part that is usually missing on a bare TeX install.
    $kpse = Get-Tool 'kpsewhich'
    if ($kpse) {
        # Exit code alone is not enough: MiKTeX's kpsewhich can exit 0 while
        # printing nothing for a package the basic install does not carry.
        # Require an actual path back.
        $r = Invoke-Tool $kpse @('xepersian.sty')
        if ($r.ExitCode -ne 0) { return $false }
        $hit = $r.Output | Where-Object { "$_" -match 'xepersian\.sty' }
        if (-not $hit) { return $false }
    }
    return $true
}

function Find-Chromium {
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

function Show-TexError {
    param([string]$LogFile)
    if (-not (Test-Path -LiteralPath $LogFile -PathType Leaf)) { return }
    $errs = Get-Content -LiteralPath $LogFile -Encoding UTF8 |
        Where-Object { $_ -like '!*' } |
        Select-Object -First 20
    if ($errs) {
        Write-Log "--- first TeX errors in $LogFile ---"
        $errs | ForEach-Object { [Console]::Error.WriteLine($_) }
    }
    else {
        # A truncated log with no '!' line usually means the engine died
        # mid-run rather than rejecting the document - say so instead of
        # printing an empty section under a heading that promises errors.
        Write-Log "no '!' error line in $LogFile; the engine stopped mid-run"
    }
    Write-Log '--- last 25 log lines ---'
    Get-Content -LiteralPath $LogFile -Encoding UTF8 -Tail 25 |
        ForEach-Object { [Console]::Error.WriteLine($_) }
}

function Show-DriverFailure {
    # xdvipdfmx cannot embed a *named instance* of a variable font, and a
    # named instance is exactly what XeTeX hands it for any family that is
    # installed only as a variable face - Vazirmatn from Google Fonts among
    # them. What it prints is "Invalid TTC index" and "Invalid font: -1 (4)",
    # which says nothing about fonts to anyone who has not met it before.
    # Translate it.
    param($Output, [string]$SourceDir)
    $hit = $Output | Where-Object {
        "$_" -like '*Invalid TTC index*' -or "$_" -like '*Invalid font: -1*'
    }
    if (-not $hit) { return }
    Write-Log 'that is a variable font: XeTeX selected a named instance of it and'
    Write-Log '  the PDF driver cannot embed one. The same file loaded by path'
    Write-Log '  works, so put the TTFs beside the document and rebuild:'
    Write-Log "    scripts\fetch-vazirmatn.ps1 $(Join-Path $SourceDir 'fonts')"
}

# 0 = built, 1 = engine unavailable, 2 = engine present but failed.
function Invoke-TexBuild {
    param([string]$SourceName, [string]$Stem, [string]$Destination)
    if (-not (Test-XeLaTeX)) { return 1 }
    $pdf = "$Stem.pdf"
    $log = "$Stem.log"
    $xelatex = Get-Tool 'xelatex'
    $latexmk = Get-Tool 'latexmk'
    $useLatexmk = [bool]$latexmk
    $r = $null

    # Clear artefacts from a previous run first. Without this a stale .log
    # makes "latexmk left no .log" read as "latexmk reached the compiler",
    # so the fallback never fires and the old log gets reported as this
    # build's error; a stale .pdf could likewise be shipped as a success.
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $pdf -Force -ErrorAction SilentlyContinue

    if ($useLatexmk) {
        Write-Log 'engine: latexmk -xelatex'
        $r = Invoke-Tool $latexmk @(
            '-xelatex', '-interaction=nonstopmode', '-halt-on-error',
            '-silent', $SourceName)
        if ($r.ExitCode -ne 0 -and -not (Test-Path -LiteralPath $log -PathType Leaf)) {
            # No .log at all means the compiler was never reached - a
            # latexmk problem (MiKTeX ships it as a Perl script, so a
            # missing Perl kills it) rather than a broken document. Any
            # real TeX error writes a .log first, so retrying here cannot
            # hide one.
            Write-Log 'latexmk wrote no .log, so it never reached the compiler:'
            Write-ToolOutput $r.Output
            Write-Log 'retrying with xelatex directly'
            $useLatexmk = $false
        }
    }

    if (-not $useLatexmk) {
        Write-Log 'engine: xelatex (two passes)'
        $r = Invoke-Tool $xelatex @(
            '-interaction=nonstopmode', '-halt-on-error', $SourceName)
        if ($r.ExitCode -eq 0) {
            $r = Invoke-Tool $xelatex @(
                '-interaction=nonstopmode', '-halt-on-error', $SourceName)
        }
    }

    if ($r.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $log -PathType Leaf) {
            Show-TexError $log
        }
        else {
            # Never claim "the error is above" when nothing was printed.
            Write-Log "no $log was written; the engine's own output follows"
            Write-ToolOutput $r.Output
        }
        return 2
    }
    if (-not (Test-Path -LiteralPath $pdf -PathType Leaf)) {
        Write-Log "expected PDF missing: $pdf"
        return 2
    }
    # A zero exit code from xelatex only means TeX itself was happy. The
    # PDF driver runs afterwards and reports its own failure in the log
    # while xelatex still exits 0, so check for that before believing it.
    if (Test-Path -LiteralPath $log -PathType Leaf) {
        $driver = Get-Content -LiteralPath $log -Encoding UTF8 |
            Where-Object { $_ -like '*driver return code*' }
        if ($driver) {
            Write-Log 'the PDF driver failed even though xelatex exited 0:'
            $driver | ForEach-Object { [Console]::Error.WriteLine($_) }
            Write-ToolOutput $r.Output
            Show-DriverFailure $r.Output $srcDir
            return 2
        }
    }
    if (-not (Test-PdfStructure $pdf)) {
        Write-Log "$pdf is truncated (no %%EOF); the driver did not finish"
        Write-ToolOutput $r.Output
        Show-DriverFailure $r.Output $srcDir
        return 2
    }
    $script:UsedEngine = 'xelatex'
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

function ConvertTo-FileUri {
    param([string]$LiteralPath)
    return ([Uri](Resolve-Path -LiteralPath $LiteralPath).ProviderPath).AbsoluteUri
}

function Invoke-HtmlBuild {
    param([string]$Html, [string]$Destination)
    $script:UsedEngine = 'html'
    Write-Log 'HTML engines may store visual text order; selectable Persian requires XeLaTeX'
    Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue

    if ($Engine -ne 'weasyprint') {
        $browser = Find-Chromium
        if ($browser) {
            Write-Log "engine: $([IO.Path]::GetFileName($browser)) --print-to-pdf"
            # A dedicated profile directory keeps the headless run from
            # attaching to an already-open Edge/Chrome window, which is the
            # usual reason --print-to-pdf silently writes nothing on Windows.
            $profileDir = Join-Path ([IO.Path]::GetTempPath()) ('fa-pdf-' + [Guid]::NewGuid().ToString('N'))
            try {
                # Without a virtual-time budget Chromium can print before the
                # webfonts finish loading, which produces fallback boxes for
                # Persian. --disable-gpu paints raster images as black
                # rectangles; do not pass it.
                $r = Invoke-Browser $browser @(
                    '--headless=new',
                    '--no-pdf-header-footer',
                    '--virtual-time-budget=10000',
                    '--run-all-compositor-stages-before-draw',
                    "--user-data-dir=$profileDir",
                    "--print-to-pdf=$Destination",
                    (ConvertTo-FileUri $Html)
                )
            }
            finally {
                Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            if ($r.ExitCode -ne 0) {
                Write-ToolFailure "$([IO.Path]::GetFileName($browser)) --print-to-pdf" $r
                Write-Log "  source: $Html"
                Write-Log "  target: $Destination"
                return 2
            }
            # Headless Chromium can exit 0 without writing the file.
            if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
                Write-Log "the browser exited 0 but wrote no PDF: $Destination"
                Write-ToolOutput $r.Output
                return 2
            }
            if (-not (Test-PdfStructure $Destination)) {
                Write-Log "the browser wrote a truncated PDF: $Destination"
                Write-ToolOutput $r.Output
                return 2
            }
            return 0
        }
    }

    $weasyprint = Get-Tool 'weasyprint'
    if ($weasyprint) {
        Write-Log 'engine: weasyprint (keeps its bidi warnings; read them)'
        $r = Invoke-Tool $weasyprint @($Html, $Destination)
        if ($r.ExitCode -ne 0) {
            Write-ToolFailure 'weasyprint' $r
            return 2
        }
        return 0
    }

    $python = Get-Tool 'python'
    if (-not $python) { $python = Get-Tool 'python3' }
    if ($python) {
        $probe = Invoke-Tool $python @('-c', 'import weasyprint')
        if ($probe.ExitCode -eq 0) {
            Write-Log 'engine: weasyprint (python module)'
            $code = 'from weasyprint import HTML; import sys; HTML(sys.argv[1]).write_pdf(sys.argv[2])'
            $r = Invoke-Tool $python @('-c', $code, $Html, $Destination)
            if ($r.ExitCode -ne 0) {
                Write-ToolOutput $r.Output
                return 2
            }
            return 0
        }
    }

    Write-Log 'no HTML engine: install Edge/Chrome, or WeasyPrint in a venv'
    Write-Log '  (py -m venv .venv; .venv\Scripts\pip install weasyprint)'
    return 1
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
$script:UsedEngine = ''
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
$r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'check-fa.py'), $srcItem.FullName,
    '--level', $Level, '--terms', $Terms, '--manifest', $Manifest, '--strict')
Write-ToolOutput $r.Output
if ($r.ExitCode -ne 0) { Write-Log 'lint failed; destination was not changed'; exit 1 }
$figures = Join-Path $srcDir 'figures'
if (Test-Path -LiteralPath $figures -PathType Container) {
    $r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'prepare-figures.py'), $figures, '--check')
    Write-ToolOutput $r.Output
    if ($r.ExitCode -ne 0) { Write-Log 'figure check failed'; exit 1 }
}

$rc = 1
Push-Location -LiteralPath $srcDir
try {
    switch ($ext) {
        'tex' {
            if ($Engine -eq 'chromium' -or $Engine -eq 'weasyprint') {
                $html = "$srcStem.html"
                if (-not (Test-Path -LiteralPath $html -PathType Leaf)) {
                    Write-Log "no $html next to the .tex"
                    exit 1
                }
                $rc = Invoke-HtmlBuild $html $localPdf
            }
            else {
                $rc = Invoke-TexBuild $srcName $srcStem $localPdf
                if ($rc -eq 2) {
                    Write-Log 'XeLaTeX is installed but the build failed.'
                    Write-Log 'Fix the problem reported above. Not falling back to HTML - a'
                    Write-Log '  fallback here would hide a real error in the .tex.'
                    exit 1
                }
                if ($rc -eq 1) {
                    Write-Log 'xelatex or xepersian not available (see scripts\preflight.ps1)'
                    $html = "$srcStem.html"
                    if (Test-Path -LiteralPath $html -PathType Leaf) {
                        Write-Log "falling back to $html"
                        $rc = Invoke-HtmlBuild $html $localPdf
                    }
                    else {
                        Write-Log 'write the HTML from assets\rtl-document.html and retry:'
                        Write-Log "  build-pdf.ps1 $(Join-Path $srcDir $html) $Slug"
                        exit 1
                    }
                }
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
New-Item -ItemType Directory -Path $destDir -Force | Out-Null
$stagedPdf = Join-Path $destDir ('.scientific-' + [Guid]::NewGuid().ToString('N') + '.pdf')
try {
    Copy-Item -LiteralPath $localPdf -Destination $stagedPdf -ErrorAction Stop
    if (Test-Path -LiteralPath $dest) { [IO.File]::Replace($stagedPdf, $dest, $null) }
    else { [IO.File]::Move($stagedPdf, $dest) }
}
catch { Write-Log 'delivery failed; previous destination was preserved'; exit 1 }
finally { Remove-Item -LiteralPath $stagedPdf -Force -ErrorAction SilentlyContinue }
Write-Output $dest
exit 0
