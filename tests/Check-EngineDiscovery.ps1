param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'skills/revayat-scientific/scripts/build-pdf.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Native build script failed parsing' }
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-AvailableEngines'
}, $false))
if ($functions.Count -ne 1) { throw 'Missing unique engine-discovery function' }
. ([scriptblock]::Create($functions[0].Extent.Text))
$script:calls = [Collections.Generic.List[string]]::new()
$script:exitCode = 0; $script:browser = $true
$python = 'fixed-test-python'
function Test-XeLaTeX { $script:calls.Add('tex'); return $true }
function Find-Chromium { $script:calls.Add('browser'); if ($script:browser) { return 'fixed-browser' }; return $null }
function Invoke-Tool {
    param($Exe, [string[]]$Arguments)
    if ($Exe -ne 'fixed-test-python') { throw 'Unexpected discovery executable' }
    if ($Arguments.Count -ne 2 -or $Arguments[0] -ne '-c') { throw 'Unexpected discovery command' }
    if ($Arguments[1] -eq 'import playwright.sync_api, pymupdf') { $script:calls.Add('chromium') }
    elseif ($Arguments[1] -eq 'from weasyprint import HTML; from weasyprint.urls import URLFetcher, URLFetcherResponse, FatalURLFetchingError; import pymupdf') { $script:calls.Add('weasyprint') }
    else { throw 'Unknown discovery import' }
    return [pscustomobject]@{ ExitCode = $script:exitCode }
}
foreach ($case in @(
    @('chromium','chromium','browser,chromium'), @('tex','tex','tex'),
    @('weasyprint','weasyprint','weasyprint'), @('auto','tex,chromium,weasyprint','tex,browser,chromium,weasyprint')
)) {
    $script:calls.Clear(); $actual = @(Get-AvailableEngines $case[0])
    if (($actual -join ',') -ne $case[1] -or ($script:calls -join ',') -ne $case[2]) { throw 'Engine discovery crossed the requested boundary' }
}
$script:exitCode = 1; $script:calls.Clear()
if (@(Get-AvailableEngines 'chromium').Count -ne 0 -or ($script:calls -join ',') -ne 'browser,chromium') { throw 'Unavailable explicit engine was accepted or fell back' }
$script:browser = $false; $script:calls.Clear()
if (@(Get-AvailableEngines 'chromium').Count -ne 0 -or ($script:calls -join ',') -ne 'browser') { throw 'Absent browser invoked an import or fallback' }
[Console]::Out.WriteLine('ENGINE_DISCOVERY_OK native_tools_invoked=false')
