#Requires -Version 5.1
# Shared verification for the Windows build entry point; functions run in its scope.
function Test-OutputPdf {
    param([string]$Pdf, [string]$WorkDir, [string]$Stem)
    if (-not (Test-PdfStructure $Pdf)) {
        Write-Log "VERIFY FAIL: $Pdf is empty or truncated (no %%EOF trailer)"
        return $false
    }
    foreach ($name in @('pdfinfo', 'pdffonts', 'pdftoppm')) {
        if (-not (Get-Tool $name)) {
            Write-Log "VERIFY FAIL: $name not found (install poppler)"
            return $false
        }
    }
    $r = Invoke-Tool (Get-Tool 'pdfinfo') @($Pdf)
    $line = $r.Output | Where-Object { "$_" -match '^Pages:\s+(\d+)' } | Select-Object -First 1
    if ($r.ExitCode -ne 0 -or -not $line -or "$line" -notmatch '^Pages:\s+(\d+)') {
        Write-Log 'VERIFY FAIL: could not read page count'
        return $false
    }
    $pages = [int]$Matches[1]
    if ($pages -lt 1) { Write-Log 'VERIFY FAIL: empty PDF'; return $false }
    Write-Log "pages: $pages"
    $r = Invoke-Tool (Get-Tool 'pdffonts') @($Pdf)
    $embedded = $r.Output | Select-Object -Skip 2 | Where-Object {
        $fields = "$_".Trim() -split '\s+'
        $fields.Count -ge 8 -and $fields[-5] -eq 'yes'
    }
    if ($r.ExitCode -ne 0 -or -not $embedded) {
        Write-Log 'VERIFY FAIL: no embedded font; Persian may render as boxes'
        return $false
    }
    $samples = ,@('first', 1)
    if ($pages -gt 1) { $samples += ,@('last', $pages) }
    if ($pages -gt 2) { $samples += ,@('mid', [int][Math]::Ceiling($pages / 2)) }
    foreach ($sample in $samples) {
        $prefix = Join-Path $WorkDir "verify-$Stem-$($sample[0])"
        Remove-Item -LiteralPath "$prefix.png" -Force -ErrorAction SilentlyContinue
        $page = [string]$sample[1]
        $r = Invoke-Tool (Get-Tool 'pdftoppm') @(
            '-singlefile', '-png', '-r', '110', '-f', $page, '-l', $page, $Pdf, $prefix)
        $raster = Get-Item -LiteralPath "$prefix.png" -ErrorAction SilentlyContinue
        if ($r.ExitCode -ne 0 -or -not $raster -or $raster.Length -eq 0) {
            Write-Log "VERIFY FAIL: $($sample[0])-page raster was not written"
            return $false
        }
    }
    Write-Log 'rasterised first/middle/last samples; inspect their display visually'
    $order = ''
    if ((Invoke-Tool $python @('-c', 'import pymupdf')).ExitCode -eq 0) {
        $r = Invoke-Tool $python @((Join-Path $PSScriptRoot 'check-pdf-text-order.py'),
            $Pdf, '--source', $srcItem.FullName)
        Write-ToolOutput $r.Output
        if ($r.ExitCode -notin @(0, 2)) {
            Write-Log 'VERIFY FAIL: check-pdf-text-order could not run'
            return $false
        }
        $order = ($r.Output | ForEach-Object { "$_" }) -join "`n"
    }
    else { Write-Log 'VERIFY FAIL: PyMuPDF missing; text extraction order is unverified'; return $false }
    if ($order -match 'check-pdf-text-order: visual') {
        if (Test-XeLaTeX) {
            Write-Log 'VERIFY FAIL: PyMuPDF extraction reverses source phrases; check ActualText and fonts'
            return $false
        }
        Write-Log 'VERIFY WARN: PyMuPDF extraction is reversed; selectable text is unverified'
    }
    elseif ($order -notmatch 'check-pdf-text-order: logical') {
        Write-Log 'VERIFY FAIL: Persian extraction order is inconclusive'
        return $false
    }
    return $true
}
