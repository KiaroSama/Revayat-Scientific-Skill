#Requires -Version 5.1
# Forward arguments unchanged to the shared installer; no profile or fixed CWD.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
foreach ($name in @('python', 'python3', 'py')) {
    $tool = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($tool) {
        $prefix = @()
        if ($name -eq 'py') { $prefix = @('-3') }
        & $tool.Source @prefix (Join-Path $PSScriptRoot 'install.py') @args
        exit $LASTEXITCODE
    }
}
[Console]::Error.WriteLine('install: Python 3.10+ is required')
exit 1
