[CmdletBinding()]
param(
    [string]$Binary,
    [string]$OutputDirectory,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Binary) {
    $Binary = Join-Path $repoRoot 'fixtures\pe-x64-msvc\artifacts\milestone2-symbolized.exe'
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot 'docs\images'
}

$Binary = [IO.Path]::GetFullPath($Binary)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "Screenshot fixture does not exist: $Binary"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        & cargo build --locked -p resymbol-workbench --features screenshot --bin resymbol-workbench
        if ($LASTEXITCODE -ne 0) {
            throw "Screenshot workbench build failed with exit code $LASTEXITCODE"
        }
    }

    $executable = Join-Path $repoRoot 'target\debug\resymbol-workbench.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Screenshot executable does not exist: $executable"
    }

    $priorScreenshot = $env:EFRAME_SCREENSHOT_TO
    $priorTab = $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB
    $priorZoom = $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM
    try {
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM = '1'
        foreach ($tab in @('overview', 'functions', 'graph', 'address-space')) {
            $destination = Join-Path $OutputDirectory "workbench-$tab.png"
            Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            $env:EFRAME_SCREENSHOT_TO = $destination
            $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB = $tab

            & $executable $Binary
            if ($LASTEXITCODE -ne 0) {
                throw "Screenshot capture for '$tab' failed with exit code $LASTEXITCODE"
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
                throw "Screenshot capture for '$tab' did not create $destination"
            }

            Add-Type -AssemblyName System.Drawing
            $image = [Drawing.Image]::FromFile($destination)
            try {
                if ($image.Width -ne 1440 -or $image.Height -ne 900) {
                    throw "Screenshot '$tab' is $($image.Width)x$($image.Height), expected 1440x900"
                }
            }
            finally {
                $image.Dispose()
            }
            Write-Host "Captured $destination"
        }
    }
    finally {
        $env:EFRAME_SCREENSHOT_TO = $priorScreenshot
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB = $priorTab
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM = $priorZoom
    }
}
finally {
    Pop-Location
}
