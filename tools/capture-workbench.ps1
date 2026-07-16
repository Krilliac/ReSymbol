[CmdletBinding()]
param(
    [string]$Binary,
    [string]$OutputDirectory,
    [switch]$SkipBuild,
    [ValidateRange(10, 600)]
    [int]$CaptureTimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$captureWidth = 1440
$captureHeight = 900
$captureTabs = @('overview', 'functions', 'graph', 'address-space')

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

    # Eframe/winit is DPI-aware. A non-100% desktop scale changes the physical framebuffer, so the
    # exact dimension check below is the authoritative DPI gate instead of silently resampling.
    Add-Type -AssemblyName System.Drawing
    $captures = [Collections.Generic.List[object]]::new()
    $manifestPath = Join-Path $OutputDirectory 'capture-manifest.json'
    Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue

    $priorScreenshot = $env:EFRAME_SCREENSHOT_TO
    $priorTab = $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB
    $priorZoom = $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM
    try {
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM = '1'
        foreach ($tab in $captureTabs) {
            $destination = Join-Path $OutputDirectory "workbench-$tab.png"
            Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            $env:EFRAME_SCREENSHOT_TO = $destination
            $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB = $tab

            $quotedBinary = '"{0}"' -f $Binary
            $startParameters = @{
                FilePath = $executable
                ArgumentList = $quotedBinary
                WorkingDirectory = $repoRoot
                PassThru = $true
            }
            $process = Start-Process @startParameters
            try {
                if (-not $process.WaitForExit($CaptureTimeoutSeconds * 1000)) {
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    throw "Screenshot capture for '$tab' exceeded ${CaptureTimeoutSeconds}s"
                }
                if ($process.ExitCode -ne 0) {
                    throw "Screenshot capture for '$tab' failed with exit code $($process.ExitCode)"
                }
            }
            finally {
                $process.Dispose()
            }
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
                throw "Screenshot capture for '$tab' did not create $destination"
            }

            $image = [Drawing.Image]::FromFile($destination)
            try {
                if ($image.RawFormat.Guid -ne [Drawing.Imaging.ImageFormat]::Png.Guid) {
                    throw "Screenshot '$tab' is not a PNG image"
                }
                if ($image.Width -ne $captureWidth -or $image.Height -ne $captureHeight) {
                    throw "Screenshot '$tab' is $($image.Width)x$($image.Height), expected ${captureWidth}x${captureHeight}. Ensure the capture desktop uses 100% DPI scaling."
                }

                $file = Get-Item -LiteralPath $destination
                $captures.Add([ordered]@{
                    file = $file.Name
                    view = $tab
                    width = $image.Width
                    height = $image.Height
                    bytes = $file.Length
                    sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
                })
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

    if ($captures.Count -ne $captureTabs.Count) {
        throw "Captured $($captures.Count) views, expected $($captureTabs.Count)"
    }

    $manifest = [ordered]@{
        schema_version = 1
        fixture = [ordered]@{
            file = [IO.Path]::GetFileName($Binary)
            sha256 = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        viewport = [ordered]@{
            width = $captureWidth
            height = $captureHeight
            ui_zoom = 1
        }
        captures = $captures
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText(
        $manifestPath,
        "$manifestJson`n",
        [Text.UTF8Encoding]::new($false)
    )
    Write-Host "Wrote capture manifest $manifestPath"
}
finally {
    Pop-Location
}
