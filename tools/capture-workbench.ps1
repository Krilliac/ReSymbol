[CmdletBinding()]
param(
    [string]$Binary,
    [string]$OutputDirectory,
    [ValidateRange(640, 3840)]
    [int]$CaptureWidth = 1440,
    [ValidateRange(480, 2160)]
    [int]$CaptureHeight = 900,
    [ValidateSet('overview', 'functions', 'functions-focused', 'graph', 'address-space', 'disassembly', 'debugger-sandbox')]
    [string[]]$CaptureTabs = @('overview', 'functions', 'graph', 'address-space', 'disassembly', 'debugger-sandbox'),
    [switch]$SkipBuild,
    [ValidateRange(10, 600)]
    [int]$CaptureTimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$maxCapturedProcessLogChars = 16 * 1024
$captureTerminationTimeoutMilliseconds = 5 * 1000

function Write-BoundedCaptureProcessLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [AllowEmptyString()]
        [string]$Value
    )

    if (-not $Value) {
        return
    }
    if ($Value.Length -gt $maxCapturedProcessLogChars) {
        $Value = $Value.Substring(0, $maxCapturedProcessLogChars) + "`n[output truncated]"
    }
    Write-Host "$Label`n$Value"
}

function Resolve-CargoTargetDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        return [IO.Path]::GetFullPath((Join-Path $RepoRoot 'target'))
    }

    $candidate = $env:CARGO_TARGET_DIR
    if (-not [IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $RepoRoot $candidate
    }
    return [IO.Path]::GetFullPath($candidate)
}

if (-not ('ReSymbol.WorkbenchCaptureDpi' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace ReSymbol {
    public static class WorkbenchCaptureDpi {
        [DllImport("user32.dll")]
        public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr value);

        [DllImport("user32.dll")]
        public static extern uint GetDpiForSystem();
    }
}
'@
}

# PowerShell is normally DPI-virtualized to 96 DPI. Query under the same per-monitor-aware-v2
# context used by the native workbench, then keep both framebuffer pixels and egui layout fixed.
$priorDpiContext = [ReSymbol.WorkbenchCaptureDpi]::SetThreadDpiAwarenessContext([IntPtr](-4))
try {
    $desktopDpi = [ReSymbol.WorkbenchCaptureDpi]::GetDpiForSystem()
}
finally {
    [void][ReSymbol.WorkbenchCaptureDpi]::SetThreadDpiAwarenessContext($priorDpiContext)
}
if ($desktopDpi -lt 96 -or $desktopDpi -gt 768) {
    throw "Capture desktop reported unsupported DPI $desktopDpi"
}
$dpiScale = [double]$desktopDpi / 96.0
$viewportWidthPoints = [double]$captureWidth / $dpiScale
$viewportHeightPoints = [double]$captureHeight / $dpiScale
$uiZoom = 1.0 / $dpiScale
$invariant = [Globalization.CultureInfo]::InvariantCulture
$viewportPoints = '{0},{1}' -f @(
    $viewportWidthPoints.ToString('R', $invariant),
    $viewportHeightPoints.ToString('R', $invariant)
)
$uiZoomText = $uiZoom.ToString('R', $invariant)

$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoTargetDirectory = Resolve-CargoTargetDirectory -RepoRoot $repoRoot
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

    $executable = Join-Path $cargoTargetDirectory 'debug\resymbol-workbench.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Screenshot executable does not exist: $executable"
    }

    # The application owns a fixed native capture viewport. Exact output validation below is the
    # authoritative framebuffer gate; captured pixels are never resized or resampled.
    Add-Type -AssemblyName System.Drawing
    $captures = [Collections.Generic.List[object]]::new()
    $manifestPath = Join-Path $OutputDirectory 'capture-manifest.json'
    Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue

    $priorEframeScreenshot = $env:EFRAME_SCREENSHOT_TO
    $priorScreenshot = $env:RESYMBOL_WORKBENCH_SCREENSHOT_TO
    $priorTab = $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB
    $priorZoom = $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM
    $priorViewport = $env:RESYMBOL_WORKBENCH_SCREENSHOT_VIEWPORT_POINTS
    try {
        # ReSymbol owns the delayed in-app capture. Keep eframe's private second-pass hook disabled;
        # it fires before this application's panels have settled on some Windows GL drivers.
        $env:EFRAME_SCREENSHOT_TO = $null
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM = $uiZoomText
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_VIEWPORT_POINTS = $viewportPoints
        foreach ($tab in $captureTabs) {
            $destination = Join-Path $OutputDirectory "workbench-$tab.png"
            $statePath = "$destination.state.ron"
            Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
            $env:RESYMBOL_WORKBENCH_SCREENSHOT_TO = $destination
            $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB = $tab

            $quotedBinary = '"{0}"' -f $Binary
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $executable
            $startInfo.Arguments = $quotedBinary
            $startInfo.WorkingDirectory = $repoRoot
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $startInfo.CreateNoWindow = $false
            # Keep the native window visible while the OpenGL framebuffer is sampled. A hidden or
            # minimized WGL surface can return partially cleared frames on Windows, even though the
            # application has completed all egui passes. The capture closes itself immediately.
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            if (-not $process.Start()) {
                $process.Dispose()
                throw "Screenshot capture for '$tab' could not start"
            }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            try {
                $timedOut = -not $process.WaitForExit($CaptureTimeoutSeconds * 1000)
                if ($timedOut) {
                    try {
                        $process.Kill()
                    }
                    catch {
                        # The process can exit between the timed wait and Kill. The bounded wait
                        # below is authoritative and also prevents a failed Kill from hanging CI.
                    }
                    if (-not $process.WaitForExit($captureTerminationTimeoutMilliseconds)) {
                        throw "Screenshot capture for '$tab' exceeded ${CaptureTimeoutSeconds}s and could not be terminated within $($captureTerminationTimeoutMilliseconds / 1000)s"
                    }
                }
                $capturedStdout = $stdoutTask.GetAwaiter().GetResult()
                $capturedStderr = $stderrTask.GetAwaiter().GetResult()
                if ($timedOut) {
                    Write-BoundedCaptureProcessLog "Screenshot process stdout for '$tab':" $capturedStdout
                    Write-BoundedCaptureProcessLog "Screenshot process stderr for '$tab':" $capturedStderr
                    throw "Screenshot capture for '$tab' exceeded ${CaptureTimeoutSeconds}s"
                }
                $exitCode = $process.ExitCode
                if ($exitCode -ne 0) {
                    Write-BoundedCaptureProcessLog "Screenshot process stdout for '$tab':" $capturedStdout
                    Write-BoundedCaptureProcessLog "Screenshot process stderr for '$tab':" $capturedStderr
                    throw "Screenshot capture for '$tab' failed with exit code $exitCode"
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
                    throw "Screenshot '$tab' is $($image.Width)x$($image.Height), expected ${captureWidth}x${captureHeight}."
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
        foreach ($tab in $captureTabs) {
            $statePath = Join-Path $OutputDirectory "workbench-$tab.png.state.ron"
            Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
        }
        $env:EFRAME_SCREENSHOT_TO = $priorEframeScreenshot
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_TO = $priorScreenshot
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_TAB = $priorTab
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_ZOOM = $priorZoom
        $env:RESYMBOL_WORKBENCH_SCREENSHOT_VIEWPORT_POINTS = $priorViewport
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
            desktop_dpi = $desktopDpi
            width_points = $viewportWidthPoints
            height_points = $viewportHeightPoints
            ui_zoom = $uiZoom
            effective_pixels_per_point = 1
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
