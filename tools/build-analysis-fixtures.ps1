[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$CheckDeterminism,
    [switch]$VerifyCheckedIn,
    [switch]$Install
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$fixtureRoot = Join-Path $repoRoot "fixtures\pe-x64-msvc"
$source = Join-Path $fixtureRoot "src\milestone2.cpp"
$oraclePath = Join-Path $fixtureRoot "expected.json"
$oracle = Get-Content -LiteralPath $oraclePath -Raw | ConvertFrom-Json

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot "target\fixtures\pe-x64-msvc"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

foreach ($tool in @("cl.exe", "link.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is unavailable. Run from a VS 2022 x64 developer environment."
    }
}

function Normalize-Version {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }
    return $Value.Trim().TrimEnd([char]'\')
}

function Assert-ExactValue {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowEmptyString()][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    if ($Actual -cne $Expected) {
        throw "$Label is '$Actual'; expected '$Expected' from fixtures\pe-x64-msvc\expected.json"
    }
}

function Assert-RecordedToolchain {
    $clPath = (Get-Command "cl.exe" -CommandType Application).Source
    $linkPath = (Get-Command "link.exe" -CommandType Application).Source
    $clVersion = (Get-Item -LiteralPath $clPath).VersionInfo.FileVersion
    $linkVersion = (Get-Item -LiteralPath $linkPath).VersionInfo.FileVersion

    Assert-ExactValue -Label "target architecture" -Actual $env:VSCMD_ARG_TGT_ARCH -Expected "x64"
    Assert-ExactValue -Label "MSVC toolset" -Actual (Normalize-Version $env:VCToolsVersion) -Expected $oracle.toolchain.toolset
    Assert-ExactValue -Label "Windows SDK" -Actual (Normalize-Version $env:WindowsSDKVersion) -Expected $oracle.toolchain.windows_sdk
    Assert-ExactValue -Label "cl.exe file version" -Actual $clVersion -Expected $oracle.toolchain.cl_file_version
    Assert-ExactValue -Label "link.exe file version" -Actual $linkVersion -Expected $oracle.toolchain.link_file_version
}

Assert-RecordedToolchain

$fixtureVariants = @(
    [pscustomobject]@{
        Name = "symbolized"
        WithSymbols = $true
        OptimizationArguments = @("/O2", "/Ob1", "/Oi")
    },
    [pscustomobject]@{
        Name = "stripped"
        WithSymbols = $false
        OptimizationArguments = @("/O2", "/Ob1", "/Oi")
    },
    [pscustomobject]@{
        Name = "unoptimized-symbolized"
        WithSymbols = $true
        OptimizationArguments = @("/Od", "/Ob0", "/Oi-")
    },
    [pscustomobject]@{
        Name = "unoptimized-stripped"
        WithSymbols = $false
        OptimizationArguments = @("/Od", "/Ob0", "/Oi-")
    }
)

$executableRelativePaths = @(
    $fixtureVariants | ForEach-Object {
        Join-Path $_.Name "milestone2-$($_.Name).exe"
    }
)

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Build-Variant {
    param(
        [Parameter(Mandatory = $true)][string]$PassDirectory,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$WithSymbols,
        [Parameter(Mandatory = $true)][string[]]$OptimizationArguments
    )

    $variantDirectory = Join-Path $PassDirectory $Name
    New-Item -ItemType Directory -Path $variantDirectory -Force | Out-Null
    $object = Join-Path $variantDirectory "milestone2.obj"
    $executable = Join-Path $variantDirectory "milestone2-$Name.exe"
    $pdb = Join-Path $variantDirectory "milestone2-$Name.pdb"
    $importLibrary = [System.IO.Path]::ChangeExtension($executable, ".lib")
    $exportsObject = [System.IO.Path]::ChangeExtension($executable, ".exp")

    foreach ($generatedFile in @(
        $object,
        $executable,
        $pdb,
        $importLibrary,
        $exportsObject
    )) {
        if (Test-Path -LiteralPath $generatedFile) {
            Remove-Item -LiteralPath $generatedFile -Force
        }
    }

    $compileArguments = @(
        "/nologo",
        "/c",
        "/std:c++17"
    ) + $OptimizationArguments + @(
        "/Gy",
        "/Gw",
        "/GR",
        "/MD",
        "/GS-",
        "/Brepro",
        "/experimental:deterministic",
        "/W4",
        "/WX",
        "/Fo$object",
        "/pathmap:$repoRoot=R:\resymbol",
        $source
    )
    if ($WithSymbols) {
        $compileArguments = @("/Z7") + $compileArguments
    }
    Invoke-Checked -FilePath "cl.exe" -Arguments $compileArguments

    $linkArguments = @(
        "/nologo",
        "/machine:x64",
        "/subsystem:console",
        "/entry:fixture_entry",
        "/dynamicbase",
        "/nxcompat",
        "/incremental:no",
        "/opt:ref",
        "/opt:noicf",
        "/Brepro",
        "/out:$([System.IO.Path]::GetFileName($executable))",
        $([System.IO.Path]::GetFileName($object)),
        "ucrt.lib",
        "kernel32.lib"
    )
    if ($WithSymbols) {
        $linkArguments = @(
            "/debug:full",
            "/pdb:$([System.IO.Path]::GetFileName($pdb))",
            "/pdbaltpath:%_PDB%"
        ) + $linkArguments
    } else {
        $linkArguments = @("/debug:none") + $linkArguments
    }
    Push-Location $variantDirectory
    try {
        Invoke-Checked -FilePath "link.exe" -Arguments $linkArguments
    } finally {
        Pop-Location
    }
}

function Build-Pass {
    param([Parameter(Mandatory = $true)][string]$PassDirectory)

    foreach ($variant in $fixtureVariants) {
        Build-Variant `
            -PassDirectory $PassDirectory `
            -Name $variant.Name `
            -WithSymbols $variant.WithSymbols `
            -OptimizationArguments $variant.OptimizationArguments
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$buildPass = Join-Path $OutputDirectory "build"
Build-Pass -PassDirectory $buildPass

if ($CheckDeterminism) {
    $snapshot = Join-Path $OutputDirectory "snapshot"
    foreach ($relativePath in $executableRelativePaths) {
        $snapshotPath = Join-Path $snapshot $relativePath
        New-Item -ItemType Directory -Path (Split-Path -Parent $snapshotPath) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $buildPass $relativePath) -Destination $snapshotPath -Force
    }
    Build-Pass -PassDirectory $buildPass
    foreach ($relativePath in $executableRelativePaths) {
        $first = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $snapshot $relativePath)).Hash
        $second = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $buildPass $relativePath)).Hash
        if ($first -ne $second) {
            throw "fixture output is not deterministic: $relativePath"
        }
    }
}

if ($VerifyCheckedIn) {
    $artifactDirectory = Join-Path $fixtureRoot "artifacts"
    $expectedArtifactNames = @(
        $executableRelativePaths |
            ForEach-Object { [System.IO.Path]::GetFileName($_) } |
            Sort-Object
    )
    $checkedInArtifactNames = @(
        Get-ChildItem -LiteralPath $artifactDirectory -Filter "*.exe" -File |
            ForEach-Object { $_.Name } |
            Sort-Object
    )
    $artifactDifference = Compare-Object `
        -ReferenceObject $expectedArtifactNames `
        -DifferenceObject $checkedInArtifactNames
    if ($artifactDifference) {
        $inventory = $artifactDifference |
            ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }
        throw "checked-in fixture executable inventory differs from the build matrix: $($inventory -join ', ')"
    }
    foreach ($relativePath in $executableRelativePaths) {
        $artifactName = [System.IO.Path]::GetFileName($relativePath)
        $builtHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $buildPass $relativePath)).Hash
        $checkedInHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $artifactDirectory $artifactName)).Hash
        if ($builtHash -ne $checkedInHash) {
            throw "generated fixture does not match the checked-in artifact: $artifactName"
        }
    }
}

if ($Install) {
    $artifactDirectory = Join-Path $fixtureRoot "artifacts"
    New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
    foreach ($relativePath in $executableRelativePaths) {
        Copy-Item -LiteralPath (Join-Path $buildPass $relativePath) -Destination $artifactDirectory -Force
    }
}

foreach ($relativePath in $executableRelativePaths) {
    $generatedPath = Join-Path $buildPass $relativePath
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
    Write-Output "$hash  $relativePath"
}
