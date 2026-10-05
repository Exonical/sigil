[CmdletBinding()]
param(
    [string]$SignThumbprint
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repoRoot
try {
    $sdkVersion = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not query the .NET SDK version.'
    }
    if ($sdkVersion -ne '10.0.401') {
        throw "WiX build requires .NET SDK 10.0.401; found $sdkVersion."
    }

    $metadataJson = & cargo metadata --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not read Cargo package versions.'
    }
    $metadata = $metadataJson | ConvertFrom-Json
    $versions = @(
        $metadata.packages |
            Where-Object { $_.name -in @('sigil-cli', 'sigil-gui', 'sigil-agent') } |
            Select-Object -ExpandProperty version -Unique
    )
    if ($versions.Count -ne 1 -or $versions[0] -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
        throw 'The CLI, GUI, and agent must have the same numeric Cargo version for MSI packaging.'
    }
    $version = $versions[0]

    if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        $cargoTargetDir = Join-Path $repoRoot 'target'
    } elseif ([System.IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) {
        $cargoTargetDir = $env:CARGO_TARGET_DIR
    } else {
        $cargoTargetDir = Join-Path $repoRoot $env:CARGO_TARGET_DIR
    }
    $releaseDir = Join-Path $cargoTargetDir 'release'
    $installerDir = Join-Path $repoRoot 'target\installer'
    if (-not (Test-Path (Join-Path $repoRoot 'target'))) {
        throw 'The workspace target directory is missing.'
    }
    New-Item -ItemType Directory -Path $installerDir -Force | Out-Null

    & cargo build --release -p sigil-cli -p sigil-gui -p sigil-agent
    if ($LASTEXITCODE -ne 0) {
        throw 'The release CLI, GUI, and agent build failed.'
    }

    $cms = Join-Path $releaseDir 'cms.exe'
    $gui = Join-Path $releaseDir 'sigil-gui.exe'
    $agent = Join-Path $releaseDir 'sigil-agent.exe'
    foreach ($executable in @($cms, $gui, $agent)) {
        if (-not (Test-Path $executable)) {
            throw "Expected release executable was not produced: $executable"
        }
    }
    $help = (& $cms --help 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not inspect the release CLI help.'
    }
    if ($help -match '--direct-mock') {
        throw 'The release CLI unexpectedly includes --direct-mock.'
    }
    $mockProbe = (& $cms --direct-mock device list --json 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) {
        throw 'The release CLI unexpectedly accepted --direct-mock.'
    }
    if ($mockProbe -notmatch 'unexpected argument|unrecognized option|unexpected value') {
        throw "The release CLI rejected --direct-mock for an unexpected reason: $mockProbe"
    }
    $agentFeatures = & cargo tree --no-default-features -p sigil-agent -e features
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not inspect release agent features.'
    }
    if (($agentFeatures | Out-String) -match 'dev-grants') {
        throw 'The release agent unexpectedly includes dev-grants.'
    }

    & dotnet tool restore
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not restore the pinned local WiX tool.'
    }
    & dotnet wix extension add WixToolset.Util.wixext/5.0.2
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not acquire WixToolset.Util.wixext 5.0.2.'
    }

    $wxs = Join-Path $PSScriptRoot 'Sigil.wxs'
    $msi = Join-Path $installerDir "Sigil-$version-x64.msi"
    & dotnet wix build $wxs -arch x64 -d "Version=$version" -d "BuildDir=$releaseDir" -ext WixToolset.Util.wixext/5.0.2 -out $msi
    if ($LASTEXITCODE -ne 0) {
        throw 'WiX failed to build the MSI.'
    }

    if ($SignThumbprint) {
        $signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if (-not $signTool) {
            throw 'signtool.exe is required when -SignThumbprint is supplied.'
        }
        foreach ($file in @($cms, $gui, $agent, $msi)) {
            & $signTool.Source sign /fd SHA256 /sha1 $SignThumbprint $file
            if ($LASTEXITCODE -ne 0) {
                throw "Signing failed for $file."
            }
        }
    } else {
        Write-Host 'unsigned'
    }

    Write-Host "Created $msi ($((Get-Item $msi).Length) bytes)"
} finally {
    Pop-Location
}
