$ErrorActionPreference = 'Stop'

# Dev Smallstep step-ca. Runs the pinned image on the rootless podman-machine-default connection.
# Secrets and CA state live under dev\.secrets\stepca (ignored by git). Nothing secret is printed.

$image = 'docker.io/smallstep/step-ca:0.30.2'
$container = 'sigil-stepca'
$connection = 'podman-machine-default'
$port = 9100

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$stepDir = Join-Path $root 'dev\.secrets\stepca'
New-Item -ItemType Directory -Path $stepDir -Force | Out-Null
$stepDir = (Resolve-Path $stepDir).Path

function New-Secret {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes)
}

function Ensure-SecretFile([string]$name) {
    $path = Join-Path $stepDir $name
    if (-not (Test-Path -LiteralPath $path)) {
        Set-Content -LiteralPath $path -Value (New-Secret) -NoNewline -Encoding ascii
    }
}

function Invoke-Podman([string[]]$PodmanArgs) {
    & podman --connection $connection @PodmanArgs
    if ($LASTEXITCODE -ne 0) { throw "podman $($PodmanArgs[0]) failed with exit code $LASTEXITCODE" }
}

function Invoke-Step([string[]]$StepArgs) {
    Invoke-Podman (@('run', '--rm', '-v', "${stepDir}:/home/step", '-e', 'STEPPATH=/home/step', $image) + $StepArgs)
}

Ensure-SecretFile 'ca-password.txt'
Ensure-SecretFile 'provisioner-password.txt'

if (-not (Test-Path -LiteralPath (Join-Path $stepDir 'config\ca.json'))) {
    Invoke-Step @(
        'step', 'ca', 'init',
        '--deployment-type=standalone', '--name=Sigil Dev CA',
        '--dns=localhost', '--dns=127.0.0.1', '--address=:9000',
        '--provisioner=admin',
        '--password-file=/home/step/ca-password.txt',
        '--provisioner-password-file=/home/step/ca-password.txt',
        '--no-db'
    )
}

if (-not (Test-Path -LiteralPath (Join-Path $stepDir 'provisioner.jwk'))) {
    Invoke-Step @(
        'step', 'crypto', 'jwk', 'create',
        '/home/step/sigil-backend.pub.jwk', '/home/step/provisioner.jwk',
        '--kty=EC', '--crv=P-256', '--alg=ES256', '--use=sig',
        '--password-file=/home/step/provisioner-password.txt'
    )
    Invoke-Step @(
        'step', 'ca', 'provisioner', 'add', 'sigil-backend',
        '--type=JWK', '--public-key=/home/step/sigil-backend.pub.jwk'
    )
    $caPath = Join-Path $stepDir 'config\ca.json'
    $ca = Get-Content -LiteralPath $caPath -Raw | ConvertFrom-Json
    $provisioner = $ca.authority.provisioners | Where-Object { $_.name -eq 'sigil-backend' }
    $provisioner.claims = [pscustomobject]@{
        enableSSHCA = $false; disableRenewal = $false; allowRenewalAfterExpiry = $false
        disableSmallstepExtensions = $false
        minTLSCertDuration = '5m'; maxTLSCertDuration = '2160h'; defaultTLSCertDuration = '720h'
    }
    $ca.authority | Add-Member -NotePropertyName claims -NotePropertyValue ([pscustomobject]@{ minTLSCertDuration = '5m'; maxTLSCertDuration = '2160h'; defaultTLSCertDuration = '720h' }) -Force
    $ca | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $caPath -Encoding utf8
    Remove-Item -LiteralPath (Join-Path $stepDir 'sigil-backend.pub.jwk') -ErrorAction SilentlyContinue
}

Copy-Item -LiteralPath (Join-Path $stepDir 'certs\root_ca.crt') -Destination (Join-Path $stepDir 'root_ca.crt') -Force

$running = & podman --connection $connection ps --filter "name=^$container$" --format '{{.Names}}'
if ($running -ne $container) {
    & podman --connection $connection rm -f $container *> $null
    Invoke-Podman @(
        'run', '-d', '--name', $container, '-p', "${port}:9000",
        '-v', "${stepDir}:/home/step", $image,
        'step-ca', '/home/step/config/ca.json', '--password-file=/home/step/ca-password.txt'
    )
}

Write-Output "step-ca is running at https://localhost:$port (container $container)."
Write-Output "Root certificate: $(Join-Path $stepDir 'root_ca.crt')"
Write-Output "Provisioner: sigil-backend (encrypted key: $(Join-Path $stepDir 'provisioner.jwk'), password file: $(Join-Path $stepDir 'provisioner-password.txt'))"



