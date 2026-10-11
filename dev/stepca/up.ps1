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
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
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

# Revocation needs an authority database. The badger DB lives on the persistent volume, and the root and intermediate are unchanged.
$caPath = Join-Path $stepDir 'config\ca.json'
$caConfig = Get-Content -LiteralPath $caPath -Raw | ConvertFrom-Json
if (-not $caConfig.db) {
    $caConfig | Add-Member -NotePropertyName db -NotePropertyValue ([pscustomobject]@{ type = 'badgerv2'; dataSource = '/home/step/db' }) -Force
    $caConfig | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $caPath -Encoding utf8
}

# SCEP (RFC 8894). The decrypter is an RSA certificate signed by the intermediate. step-ca uses its key to decrypt PKCSReq
# and to sign CertRep. The RA certificate is self-signed and is used only by the backend. The challenge is a static dev
# value; part 2 replaces it with a webhook.
Ensure-SecretFile 'scep-challenge.txt'
if (-not (Test-Path -LiteralPath (Join-Path $stepDir 'scep-decrypter.crt'))) {
    Invoke-Step @(
        'step', 'certificate', 'create', 'Sigil Dev SCEP Decrypter',
        '/home/step/scep-decrypter.crt', '/home/step/scep-decrypter.key',
        '--ca=/home/step/certs/intermediate_ca.crt', '--ca-key=/home/step/secrets/intermediate_ca_key',
        '--ca-password-file=/home/step/ca-password.txt',
        '--kty=RSA', '--size=3072', '--profile=leaf', '--not-after=17520h',
        '--no-password', '--insecure', '--force'
    )
}
if (-not (Test-Path -LiteralPath (Join-Path $stepDir 'scep-ra.crt'))) {
    Invoke-Step @(
        'step', 'certificate', 'create', 'Sigil Dev SCEP RA',
        '/home/step/scep-ra.crt', '/home/step/scep-ra.key',
        '--profile=self-signed', '--subtle', '--kty=RSA', '--size=3072', '--not-after=17520h',
        '--no-password', '--insecure'
    )
}

$scepProvisioner = [pscustomobject]@{
    type                           = 'SCEP'
    name                           = 'sigil-scep'
    challenge                      = [IO.File]::ReadAllText((Join-Path $stepDir 'scep-challenge.txt')).Trim()
    includeRoot                    = $false
    minimumPublicKeyLength         = 2048
    encryptionAlgorithmIdentifier  = 2
    decrypterCertificate           = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes([IO.File]::ReadAllText((Join-Path $stepDir 'scep-decrypter.crt'))))
    decrypterKeyPEM                = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes([IO.File]::ReadAllText((Join-Path $stepDir 'scep-decrypter.key'))))
    claims                         = [pscustomobject]@{ minTLSCertDuration = '5m'; maxTLSCertDuration = '2160h'; defaultTLSCertDuration = '720h' }
}
$caConfig = Get-Content -LiteralPath $caPath -Raw | ConvertFrom-Json
$existingScep = @($caConfig.authority.provisioners | Where-Object { $_.name -eq 'sigil-scep' })
$caChanged = $false
if ($existingScep.Count -eq 0 -or ($existingScep[0] | ConvertTo-Json -Depth 10 -Compress) -ne ($scepProvisioner | ConvertTo-Json -Depth 10 -Compress)) {
    $others = @($caConfig.authority.provisioners | Where-Object { $_.name -ne 'sigil-scep' })
    $caConfig.authority.provisioners = @($others) + $scepProvisioner
    [IO.File]::WriteAllText($caPath, ($caConfig | ConvertTo-Json -Depth 30), (New-Object Text.UTF8Encoding $false))
    $caChanged = $true
}

$running = & podman --connection $connection ps --filter "name=^$container$" --format '{{.Names}}'
if ($running -ne $container -or $caChanged) {
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



