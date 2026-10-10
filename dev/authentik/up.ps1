$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$podmanConnection = 'podman-machine-default'
$secretsDirectory = Join-Path $root 'dev\.secrets'
$environmentFile = Join-Path $secretsDirectory 'authentik.env'
$usersFile = Join-Path $secretsDirectory 'users.txt'
$clientFile = Join-Path $secretsDirectory 'test-client.txt'
$caFile = Join-Path $secretsDirectory 'authentik-ca.pem'
$blueprint = Join-Path $PSScriptRoot 'sigil.yaml'
$networkName = 'sigil-authentik'
$testDatabaseContainer = 'sigil-test-pg'
$testDatabaseImage = 'docker.io/library/postgres:17'
$testDatabaseVolume = 'sigil-test-pg-data'
$databaseContainer = 'sigil-authentik-db'
$serverContainer = 'sigil-authentik-server'
$workerContainer = 'sigil-authentik-worker'
$image = 'ghcr.io/goauthentik/server:2026.8.3'
$databaseImage = 'docker.io/library/postgres:17-alpine'

if (-not (Get-Command podman -ErrorAction SilentlyContinue)) {
    throw 'Podman is required to run the local Authentik environment.'
}
New-Item -ItemType Directory -Path $secretsDirectory -Force | Out-Null

function New-RandomSecret {
    param([int]$ByteCount = 32)
    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        $generator.Dispose()
    }
}

function Read-KeyValueFile {
    param([string]$Path)
    $values = @{}
    if (Test-Path -LiteralPath $Path) {
        foreach ($line in Get-Content -LiteralPath $Path) {
            if ($line -match '^([^=]+)=(.*)$') {
                $values[$Matches[1]] = $Matches[2]
            }
        }
    }
    return $values
}

function Get-OrCreateSecret {
    param(
        [hashtable]$Values,
        [string]$Name,
        [int]$Bytes = 32
    )
    if (-not $Values.ContainsKey($Name) -or [string]::IsNullOrWhiteSpace($Values[$Name])) {
        $Values[$Name] = New-RandomSecret -ByteCount $Bytes
    }
    return $Values[$Name]
}

function Write-KeyValueFile {
    param([string]$Path, [hashtable]$Values)
    $lines = foreach ($name in ($Values.Keys | Sort-Object)) {
        "$name=$($Values[$name])"
    }
    Set-Content -LiteralPath $Path -Value $lines -Encoding ascii
}

$environment = Read-KeyValueFile $environmentFile
$users = Read-KeyValueFile $usersFile
$client = Read-KeyValueFile $clientFile
$environment.AUTHENTIK_SECRET_KEY = Get-OrCreateSecret $environment 'AUTHENTIK_SECRET_KEY' 48
$environment.AUTHENTIK_POSTGRESQL__HOST = $databaseContainer
$environment.AUTHENTIK_POSTGRESQL__USER = 'authentik'
$environment.AUTHENTIK_POSTGRESQL__NAME = 'authentik'
$environment.AUTHENTIK_POSTGRESQL__PASSWORD = Get-OrCreateSecret $environment 'AUTHENTIK_POSTGRESQL__PASSWORD'
$environment.AUTHENTIK_BOOTSTRAP_EMAIL = 'admin1@example.test'
$environment.AUTHENTIK_BOOTSTRAP_PASSWORD = Get-OrCreateSecret $environment 'AUTHENTIK_BOOTSTRAP_PASSWORD'
$environment.AUTHENTIK_BOOTSTRAP_TOKEN = Get-OrCreateSecret $environment 'AUTHENTIK_BOOTSTRAP_TOKEN'
$environment.AUTHENTIK_HOST = 'https://localhost:9443'
$environment.AUTHENTIK_HOST_BROWSER = 'https://localhost:9443'
$users.admin1 = Get-OrCreateSecret $users 'admin1' 32
$users.helpdesk1 = Get-OrCreateSecret $users 'helpdesk1' 32
$users.user1 = Get-OrCreateSecret $users 'user1' 32
$client.username = 'admin1'
$client.client_id = 'sigil-dev-test'
$client.app_password = Get-OrCreateSecret $client 'app_password' 32
$client.client_secret = Get-OrCreateSecret $client 'client_secret' 32
$environment.SIGIL_ADMIN1_PASSWORD = $users.admin1
$environment.SIGIL_HELPDESK1_PASSWORD = $users.helpdesk1
$environment.SIGIL_USER1_PASSWORD = $users.user1
$environment.SIGIL_DEV_TEST_CLIENT_ID = $client.client_id
$environment.SIGIL_DEV_TEST_APP_PASSWORD = $client.app_password
$environment.SIGIL_DEV_TEST_CLIENT_SECRET = $client.client_secret
Write-KeyValueFile $environmentFile $environment
Write-KeyValueFile $usersFile $users
Write-KeyValueFile $clientFile $client

function Invoke-Podman {
    param([string[]]$Arguments)
    & podman --connection $podmanConnection @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Podman command failed: podman $($Arguments[0])"
    }
}

function Ensure-Volume {
    param([string]$Name)
    & podman --connection $podmanConnection volume exists $Name 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-Podman @('volume', 'create', $Name)
    }
}

function Ensure-Network {
    & podman --connection $podmanConnection network exists $networkName 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-Podman @('network', 'create', $networkName)
    }
}

function Ensure-Container {
    param(
        [string]$Name,
        [string]$Image,
        [string[]]$RunArguments,
        [string[]]$Command = @()
    )
    & podman --connection $podmanConnection container exists $Name 2>$null
    if ($LASTEXITCODE -eq 0) {
        $containerState = (& podman --connection $podmanConnection inspect --format '{{.State.Status}}' $Name 2>$null).Trim()
        if ($containerState -eq 'running') {
            return
        }
        if ($containerState -eq 'exited' -or $containerState -eq 'created') {
            Invoke-Podman @('start', $Name)
            return
        }
        throw "Existing Authentik container $Name is in state $containerState."
    }
    Invoke-Podman (@('run', '--detach', '--name', $Name, '--network', $networkName, '--restart', 'unless-stopped') + $RunArguments + @($Image) + $Command)
}

Ensure-Network
Ensure-Volume $testDatabaseVolume
Ensure-Volume 'sigil-authentik-postgres'
Ensure-Volume 'sigil-authentik-media'

$testDatabaseEnvFile = Join-Path $secretsDirectory 'sigil-test-pg.env'
Set-Content -LiteralPath $testDatabaseEnvFile -Value 'POSTGRES_PASSWORD=sigil-test' -Encoding ascii
Ensure-Container $testDatabaseContainer $testDatabaseImage @(
    '--publish', '0.0.0.0:55432:5432',
    '--mount', "type=volume,source=$testDatabaseVolume,target=/var/lib/postgresql/data",
    '--env-file', $testDatabaseEnvFile
)

$testDatabaseReady = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    & podman --connection $podmanConnection exec $testDatabaseContainer pg_isready -U postgres -d postgres 2>$null
    if ($LASTEXITCODE -eq 0) {
        $testDatabaseReady = $true
        break
    }
    Start-Sleep -Seconds 2
}
if (-not $testDatabaseReady) {
    throw 'The rootless sigil-test-pg database did not become ready.'
}

$databaseEnv = @(
    'POSTGRES_USER=authentik',
    'POSTGRES_DB=authentik',
    "POSTGRES_PASSWORD=$($environment.AUTHENTIK_POSTGRESQL__PASSWORD)"
) -join "`n"
$databaseEnvFile = Join-Path $secretsDirectory 'authentik-postgres.env'
Set-Content -LiteralPath $databaseEnvFile -Value $databaseEnv -Encoding ascii
Ensure-Container $databaseContainer $databaseImage @(
    '--env-file', $databaseEnvFile,
    '--mount', 'type=volume,source=sigil-authentik-postgres,target=/var/lib/postgresql/data'
)

$databaseReady = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    & podman --connection $podmanConnection exec $databaseContainer pg_isready -U authentik -d authentik 2>$null
    if ($LASTEXITCODE -eq 0) {
        $databaseReady = $true
        break
    }
    Start-Sleep -Seconds 2
}
if (-not $databaseReady) {
    throw 'Authentik PostgreSQL did not become ready.'
}

$blueprintMount = "type=bind,source=$blueprint,target=/blueprints/sigil.yaml,ro"
$mediaMount = 'type=volume,source=sigil-authentik-media,target=/media'
Ensure-Container $serverContainer $image @(
    '--env-file', $environmentFile,
    '--publish', '9000:9000',
    '--publish', '9443:9443',
    '--mount', $mediaMount
) @('server')

$schemaReady = $false
for ($attempt = 0; $attempt -lt 90; $attempt++) {
    $migrationState = & podman --connection $podmanConnection exec $databaseContainer psql -U authentik -d authentik -tAc "SELECT to_regclass('public.authentik_tasks_workerstatus') IS NOT NULL" 2>$null
    if ($LASTEXITCODE -eq 0 -and ($migrationState -join '').Trim() -eq 't') {
        $schemaReady = $true
        break
    }
    Start-Sleep -Seconds 2
}
if (-not $schemaReady) {
    throw 'Authentik database migrations did not create the worker-status table.'
}

Ensure-Container $workerContainer $image @(
    '--env-file', $environmentFile,
    '--mount', $mediaMount,
    '--mount', $blueprintMount
) @('worker')

$discoveryUrl = 'https://localhost:9443/application/o/sigil/.well-known/openid-configuration'
$discoveryCode = 'import ssl,urllib.request;print(urllib.request.urlopen("https://localhost:9443/application/o/sigil/.well-known/openid-configuration",context=ssl._create_unverified_context(),timeout=5).read().decode())'
$providerReady = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    $discoveryOutput = & podman --connection $podmanConnection exec $serverContainer python -c $discoveryCode 2>$null
    if ($LASTEXITCODE -eq 0) {
        try {
            $discovery = ($discoveryOutput -join "`n") | ConvertFrom-Json
            if ($discovery.issuer) {
                $providerReady = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    } else {
        Start-Sleep -Seconds 2
    }
}
if (-not $providerReady) {
    throw 'The Sigil OIDC provider blueprint did not become available inside the Authentik server.'
}

$certificateCode = 'import base64,socket,ssl;connection=ssl._create_unverified_context().wrap_socket(socket.create_connection(("localhost",9443),timeout=5),server_hostname="localhost");print(base64.b64encode(connection.getpeercert(binary_form=True)).decode())'
$certificateOutput = & podman --connection $podmanConnection exec $serverContainer python -c $certificateCode 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($certificateOutput -join ''))) {
    throw 'Could not export the Authentik HTTPS certificate.'
}
$base64 = ($certificateOutput -join '').Trim()
$pem = "-----BEGIN CERTIFICATE-----`n" +
    ([regex]::Replace($base64, '.{1,64}', '$&' + "`n")) +
    "-----END CERTIFICATE-----`n"
Set-Content -LiteralPath $caFile -Value $pem -Encoding ascii

Write-Output "Authentik $($image.Split(':')[-1]) server, worker and PostgreSQL are running."
Write-Output "Container-local OIDC discovery issuer: $($discovery.issuer)"
Write-Output "Container-local OIDC discovery URL: $discoveryUrl"
