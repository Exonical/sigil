$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$backendDirectory = Join-Path $root 'backend'
$secretsRoot = Join-Path $root 'dev\.secrets'
$secretsDirectory = Join-Path $secretsRoot 'backend'
$configPath = Join-Path $secretsDirectory 'backend.toml'
$machineDNS = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName.TrimEnd('.').ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($machineDNS)) {
    throw 'Could not determine the machine FQDN.'
}
New-Item -ItemType Directory -Path $secretsDirectory -Force | Out-Null

Push-Location $backendDirectory
try {
    & go run ./cmd/sigil-devcerts --out-dir $secretsDirectory --dns $machineDNS
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create the local backend TLS identity.'
    }

    $grantPrivate = Join-Path $secretsDirectory 'grant-signing-key.pem'
    $grantPublic = Join-Path $secretsDirectory 'grant-signing-public.pem'
    if (-not (Test-Path $grantPrivate) -and -not (Test-Path $grantPublic)) {
        & go run ./cmd/sigil-server keygen --out $grantPrivate --public-out $grantPublic
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not create the backend grant signing key.'
        }
    } elseif (-not (Test-Path $grantPrivate) -or -not (Test-Path $grantPublic)) {
        throw 'Only one backend grant signing key file exists; inspect it before retrying.'
    }

    $kekPath = Join-Path $secretsDirectory 'escrow-kek.key'
    if (-not (Test-Path $kekPath)) {
        & go run ./cmd/sigil-server escrow keygen --out $kekPath
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not create the escrow KEK.'
        }
    }
} finally {
    Pop-Location
}

$databaseURL = 'postgres://postgres:sigil-test@localhost:55432/postgres?sslmode=disable'
$config = @"
listen_grpc = "localhost:50443"
database_url = "$databaseURL"

[tls]
cert_file = "backend-server.crt"
key_file = "backend-server.key"
client_ca_file = "../station-client-ca.pem"

[oidc]
issuer = "https://localhost:9443/application/o/sigil/"
ca_file = "../authentik-ca.pem"
audience = "sigil"
groups_claim = "groups"

[oidc.role_groups]
admin = ["sigil-admins"]
helpdesk = ["sigil-helpdesk"]

[grants]
key_id = "sigil-dev-v1"
signing_key_file = "grant-signing-key.pem"
lifetime_seconds = 120

[policy]
self_service_operations = ["PIV_MANAGED_INITIALIZE", "PIV_CHANGE_PUK", "PIV_CHANGE_MANAGEMENT_KEY", "PIV_GENERATE_KEY", "PIV_IMPORT_CERTIFICATE"]

[ca.dev-step]
type = "step"
url = "https://localhost:9100"
root_file = "../stepca/root_ca.crt"
provisioner = "sigil-backend"
provisioner_key_file = "../stepca/provisioner.jwk"
provisioner_password_file = "../stepca/provisioner-password.txt"

[[profiles]]
name = "piv-authentication"
display_name = "PIV Authentication"
slot = "9a"
algorithm = "p256"
pin_policy = "once"
touch_policy = "never"
subject = "CN={username}"
email_san = true
validity_hours = 720
ca = "dev-step"
roles = ["admin", "helpdesk", "user"]

[escrow]
kek_id = "sigil-dev-v1"
kek_file = "escrow-kek.key"
"@
Set-Content -LiteralPath $configPath -Value $config -Encoding ascii

if (-not (Test-Path (Join-Path $secretsRoot 'authentik-ca.pem'))) {
    throw 'Run dev/authentik/up.ps1 first; the Authentik CA bundle is missing.'
}

Push-Location $backendDirectory
try {
    & go run ./cmd/sigil-server migrate --config $configPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Backend database migrations failed.'
    }

    $stationCertificate = Join-Path $secretsRoot 'station-client-ca.pem'
    if (-not (Test-Path $stationCertificate)) {
        Write-Warning 'The LocalMachine station certificate is not present.'
        Write-Output 'Run installer/dev/new-station-cert.ps1 from an elevated PowerShell session, then rerun this script.'
        Write-Output "Backend config: $configPath"
        Write-Output "After station registration, start with: go run ./cmd/sigil-server serve --config `"$configPath`""
        return
    }

    & go run ./cmd/sigil-server station add --config $configPath --id $machineDNS --dns $machineDNS --mode station --name $env:COMPUTERNAME
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not register this machine as a station.'
    }
} finally {
    Pop-Location
}

Write-Output "Backend database is migrated and station $machineDNS is registered."
Write-Output "Start with: go run ./cmd/sigil-server serve --config `"$configPath`""
