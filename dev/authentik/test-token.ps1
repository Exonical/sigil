$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Run this script with PowerShell 7 or later.'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$podmanConnection = 'podman-machine-default'
$clientFile = Join-Path $root 'dev\.secrets\test-client.txt'
if (-not (Test-Path -LiteralPath $clientFile)) {
    throw 'Run dev/authentik/up.ps1 first to generate the development client credentials.'
}

$clientValues = @{}
foreach ($line in Get-Content -LiteralPath $clientFile) {
    if ($line -match '^([^=]+)=(.*)$') {
        $clientValues[$Matches[1]] = $Matches[2]
    }
}
if (-not $clientValues.username -or -not $clientValues.client_id -or -not $clientValues.app_password) {
    throw 'Development client credentials are incomplete.'
}

$usernamePassword = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes("$($clientValues.username):$($clientValues.app_password)")
)
$clientCredentials = @{
    grant_type    = 'client_credentials'
    client_id     = $clientValues.client_id
    client_secret = $usernamePassword
    scope         = 'openid profile email offline_access'
}
$claims = $null
try {
    $serviceToken = Invoke-RestMethod `
        -Method Post `
        -Uri 'https://localhost:9443/application/o/token/' `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body $clientCredentials `
        -SkipCertificateCheck
    $exchangeRequest = @{
        grant_type         = 'urn:ietf:params:oauth:grant-type:token-exchange'
        client_id          = $clientValues.client_id
        client_secret      = $clientValues.client_secret
        subject_token      = $serviceToken.access_token
        subject_token_type = 'urn:ietf:params:oauth:token-type:access_token'
        audience           = 'sigil'
        scope              = 'openid profile email offline_access'
    }
    $tokenResponse = Invoke-RestMethod `
        -Method Post `
        -Uri 'https://localhost:9443/application/o/token/' `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body $exchangeRequest `
        -SkipCertificateCheck
    $parts = $tokenResponse.access_token.Split('.')
    if ($parts.Length -ne 3) {
        throw 'Authentik returned an access token that is not a JWT.'
    }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    $claims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
} catch {
    $tokenCode = 'import base64,json,os,ssl,urllib.parse,urllib.request;ctx=ssl._create_unverified_context();url="https://localhost:9443/application/o/token/";secret=base64.b64encode(("admin1:"+os.environ["SIGIL_DEV_TEST_APP_PASSWORD"]).encode()).decode();post=lambda values:json.loads(urllib.request.urlopen(urllib.request.Request(url,data=urllib.parse.urlencode(values).encode()),context=ctx,timeout=15).read());source=post({"grant_type":"client_credentials","client_id":"sigil-dev-test","client_secret":secret,"scope":"openid profile email offline_access"});target=post({"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","client_id":"sigil-dev-test","client_secret":os.environ["SIGIL_DEV_TEST_CLIENT_SECRET"],"subject_token":source["access_token"],"subject_token_type":"urn:ietf:params:oauth:token-type:access_token","audience":"sigil","scope":"openid profile email offline_access"});payload=target["access_token"].split(".")[1];payload += "="*((4-len(payload)%4)%4);claims=json.loads(base64.urlsafe_b64decode(payload));print(json.dumps({k:claims.get(k) for k in ("iss","aud","groups")}))'
    $claimOutput = & podman --connection $podmanConnection exec sigil-authentik-server python -c $tokenCode 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($claimOutput -join ''))) {
        throw 'Could not mint a development OIDC token.'
    }
    $claims = ($claimOutput -join "`n") | ConvertFrom-Json
}
[pscustomobject]@{
    iss    = $claims.iss
    aud    = $claims.aud
    groups = $claims.groups
} | ConvertTo-Json -Depth 5
Write-Output 'signature=[redacted]'
