$ErrorActionPreference = 'Stop'

$principal = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
)
$isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$secretsRoot = Join-Path $root 'dev\.secrets'
$backendDirectory = Join-Path $secretsRoot 'backend'
$agentDirectory = Join-Path $secretsRoot 'agent'
$configPath = Join-Path $agentDirectory 'agent.toml'

foreach ($source in @(
    (Join-Path $backendDirectory 'backend-server.crt'),
    (Join-Path $backendDirectory 'grant-signing-public.pem')
)) {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing backend public configuration file: $source. Run dev/backend/setup.ps1 first."
    }
}

New-Item -ItemType Directory -Path $agentDirectory -Force | Out-Null
if ($isAdministrator) {
    $directoryAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetSecurityDescriptorSddlForm(
        'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)'
    )
    Set-Acl -LiteralPath $agentDirectory -AclObject $directoryAcl
}

Copy-Item -LiteralPath (Join-Path $backendDirectory 'backend-server.crt') `
    -Destination (Join-Path $agentDirectory 'backend-server.crt') -Force
Copy-Item -LiteralPath (Join-Path $backendDirectory 'grant-signing-public.pem') `
    -Destination (Join-Path $agentDirectory 'grant-signing-public.pem') -Force
Copy-Item -LiteralPath (Join-Path $root 'dev\.secrets\stepca\root_ca.crt') -Destination (Join-Path $agentDirectory 'issuing-ca.crt') -Force

$config = @'
grant_keys = { "sigil-dev-v1" = "grant-signing-public.pem" }
data_dir = "data"
issuing_ca_files = ["issuing-ca.crt"]

[backend]
url = "https://localhost:50443"
server_ca_file = "backend-server.crt"

[backend.client_certificate]
store = "LocalMachine"
'@
Set-Content -LiteralPath $configPath -Value $config -Encoding ascii

if ($isAdministrator) {
    $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)')
    foreach ($path in @(
        $configPath,
        (Join-Path $agentDirectory 'backend-server.crt'),
        (Join-Path $agentDirectory 'grant-signing-public.pem'),
        (Join-Path $agentDirectory 'issuing-ca.crt')
    )) {
        Set-Acl -LiteralPath $path -AclObject $fileAcl
    }
}

Write-Output "Wrote agent configuration: $configPath"
if (-not $isAdministrator) {
    Write-Warning 'The development config directory was not protected. Run this script elevated before using the config without --dev-insecure-config.'
} else {
    Write-Output 'The agent config directory uses the protected Sigil ACL.'
}
