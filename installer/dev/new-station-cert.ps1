$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run installer/dev/new-station-cert.ps1 from an elevated PowerShell session.'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$secretsDirectory = Join-Path $root 'dev\.secrets'
$publicCertificatePath = Join-Path $secretsDirectory 'station-client-ca.pem'
$dnsName = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName.TrimEnd('.').ToLowerInvariant()
if ([string]::IsNullOrWhiteSpace($dnsName)) {
    throw 'Could not determine the machine FQDN.'
}

New-Item -ItemType Directory -Path $secretsDirectory -Force | Out-Null
$now = Get-Date
$certificate = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.FriendlyName -eq 'Sigil dev station' -and
        $_.HasPrivateKey -and
        $_.NotBefore -le $now -and
        $_.NotAfter -gt $now -and
        $_.DnsNameList.Unicode -contains $dnsName -and
        $_.EnhancedKeyUsageList.ObjectId.Value -contains '1.3.6.1.5.5.7.3.2'
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $certificate) {
    $certificate = New-SelfSignedCertificate `
        -Subject "CN=$dnsName" `
        -FriendlyName 'Sigil dev station' `
        -CertStoreLocation Cert:\LocalMachine\My `
        -DnsName $dnsName `
        -KeyAlgorithm ECDSA_nistP256 `
        -KeyExportPolicy NonExportable `
        -Provider 'Microsoft Software Key Storage Provider' `
        -TextExtension '2.5.29.37={text}1.3.6.1.5.5.7.3.2' `
        -NotAfter $now.AddYears(1)
}

$base64 = [Convert]::ToBase64String($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
$pem = "-----BEGIN CERTIFICATE-----`n" +
    ([regex]::Replace($base64, '.{1,64}', '$&' + "`n")) +
    "-----END CERTIFICATE-----`n"
Set-Content -LiteralPath $publicCertificatePath -Value $pem -Encoding ascii

Write-Output "Station DNS name: $dnsName"
Write-Output "Station certificate thumbprint: $($certificate.Thumbprint)"
Write-Output "Public station certificate: $publicCertificatePath"
