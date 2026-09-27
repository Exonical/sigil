# PIV certificate fixtures

These public self-signed certificates are test data only. The corresponding private keys are temporary and are not stored in the repository. The subject organization is `Sigil Test Fixture`; each certificate is valid from 2025-01-01T00:00:00Z through 2035-01-01T00:00:00Z.

The fixtures can be regenerated in PowerShell with Git for Windows OpenSSL:

```powershell
$openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'
$work = Join-Path $env:TEMP 'sigil-m3-piv-fixtures'
$fixture = (Resolve-Path '.\crates\sigil-mock\fixtures').Path
New-Item -ItemType Directory -Path "$work\newcerts" -Force | Out-Null
New-Item -ItemType File -Path "$work\index.txt" -Force | Out-Null
Set-Content -Path "$work\serial" -Value '1001' -Encoding ascii
$workConfig = $work.Replace('\', '/')
@"
[ ca ]
default_ca = local_ca
[ local_ca ]
database = $workConfig/index.txt
new_certs_dir = $workConfig/newcerts
serial = $workConfig/serial
default_md = sha256
policy = policy_any
x509_extensions = v3_ca
[ policy_any ]
commonName = supplied
organizationName = supplied
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"@ | Set-Content -Path "$work\openssl.cnf" -Encoding ascii
& $openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$work\piv-9a.key"
& $openssl req -new -key "$work\piv-9a.key" -subj '/O=Sigil Test Fixture/CN=Simulated PIV Authentication' -out "$work\piv-9a.csr"
& $openssl ca -selfsign -batch -config "$work\openssl.cnf" -keyfile "$work\piv-9a.key" -in "$work\piv-9a.csr" -startdate 20250101000000Z -enddate 20350101000000Z -extensions v3_ca -out "$work\piv-9a.pem"
& $openssl x509 -in "$work\piv-9a.pem" -outform DER -out "$fixture\piv-9a-p256.der"
& $openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work\piv-9d.key"
& $openssl req -new -key "$work\piv-9d.key" -subj '/O=Sigil Test Fixture/CN=Simulated PIV Key Management' -out "$work\piv-9d.csr"
& $openssl ca -selfsign -batch -config "$work\openssl.cnf" -keyfile "$work\piv-9d.key" -in "$work\piv-9d.csr" -startdate 20250101000000Z -enddate 20350101000000Z -extensions v3_ca -out "$work\piv-9d.pem"
& $openssl x509 -in "$work\piv-9d.pem" -outform DER -out "$fixture\piv-9d-rsa2048.der"
& $openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$work\piv-9e.key"
& $openssl req -new -key "$work\piv-9e.key" -subj '/O=Sigil Test Fixture/CN=Simulated PIV Card Authentication' -out "$work\piv-9e.csr"
& $openssl ca -selfsign -batch -config "$work\openssl.cnf" -keyfile "$work\piv-9e.key" -in "$work\piv-9e.csr" -startdate 20250101000000Z -enddate 20350101000000Z -extensions v3_ca -out "$work\piv-9e.pem"
& $openssl x509 -in "$work\piv-9e.pem" -outform DER -out "$fixture\piv-9e-p256.der"
Remove-Item "$work\*.key" -Force
```
