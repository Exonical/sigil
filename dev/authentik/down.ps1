$ErrorActionPreference = "Stop"
$podmanConnection = 'podman-machine-default'

foreach ($name in @('sigil-authentik-worker', 'sigil-authentik-server', 'sigil-authentik-db')) {
    & podman --connection $podmanConnection container exists $name 2>$null
    if ($LASTEXITCODE -eq 0) {
        & podman --connection $podmanConnection stop --time 15 $name
        if ($LASTEXITCODE -ne 0) {
            throw "Could not stop Authentik container $name."
        }
    }
}
