package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadAppliesDefaultsAndValidatesFiles(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"server.crt", "server.key", "client-ca.crt", "grant-key.pem"} {
		mode := os.FileMode(0o644)
		if name == "server.key" || name == "grant-key.pem" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(directory, name), []byte("test"), mode); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(directory, "sigil-server.toml")
	config := `
listen_grpc = "127.0.0.1:0"
database_url = "postgres://sigil:test@127.0.0.1:5432/sigil?sslmode=disable"

[tls]
cert_file = "server.crt"
key_file = "server.key"
client_ca_file = "client-ca.crt"

[oidc]
issuer = "https://issuer.example"
audience = "sigil"

[grants]
key_id = "test"
signing_key_file = "grant-key.pem"

[policy]
self_service_operations = ["PIV_DELETE_KEY"]
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.OIDC.GroupsClaim != "groups" || loaded.Grants.LifetimeSeconds != 120 {
		t.Fatalf("defaults not applied: groups_claim=%q lifetime=%d", loaded.OIDC.GroupsClaim, loaded.Grants.LifetimeSeconds)
	}
	if len(loaded.Policy.SelfServiceOperations) != 1 ||
		loaded.Policy.SelfServiceOperations[0] != "PIV_DELETE_KEY" {
		t.Fatalf("PIV_DELETE_KEY self-service operation was not accepted: %+v", loaded.Policy.SelfServiceOperations)
	}
}

func TestValidateRejectsUnsafeGrantLifetimeAndUnknownPolicyOperations(t *testing.T) {
	directory := t.TempDir()
	paths := map[string]string{}
	for _, name := range []string{"server.crt", "server.key", "client-ca.crt", "grant-key.pem"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	base := Config{
		ListenGRPC:  "127.0.0.1:8443",
		DatabaseURL: "postgres://example",
		TLS: TLS{
			CertFile:     paths["server.crt"],
			KeyFile:      paths["server.key"],
			ClientCAFile: paths["client-ca.crt"],
		},
		OIDC: OIDC{Issuer: "https://issuer.example", Audience: "sigil"},
		Grants: Grants{
			KeyID:           "key",
			SigningKeyFile:  paths["grant-key.pem"],
			LifetimeSeconds: 301,
		},
	}
	if err := base.Validate(); err == nil {
		t.Fatal("grant lifetime above 300 seconds was accepted")
	}
	base.Grants.LifetimeSeconds = 120
	base.Policy.SelfServiceOperations = []string{"FIDO_FINGERPRINT_REMOVE"}
	if err := base.Validate(); err == nil {
		t.Fatal("non-PIV self-service operation was accepted")
	}
}

func TestCheckPrivateFileRejectsGroupReadableFilesOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode-bit validation")
	}
	path := filepath.Join(t.TempDir(), "private-key.pem")
	if err := os.WriteFile(path, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(path); err == nil {
		t.Fatal("group-readable key was accepted")
	}
}
