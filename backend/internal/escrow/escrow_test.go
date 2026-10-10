package escrow

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnvelopeRoundTripAndRejectsAuthenticationChanges(t *testing.T) {
	current := bytes.Repeat([]byte{0x31}, 32)
	keyring, err := NewKeyring("current", current, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	context := Context{
		Vendor: "Yubico", Serial: "39192733", Kind: "management_key",
		Algorithm: "aes256", Version: 3,
	}
	secret := bytes.Repeat([]byte{0x7a}, 32)
	envelope, err := keyring.Encrypt(context, secret)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := keyring.Decrypt(context, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatal("decrypted value does not match")
	}
	clear(opened)

	changedContext := context
	changedContext.Serial = "different"
	if _, err := keyring.Decrypt(changedContext, envelope); err == nil {
		t.Fatal("changed AAD was accepted")
	}
	tamperedCiphertext := envelope
	tamperedCiphertext.Ciphertext = bytes.Clone(envelope.Ciphertext)
	tamperedCiphertext.Ciphertext[0] ^= 1
	if _, err := keyring.Decrypt(context, tamperedCiphertext); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	tamperedWrappedDEK := envelope
	tamperedWrappedDEK.WrappedDEK = bytes.Clone(envelope.WrappedDEK)
	tamperedWrappedDEK.WrappedDEK[0] ^= 1
	if _, err := keyring.Decrypt(context, tamperedWrappedDEK); err == nil {
		t.Fatal("tampered wrapped DEK was accepted")
	}
}

func TestEnvelopeDecryptsWithPreviousKEK(t *testing.T) {
	previous := bytes.Repeat([]byte{0x11}, 32)
	current := bytes.Repeat([]byte{0x22}, 32)
	legacy, err := NewKeyring("old-key", previous, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	context := Context{Vendor: "Yubico", Serial: "token", Kind: "puk", Version: 1}
	value := []byte("12345678")
	envelope, err := legacy.Encrypt(context, value)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewKeyring("new-key", current, map[string][]byte{"old-key": previous})
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	opened, err := rotated.Decrypt(context, envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	if !bytes.Equal(opened, value) {
		t.Fatal("previous-KEK plaintext does not match")
	}
}

func TestGenerateManagedValuesAndKEKFile(t *testing.T) {
	puk, err := GeneratePUK()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(puk)
	if err := validateSecret(Context{Vendor: "Yubico", Serial: "token", Kind: "puk", Version: 1}, puk); err != nil {
		t.Fatal(err)
	}
	managementKey, err := GenerateManagementKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(managementKey)
	if err := validateSecret(Context{Vendor: "Yubico", Serial: "token", Kind: "management_key", Algorithm: "aes256", Version: 1}, managementKey); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "kek.key")
	if err := WriteNewKEK(path); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(key) != 32 {
		t.Fatalf("generated KEK is invalid: %v", err)
	}
	clear(key)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("KEK file mode = %o, want 600", info.Mode().Perm())
		}
	}
}
