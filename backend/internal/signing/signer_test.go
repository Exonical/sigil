package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSignerUsesP256AndLowS(t *testing.T) {
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := NewFileSigner("test-key", path)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("deterministic protobuf grant bytes")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	publicBlock, _ := pem.Decode(publicPEM)
	publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || parsedPublic.Curve.Params().Name != elliptic.P256().Params().Name {
		t.Fatal("generated public key is not P-256")
	}
	if !Verify(parsedPublic, message, signature) {
		t.Fatal("signature did not verify")
	}
	var parsedSignature ecdsaDER
	rest, err := asn1.Unmarshal(signature, &parsedSignature)
	if err != nil || len(rest) != 0 {
		t.Fatalf("decode DER signature: %v", err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if parsedSignature.S.Cmp(halfOrder) > 0 {
		t.Fatal("signature S value was not normalized")
	}
}
