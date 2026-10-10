package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestLiveStepRevokeAgainstDevStepCA issues a certificate with the dev step-ca and passively revokes it.
// It uses the same environment variables as TestLiveStepSignAgainstDevStepCA.
func TestLiveStepRevokeAgainstDevStepCA(t *testing.T) {
	url := os.Getenv("SIGIL_LIVE_STEP_URL")
	if url == "" {
		t.Skip("SIGIL_LIVE_STEP_URL is not set")
	}
	if os.Getenv("SIGIL_LIVE_STEP_REVOKE") == "" {
		t.Skip("set SIGIL_LIVE_STEP_REVOKE=1 once the step-ca has an authority database; the dev CA was initialized with --no-db and returns HTTP 501 for revocation")
	}
	root, err := os.ReadFile(os.Getenv("SIGIL_LIVE_STEP_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(os.Getenv("SIGIL_LIVE_STEP_PROVISIONER_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	password, err := os.ReadFile(os.Getenv("SIGIL_LIVE_STEP_PROVISIONER_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadProvisionerKey(encrypted, password)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewStep(StepConfig{URL: url, RootPEM: root, Provisioner: "sigil-backend", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "live-revoke-user"}}, subjectKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := client.Sign(context.Background(), csr, SignRequest{
		Subject:   "live-revoke-user",
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	serialHex := hex.EncodeToString(leaf.SerialNumber.Bytes())
	if err := client.Revoke(context.Background(), serialHex, 5, "cessation of operation (live test)"); err != nil {
		t.Fatal(err)
	}
	t.Logf("live step-ca passively revoked serial %s", serialHex)
	repeat := client.Revoke(context.Background(), serialHex, 5, "cessation of operation (live test)")
	t.Logf("live step-ca repeat revoke result: %v", repeat)
}
