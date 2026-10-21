package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"
)

// TestLiveStepSignAgainstDevStepCA signs a CSR with the dev step-ca. It needs the dev CA running and these
// environment variables: SIGIL_LIVE_STEP_URL, SIGIL_LIVE_STEP_ROOT, SIGIL_LIVE_STEP_PROVISIONER_KEY and
// SIGIL_LIVE_STEP_PROVISIONER_PASSWORD (paths). Run with: go test ./internal/ca -run Live -tags live.
func TestLiveStepSignAgainstDevStepCA(t *testing.T) {
	url := os.Getenv("SIGIL_LIVE_STEP_URL")
	if url == "" {
		t.Skip("SIGIL_LIVE_STEP_URL is not set")
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
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "live-test-user"}}, subjectKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := client.Sign(context.Background(), csr, SignRequest{
		Subject:   "live-test-user",
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
	if leaf.Subject.CommonName != "live-test-user" {
		t.Fatalf("live CN = %q", leaf.Subject.CommonName)
	}
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime > 2*time.Hour {
		t.Fatalf("live lifetime = %s, want about one hour as requested", lifetime)
	}
	t.Logf("live step-ca issued serial=%x not_after=%s", leaf.SerialNumber, leaf.NotAfter.Format(time.RFC3339))
}
