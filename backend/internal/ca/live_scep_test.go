package ca

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveSCEPSignAgainstDevStepCA issues a certificate through the dev step-ca's SCEP provisioner and checks it. It
// also sends a wrong challenge and expects the CA to refuse it. It needs these environment variables:
// SIGIL_LIVE_SCEP_URL (the full provisioner URL), SIGIL_LIVE_SCEP_ROOT (root PEM), SIGIL_LIVE_SCEP_RA_CERT and
// SIGIL_LIVE_SCEP_RA_KEY (paths to the RA certificate and key), and SIGIL_LIVE_SCEP_CHALLENGE (path to the challenge).
// When SIGIL_LIVE_STEP_URL, SIGIL_LIVE_STEP_ROOT, SIGIL_LIVE_STEP_PROVISIONER_KEY and
// SIGIL_LIVE_STEP_PROVISIONER_PASSWORD are also set, the issued certificate is revoked with the native Step client.
func TestLiveSCEPSignAgainstDevStepCA(t *testing.T) {
	url := os.Getenv("SIGIL_LIVE_SCEP_URL")
	if url == "" {
		t.Skip("SIGIL_LIVE_SCEP_URL is not set")
	}
	root, err := os.ReadFile(os.Getenv("SIGIL_LIVE_SCEP_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	raCert, raKey, err := LoadSCEPRegistrationAuthority(os.Getenv("SIGIL_LIVE_SCEP_RA_CERT"), os.Getenv("SIGIL_LIVE_SCEP_RA_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	challengeBytes, err := os.ReadFile(os.Getenv("SIGIL_LIVE_SCEP_CHALLENGE"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := strings.TrimSpace(string(challengeBytes))
	client, err := NewSCEP(SCEPConfig{URL: url, RootPEM: root, RACert: raCert, RAKey: raKey, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}

	const commonName = "live-scep-user"
	const email = "live-scep-user@example.test"
	key := newP256(t)
	request := scepRequest(commonName, email)
	chain, err := client.Sign(context.Background(), scepCSR(t, key, commonName, email, challenge), request)
	if err != nil {
		t.Fatalf("live SCEP issuance: %v", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != commonName {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != email {
		t.Fatalf("email SANs = %v", leaf.EmailAddresses)
	}
	if !bytesEqual(leaf.RawSubjectPublicKeyInfo, mustSPKI(t, key)) {
		t.Fatal("leaf key is not the CSR key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("root PEM has no certificates")
	}
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to the root: %v", err)
	}
	lifetime := time.Until(leaf.NotAfter)
	if lifetime < 719*time.Hour || lifetime > 721*time.Hour {
		t.Fatalf("lifetime from now = %s, want about 720h from the provisioner default", lifetime)
	}
	serialHex := hex.EncodeToString(leaf.SerialNumber.Bytes())
	t.Logf("issued serial=%s subject=CN=%s email=%s notBefore=%s notAfter=%s chain=%d",
		serialHex, leaf.Subject.CommonName, leaf.EmailAddresses[0],
		leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), len(chain))

	_, err = client.Sign(context.Background(), scepCSR(t, newP256(t), commonName, email, "not-the-challenge"), request)
	if err == nil || !strings.Contains(err.Error(), "CA rejected the SCEP request") {
		t.Fatalf("wrong challenge: err = %v, want the CA to reject it", err)
	}
	t.Logf("wrong challenge refused: %v", err)

	if os.Getenv("SIGIL_LIVE_STEP_PROVISIONER_KEY") == "" {
		return
	}
	revokeWithNativeStep(t, serialHex)
}

// revokeWithNativeStep revokes a certificate through the native Step client, which is the path the backend uses.
func revokeWithNativeStep(t *testing.T, serialHex string) {
	t.Helper()
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
	stepClient, err := NewStep(StepConfig{URL: os.Getenv("SIGIL_LIVE_STEP_URL"), RootPEM: root, Provisioner: "sigil-backend", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := stepClient.Revoke(context.Background(), serialHex, 0, "live SCEP test cleanup"); err != nil {
		t.Fatalf("native Step revoke of SCEP-issued serial %s: %v", serialHex, err)
	}
	t.Logf("revoked SCEP-issued serial=%s with the native Step client", serialHex)
}

func bytesEqual(a, b []byte) bool {
	return string(a) == string(b)
}
