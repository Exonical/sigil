package attestation

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRealF9CertificateChainsToEmbeddedRoot checks a certificate read from a real YubiKey. Set
// SIGIL_ATTEST_FIXTURE_DIR to a directory holding f9-attestation.der, exported read-only with
// `cms --direct piv certificate export <device> f9 --format der`. Without the variable the test is skipped.
func TestRealF9CertificateChainsToEmbeddedRoot(t *testing.T) {
	directory := os.Getenv("SIGIL_ATTEST_FIXTURE_DIR")
	if directory == "" {
		t.Skip("SIGIL_ATTEST_FIXTURE_DIR is not set")
	}
	der, err := os.ReadFile(filepath.Join(directory, "f9-attestation.der"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := EmbeddedTrust()
	if err != nil {
		t.Fatal(err)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         trust.Roots,
		Intermediates: poolOf(trust.Intermediates),
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("real F9 certificate does not chain to a Yubico root: %v", err)
	}
	root := chains[0][len(chains[0])-1]
	if root.Subject.CommonName != "Yubico Attestation Root 1" {
		t.Fatalf("chain ends at %q, want Yubico Attestation Root 1", root.Subject.CommonName)
	}
}

func poolOf(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
