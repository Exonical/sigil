package attestation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// issueAsGiven signs a certificate with exactly the template's basic constraints and key usage. The shared issue
// helper forces CA:true on roots, so negative cases build their certificates here.
func issueAsGiven(t *testing.T, subject string, parent *testCert, key *ecdsa.PrivateKey, template *x509.Certificate) testCert {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = serial
	template.Subject = pkix.Name{CommonName: subject}
	template.NotBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	template.NotAfter = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{der: der, cert: cert, key: key}
}

// caHierarchy returns trust, a leaf, and the slot F9 certificate. The intermediate and the slot use the given templates.
func caHierarchy(t *testing.T, intermediate, slot *x509.Certificate) (Trust, testCert, testCert, time.Time) {
	t.Helper()
	root := issue(t, "Test Root", nil, newKey(t), &x509.Certificate{})
	intermediateCert := issueAsGiven(t, "Test Intermediate", &root, newKey(t), intermediate)
	slotCert := issueAsGiven(t, "Test F9", &intermediateCert, newKey(t), slot)
	leaf := issue(t, "YubiKey PIV Attestation 9a", &slotCert, newKey(t), &x509.Certificate{ExtraExtensions: validExtensions(t)})
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	return Trust{Roots: roots, Intermediates: []*x509.Certificate{intermediateCert.cert}}, leaf, slotCert, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}

func TestIntermediateWithoutTheCAFlagIsRejected(t *testing.T) {
	trust, leaf, slot, now := caHierarchy(t, &x509.Certificate{}, &x509.Certificate{BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign})
	_, err := VerifyWith(trust, leaf.der, slot.der, now)
	if err == nil || !strings.Contains(err.Error(), "not a CA certificate") {
		t.Fatalf("intermediate without the CA flag: err = %v", err)
	}
}

func TestIntermediateWhoseKeyUsageForbidsCertSigningIsRejected(t *testing.T) {
	intermediate := &x509.Certificate{BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature}
	trust, leaf, slot, now := caHierarchy(t, intermediate, &x509.Certificate{BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign})
	_, err := VerifyWith(trust, leaf.der, slot.der, now)
	if err == nil || !strings.Contains(err.Error(), "keyCertSign") {
		t.Fatalf("intermediate without keyCertSign: err = %v", err)
	}
}

func TestSlotF9WithoutTheCAFlagIsRejected(t *testing.T) {
	trust, leaf, slot, now := caHierarchy(t, &x509.Certificate{BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, &x509.Certificate{})
	_, err := VerifyWith(trust, leaf.der, slot.der, now)
	if err == nil || !strings.Contains(err.Error(), "slot F9 certificate is not a CA certificate") {
		t.Fatalf("slot F9 without the CA flag: err = %v", err)
	}
}

func TestCompliantHierarchyStillVerifies(t *testing.T) {
	trust, leaf, slot, now := caHierarchy(t, &x509.Certificate{BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, &x509.Certificate{BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign})
	if _, err := VerifyWith(trust, leaf.der, slot.der, now); err != nil {
		t.Fatal(err)
	}
}
