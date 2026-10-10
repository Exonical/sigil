package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

type testCert struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func issue(t *testing.T, subject string, parent *testCert, key *ecdsa.PrivateKey, template *x509.Certificate) testCert {
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
	if parent == nil {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
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

type hierarchy struct {
	root, intermediate, slot testCert
	leafKey                  *ecdsa.PrivateKey
	trust                    Trust
	now                      time.Time
}

func newHierarchy(t *testing.T, leafExtensions []pkix.Extension) (hierarchy, testCert) {
	t.Helper()
	return newHierarchyWithSubject(t, "YubiKey PIV Attestation 9a", leafExtensions)
}

func newHierarchyWithSubject(t *testing.T, subject string, leafExtensions []pkix.Extension) (hierarchy, testCert) {
	t.Helper()
	root := issue(t, "Test Yubico Root", nil, newKey(t), &x509.Certificate{})
	intermediate := issue(t, "Test Yubico Intermediate", &root, newKey(t), &x509.Certificate{
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	})
	slot := issue(t, "Test F9 Intermediate", &intermediate, newKey(t), &x509.Certificate{
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	})
	leafKey := newKey(t)
	leaf := issue(t, subject, &slot, leafKey, &x509.Certificate{
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: leafExtensions,
	})
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	return hierarchy{
		root: root, intermediate: intermediate, slot: slot, leafKey: leafKey,
		trust: Trust{Roots: roots, Intermediates: []*x509.Certificate{intermediate.cert}},
		now:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	}, leaf
}

func validExtensions(t *testing.T) []pkix.Extension {
	t.Helper()
	serial, err := asn1.Marshal(int64(39192733))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := asn1.Marshal([]byte{0x02, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	firmware, err := asn1.Marshal("5.7.4")
	if err != nil {
		t.Fatal(err)
	}
	return []pkix.Extension{
		{Id: oidSerial, Value: serial},
		{Id: oidPolicy, Value: policy},
		{Id: oidFirmware, Value: firmware},
	}
}

func TestVerifyAcceptsAChainToTheTrustedRoot(t *testing.T) {
	h, leaf := newHierarchy(t, validExtensions(t))
	result, err := VerifyWith(h.trust, leaf.der, h.slot.der, h.now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Serial != 39192733 || result.PinPolicy != 0x02 || result.TouchPolicy != 0x01 || result.Firmware != "5.7.4" {
		t.Fatalf("unexpected attestation %+v", result)
	}
	if string(result.SubjectPublicKeyInfo) != string(leaf.cert.RawSubjectPublicKeyInfo) {
		t.Fatal("attested key does not match the leaf key")
	}
}

func TestVerifyRejectsAChainThatDoesNotReachTheTrustedRoot(t *testing.T) {
	h, leaf := newHierarchy(t, validExtensions(t))
	otherRoot := issue(t, "Unrelated Root", nil, newKey(t), &x509.Certificate{})
	roots := x509.NewCertPool()
	roots.AddCert(otherRoot.cert)
	_, err := VerifyWith(Trust{Roots: roots, Intermediates: h.trust.Intermediates}, leaf.der, h.slot.der, h.now)
	if err == nil {
		t.Fatal("a chain to an untrusted root must be rejected")
	}
}

func TestVerifyRejectsAnIntermediateThatIsNotFromTheTrustedHierarchy(t *testing.T) {
	h, leaf := newHierarchy(t, validExtensions(t))
	unrelated := issue(t, "Unrelated F9", nil, newKey(t), &x509.Certificate{})
	if _, err := VerifyWith(h.trust, leaf.der, unrelated.der, h.now); err == nil {
		t.Fatal("an F9 certificate outside the trusted hierarchy must be rejected")
	}
}

func TestVerifyRejectsExpiredChains(t *testing.T) {
	h, leaf := newHierarchy(t, validExtensions(t))
	if _, err := VerifyWith(h.trust, leaf.der, h.slot.der, time.Date(2041, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("an expired chain must be rejected")
	}
}

func TestVerifyRequiresTheSerialAndPolicyExtensions(t *testing.T) {
	extensions := validExtensions(t)
	h, leaf := newHierarchy(t, extensions[1:])
	if _, err := VerifyWith(h.trust, leaf.der, h.slot.der, h.now); err == nil {
		t.Fatal("missing serial extension must be rejected")
	}
	h, leaf = newHierarchy(t, []pkix.Extension{extensions[0]})
	if _, err := VerifyWith(h.trust, leaf.der, h.slot.der, h.now); err == nil {
		t.Fatal("missing usage policy extension must be rejected")
	}
}

func TestVerifyRejectsMalformedPolicy(t *testing.T) {
	extensions := validExtensions(t)
	bad, err := asn1.Marshal([]byte{0x02})
	if err != nil {
		t.Fatal(err)
	}
	extensions[1].Value = bad
	h, leaf := newHierarchy(t, extensions)
	if _, err := VerifyWith(h.trust, leaf.der, h.slot.der, h.now); err == nil {
		t.Fatal("a one-byte usage policy must be rejected")
	}
}

func TestEmbeddedYubicoTrustLoads(t *testing.T) {
	trust, err := EmbeddedTrust()
	if err != nil {
		t.Fatal(err)
	}
	if len(trust.Intermediates) == 0 {
		t.Fatal("embedded intermediates are empty")
	}
	if trust.Roots == nil {
		t.Fatal("embedded roots are missing")
	}
}

func TestVerifyReportsTheAttestedSlotFromTheSubject(t *testing.T) {
	h, leaf := newHierarchy(t, validExtensions(t))
	result, err := VerifyWith(h.trust, leaf.der, h.slot.der, h.now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Slot != 0x9a {
		t.Fatalf("slot = %#x, want 0x9a", result.Slot)
	}
}

func TestVerifyAcceptsAnyTwoDigitSlotSubject(t *testing.T) {
	h, leaf := newHierarchyWithSubject(t, "YubiKey PIV Attestation f9", validExtensions(t))
	result, err := VerifyWith(h.trust, leaf.der, h.slot.der, h.now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Slot != 0xf9 {
		t.Fatalf("slot = %#x, want 0xf9", result.Slot)
	}
}

func TestVerifyRejectsMalformedAttestationSubjects(t *testing.T) {
	for _, subject := range []string{
		"YubiKey PIV Attestation",
		"YubiKey PIV Attestation 9",
		"YubiKey PIV Attestation 9A",
		"YubiKey PIV Attestation 9a1",
		"YubiKey PIV Attestation zz",
		"Some Other Certificate 9a",
	} {
		h, leaf := newHierarchyWithSubject(t, subject, validExtensions(t))
		if _, err := VerifyWith(h.trust, leaf.der, h.slot.der, h.now); err == nil {
			t.Fatalf("subject %q must be rejected", subject)
		}
	}
}
