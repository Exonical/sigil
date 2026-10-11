package gateway

import (
	"bytes"
	"crypto/x509"
	"time"

	"github.com/Exonical/sigil/backend/internal/ca"
)

// issuedCertificateMismatch reports why a CA-issued certificate does not match the approved request, or returns "" when
// it matches. The backend checks these fields itself because the CA is not trusted to enforce them.
func issuedCertificateMismatch(leaf *x509.Certificate, chain [][]byte, csr *x509.CertificateRequest, request ca.SignRequest, roots *x509.CertPool, now time.Time) string {
	const clockSkew = 5 * time.Minute
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return "public key differs from the request"
	}
	if leaf.Subject.CommonName != request.Subject {
		return "subject differs from the approved subject"
	}
	if !sameStrings(leaf.EmailAddresses, request.EmailAddresses) {
		return "email addresses differ from the approved addresses"
	}
	if leaf.NotAfter.After(request.NotAfter.Add(clockSkew)) {
		return "validity exceeds the requested lifetime"
	}
	if leaf.NotBefore.After(now.Add(clockSkew)) {
		return "certificate is not valid yet"
	}
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return "chain contains a malformed certificate"
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return "certificate does not chain to a configured root"
	}
	return ""
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
