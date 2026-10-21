package gateway

import (
	"crypto/x509"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A CA that returns a certificate that does not match the approved request must not be stored, and the issued
// serial must be revoked.
func TestIssueCertificateRejectsAMismatchedCertificateStoresNothingAndRevokes(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(template *x509.Certificate, publicKey any) any
	}{
		{"wrong key", func(template *x509.Certificate, _ any) any {
			return mustP256(t).Public()
		}},
		{"wrong common name", func(template *x509.Certificate, publicKey any) any {
			template.Subject.CommonName = "mallory"
			return publicKey
		}},
		{"missing email", func(template *x509.Certificate, publicKey any) any {
			template.EmailAddresses = nil
			return publicKey
		}},
		{"validity too long", func(template *x509.Certificate, publicKey any) any {
			template.NotAfter = template.NotAfter.Add(48 * time.Hour)
			return publicKey
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := setupIssuance(t)
			f.seedToken(t, "39192733", "active", "alice")
			key := mustP256(t)
			f.service.issuers.attest = stubAttestation(serialNumber(t, "39192733"), 0x9a, spkiOf(t, key))
			f.ca.tamper = test.tamper

			_, err := f.issue(t, f.operatorCert, "bob", []string{"helpdesk"}, "39192733", key,
				[]byte("attestation-ok"), []byte("f9-ok"), "piv-authentication")
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("code = %v, want FailedPrecondition (err %v)", status.Code(err), err)
			}
			if message := status.Convert(err).Message(); message != "certificate authority returned a certificate that does not match the request" {
				t.Fatalf("message = %q", message)
			}
			if active, superseded := f.certificateCounts(t, "39192733"); active != 0 || superseded != 0 {
				t.Fatalf("a mismatched certificate was stored: active=%d superseded=%d", active, superseded)
			}
			if len(f.ca.revoked) != 1 {
				t.Fatalf("revocations = %v, want exactly one attempt", f.ca.revoked)
			}
		})
	}
}
