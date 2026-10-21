package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
	"github.com/Exonical/sigil/backend/gen/sigil/admin/v1/adminv1connect"
	"github.com/Exonical/sigil/backend/internal/db"
)

// attestationDER builds a self-signed certificate with the Yubico attestation extensions for the given slot CN.
func attestationDER(t *testing.T, subject string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := asn1.Marshal(big.NewInt(39192733))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := asn1.Marshal([]byte{0x02, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}, Value: serial},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}, Value: policy},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// insertAttestedCertificate stores a certificate with the attestation columns set, as issuance does.
func (f adminFixture) insertAttestedCertificate(t *testing.T, tokenID, serial string, der []byte) string {
	t.Helper()
	tx, err := f.store.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.store.InsertCertificate(f.ctx, tx, db.CertificateRecord{
		TokenID: tokenID, Slot: "9a", Profile: "piv-authentication", UserID: f.userID,
		SerialNumber: serial, Subject: "CN=alice", NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IssuedByStation: "station-admin-test", DER: []byte{1},
		AttestationDER: der, AttestationIntermediateDER: []byte("f9"),
		AttestedFirmware: "5.7.4", AttestationRoot: "Yubico Attestation Root 1",
	})
	if err != nil {
		_ = tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGetCertificateAttestationReturnsTheStoredDERAndAuditsTheRead(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	der := attestationDER(t, "YubiKey PIV Attestation 9A")
	certID := f.insertAttestedCertificate(t, tokenID, "att-1", der)

	response, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.GetCertificateAttestation, &adminv1.CertificateAttestationRequest{CertificateId: certID})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Msg.AttestationDer) != string(der) || string(response.Msg.AttestationIntermediateDer) != "f9" {
		t.Fatal("the stored attestation DER must be returned unchanged")
	}
	summary := response.Msg.Summary
	if !summary.Present || summary.Root != "Yubico Attestation Root 1" || summary.Firmware != "5.7.4" {
		t.Fatalf("summary = %v", summary)
	}
	if summary.Slot != "9a" || summary.AttestedSerial != "39192733" || summary.PinPolicy != "02" || summary.TouchPolicy != "01" {
		t.Fatalf("parsed fields = %v", summary)
	}

	actor, target, detail := readAuditRow(t, f, "Admin.GetCertificateAttestation")
	if actor != "helpdesk-user" || target != certID {
		t.Fatalf("audit actor=%q target=%q", actor, target)
	}
	if detail["certificate_id"] != certID {
		t.Fatalf("audit detail = %v", detail)
	}
	for key := range detail {
		if strings.Contains(key, "der") {
			t.Fatalf("audit detail must not carry DER data: %v", detail)
		}
	}
	assertChainVerifies(t, f)
}

func TestGetCertificateAttestationDeniesOrdinaryUsersAndUnknownCertificates(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	certID := f.insertAttestedCertificate(t, tokenID, "att-2", attestationDER(t, "YubiKey PIV Attestation 9A"))

	if _, err := call(f, "user-token", adminv1connect.AdminServiceClient.GetCertificateAttestation, &adminv1.CertificateAttestationRequest{CertificateId: certID}); codeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("plain user = %v, want PermissionDenied", codeOf(err))
	}
	if _, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.GetCertificateAttestation, &adminv1.CertificateAttestationRequest{CertificateId: "00000000-0000-0000-0000-000000000000"}); codeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown certificate = %v, want NotFound", codeOf(err))
	}
}

func TestGetTokenSummarizesEachCertificatesAttestation(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	f.insertAttestedCertificate(t, tokenID, "att-3", attestationDER(t, "YubiKey PIV Attestation 9A"))
	f.insertCertificate(t, tokenID, "plain-3", "9c")

	response, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.GetToken, tokenRefOf("39192733"))
	if err != nil {
		t.Fatal(err)
	}
	var attested, plain *adminv1.AttestationSummary
	for _, certificate := range response.Msg.Certificates {
		switch certificate.SerialNumber {
		case "att-3":
			attested = certificate.Attestation
		case "plain-3":
			plain = certificate.Attestation
		}
	}
	if attested == nil || !attested.Present || attested.Root != "Yubico Attestation Root 1" {
		t.Fatalf("attested summary = %v", attested)
	}
	if plain == nil || plain.Present {
		t.Fatalf("a certificate without an attestation must report present=false: %v", plain)
	}
}
