package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/attestation"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/signing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeCA signs the CSR key with a test CA and records what the backend asked for.
type fakeCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	calls   int
	request ca.SignRequest
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key := mustP256(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCA{key: key, cert: cert}
}

func (f *fakeCA) Revoke(_ context.Context, _ string, _ int, _ string) error {
	return nil
}

func (f *fakeCA) Sign(_ context.Context, csrDER []byte, request ca.SignRequest) ([][]byte, error) {
	f.calls++
	f.request = request
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(int64(1000 + f.calls)),
		Subject:        pkix.Name{CommonName: request.Subject},
		NotBefore:      request.NotBefore,
		NotAfter:       request.NotAfter,
		EmailAddresses: request.EmailAddresses,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, template, f.cert, csr.PublicKey, f.key)
	if err != nil {
		return nil, err
	}
	return [][]byte{leaf, f.cert.Raw}, nil
}

// stubAttestation accepts only the attestation bytes "attestation-ok" with F9 bytes "f9-ok".
// It reports the given serial and the attested key.
func stubAttestation(serial uint32, slot byte, attestedKey []byte) func([]byte, []byte, time.Time) (attestation.Attestation, error) {
	return func(attestationDER, intermediate []byte, _ time.Time) (attestation.Attestation, error) {
		if string(attestationDER) != "attestation-ok" || string(intermediate) != "f9-ok" {
			return attestation.Attestation{}, errors.New("attestation chain does not verify")
		}
		return attestation.Attestation{Serial: serial, Slot: slot, PinPolicy: 0x02, TouchPolicy: 0x01, SubjectPublicKeyInfo: attestedKey}, nil
	}
}

type issuanceFixture struct {
	ctx          context.Context
	store        *db.Store
	service      *Server
	issuer       *oidcTestIssuer
	ca           *fakeCA
	operatorCert *x509.Certificate
	userCert     *x509.Certificate
	csrCN        string
}

func setupIssuance(t *testing.T) issuanceFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	store := openGatewayTestStore(t)
	issuer := newGatewayTestIssuer(t)
	pki := newTestPKI(t)
	operatorCert := pki.issueClient(t, "ignored", []string{"station-ops.example.test"})
	userCert := pki.issueClient(t, "ignored", []string{"station-user.example.test"})
	if err := addTestStation(ctx, store, "station-ops", "station-ops.example.test", "station"); err != nil {
		t.Fatal(err)
	}
	if err := addTestStation(ctx, store, "station-user", "station-user.example.test", "user"); err != nil {
		t.Fatal(err)
	}
	keyPEM, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signingKeyPath := filepath.Join(t.TempDir(), "grant-private.pem")
	if err := os.WriteFile(signingKeyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := signing.NewFileSigner("issuance-test-key", signingKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := authn.New(ctx, authn.Config{Issuer: issuer.server.URL, Audience: "sigil-backend", GroupsClaim: "groups"}, store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		OIDC:   config.OIDC{RoleGroups: config.RoleGroups{Helpdesk: []string{"helpdesk"}}},
		Grants: config.Grants{LifetimeSeconds: 120},
		Profiles: []config.Profile{{
			Name: "piv-authentication", DisplayName: "PIV Authentication", Slot: "9a", Algorithm: "p256",
			PinPolicy: "once", TouchPolicy: "never", Subject: "CN={username}", EmailSAN: true,
			ValidityHours: 720, CA: "dev-step", Roles: []string{"helpdesk"},
		}},
	}
	service := New(store, authenticator, signer, cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	t.Cleanup(service.Close)
	fake := newFakeCA(t)
	service.ConfigureIssuance(map[string]ca.CA{"dev-step": fake})
	return issuanceFixture{
		ctx: ctx, store: store, service: service, issuer: issuer, ca: fake,
		operatorCert: operatorCert.Leaf, userCert: userCert.Leaf, csrCN: "alice",
	}
}

// seedToken inserts an inventory token. assignedSubject is the OIDC subject of the assigned user, or "".
func (f issuanceFixture) seedToken(t *testing.T, serial, status, assignedSubject string) {
	t.Helper()
	var userID *string
	if assignedSubject != "" {
		id, err := f.store.UpsertUser(f.ctx, f.issuer.server.URL, assignedSubject, assignedSubject,
			assignedSubject+"@example.test", assignedSubject)
		if err != nil {
			t.Fatal(err)
		}
		userID = &id
	}
	if _, err := f.store.Pool.Exec(f.ctx, `
		INSERT INTO tokens(vendor, model, serial, status, assigned_user_id, last_station_id)
		VALUES('Yubico', 'YubiKey 5 FIPS', $1, $2, $3::uuid, 'station-ops')
	`, serial, status, userID); err != nil {
		t.Fatal(err)
	}
}

// issue calls IssueCertificate as the caller, from the given station certificate.
func (f issuanceFixture) issue(t *testing.T, stationCert *x509.Certificate, caller string, groups []string,
	serial string, csrKey *ecdsa.PrivateKey, attestationDER, intermediate []byte, profile string) (*backendv1.IssueCertificateResponse, error) {
	t.Helper()
	token := f.issuer.token(t, caller, groups, time.Now().Add(time.Hour))
	return f.service.IssueCertificate(contextForPeerCertificate(stationCert), &backendv1.IssueCertificateRequest{
		AccessToken:                token,
		TokenVendor:                "Yubico",
		TokenSerial:                serial,
		CallerOsUser:               "S-1-5-21-test",
		Profile:                    profile,
		CsrDer:                     csrFor(t, csrKey, f.csrCN),
		AttestationDer:             attestationDER,
		AttestationIntermediateDer: intermediate,
	})
}

func (f issuanceFixture) auditDenied(t *testing.T, serial, reason string) bool {
	t.Helper()
	var count int
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT count(*) FROM audit_events
		WHERE action='IssueCertificate' AND target_id=$1 AND outcome='denied' AND detail->>'reason'=$2
	`, serial, reason).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count == 1
}

func (f issuanceFixture) certificateCounts(t *testing.T, serial string) (active, superseded int) {
	t.Helper()
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT count(*) FILTER (WHERE certificates.status='active'),
		       count(*) FILTER (WHERE certificates.status='superseded')
		FROM certificates JOIN tokens ON tokens.id=certificates.token_id WHERE tokens.serial=$1
	`, serial).Scan(&active, &superseded); err != nil {
		t.Fatal(err)
	}
	return active, superseded
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey, commonName string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustP384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func spkiOf(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func serialNumber(t *testing.T, serial string) uint32 {
	t.Helper()
	value, err := strconv.ParseUint(serial, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(value)
}

func TestIssueCertificateOperatorEnrollsAssignedTokenAndSupersedes(t *testing.T) {
	f := setupIssuance(t)
	f.seedToken(t, "39192733", "active", "alice")
	key := mustP256(t)
	f.service.issuers.attest = stubAttestation(serialNumber(t, "39192733"), 0x9a, spkiOf(t, key))

	first, err := f.issue(t, f.operatorCert, "bob", []string{"helpdesk"}, "39192733", key,
		[]byte("attestation-ok"), []byte("f9-ok"), "piv-authentication")
	if err != nil {
		t.Fatal(err)
	}
	if first.Subject != "CN=alice" || len(first.ChainDer) != 2 {
		t.Fatalf("issued subject=%q chain=%d", first.Subject, len(first.ChainDer))
	}
	if f.ca.request.Subject != "alice" || len(f.ca.request.EmailAddresses) != 1 {
		t.Fatalf("CA request = %+v; the subject must come from the assigned user", f.ca.request)
	}
	if active, superseded := f.certificateCounts(t, "39192733"); active != 1 || superseded != 0 {
		t.Fatalf("after first issue active=%d superseded=%d", active, superseded)
	}

	second, err := f.issue(t, f.operatorCert, "bob", []string{"helpdesk"}, "39192733", key,
		[]byte("attestation-ok"), []byte("f9-ok"), "piv-authentication")
	if err != nil {
		t.Fatal(err)
	}
	if second.SerialNumber == first.SerialNumber {
		t.Fatal("the second issuance must produce a new serial number")
	}
	if active, superseded := f.certificateCounts(t, "39192733"); active != 1 || superseded != 1 {
		t.Fatalf("after reissue active=%d superseded=%d; the previous certificate must be superseded", active, superseded)
	}
}

func TestIssueCertificateSelfServiceRequiresTheAssignedUserAndAMatchingRole(t *testing.T) {
	f := setupIssuance(t)
	f.seedToken(t, "1000001", "active", "alice")
	f.seedToken(t, "1000002", "active", "alice")
	key := mustP256(t)
	f.service.issuers.attest = stubAttestation(serialNumber(t, "1000001"), 0x9a, spkiOf(t, key))

	if _, err := f.issue(t, f.userCert, "alice", []string{"helpdesk"}, "1000001", key,
		[]byte("attestation-ok"), []byte("f9-ok"), "piv-authentication"); err != nil {
		t.Fatalf("the assigned user with a matching role must self-enroll: %v", err)
	}
	f.service.issuers.attest = stubAttestation(serialNumber(t, "1000002"), 0x9a, spkiOf(t, key))
	_, err := f.issue(t, f.userCert, "bob", []string{"helpdesk"}, "1000002", key,
		[]byte("attestation-ok"), []byte("f9-ok"), "piv-authentication")
	if status.Code(err) != codes.PermissionDenied || !f.auditDenied(t, "1000002", "user is not authorized to enroll a certificate on this token") {
		t.Fatalf("a different user must not self-enroll alice's token; err=%v", err)
	}
}

func TestIssueCertificateRejectionsAreAuditedAndIssueNothing(t *testing.T) {
	cases := []struct {
		name           string
		serial         string
		tokenStatus    string
		assigned       string
		profile        string
		csrKey         func(*testing.T) *ecdsa.PrivateKey
		attestedKey    func(*testing.T, *ecdsa.PrivateKey) []byte
		attestedSerial string
		attestedSlot   byte
		csrCN          string
		attestation    []byte
		wantCode       codes.Code
		reason         string
	}{
		{name: "CSR subject does not match the assigned user", serial: "2000008", tokenStatus: "active", assigned: "alice", profile: "piv-authentication", csrCN: "mallory", wantCode: codes.FailedPrecondition, reason: "certificate request subject does not match the assigned user"},
		{name: "attested slot differs from the profile", serial: "2000009", tokenStatus: "active", assigned: "alice", profile: "piv-authentication", attestedSlot: 0x9c, wantCode: codes.FailedPrecondition, reason: "attestation slot does not match the profile"},
		{name: "unassigned token", serial: "2000001", tokenStatus: "active", assigned: "", profile: "piv-authentication",
			wantCode: codes.PermissionDenied, reason: "token is not assigned to a user"},
		{name: "inactive token", serial: "2000002", tokenStatus: "unassigned", assigned: "alice", profile: "piv-authentication",
			wantCode: codes.PermissionDenied, reason: "token is not active"},
		{name: "unknown profile", serial: "2000003", tokenStatus: "active", assigned: "alice", profile: "missing",
			wantCode: codes.PermissionDenied, reason: "profile is not defined"},
		{name: "attestation does not verify", serial: "2000004", tokenStatus: "active", assigned: "alice", profile: "piv-authentication",
			attestation: []byte("forged"), wantCode: codes.FailedPrecondition, reason: "attestation chain does not verify"},
		{name: "attested serial differs from the token", serial: "2000005", tokenStatus: "active", assigned: "alice", profile: "piv-authentication",
			attestedSerial: "9999999", wantCode: codes.FailedPrecondition, reason: "attestation serial number does not match the token"},
		{name: "CSR key is P-384 for a P-256 profile", serial: "2000006", tokenStatus: "active", assigned: "alice", profile: "piv-authentication",
			csrKey: mustP384, wantCode: codes.FailedPrecondition, reason: "certificate request key does not match the profile algorithm"},
		{name: "attested key differs from the CSR key", serial: "2000007", tokenStatus: "active", assigned: "alice", profile: "piv-authentication",
			attestedKey: func(t *testing.T, _ *ecdsa.PrivateKey) []byte { return spkiOf(t, mustP256(t)) },
			wantCode:    codes.FailedPrecondition, reason: "attested key does not match the certificate request key"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := setupIssuance(t)
			f.seedToken(t, test.serial, test.tokenStatus, test.assigned)
			if test.csrCN != "" {
				f.csrCN = test.csrCN
			}
			key := mustP256(t)
			attestedKey := spkiOf(t, key)
			if test.attestedKey != nil {
				attestedKey = test.attestedKey(t, key)
			}
			attestedSerial := serialNumber(t, test.serial)
			if test.attestedSerial != "" {
				attestedSerial = serialNumber(t, test.attestedSerial)
			}
			slot := byte(0x9a)
			if test.attestedSlot != 0 {
				slot = test.attestedSlot
			}
			f.service.issuers.attest = stubAttestation(attestedSerial, slot, attestedKey)
			csrKey := key
			if test.csrKey != nil {
				csrKey = test.csrKey(t)
			}
			attestation := test.attestation
			if attestation == nil {
				attestation = []byte("attestation-ok")
			}
			_, err := f.issue(t, f.operatorCert, "bob", []string{"helpdesk"}, test.serial, csrKey,
				attestation, []byte("f9-ok"), test.profile)
			if status.Code(err) != test.wantCode {
				t.Fatalf("code = %v, want %v (err %v)", status.Code(err), test.wantCode, err)
			}
			if !f.auditDenied(t, test.serial, test.reason) {
				t.Fatalf("expected a denied IssueCertificate audit record with reason %q", test.reason)
			}
			if active, _ := f.certificateCounts(t, test.serial); active != 0 {
				t.Fatalf("a rejected request issued %d certificates", active)
			}
			if f.ca.calls != 0 {
				t.Fatalf("the CA was called %d times for a rejected request", f.ca.calls)
			}
		})
	}
}
