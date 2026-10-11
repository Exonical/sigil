package admin

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
	"github.com/Exonical/sigil/backend/gen/sigil/admin/v1/adminv1connect"
	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/db"
)

// fakeRevoker is a test CA. It records revocations, can refuse specific serials, and can report serials as
// already revoked, which is the behavior of step-ca for a repeated revoke.
type fakeRevoker struct {
	mu      sync.Mutex
	revoked map[string]int
	reasons map[string]int
	refuse  map[string]bool
	already map[string]bool
}

func newFakeRevoker() *fakeRevoker {
	return &fakeRevoker{revoked: map[string]int{}, reasons: map[string]int{}, refuse: map[string]bool{}, already: map[string]bool{}}
}

func (f *fakeRevoker) Roots() *x509.CertPool {
	return x509.NewCertPool()
}

func (f *fakeRevoker) Sign(context.Context, []byte, ca.SignRequest) ([][]byte, error) {
	return nil, errors.New("not used by admin tests")
}

func (f *fakeRevoker) Revoke(_ context.Context, serial string, reasonCode int, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse[serial] {
		return errors.New("fake CA refused the revocation")
	}
	if f.already[serial] {
		return ca.ErrAlreadyRevoked
	}
	f.revoked[serial]++
	f.reasons[serial] = reasonCode
	return nil
}

func (f *fakeRevoker) calls(serial string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[serial]
}

func (f adminFixture) useCA(fake *fakeRevoker) {
	f.service.WithCertificateAuthorities(map[string]ca.CA{"dev-step": fake}, map[string]string{"piv-authentication": "dev-step"})
}

// insertCertificate issues a test certificate for a token slot and returns its id.
func (f adminFixture) insertCertificate(t *testing.T, tokenID, serial, slot string) string {
	t.Helper()
	tx, err := f.store.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.store.InsertCertificate(f.ctx, tx, db.CertificateRecord{
		TokenID: tokenID, Slot: slot, Profile: "piv-authentication", UserID: f.userID,
		SerialNumber: serial, Subject: "CN=alice", NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IssuedByStation: "station-admin-test", DER: []byte{1},
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

func (f adminFixture) tokenStatus(t *testing.T, serial string) string {
	t.Helper()
	var status string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT status FROM tokens WHERE serial = $1`, serial).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func (f adminFixture) certificateStatus(t *testing.T, id string) string {
	t.Helper()
	var status string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT status FROM certificates WHERE id = $1::uuid`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func tokenRefOf(serial string) *adminv1.TokenRef {
	return &adminv1.TokenRef{Vendor: "Yubico", Serial: serial}
}

func TestHelpdeskIsDeniedAdminOnlyRPCs(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	f.useCA(newFakeRevoker())
	helpdesk := "helpdesk-token"

	checks := map[string]error{}
	_, checks["DeleteKey"] = call(f, helpdesk, adminv1connect.AdminServiceClient.DeleteKey, &adminv1.DeleteKeyRequest{Token: tokenRefOf("39192733"), ConfirmSerial: "39192733"})
	_, checks["RevokeCertificate"] = call(f, helpdesk, adminv1connect.AdminServiceClient.RevokeCertificate, &adminv1.RevokeCertificateRequest{CertificateId: "x", Reason: "keyCompromise"})
	_, checks["AddStation"] = call(f, helpdesk, adminv1connect.AdminServiceClient.AddStation, &adminv1.AddStationRequest{DnsName: "x.example.test", Mode: "station"})
	_, checks["SetStationStatus"] = call(f, helpdesk, adminv1connect.AdminServiceClient.SetStationStatus, &adminv1.SetStationStatusRequest{Id: "station-admin-test", Status: "disabled"})
	_, checks["VerifyAudit"] = call(f, helpdesk, adminv1connect.AdminServiceClient.VerifyAudit, &adminv1.Empty{})
	for name, err := range checks {
		if codeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("%s for helpdesk: code = %v, want PermissionDenied", name, codeOf(err))
		}
	}
	if f.tokenStatus(t, "39192733") != "active" {
		t.Fatal("a denied DeleteKey must not retire the token")
	}
}

func TestHelpdeskCanRunTheOperatorChanges(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "40000001", "unassigned", nil)
	if _, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.AssignToken, &adminv1.AssignTokenRequest{Token: tokenRefOf("40000001"), UsernameOrEmail: "alice"}); err != nil {
		t.Fatalf("helpdesk assign: %v", err)
	}
	if _, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.SetNickname, &adminv1.SetNicknameRequest{Token: tokenRefOf("40000001"), Nickname: "front desk"}); err != nil {
		t.Fatalf("helpdesk nickname: %v", err)
	}
}

func TestDeleteKeyRejectsAConfirmationThatDoesNotMatch(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	f.insertCertificate(t, tokenID, "cert-a", "9a")
	fake := newFakeRevoker()
	f.useCA(fake)

	_, err := call(f, "admin-token", adminv1connect.AdminServiceClient.DeleteKey, &adminv1.DeleteKeyRequest{Token: tokenRefOf("39192733"), ConfirmSerial: "39192734"})
	if codeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", codeOf(err))
	}
	if fake.calls("cert-a") != 0 || f.tokenStatus(t, "39192733") != "active" {
		t.Fatal("a mismatched confirmation must change nothing")
	}
}

func TestDeleteKeyRevokesEveryActiveCertificateAndRetiresTheToken(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	f.insertCertificate(t, tokenID, "cert-a", "9a")
	f.insertCertificate(t, tokenID, "cert-b", "9c")
	fake := newFakeRevoker()
	f.useCA(fake)

	response, err := call(f, "admin-token", adminv1connect.AdminServiceClient.DeleteKey, &adminv1.DeleteKeyRequest{Token: tokenRefOf("39192733"), ConfirmSerial: "39192733"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.Revoked != 2 || len(response.Msg.FailedCertificateIds) != 0 {
		t.Fatalf("DeleteKey response = %v", response.Msg)
	}
	if fake.reasons["cert-a"] != 5 || fake.reasons["cert-b"] != 5 {
		t.Fatalf("CA reasons = %v, want cessationOfOperation (5)", fake.reasons)
	}
	if f.tokenStatus(t, "39192733") != "retired" {
		t.Fatal("the token must be retired")
	}
	if f.certificateStatus(t, certificateID(t, f, "cert-a")) != "revoked" {
		t.Fatal("the active certificate must be revoked")
	}
}

func certificateID(t *testing.T, f adminFixture, serial string) string {
	t.Helper()
	var id string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT id::text FROM certificates WHERE serial_number = $1`, serial).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDeleteKeyPartialFailureLeavesTheTokenRetiredAndRetryCompletes(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	f.insertCertificate(t, tokenID, "cert-a", "9a")
	f.insertCertificate(t, tokenID, "cert-b", "9c")
	fake := newFakeRevoker()
	fake.refuse["cert-b"] = true
	f.useCA(fake)

	_, err := call(f, "admin-token", adminv1connect.AdminServiceClient.DeleteKey, &adminv1.DeleteKeyRequest{Token: tokenRefOf("39192733"), ConfirmSerial: "39192733"})
	if codeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("partial failure code = %v, want FailedPrecondition", codeOf(err))
	}
	failedID := certificateID(t, f, "cert-b")
	if !strings.Contains(err.Error(), failedID) {
		t.Fatalf("the error must list the failed certificate id: %v", err)
	}
	if f.certificateStatus(t, certificateID(t, f, "cert-a")) != "revoked" || f.certificateStatus(t, failedID) != "active" {
		t.Fatal("the revocable certificate must be revoked and the refused one must stay active")
	}
	if f.tokenStatus(t, "39192733") != "retired" {
		t.Fatal("a partial failure must still leave the token retired")
	}

	delete(fake.refuse, "cert-b")
	response, err := call(f, "admin-token", adminv1connect.AdminServiceClient.DeleteKey, &adminv1.DeleteKeyRequest{Token: tokenRefOf("39192733"), ConfirmSerial: "39192733"})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if response.Msg.Revoked != 1 {
		t.Fatalf("retry revoked %d, want only the remaining certificate", response.Msg.Revoked)
	}
	if f.certificateStatus(t, failedID) != "revoked" || fake.calls("cert-a") != 1 {
		t.Fatal("the retry must revoke the remaining certificate and not repeat finished ones")
	}
}

func TestAlreadyRevokedAtTheCAIsSuccessAndIsAuditedAsSuch(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	certID := f.insertCertificate(t, tokenID, "cert-a", "9a")
	fake := newFakeRevoker()
	fake.already["cert-a"] = true
	f.useCA(fake)

	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.RevokeCertificate, &adminv1.RevokeCertificateRequest{CertificateId: certID, Reason: "keyCompromise"}); err != nil {
		t.Fatalf("already-revoked must succeed: %v", err)
	}
	if f.certificateStatus(t, certID) != "revoked" {
		t.Fatal("the local certificate must be marked revoked")
	}
	var alreadyRevoked bool
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT (detail->>'already_revoked')::boolean FROM audit_events
		WHERE action = 'RevokeCertificate' AND target_id = $1 AND outcome = 'success'
	`, certID).Scan(&alreadyRevoked); err != nil {
		t.Fatal(err)
	}
	if !alreadyRevoked {
		t.Fatal("the audit record must carry already_revoked: true")
	}
}

func TestRevokeCertificateRecordsTheReasonAndRejectsUnknownOnes(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	certID := f.insertCertificate(t, tokenID, "cert-a", "9a")
	fake := newFakeRevoker()
	f.useCA(fake)

	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.RevokeCertificate, &adminv1.RevokeCertificateRequest{CertificateId: certID, Reason: "because"}); codeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown reason code = %v, want InvalidArgument", codeOf(err))
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.RevokeCertificate, &adminv1.RevokeCertificateRequest{CertificateId: certID, Reason: "superseded"}); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT revocation_reason FROM certificates WHERE id = $1::uuid`, certID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "superseded" || fake.reasons["cert-a"] != 4 {
		t.Fatalf("reason = %q, CA code = %d; want superseded (4)", reason, fake.reasons["cert-a"])
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.RevokeCertificate, &adminv1.RevokeCertificateRequest{CertificateId: certID, Reason: "superseded"}); codeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("second revoke = %v, want FailedPrecondition", codeOf(err))
	}
}

func TestMarkFoundBeforeRevocationRestoresTheAssignedToken(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	certID := f.insertCertificate(t, tokenID, "cert-a", "9a")
	f.useCA(newFakeRevoker())

	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.ReportLost, tokenRefOf("39192733")); err != nil {
		t.Fatal(err)
	}
	if f.tokenStatus(t, "39192733") != "lost" {
		t.Fatal("ReportLost must block the token")
	}
	response, err := call(f, "admin-token", adminv1connect.AdminServiceClient.MarkFound, tokenRefOf("39192733"))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.ReEnrollmentRequired {
		t.Fatal("no certificate was revoked, so re-enrollment is not required")
	}
	if f.tokenStatus(t, "39192733") != "active" || f.certificateStatus(t, certID) != "active" {
		t.Fatal("the token and its certificate must return to active")
	}
}

func TestMarkFoundAfterRevocationRequiresReEnrollment(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	certID := f.insertCertificate(t, tokenID, "cert-a", "9a")
	f.useCA(newFakeRevoker())

	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.ReportLost, tokenRefOf("39192733")); err != nil {
		t.Fatal(err)
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.RevokeCertificate, &adminv1.RevokeCertificateRequest{CertificateId: certID, Reason: "keyCompromise"}); err != nil {
		t.Fatal(err)
	}
	response, err := call(f, "admin-token", adminv1connect.AdminServiceClient.MarkFound, tokenRefOf("39192733"))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Msg.ReEnrollmentRequired {
		t.Fatal("a revoked certificate means the user must enroll again")
	}
	if f.tokenStatus(t, "39192733") != "active" {
		t.Fatal("the token is found and active again")
	}
}

func TestMarkFoundRejectsATokenThatIsNotLost(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	_, err := call(f, "admin-token", adminv1connect.AdminServiceClient.MarkFound, tokenRefOf("39192733"))
	if codeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", codeOf(err))
	}
}

func TestAssignUnassignAndNicknameUniquenessPerUser(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	f.seedToken(t, "40000001", "unassigned", nil)

	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.AssignToken, &adminv1.AssignTokenRequest{Token: tokenRefOf("40000001"), UsernameOrEmail: "alice@example.test"}); err != nil {
		t.Fatalf("assign by email: %v", err)
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.AssignToken, &adminv1.AssignTokenRequest{Token: tokenRefOf("40000001"), UsernameOrEmail: "nobody"}); codeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unknown user = %v, want FailedPrecondition", codeOf(err))
	}
	// Both tokens are now assigned to alice. Her nicknames are unique among them.
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.SetNickname, &adminv1.SetNicknameRequest{Token: tokenRefOf("40000001"), Nickname: "39192733 desk"}); codeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate nickname for one user = %v, want AlreadyExists", codeOf(err))
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.SetNickname, &adminv1.SetNicknameRequest{Token: tokenRefOf("40000001"), Nickname: ""}); err != nil {
		t.Fatalf("clearing a nickname: %v", err)
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.UnassignToken, tokenRefOf("40000001")); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if f.tokenStatus(t, "40000001") != "unassigned" {
		t.Fatal("unassign must return the token to unassigned")
	}
}

func TestAddStationAndSetStatusRoundTrip(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.AddStation, &adminv1.AddStationRequest{DnsName: "New-Station.example.test.", Mode: "station"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.AddStation, &adminv1.AddStationRequest{DnsName: "new-station.example.test", Mode: "station"}); codeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate station = %v, want AlreadyExists", codeOf(err))
	}
	listed, err := call(f, "admin-token", adminv1connect.AdminServiceClient.ListStations, &adminv1.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, station := range listed.Msg.Stations {
		if station.DnsName == "new-station.example.test" && station.Status == "active" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stations = %v; the new station must be listed as active", listed.Msg.Stations)
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.SetStationStatus, &adminv1.SetStationStatusRequest{Id: "new-station.example.test", Status: "disabled"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.SetStationStatus, &adminv1.SetStationStatusRequest{Id: "new-station.example.test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditPagingWalksEveryEventOnceNewestFirst(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	for i := 0; i < 5; i++ {
		nickname := "desk " + string(rune('a'+i))
		if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.SetNickname, &adminv1.SetNicknameRequest{Token: tokenRefOf("39192733"), Nickname: nickname}); err != nil {
			t.Fatal(err)
		}
	}
	var seen []int64
	var cursor int64
	for pages := 0; pages < 10; pages++ {
		page, err := call(f, "admin-token", adminv1connect.AdminServiceClient.ListAudit, &adminv1.ListAuditRequest{Action: "SetNickname", BeforeSeq: cursor, PageSize: 2})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Msg.Events {
			seen = append(seen, event.Seq)
		}
		if page.Msg.NextBeforeSeq == 0 {
			break
		}
		cursor = page.Msg.NextBeforeSeq
	}
	if len(seen) != 5 {
		t.Fatalf("paged %d SetNickname events, want 5", len(seen))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] >= seen[i-1] {
			t.Fatalf("events not strictly newest first: %v", seen)
		}
	}
	verified, err := call(f, "admin-token", adminv1connect.AdminServiceClient.VerifyAudit, &adminv1.Empty{})
	if err != nil || !verified.Msg.Ok {
		t.Fatalf("audit chain verification = %v, %v", verified, err)
	}
}

func TestListCertificatesFiltersByStatusAndToken(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)
	f.insertCertificate(t, tokenID, "cert-a", "9a")
	f.seedToken(t, "40000001", "unassigned", nil)

	active, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListCertificates, &adminv1.ListCertificatesRequest{Status: "active"})
	if err != nil || len(active.Msg.Certificates) != 1 || active.Msg.Certificates[0].TokenSerial != "39192733" {
		t.Fatalf("active filter = %v, %v", active, err)
	}
	none, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListCertificates, &adminv1.ListCertificatesRequest{TokenSerial: "40000001"})
	if err != nil || len(none.Msg.Certificates) != 0 {
		t.Fatalf("token filter = %v, %v", none, err)
	}
}
