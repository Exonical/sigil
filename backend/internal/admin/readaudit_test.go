package admin

import (
	"encoding/json"
	"testing"

	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
	"github.com/Exonical/sigil/backend/gen/sigil/admin/v1/adminv1connect"
	"github.com/Exonical/sigil/backend/internal/audit"
)

// readAuditRow returns the detail of the newest audit record with the given action, and its actor and target.
func readAuditRow(t *testing.T, f adminFixture, action string) (actor, target string, detail map[string]any) {
	t.Helper()
	var detailJSON string
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT actor_id, target_id, detail::text FROM audit_events WHERE action = $1 ORDER BY seq DESC LIMIT 1
	`, action).Scan(&actor, &target, &detailJSON); err != nil {
		t.Fatalf("no %s audit record: %v", action, err)
	}
	if err := json.Unmarshal([]byte(detailJSON), &detail); err != nil {
		t.Fatal(err)
	}
	return actor, target, detail
}

func countAudit(t *testing.T, f adminFixture) int {
	t.Helper()
	var count int
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func assertChainVerifies(t *testing.T, f adminFixture) {
	t.Helper()
	if err := audit.Verify(f.ctx, f.store.Pool); err != nil {
		t.Fatalf("the audit chain must verify after reads: %v", err)
	}
}

func TestGetTokenIsChainAuditedWithoutResponseData(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	if _, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.GetToken, tokenRefOf("39192733")); err != nil {
		t.Fatal(err)
	}
	actor, target, detail := readAuditRow(t, f, "Admin.GetToken")
	if actor != "helpdesk-user" || target != "39192733" {
		t.Fatalf("actor=%q target=%q, want the helpdesk user and the token serial", actor, target)
	}
	if detail["vendor"] != "Yubico" {
		t.Fatalf("detail = %v, want the request filters", detail)
	}
	for _, forbidden := range []string{"certificates", "escrow", "audit", "token", "assigned_user"} {
		if _, present := detail[forbidden]; present {
			t.Fatalf("detail must not carry response data; found %q in %v", forbidden, detail)
		}
	}
	assertChainVerifies(t, f)
}

func TestListAuditIsChainAuditedWithItsFiltersOnly(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.SetNickname, &adminv1.SetNicknameRequest{Token: tokenRefOf("39192733"), Nickname: "walk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(f, "admin-token", adminv1connect.AdminServiceClient.ListAudit, &adminv1.ListAuditRequest{Action: "SetNickname", PageSize: 5}); err != nil {
		t.Fatal(err)
	}
	actor, target, detail := readAuditRow(t, f, "Admin.ListAudit")
	if actor != "admin-user" || target != "" {
		t.Fatalf("actor=%q target=%q, want the admin user and no target", actor, target)
	}
	if detail["action"] != "SetNickname" || detail["page_size"] != float64(5) {
		t.Fatalf("detail = %v, want the action and page-size filters", detail)
	}
	if _, present := detail["events"]; present {
		t.Fatal("ListAudit detail must not contain the returned events")
	}
	assertChainVerifies(t, f)
}

func TestVerifyAuditIsChainAuditedWithItsResult(t *testing.T) {
	f := newAdminFixture(t)
	response, err := call(f, "admin-token", adminv1connect.AdminServiceClient.VerifyAudit, &adminv1.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	actor, target, detail := readAuditRow(t, f, "Admin.VerifyAudit")
	if actor != "admin-user" || target != "" {
		t.Fatalf("actor=%q target=%q", actor, target)
	}
	if detail["ok"] != response.Msg.Ok {
		t.Fatalf("detail ok=%v, response ok=%v", detail["ok"], response.Msg.Ok)
	}
	assertChainVerifies(t, f)
}

func TestHighVolumeReadsDoNotWriteTheChain(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	before := countAudit(t, f)
	if _, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.GetDashboard, &adminv1.Empty{}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListTokens, &adminv1.ListTokensRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListStations, &adminv1.Empty{}); err != nil {
		t.Fatal(err)
	}
	if after := countAudit(t, f); after != before {
		t.Fatalf("audit rows went from %d to %d; high-volume reads must only be logged", before, after)
	}
}
