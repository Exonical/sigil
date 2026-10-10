package policy

import (
	"testing"

	"github.com/Exonical/sigil/backend/internal/db"
)

func TestAuthorizeIssuance(t *testing.T) {
	const alice = "user-alice"
	const bob = "user-bob"
	assigned := func(id string) *string { return &id }
	active := &db.Token{Status: "active", AssignedUserID: assigned(alice)}
	operatorStation := db.Station{Status: "active", Mode: "station"}
	userStation := db.Station{Status: "active", Mode: "user"}
	profileRoles := []string{"admin", "helpdesk", "user"}

	tests := []struct {
		name    string
		request IssuanceRequest
		allowed bool
		reason  string
	}{
		{
			name:    "station helpdesk enrolls any assigned active token",
			request: IssuanceRequest{Roles: []string{"helpdesk"}, Station: operatorStation, Token: active, UserID: bob, ProfileRoles: profileRoles},
			allowed: true,
		},
		{
			name:    "station admin enrolls any assigned active token",
			request: IssuanceRequest{Roles: []string{"admin"}, Station: operatorStation, Token: active, UserID: bob, ProfileRoles: []string{"admin"}},
			allowed: true,
		},
		{
			name:    "operator role is ignored on a user-mode machine",
			request: IssuanceRequest{Roles: []string{"helpdesk"}, Station: userStation, Token: active, UserID: bob, ProfileRoles: []string{"admin", "helpdesk"}},
			allowed: false,
			reason:  "user is not authorized to enroll a certificate on this token",
		},
		{
			name:    "assigned user self-enrolls when a role matches the profile",
			request: IssuanceRequest{Roles: []string{"user"}, Station: userStation, Token: active, UserID: alice, ProfileRoles: profileRoles},
			allowed: true,
		},
		{
			name:    "assigned user without a matching profile role is denied",
			request: IssuanceRequest{Roles: []string{"auditor"}, Station: userStation, Token: active, UserID: alice, ProfileRoles: profileRoles},
			allowed: false,
			reason:  "user is not authorized to enroll a certificate on this token",
		},
		{
			name:    "a different user cannot self-enroll another person's token",
			request: IssuanceRequest{Roles: []string{"user"}, Station: userStation, Token: active, UserID: bob, ProfileRoles: profileRoles},
			allowed: false,
			reason:  "user is not authorized to enroll a certificate on this token",
		},
		{
			name:    "unassigned token is rejected even for operators",
			request: IssuanceRequest{Roles: []string{"admin"}, Station: operatorStation, Token: &db.Token{Status: "active"}, UserID: bob, ProfileRoles: profileRoles},
			allowed: false,
			reason:  "token is not assigned to a user",
		},
		{
			name:    "unassigned status is rejected",
			request: IssuanceRequest{Roles: []string{"admin"}, Station: operatorStation, Token: &db.Token{Status: "unassigned"}, UserID: bob, ProfileRoles: profileRoles},
			allowed: false,
			reason:  "token is not active",
		},
		{
			name:    "lost token is rejected",
			request: IssuanceRequest{Roles: []string{"admin"}, Station: operatorStation, Token: &db.Token{Status: "lost", AssignedUserID: assigned(alice)}, UserID: bob, ProfileRoles: profileRoles},
			allowed: false,
			reason:  "token is not active",
		},
		{
			name:    "missing token is rejected",
			request: IssuanceRequest{Roles: []string{"admin"}, Station: operatorStation, UserID: bob, ProfileRoles: profileRoles},
			allowed: false,
			reason:  "token is not in inventory",
		},
		{
			name:    "inactive station is rejected",
			request: IssuanceRequest{Roles: []string{"admin"}, Station: db.Station{Status: "revoked", Mode: "station"}, Token: active, UserID: bob, ProfileRoles: profileRoles},
			allowed: false,
			reason:  "station is not active",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := AuthorizeIssuance(test.request)
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %v (%s), want %v", decision.Allowed, decision.Reason, test.allowed)
			}
			if !test.allowed && decision.Reason != test.reason {
				t.Fatalf("reason = %q, want %q", decision.Reason, test.reason)
			}
		})
	}
}

func TestProfileVisible(t *testing.T) {
	if !ProfileVisible([]string{"auditor", "user"}, []string{"user"}) {
		t.Fatal("a matching role should expose the profile")
	}
	if ProfileVisible([]string{"auditor"}, []string{"admin", "helpdesk"}) {
		t.Fatal("no matching role should hide the profile")
	}
}
