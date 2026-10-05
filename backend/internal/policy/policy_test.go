package policy

import (
	"testing"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	"github.com/Exonical/sigil/backend/internal/db"
)

func TestAuthorize(t *testing.T) {
	assigned := "user-1"
	tests := []struct {
		name    string
		request Request
		allowed bool
	}{
		{
			name: "admin at station may use unassigned token",
			request: Request{
				Roles:     []string{"admin"},
				Station:   db.Station{Mode: "station", Status: "active"},
				Token:     &db.Token{Status: "unassigned"},
				Operation: agentv1.Operation_PIV_GENERATE_KEY,
			},
			allowed: true,
		},
		{
			name: "admin at station may delete a PIV key",
			request: Request{
				Roles:     []string{"admin"},
				Station:   db.Station{Mode: "station", Status: "active"},
				Token:     &db.Token{Status: "unassigned"},
				Operation: agentv1.Operation_PIV_DELETE_KEY,
			},
			allowed: true,
		},
		{
			name: "helpdesk at station may use active token",
			request: Request{
				Roles:     []string{"helpdesk"},
				Station:   db.Station{Mode: "station", Status: "active"},
				Token:     &db.Token{Status: "active"},
				Operation: agentv1.Operation_PIV_IMPORT_CERTIFICATE,
			},
			allowed: true,
		},
		{
			name: "admin from user station is denied",
			request: Request{
				Roles:     []string{"admin"},
				Station:   db.Station{Mode: "user", Status: "active"},
				Token:     &db.Token{Status: "active"},
				Operation: agentv1.Operation_PIV_GENERATE_KEY,
			},
		},
		{
			name: "helpdesk may self-serve at a user station",
			request: Request{
				Roles:                 []string{"helpdesk"},
				Station:               db.Station{Mode: "user", Status: "active"},
				Token:                 &db.Token{Status: "active", AssignedUserID: &assigned},
				Operation:             agentv1.Operation_PIV_UNBLOCK_PIN,
				UserID:                assigned,
				SelfServiceOperations: []string{"PIV_UNBLOCK_PIN"},
			},
			allowed: true,
		},
		{
			name: "helpdesk at a user station cannot use a non-self-service operation",
			request: Request{
				Roles:                 []string{"helpdesk"},
				Station:               db.Station{Mode: "user", Status: "active"},
				Token:                 &db.Token{Status: "active", AssignedUserID: &assigned},
				Operation:             agentv1.Operation_PIV_GENERATE_KEY,
				UserID:                assigned,
				SelfServiceOperations: []string{"PIV_UNBLOCK_PIN"},
			},
		},
		{
			name: "helpdesk at a user station cannot self-serve on another user's token",
			request: Request{
				Roles:                 []string{"helpdesk"},
				Station:               db.Station{Mode: "user", Status: "active"},
				Token:                 &db.Token{Status: "active", AssignedUserID: &assigned},
				Operation:             agentv1.Operation_PIV_UNBLOCK_PIN,
				UserID:                "other",
				SelfServiceOperations: []string{"PIV_UNBLOCK_PIN"},
			},
		},
		{
			name: "disabled station is denied",
			request: Request{
				Roles:     []string{"admin"},
				Station:   db.Station{Mode: "station", Status: "disabled"},
				Token:     &db.Token{Status: "unassigned"},
				Operation: agentv1.Operation_PIV_GENERATE_KEY,
			},
		},
		{
			name: "self service is limited to assigned active token",
			request: Request{
				Roles:                 []string{"user"},
				Station:               db.Station{Mode: "user", Status: "active"},
				Token:                 &db.Token{Status: "active", AssignedUserID: &assigned},
				Operation:             agentv1.Operation_PIV_UNBLOCK_PIN,
				UserID:                assigned,
				SelfServiceOperations: []string{"PIV_UNBLOCK_PIN"},
			},
			allowed: true,
		},
		{
			name: "self service cannot use another user's token",
			request: Request{
				Roles:                 []string{"user"},
				Station:               db.Station{Mode: "user", Status: "active"},
				Token:                 &db.Token{Status: "active", AssignedUserID: &assigned},
				Operation:             agentv1.Operation_PIV_UNBLOCK_PIN,
				UserID:                "other",
				SelfServiceOperations: []string{"PIV_UNBLOCK_PIN"},
			},
		},
		{
			name: "self service cannot use an unassigned token",
			request: Request{
				Roles:                 []string{"user"},
				Station:               db.Station{Mode: "user", Status: "active"},
				Token:                 &db.Token{Status: "unassigned"},
				Operation:             agentv1.Operation_PIV_UNBLOCK_PIN,
				UserID:                assigned,
				SelfServiceOperations: []string{"PIV_UNBLOCK_PIN"},
			},
		},
		{
			name: "lost token is denied to operators",
			request: Request{
				Roles:     []string{"admin"},
				Station:   db.Station{Mode: "station", Status: "active"},
				Token:     &db.Token{Status: "lost"},
				Operation: agentv1.Operation_PIV_GENERATE_KEY,
			},
		},
		{
			name: "retired token is denied to operators",
			request: Request{
				Roles:     []string{"helpdesk"},
				Station:   db.Station{Mode: "station", Status: "active"},
				Token:     &db.Token{Status: "retired"},
				Operation: agentv1.Operation_PIV_GENERATE_KEY,
			},
		},
		{
			name: "unknown token is denied",
			request: Request{
				Roles:     []string{"admin"},
				Station:   db.Station{Mode: "station", Status: "active"},
				Operation: agentv1.Operation_PIV_GENERATE_KEY,
			},
		},
		{
			name: "unspecified operation is denied",
			request: Request{
				Roles:   []string{"admin"},
				Station: db.Station{Mode: "station", Status: "active"},
				Token:   &db.Token{Status: "unassigned"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := Authorize(test.request)
			if decision.Allowed != test.allowed {
				t.Fatalf("decision=%+v allowed=%v", decision, test.allowed)
			}
			if decision.Reason == "" {
				t.Fatal("decision has no reason")
			}
		})
	}
}
