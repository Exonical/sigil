package gateway

import (
	"reflect"
	"testing"

	"github.com/Exonical/sigil/backend/internal/audit"
)

func TestAuditDecisionEventAddsHandlerDetail(t *testing.T) {
	decision := auditDecision{
		actorType: "user", actorID: "user-1", action: "IssueCertificate",
		targetType: "token", targetID: "12345678",
		detail: map[string]any{"profile": "piv-auth"},
	}
	detail := map[string]any{"reason": "token is not in inventory"}

	got := decision.event(audit.OutcomeDenied, detail)
	want := audit.Event{
		ActorType: "user", ActorID: "user-1", Action: "IssueCertificate",
		TargetType: "token", TargetID: "12345678", Outcome: "denied",
		Detail: map[string]any{"profile": "piv-auth", "reason": "token is not in inventory"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("event = %#v, want %#v", got, want)
	}
	if len(detail) != 1 || len(decision.detail) != 1 {
		t.Fatalf("event modified its inputs: detail %v, handler detail %v", detail, decision.detail)
	}
	if got := decision.event(audit.OutcomeSuccess, nil).Detail; !reflect.DeepEqual(got, map[string]any{"profile": "piv-auth"}) {
		t.Fatalf("event without detail = %v", got)
	}
}
