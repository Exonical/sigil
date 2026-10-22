package gateway

import (
	"context"
	"reflect"
	"testing"

	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestAuditDecisionStandaloneReturnsTheFailureWhenTheAuditCannotBeRecorded(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://sigil@localhost:1/sigil")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	decision := auditDecision{
		actorType: "user", actorID: "user-1", action: "AuthorizeManagedOperation",
		targetType: "token", targetID: "12345678",
		detail:  map[string]any{"operation": "PIV_SET_RETRIES"},
		failure: "could not record managed-operation decision",
	}

	for name, err := range map[string]error{
		"deny": decision.denyStandalone(ctx, pool, codes.InvalidArgument, "not supported"),
		"fail": decision.failStandalone(ctx, pool, "escrow is not configured",
			status.Error(codes.FailedPrecondition, "managed escrow is not configured")),
	} {
		if status.Code(err) != codes.Internal || status.Convert(err).Message() != decision.failure {
			t.Fatalf("%s with unrecordable audit = %v, want Internal %q", name, err, decision.failure)
		}
	}
}
