package gateway

import (
	"context"
	"log/slog"
	"maps"

	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// auditTx is a handler's write transaction. It rolls back unless Commit succeeds, so a handler cannot leave a
// recorded decision uncommitted or forget the rollback.
type auditTx struct {
	pgx.Tx
	logger    *slog.Logger
	committed bool
}

func (s *Server) beginAuditTx(ctx context.Context) (*auditTx, error) {
	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &auditTx{Tx: tx, logger: s.logger}, nil
}

// Commit commits the transaction and marks it committed.
func (t *auditTx) Commit(ctx context.Context) error {
	if err := t.Tx.Commit(ctx); err != nil {
		return err
	}
	t.committed = true
	return nil
}

func (t *auditTx) rollbackUnlessCommitted(ctx context.Context) {
	if !t.committed {
		_ = t.Tx.Rollback(ctx)
	}
}

// auditAndCommit appends event and commits the transaction. Failures are logged here.
func (t *auditTx) auditAndCommit(ctx context.Context, event audit.Event) error {
	if _, err := audit.Append(ctx, t, event); err != nil {
		t.logger.Error("append audit event failed", "action", event.Action, "outcome", event.Outcome, "error", err)
		return err
	}
	if err := t.Commit(ctx); err != nil {
		t.logger.Error("commit audited transaction failed", "action", event.Action, "outcome", event.Outcome, "error", err)
		return err
	}
	return nil
}

// auditDecision records one handler's decision about its target inside tx. detail holds the keys every
// decision of the handler carries; failure is the Internal message returned when a decision cannot be recorded.
type auditDecision struct {
	tx                                               *auditTx
	actorType, actorID, action, targetType, targetID string
	detail                                           map[string]any
	failure                                          string
}

// event builds the decision's audit event from the handler keys plus detail.
func (d auditDecision) event(outcome audit.Outcome, detail map[string]any) audit.Event {
	merged := make(map[string]any, len(detail)+len(d.detail))
	maps.Copy(merged, detail)
	maps.Copy(merged, d.detail)
	return audit.Event{
		ActorType: d.actorType, ActorID: d.actorID, Action: d.action,
		TargetType: d.targetType, TargetID: d.targetID, Outcome: string(outcome), Detail: merged,
	}
}

// record audits the decision and commits it, returning an Internal status if either step fails.
func (d auditDecision) record(ctx context.Context, outcome audit.Outcome, detail map[string]any) error {
	if err := d.tx.auditAndCommit(ctx, d.event(outcome, detail)); err != nil {
		return status.Error(codes.Internal, d.failure)
	}
	return nil
}

// deny records a policy or validation rejection with its reason, commits it, and returns it as a status with code.
func (d auditDecision) deny(ctx context.Context, code codes.Code, reason string, detail map[string]any) error {
	return d.conclude(ctx, code, audit.OutcomeDenied, reason, detail)
}

// fail records a backend or upstream failure with its reason, commits it, and returns it as a status with code.
func (d auditDecision) fail(ctx context.Context, code codes.Code, reason string, detail map[string]any) error {
	return d.conclude(ctx, code, audit.OutcomeError, reason, detail)
}

func (d auditDecision) conclude(ctx context.Context, code codes.Code, outcome audit.Outcome, reason string, detail map[string]any) error {
	withReason := make(map[string]any, len(detail)+1)
	maps.Copy(withReason, detail)
	withReason["reason"] = reason
	if err := d.record(ctx, outcome, withReason); err != nil {
		return err
	}
	return status.Error(code, reason)
}
