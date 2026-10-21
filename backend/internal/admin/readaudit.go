package admin

import (
	"context"
	"log/slog"
)

// auditRead appends a chained audit record for a sensitive read. The detail carries the request filters only,
// never response data, so the chain records who looked at what without copying it.
func (s *Service) auditRead(ctx context.Context, action, targetType, targetID string, detail map[string]any) error {
	if err := auditStandalone(ctx, s, action, targetType, targetID, detail); err != nil {
		return internal("could not record the read", err)
	}
	return nil
}

// logRead writes a structured log line for a high-volume read. These reads are not chained, so the audit
// trail is not flooded, but each call is still recorded with its actor and filters.
func logRead(ctx context.Context, rpc string, filters map[string]any) {
	slog.InfoContext(ctx, "admin read", "actor", actorID(ctx), "rpc", rpc, "filters", filters)
}
