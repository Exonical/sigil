package admin

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
	"github.com/Exonical/sigil/backend/internal/audit"
)

// ListCertificates lists certificates with optional status, expiry, profile, and token filters.
func (s *Service) ListCertificates(ctx context.Context, req *connect.Request[adminv1.ListCertificatesRequest]) (*connect.Response[adminv1.ListCertificatesResponse], error) {
	logRead(ctx, "ListCertificates", map[string]any{"status": req.Msg.Status, "profile": req.Msg.Profile, "token_serial": req.Msg.TokenSerial, "expiring_before_unix": req.Msg.ExpiringBeforeUnix})
	limit, offset, err := pageBounds(req.Msg.PageSize, req.Msg.Page)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.Pool.Query(ctx, `
		SELECT c.id::text, t.serial, c.slot, c.profile, COALESCE(NULLIF(u.username, ''), u.display_name, ''),
		       c.serial_number, c.subject,
		       EXTRACT(EPOCH FROM c.not_before)::bigint, EXTRACT(EPOCH FROM c.not_after)::bigint,
		       c.status, COALESCE(EXTRACT(EPOCH FROM c.revoked_at)::bigint, 0), c.revocation_reason,
		       count(*) OVER()
		FROM certificates c
		JOIN tokens t ON t.id = c.token_id
		JOIN users u ON u.id = c.user_id
		WHERE ($1 = '' OR c.status = $1)
		  AND ($2 = 0 OR c.not_after < to_timestamp($2::double precision))
		  AND ($3 = '' OR c.profile = $3)
		  AND ($4 = '' OR t.serial = $4)
		ORDER BY c.not_after, c.id
		LIMIT $5 OFFSET $6
	`, req.Msg.Status, req.Msg.ExpiringBeforeUnix, req.Msg.Profile, req.Msg.TokenSerial, limit, offset)
	if err != nil {
		return nil, internal("could not list certificates", err)
	}
	defer rows.Close()
	response := &adminv1.ListCertificatesResponse{}
	for rows.Next() {
		var c adminv1.CertificateSummary
		var total int64
		if err := rows.Scan(&c.Id, &c.TokenSerial, &c.Slot, &c.Profile, &c.UserDisplay, &c.SerialNumber, &c.Subject,
			&c.NotBeforeUnix, &c.NotAfterUnix, &c.Status, &c.RevokedAtUnix, &c.RevocationReason, &total); err != nil {
			return nil, internal("could not read certificates", err)
		}
		response.Certificates = append(response.Certificates, &c)
		response.Total = total
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read certificates", err)
	}
	if err := s.attachAttestations(ctx, response.Certificates); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

// ListStations lists registered stations.
func (s *Service) ListStations(ctx context.Context, _ *connect.Request[adminv1.Empty]) (*connect.Response[adminv1.ListStationsResponse], error) {
	logRead(ctx, "ListStations", nil)
	rows, err := s.store.Pool.Query(ctx, `SELECT id, dns_name, display_name, mode, status FROM stations ORDER BY dns_name`)
	if err != nil {
		return nil, internal("could not list stations", err)
	}
	defer rows.Close()
	response := &adminv1.ListStationsResponse{}
	for rows.Next() {
		var station adminv1.StationSummary
		if err := rows.Scan(&station.Id, &station.DnsName, &station.DisplayName, &station.Mode, &station.Status); err != nil {
			return nil, internal("could not read stations", err)
		}
		response.Stations = append(response.Stations, &station)
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read stations", err)
	}
	return connect.NewResponse(response), nil
}

// ListUsers lists authenticated users with the number of tokens assigned to each.
func (s *Service) ListUsers(ctx context.Context, req *connect.Request[adminv1.ListUsersRequest]) (*connect.Response[adminv1.ListUsersResponse], error) {
	logRead(ctx, "ListUsers", map[string]any{"search_set": req.Msg.Search != ""})
	limit, offset, err := pageBounds(req.Msg.PageSize, req.Msg.Page)
	if err != nil {
		return nil, err
	}
	pattern := ""
	if search := strings.TrimSpace(req.Msg.Search); search != "" {
		pattern = "%" + escapeLike(search) + "%"
	}
	rows, err := s.store.Pool.Query(ctx, `
		SELECT u.id::text, u.username, u.email, u.display_name, count(t.id), count(*) OVER()
		FROM users u
		LEFT JOIN tokens t ON t.assigned_user_id = u.id
		WHERE ($1 = '' OR u.username ILIKE $1 ESCAPE '\' OR u.email ILIKE $1 ESCAPE '\' OR u.display_name ILIKE $1 ESCAPE '\')
		GROUP BY u.id
		ORDER BY u.username, u.id
		LIMIT $2 OFFSET $3
	`, pattern, limit, offset)
	if err != nil {
		return nil, internal("could not list users", err)
	}
	defer rows.Close()
	response := &adminv1.ListUsersResponse{}
	for rows.Next() {
		var entry adminv1.UserWithTokens
		var user adminv1.UserSummary
		var total int64
		if err := rows.Scan(&user.Id, &user.Username, &user.Email, &user.DisplayName, &entry.TokenCount, &total); err != nil {
			return nil, internal("could not read users", err)
		}
		entry.User = &user
		response.Users = append(response.Users, &entry)
		response.Total = total
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read users", err)
	}
	return connect.NewResponse(response), nil
}

// ListAudit pages the audit trail newest first. The cursor is the sequence number of the last event returned.
func (s *Service) ListAudit(ctx context.Context, req *connect.Request[adminv1.ListAuditRequest]) (*connect.Response[adminv1.ListAuditResponse], error) {
	limit, _, err := pageBounds(req.Msg.PageSize, 0)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.Pool.Query(ctx, `
		SELECT seq, EXTRACT(EPOCH FROM occurred_at)::bigint, actor_type, actor_id, action, target_type, target_id,
		       outcome, detail::text
		FROM audit_events
		WHERE ($1 = '' OR actor_type = $1)
		  AND ($2 = '' OR actor_id = $2)
		  AND ($3 = '' OR action = $3)
		  AND ($4 = '' OR target_id = $4)
		  AND ($5 = 0 OR occurred_at >= to_timestamp($5::double precision))
		  AND ($6 = 0 OR occurred_at <= to_timestamp($6::double precision))
		  AND ($7 = 0 OR seq < $7)
		ORDER BY seq DESC
		LIMIT $8
	`, req.Msg.ActorType, req.Msg.ActorId, req.Msg.Action, req.Msg.Target,
		req.Msg.FromUnix, req.Msg.ToUnix, req.Msg.BeforeSeq, limit)
	if err != nil {
		return nil, internal("could not read the audit trail", err)
	}
	defer rows.Close()
	response := &adminv1.ListAuditResponse{}
	for rows.Next() {
		var e adminv1.AuditEvent
		if err := rows.Scan(&e.Seq, &e.OccurredAtUnix, &e.ActorType, &e.ActorId, &e.Action, &e.TargetType, &e.TargetId,
			&e.Outcome, &e.DetailJson); err != nil {
			return nil, internal("could not read the audit trail", err)
		}
		response.Events = append(response.Events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read the audit trail", err)
	}
	if len(response.Events) == limit {
		response.NextBeforeSeq = response.Events[len(response.Events)-1].Seq
	}
	if err := s.auditRead(ctx, "Admin.ListAudit", "none", "", map[string]any{"actor_type": req.Msg.ActorType, "actor_id": req.Msg.ActorId, "action": req.Msg.Action, "target": req.Msg.Target, "from_unix": req.Msg.FromUnix, "to_unix": req.Msg.ToUnix, "before_seq": req.Msg.BeforeSeq, "page_size": limit}); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

// VerifyAudit checks the audit hash chain. A broken chain is a result, not an RPC error.
func (s *Service) VerifyAudit(ctx context.Context, _ *connect.Request[adminv1.Empty]) (*connect.Response[adminv1.VerifyAuditResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	var count int64
	if err := s.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&count); err != nil {
		return nil, internal("could not count audit events", err)
	}
	response := &adminv1.VerifyAuditResponse{Ok: true, EventsChecked: count}
	if err := audit.Verify(ctx, s.store.Pool); err != nil {
		response.Ok = false
		response.Failure = err.Error()
	}
	if err := s.auditRead(ctx, "Admin.VerifyAudit", "none", "", map[string]any{"ok": response.Ok, "events_checked": count}); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}
