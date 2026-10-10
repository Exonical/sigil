package admin

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
	auditDetailRows = 50
	certificateRows = 100
	defaultVendor   = "Yubico"
)

func pageBounds(size, page int32) (int, int, error) {
	if page < 0 {
		return 0, 0, connect.NewError(connect.CodeInvalidArgument, errors.New("page must not be negative"))
	}
	if size <= 0 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}
	return int(size), int(page) * int(size), nil
}

// escapeLike makes user text match literally inside an ILIKE pattern.
func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// GetDashboard returns counts for the portal home page.
func (s *Service) GetDashboard(ctx context.Context, _ *connect.Request[adminv1.Empty]) (*connect.Response[adminv1.DashboardResponse], error) {
	response := &adminv1.DashboardResponse{
		TokensByStatus:   map[string]int64{},
		StationsByStatus: map[string]int64{},
	}
	if err := s.countByStatus(ctx, response.TokensByStatus, `SELECT status, count(*) FROM tokens GROUP BY status`); err != nil {
		return nil, err
	}
	if err := s.countByStatus(ctx, response.StationsByStatus, `SELECT status, count(*) FROM stations GROUP BY status`); err != nil {
		return nil, err
	}
	if err := s.store.Pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status = 'active'),
			count(*) FILTER (WHERE status = 'active' AND not_after > now() AND not_after <= now() + interval '30 days')
		FROM certificates
	`).Scan(&response.ActiveCertificates, &response.CertificatesExpiring_30Days); err != nil {
		return nil, internal("could not count certificates", err)
	}
	if err := s.store.Pool.QueryRow(ctx, `
		SELECT count(DISTINCT t.id)
		FROM tokens t
		JOIN certificates c ON c.token_id = t.id AND c.status = 'active'
		WHERE t.status = 'lost'
	`).Scan(&response.LostTokensPendingRevocation); err != nil {
		return nil, internal("could not count lost tokens", err)
	}
	return connect.NewResponse(response), nil
}

func (s *Service) countByStatus(ctx context.Context, into map[string]int64, query string) error {
	rows, err := s.store.Pool.Query(ctx, query)
	if err != nil {
		return internal("could not count by status", err)
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return internal("could not read counts", err)
		}
		into[status] = count
	}
	if err := rows.Err(); err != nil {
		return internal("could not read counts", err)
	}
	return nil
}

// ListTokens lists inventory tokens with a text search over serial, nickname, and assigned user, and a status filter.
func (s *Service) ListTokens(ctx context.Context, req *connect.Request[adminv1.ListTokensRequest]) (*connect.Response[adminv1.ListTokensResponse], error) {
	limit, offset, err := pageBounds(req.Msg.PageSize, req.Msg.Page)
	if err != nil {
		return nil, err
	}
	pattern := "%" + escapeLike(strings.TrimSpace(req.Msg.Search)) + "%"
	rows, err := s.store.Pool.Query(ctx, tokenSummaryQuery(`
		WHERE ($1 = '%%' OR t.serial ILIKE $1 ESCAPE '\' OR t.nickname ILIKE $1 ESCAPE '\'
		       OR u.username ILIKE $1 ESCAPE '\' OR u.email ILIKE $1 ESCAPE '\')
		  AND ($2 = '' OR t.status = $2)
		ORDER BY t.serial
		LIMIT $3 OFFSET $4`), pattern, req.Msg.Status, limit, offset)
	if err != nil {
		return nil, internal("could not list tokens", err)
	}
	defer rows.Close()
	response := &adminv1.ListTokensResponse{}
	for rows.Next() {
		token, total, err := scanToken(rows)
		if err != nil {
			return nil, internal("could not read tokens", err)
		}
		response.Tokens = append(response.Tokens, token)
		response.Total = total
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read tokens", err)
	}
	if len(response.Tokens) == 0 && offset == 0 {
		response.Total = 0
	}
	return connect.NewResponse(response), nil
}

// tokenSummaryQuery selects token summaries; the caller appends a WHERE clause and an ORDER BY with LIMIT.
func tokenSummaryQuery(tail string) string {
	return `
		SELECT
			t.id::text, t.vendor, t.model, t.serial, t.firmware, t.form_factor, COALESCE(t.nickname, ''), t.status,
			COALESCE(u.id::text, ''), COALESCE(u.username, ''), COALESCE(u.email, ''), COALESCE(u.display_name, ''),
			COALESCE(EXTRACT(EPOCH FROM t.lost_at)::bigint, 0), EXTRACT(EPOCH FROM t.last_seen_at)::bigint,
			(SELECT count(*) FROM certificates c WHERE c.token_id = t.id AND c.status = 'active'),
			count(*) OVER()
		FROM tokens t
		LEFT JOIN users u ON u.id = t.assigned_user_id
	` + tail
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanToken(row rowScanner) (*adminv1.TokenSummary, int64, error) {
	var (
		token                adminv1.TokenSummary
		assignedID, username string
		email, displayName   string
		total                int64
		lostAt, lastSeenUnix int64
		activeCertificates   int64
	)
	if err := row.Scan(&token.Id, &token.Vendor, &token.Model, &token.Serial, &token.Firmware, &token.FormFactor,
		&token.Nickname, &token.Status, &assignedID, &username, &email, &displayName,
		&lostAt, &lastSeenUnix, &activeCertificates, &total); err != nil {
		return nil, 0, err
	}
	token.LostAtUnix = lostAt
	token.LastSeenUnix = lastSeenUnix
	token.ActiveCertificates = activeCertificates
	if assignedID != "" {
		token.AssignedUser = &adminv1.UserSummary{Id: assignedID, Username: username, Email: email, DisplayName: displayName}
	}
	return &token, total, nil
}

// GetToken returns one token with its user, certificates, escrow metadata, and recent audit events.
// Escrow values are never read: the query selects only kind, version, state, and dates.
func (s *Service) GetToken(ctx context.Context, req *connect.Request[adminv1.TokenRef]) (*connect.Response[adminv1.GetTokenResponse], error) {
	vendor := req.Msg.Vendor
	if vendor == "" {
		vendor = defaultVendor
	}
	if req.Msg.Serial == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a token serial is required"))
	}
	rows, err := s.store.Pool.Query(ctx, tokenSummaryQuery(`WHERE t.vendor = $1 AND t.serial = $2`), vendor, req.Msg.Serial)
	if err != nil {
		return nil, internal("could not read the token", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, internal("could not read the token", err)
		}
		return nil, connect.NewError(connect.CodeNotFound, errors.New("the token is not in inventory"))
	}
	token, _, err := scanToken(rows)
	if err != nil {
		return nil, internal("could not read the token", err)
	}
	rows.Close()

	response := &adminv1.GetTokenResponse{Token: token}
	if response.Certificates, err = s.certificatesFor(ctx, token.Id); err != nil {
		return nil, err
	}
	if response.Escrow, err = s.escrowFor(ctx, token.Id); err != nil {
		return nil, err
	}
	if response.Audit, err = s.auditFor(ctx, token.Serial, token.Id); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Service) certificatesFor(ctx context.Context, tokenID string) ([]*adminv1.CertificateSummary, error) {
	rows, err := s.store.Pool.Query(ctx, `
		SELECT c.id::text, t.serial, c.slot, c.profile, COALESCE(NULLIF(u.username, ''), u.display_name, ''),
		       c.serial_number, c.subject,
		       EXTRACT(EPOCH FROM c.not_before)::bigint, EXTRACT(EPOCH FROM c.not_after)::bigint,
		       c.status, COALESCE(EXTRACT(EPOCH FROM c.revoked_at)::bigint, 0), c.revocation_reason
		FROM certificates c
		JOIN tokens t ON t.id = c.token_id
		JOIN users u ON u.id = c.user_id
		WHERE c.token_id = $1
		ORDER BY c.not_after DESC
		LIMIT $2
	`, tokenID, certificateRows)
	if err != nil {
		return nil, internal("could not list certificates", err)
	}
	defer rows.Close()
	var out []*adminv1.CertificateSummary
	for rows.Next() {
		var c adminv1.CertificateSummary
		if err := rows.Scan(&c.Id, &c.TokenSerial, &c.Slot, &c.Profile, &c.UserDisplay, &c.SerialNumber, &c.Subject,
			&c.NotBeforeUnix, &c.NotAfterUnix, &c.Status, &c.RevokedAtUnix, &c.RevocationReason); err != nil {
			return nil, internal("could not read certificates", err)
		}
		out = append(out, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read certificates", err)
	}
	return out, nil
}

// escrowFor reads escrow metadata. The ciphertext, wrapped key, and nonce columns are deliberately not selected.
func (s *Service) escrowFor(ctx context.Context, tokenID string) ([]*adminv1.EscrowVersion, error) {
	rows, err := s.store.Pool.Query(ctx, `
		SELECT kind, version, state, EXTRACT(EPOCH FROM created_at)::bigint, COALESCE(EXTRACT(EPOCH FROM activated_at)::bigint, 0)
		FROM escrowed_secrets
		WHERE token_id = $1
		ORDER BY kind, version
	`, tokenID)
	if err != nil {
		return nil, internal("could not list escrow metadata", err)
	}
	defer rows.Close()
	var out []*adminv1.EscrowVersion
	for rows.Next() {
		var e adminv1.EscrowVersion
		var version int32
		if err := rows.Scan(&e.Kind, &version, &e.State, &e.CreatedAtUnix, &e.ActivatedAtUnix); err != nil {
			return nil, internal("could not read escrow metadata", err)
		}
		e.Version = version
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read escrow metadata", err)
	}
	return out, nil
}

func (s *Service) auditFor(ctx context.Context, serial, tokenID string) ([]*adminv1.AuditEvent, error) {
	rows, err := s.store.Pool.Query(ctx, `
		SELECT seq, EXTRACT(EPOCH FROM occurred_at)::bigint, actor_type, actor_id, action, target_type, target_id,
		       outcome, detail::text
		FROM audit_events
		WHERE target_type = 'token' AND target_id = ANY($1)
		ORDER BY seq DESC
		LIMIT $2
	`, []string{serial, tokenID}, auditDetailRows)
	if err != nil {
		return nil, internal("could not read the audit trail", err)
	}
	defer rows.Close()
	var out []*adminv1.AuditEvent
	for rows.Next() {
		var e adminv1.AuditEvent
		if err := rows.Scan(&e.Seq, &e.OccurredAtUnix, &e.ActorType, &e.ActorId, &e.Action, &e.TargetType, &e.TargetId,
			&e.Outcome, &e.DetailJson); err != nil {
			return nil, internal("could not read the audit trail", err)
		}
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read the audit trail", err)
	}
	return out, nil
}

// internal returns a generic client error. The cause is not sent to the browser.
func internal(message string, _ error) error {
	return connect.NewError(connect.CodeInternal, errors.New(message))
}
