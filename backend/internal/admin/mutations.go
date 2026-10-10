package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
)

// reasonCodes maps the portal's revocation reasons to RFC 5280 reason codes.
var reasonCodes = map[string]int{
	"unspecified":          0,
	"superseded":           4,
	"keyCompromise":        1,
	"cessationOfOperation": 5,
}

const maxNicknameLength = 64

func invalid(message string) error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(message))
}

func failed(message string) error {
	return connect.NewError(connect.CodeFailedPrecondition, errors.New(message))
}

func notFound(message string) error {
	return connect.NewError(connect.CodeNotFound, errors.New(message))
}

// tokenRef validates a token reference and applies the default vendor.
func tokenRef(ref *adminv1.TokenRef) (string, string, error) {
	if ref == nil || strings.TrimSpace(ref.Serial) == "" {
		return "", "", invalid("a token serial is required")
	}
	vendor := ref.Vendor
	if vendor == "" {
		vendor = defaultVendor
	}
	return vendor, ref.Serial, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func actorID(ctx context.Context) string {
	return principalFrom(ctx).userID
}

// mutate runs one change and its audit record in a single transaction. A failed change is audited as an error
// outside the rolled-back transaction, so the attempt is still visible.
func (s *Service) mutate(ctx context.Context, action, targetType, targetID string, detail map[string]any, change func(pgx.Tx) error) error {
	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		return internal("could not start the change", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := change(tx); err != nil {
		_ = tx.Rollback(ctx)
		s.auditError(ctx, action, targetType, targetID, err.Error())
		return err
	}
	if _, err := audit.Append(ctx, tx, userEvent(ctx, action, targetType, targetID, "success", detail)); err != nil {
		return internal("could not record the change", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return internal("could not commit the change", err)
	}
	return nil
}

func userEvent(ctx context.Context, action, targetType, targetID, outcome string, detail map[string]any) audit.Event {
	if detail == nil {
		detail = map[string]any{}
	}
	return audit.Event{
		ActorType:  "user",
		ActorID:    actorID(ctx),
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Outcome:    outcome,
		Detail:     detail,
	}
}

func (s *Service) auditError(ctx context.Context, action, targetType, targetID, reason string) {
	_ = audit.AppendStandalone(ctx, s.store.Pool, userEvent(ctx, action, targetType, targetID, "error", map[string]any{"reason": reason}))
}

// AssignToken assigns a signed-in user to an inventory token and marks it active.
func (s *Service) AssignToken(ctx context.Context, req *connect.Request[adminv1.AssignTokenRequest]) (*connect.Response[adminv1.Empty], error) {
	vendor, serial, err := tokenRef(req.Msg.Token)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Msg.UsernameOrEmail)
	if name == "" {
		return nil, invalid("a username or email is required")
	}
	err = s.mutate(ctx, "AssignToken", "token", serial, map[string]any{"user": name}, func(tx pgx.Tx) error {
		userID, err := s.store.FindUserByName(ctx, tx, name)
		if err != nil {
			return failed(err.Error())
		}
		if _, err := s.store.AssignToken(ctx, tx, vendor, serial, userID); err != nil {
			return failed(err.Error())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.Empty{}), nil
}

// UnassignToken clears the assigned user and returns the token to the unassigned state.
func (s *Service) UnassignToken(ctx context.Context, req *connect.Request[adminv1.TokenRef]) (*connect.Response[adminv1.Empty], error) {
	vendor, serial, err := tokenRef(req.Msg)
	if err != nil {
		return nil, err
	}
	err = s.mutate(ctx, "UnassignToken", "token", serial, nil, func(tx pgx.Tx) error {
		if _, err := s.store.UnassignToken(ctx, tx, vendor, serial); err != nil {
			return failed(err.Error())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.Empty{}), nil
}

// SetNickname sets or clears a token nickname. Nicknames are unique per assigned user.
func (s *Service) SetNickname(ctx context.Context, req *connect.Request[adminv1.SetNicknameRequest]) (*connect.Response[adminv1.Empty], error) {
	vendor, serial, err := tokenRef(req.Msg.Token)
	if err != nil {
		return nil, err
	}
	nickname := strings.TrimSpace(req.Msg.Nickname)
	if len(nickname) > maxNicknameLength {
		return nil, invalid("a nickname must be at most 64 characters")
	}
	err = s.mutate(ctx, "SetNickname", "token", serial, map[string]any{"nickname": nickname}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE tokens SET nickname = NULLIF($3, '') WHERE vendor = $1 AND serial = $2`, vendor, serial, nickname)
		if isUniqueViolation(err) {
			return connect.NewError(connect.CodeAlreadyExists, errors.New("another token of this user already has that nickname"))
		}
		if err != nil {
			return internal("could not set the nickname", err)
		}
		if tag.RowsAffected() == 0 {
			return notFound("the token is not in inventory")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.Empty{}), nil
}

// ReportLost blocks a token immediately. Its certificates are revoked by the lost-key job after the grace period.
func (s *Service) ReportLost(ctx context.Context, req *connect.Request[adminv1.TokenRef]) (*connect.Response[adminv1.Empty], error) {
	vendor, serial, err := tokenRef(req.Msg)
	if err != nil {
		return nil, err
	}
	err = s.mutate(ctx, "ReportLost", "token", serial, nil, func(tx pgx.Tx) error {
		var id, status string
		if err := tx.QueryRow(ctx, `SELECT id::text, status FROM tokens WHERE vendor = $1 AND serial = $2 FOR UPDATE`, vendor, serial).Scan(&id, &status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return notFound("the token is not in inventory")
			}
			return internal("could not read the token", err)
		}
		if status != "active" && status != "unassigned" {
			return failed(fmt.Sprintf("a token with status %q cannot be reported lost", status))
		}
		if _, err := tx.Exec(ctx, `UPDATE tokens SET status = 'lost', lost_at = now() WHERE id = $1`, id); err != nil {
			return internal("could not mark the token lost", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.Empty{}), nil
}

// MarkFound restores a lost token. Re-enrollment is required when one of its certificates was already revoked.
func (s *Service) MarkFound(ctx context.Context, req *connect.Request[adminv1.TokenRef]) (*connect.Response[adminv1.MarkFoundResponse], error) {
	vendor, serial, err := tokenRef(req.Msg)
	if err != nil {
		return nil, err
	}
	var reEnroll bool
	var restored string
	err = s.mutate(ctx, "MarkFound", "token", serial, nil, func(tx pgx.Tx) error {
		var id, status string
		var assignedUser *string
		if err := tx.QueryRow(ctx, `
			SELECT id::text, status, assigned_user_id::text FROM tokens WHERE vendor = $1 AND serial = $2 FOR UPDATE
		`, vendor, serial).Scan(&id, &status, &assignedUser); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return notFound("the token is not in inventory")
			}
			return internal("could not read the token", err)
		}
		if status != "lost" {
			return failed(fmt.Sprintf("a token with status %q is not lost", status))
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificates WHERE token_id = $1 AND status = 'revoked')`, id).Scan(&reEnroll); err != nil {
			return internal("could not read the certificates", err)
		}
		restored = "unassigned"
		if assignedUser != nil {
			restored = "active"
		}
		if _, err := tx.Exec(ctx, `UPDATE tokens SET status = $2, lost_at = NULL WHERE id = $1`, id, restored); err != nil {
			return internal("could not restore the token", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.MarkFoundResponse{ReEnrollmentRequired: reEnroll}), nil
}

type activeCertificate struct {
	id, serial, profile string
}

// DeleteKey retires a token and revokes its active certificates at the CA. It is admin-only and requires the serial
// to be typed back. If some revocations fail, the token stays retired, the failures are returned, and a retry
// revokes what remains.
func (s *Service) DeleteKey(ctx context.Context, req *connect.Request[adminv1.DeleteKeyRequest]) (*connect.Response[adminv1.DeleteKeyResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	vendor, serial, err := tokenRef(req.Msg.Token)
	if err != nil {
		return nil, err
	}
	if req.Msg.ConfirmSerial != serial {
		return nil, invalid("confirm_serial must equal the token serial")
	}
	tokenID, err := s.tokenID(ctx, vendor, serial)
	if err != nil {
		return nil, err
	}
	// The token is retired before any revocation so a partial failure still leaves it retired.
	if _, err := s.store.Pool.Exec(ctx, `UPDATE tokens SET status = 'retired' WHERE id = $1 AND status <> 'retired'`, tokenID); err != nil {
		return nil, internal("could not retire the token", err)
	}
	active, err := s.activeCertificates(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	var failedIDs []string
	revoked := 0
	for _, certificate := range active {
		alreadyRevoked, err := s.revokeAtCA(ctx, certificate.profile, certificate.serial, reasonCodes["cessationOfOperation"], "key deleted by administrator")
		if err != nil {
			failedIDs = append(failedIDs, certificate.id)
			s.auditError(ctx, "RevokeCertificate", "certificate", certificate.id, err.Error())
			continue
		}
		if err := s.markRevoked(ctx, certificate.id, "cessationOfOperation", alreadyRevoked, "DeleteKey"); err != nil {
			return nil, err
		}
		revoked++
	}
	if len(failedIDs) > 0 {
		s.auditError(ctx, "DeleteKey", "token", serial, fmt.Sprintf("%d certificate revocations failed", len(failedIDs)))
		return nil, failed(fmt.Sprintf("%d certificate(s) could not be revoked; run DeleteKey again to retry: %s", len(failedIDs), strings.Join(failedIDs, ", ")))
	}
	if err := s.mutate(ctx, "DeleteKey", "token", serial, map[string]any{"revoked": revoked}, func(pgx.Tx) error { return nil }); err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.DeleteKeyResponse{Revoked: int32(revoked)}), nil
}

// RevokeCertificate revokes one active or superseded certificate at the CA and in the inventory.
func (s *Service) RevokeCertificate(ctx context.Context, req *connect.Request[adminv1.RevokeCertificateRequest]) (*connect.Response[adminv1.Empty], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	code, ok := reasonCodes[req.Msg.Reason]
	if !ok {
		return nil, invalid("reason must be keyCompromise, cessationOfOperation, superseded or unspecified")
	}
	certificateID := req.Msg.CertificateId
	if certificateID == "" {
		return nil, invalid("a certificate id is required")
	}
	var status, serial, profile string
	if err := s.store.Pool.QueryRow(ctx, `SELECT status, serial_number, profile FROM certificates WHERE id = $1`, certificateID).Scan(&status, &serial, &profile); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, notFound("the certificate does not exist")
		}
		return nil, internal("could not read the certificate", err)
	}
	if status == "revoked" {
		return nil, failed("the certificate is already revoked")
	}
	alreadyRevoked, err := s.revokeAtCA(ctx, profile, serial, code, req.Msg.Reason)
	if err != nil {
		s.auditError(ctx, "RevokeCertificate", "certificate", certificateID, err.Error())
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the certificate authority did not revoke the certificate"))
	}
	if err := s.markRevoked(ctx, certificateID, req.Msg.Reason, alreadyRevoked, "RevokeCertificate"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.Empty{}), nil
}

// revokeAtCA revokes at the certificate's CA. A certificate the CA already reports as revoked counts as revoked.
func (s *Service) revokeAtCA(ctx context.Context, profile, serial string, code int, reason string) (bool, error) {
	name, ok := s.profileCA[profile]
	if !ok {
		return false, fmt.Errorf("profile %q has no certificate authority", profile)
	}
	authority, ok := s.cas[name]
	if !ok {
		return false, fmt.Errorf("certificate authority %q is not configured", name)
	}
	err := authority.Revoke(ctx, serial, code, reason)
	if errors.Is(err, ca.ErrAlreadyRevoked) {
		return true, nil
	}
	return false, err
}

// markRevoked records a CA revocation in the inventory and audits it. The change is only applied to certificates
// that are still active or superseded, so repeating it is harmless.
func (s *Service) markRevoked(ctx context.Context, certificateID, reason string, alreadyRevoked bool, via string) error {
	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		return internal("could not start the revocation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE certificates SET status = 'revoked', revoked_at = now(), revocation_reason = $2
		WHERE id = $1 AND status IN ('active', 'superseded')
	`, certificateID, reason); err != nil {
		return internal("could not record the revocation", err)
	}
	if _, err := audit.Append(ctx, tx, userEvent(ctx, "RevokeCertificate", "certificate", certificateID, "success", map[string]any{
		"reason":          reason,
		"already_revoked": alreadyRevoked,
		"via":             via,
	})); err != nil {
		return internal("could not audit the revocation", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return internal("could not commit the revocation", err)
	}
	return nil
}

func (s *Service) tokenID(ctx context.Context, vendor, serial string) (string, error) {
	var id string
	if err := s.store.Pool.QueryRow(ctx, `SELECT id::text FROM tokens WHERE vendor = $1 AND serial = $2`, vendor, serial).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", notFound("the token is not in inventory")
		}
		return "", internal("could not read the token", err)
	}
	return id, nil
}

func (s *Service) activeCertificates(ctx context.Context, tokenID string) ([]activeCertificate, error) {
	rows, err := s.store.Pool.Query(ctx, `
		SELECT id::text, serial_number, profile FROM certificates WHERE token_id = $1 AND status = 'active' ORDER BY id
	`, tokenID)
	if err != nil {
		return nil, internal("could not list active certificates", err)
	}
	defer rows.Close()
	var out []activeCertificate
	for rows.Next() {
		var c activeCertificate
		if err := rows.Scan(&c.id, &c.serial, &c.profile); err != nil {
			return nil, internal("could not read active certificates", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read active certificates", err)
	}
	return out, nil
}

// AddStation registers a station by DNS name. The station's certificate is bound later by the agent.
func (s *Service) AddStation(ctx context.Context, req *connect.Request[adminv1.AddStationRequest]) (*connect.Response[adminv1.Empty], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	dns := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Msg.DnsName), "."))
	if dns == "" || strings.ContainsAny(dns, " /\\") {
		return nil, invalid("a DNS name is required")
	}
	if req.Msg.Mode != "station" && req.Msg.Mode != "user" {
		return nil, invalid("mode must be station or user")
	}
	err := s.mutate(ctx, "AddStation", "station", dns, map[string]any{"mode": req.Msg.Mode}, func(tx pgx.Tx) error {
		err := s.store.AddStation(ctx, tx, db.Station{ID: dns, DNSName: dns, DisplayName: dns, Mode: req.Msg.Mode})
		if isUniqueViolation(err) {
			return connect.NewError(connect.CodeAlreadyExists, errors.New("a station with that name already exists"))
		}
		if err != nil {
			return internal("could not register the station", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.Empty{}), nil
}

// SetStationStatus enables or disables a station. A disabled station is refused by the agent gateway.
func (s *Service) SetStationStatus(ctx context.Context, req *connect.Request[adminv1.SetStationStatusRequest]) (*connect.Response[adminv1.Empty], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	id := req.Msg.Id
	if id == "" {
		return nil, invalid("a station id is required")
	}
	err := s.mutate(ctx, "SetStationStatus", "station", id, map[string]any{"status": req.Msg.Status}, func(tx pgx.Tx) error {
		switch req.Msg.Status {
		case "disabled":
			if err := s.store.DisableStation(ctx, tx, id); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return failed("the station is not active or does not exist")
				}
				return internal("could not disable the station", err)
			}
		case "active":
			tag, err := tx.Exec(ctx, `UPDATE stations SET status = 'active' WHERE id = $1 AND status = 'disabled'`, id)
			if err != nil {
				return internal("could not enable the station", err)
			}
			if tag.RowsAffected() == 0 {
				return failed("the station is not disabled or does not exist")
			}
		default:
			return invalid("status must be active or disabled")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.Empty{}), nil
}
