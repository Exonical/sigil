// Package lifecycle runs background certificate lifecycle jobs.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lostKeysLock serializes the job across backend instances that share a database.
const lostKeysLock int64 = 0x5349474c4f535431

// reasonKeyCompromise is the RFC 5280 keyCompromise reason code.
const reasonKeyCompromise = 1

// LostKeys revokes the active certificates of tokens that have been lost longer than the grace period.
// Revocation is idempotent: a certificate is only revoked while its status is active.
type LostKeys struct {
	store     *db.Store
	cas       map[string]ca.CA
	profileCA map[string]string
	grace     time.Duration
	now       func() time.Time
	logger    *slog.Logger
}

// TickResult reports one pass of the job.
type TickResult struct {
	Revoked int
	Failed  int
	// Skipped is true when another backend instance held the job lock.
	Skipped bool
}

// NewLostKeys builds the job. profileCA maps each certificate profile to the name of its CA in cas.
func NewLostKeys(store *db.Store, cas map[string]ca.CA, profileCA map[string]string, grace time.Duration, logger *slog.Logger) *LostKeys {
	return &LostKeys{store: store, cas: cas, profileCA: profileCA, grace: grace, now: time.Now, logger: logger}
}

// Run calls Tick every interval until ctx is done.
func (j *LostKeys) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := j.Tick(ctx)
			if err != nil {
				j.logger.Error("lost-key revocation pass failed", "error", err)
				continue
			}
			if result.Revoked > 0 || result.Failed > 0 {
				j.logger.Info("lost-key revocation pass finished", "revoked", result.Revoked, "failed", result.Failed)
			}
		}
	}
}

type candidate struct {
	id      string
	serial  string
	profile string
}

// Tick runs one pass. It returns without work when another instance holds the job lock.
func (j *LostKeys) Tick(ctx context.Context) (TickResult, error) {
	conn, err := j.store.Pool.Acquire(ctx)
	if err != nil {
		return TickResult{}, fmt.Errorf("acquire lost-key connection: %w", err)
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lostKeysLock).Scan(&locked); err != nil {
		return TickResult{}, fmt.Errorf("acquire lost-key lock: %w", err)
	}
	if !locked {
		return TickResult{Skipped: true}, nil
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lostKeysLock)
	}()

	candidates, err := j.candidates(ctx, conn)
	if err != nil {
		return TickResult{}, err
	}
	var result TickResult
	for _, c := range candidates {
		if err := j.revoke(ctx, c); err != nil {
			result.Failed++
			j.logger.Error("lost-key certificate revocation failed", "certificate_id", c.id, "error", err)
			if auditErr := audit.AppendStandalone(ctx, j.store.Pool, j.event(c, "error", err.Error())); auditErr != nil {
				return result, fmt.Errorf("record failed revocation: %w", auditErr)
			}
			continue
		}
		result.Revoked++
	}
	return result, nil
}

func (j *LostKeys) candidates(ctx context.Context, conn *pgxpool.Conn) ([]candidate, error) {
	rows, err := conn.Query(ctx, `
		SELECT c.id::text, c.serial_number, c.profile
		FROM certificates c
		JOIN tokens t ON t.id = c.token_id
		WHERE c.status = 'active' AND t.status = 'lost' AND t.lost_at <= $1
		ORDER BY c.id
	`, j.now().Add(-j.grace))
	if err != nil {
		return nil, fmt.Errorf("list lost-key certificates: %w", err)
	}
	defer rows.Close()
	var found []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.serial, &c.profile); err != nil {
			return nil, fmt.Errorf("scan lost-key certificate: %w", err)
		}
		found = append(found, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read lost-key certificates: %w", err)
	}
	return found, nil
}

func (j *LostKeys) revoke(ctx context.Context, c candidate) error {
	name, ok := j.profileCA[c.profile]
	if !ok {
		return fmt.Errorf("profile %q has no certificate authority", c.profile)
	}
	authority, ok := j.cas[name]
	if !ok {
		return fmt.Errorf("certificate authority %q is not configured", name)
	}
	alreadyRevoked := false
	if err := authority.Revoke(ctx, c.serial, reasonKeyCompromise, "lost key"); err != nil {
		if !errors.Is(err, ca.ErrAlreadyRevoked) {
			return err
		}
		alreadyRevoked = true
	}
	tx, err := j.store.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin revocation record: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE certificates
		SET status = 'revoked', revoked_at = $2, revocation_reason = 'keyCompromise'
		WHERE id = $1 AND status = 'active'
	`, c.id, j.now()); err != nil {
		return fmt.Errorf("mark certificate revoked: %w", err)
	}
	event := j.event(c, "success", "")
	event.Detail["already_revoked"] = alreadyRevoked
	if _, err := audit.Append(ctx, tx, event); err != nil {
		return fmt.Errorf("audit revocation: %w", err)
	}
	return tx.Commit(ctx)
}

func (j *LostKeys) event(c candidate, outcome, reason string) audit.Event {
	detail := map[string]any{"reason": "lost key", "reason_code": "keyCompromise", "serial": c.serial}
	if reason != "" {
		detail["error"] = reason
	}
	return audit.Event{
		OccurredAt: j.now(),
		ActorType:  "system",
		ActorID:    "lost-key-job",
		Action:     "RevokeCertificate",
		TargetType: "certificate",
		TargetID:   c.id,
		Outcome:    outcome,
		Detail:     detail,
	}
}
