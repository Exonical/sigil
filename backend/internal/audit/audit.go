package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const chainLock int64 = 0x534947494c415544

// Action names shared by every writer of the same operation (admin RPCs and the sigil-server CLI).
// Token events use the token serial as TargetID; station events use the station ID.
const (
	ActionAssignToken      = "AssignToken"
	ActionUnassignToken    = "UnassignToken"
	ActionAddStation       = "AddStation"
	ActionSetStationStatus = "SetStationStatus"
)

// Outcome is an audit event's result. Only policy or validation rejections are Denied; failures of the
// backend or an upstream dependency are Error.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeDenied  Outcome = "denied"
	OutcomeError   Outcome = "error"
)

type Event struct {
	OccurredAt time.Time
	ActorType  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Outcome    string
	Detail     map[string]any
}

type hashRecord struct {
	Seq        int64           `json:"seq"`
	OccurredAt string          `json:"occurred_at"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Outcome    string          `json:"outcome"`
	Detail     json.RawMessage `json:"detail"`
}

func Append(ctx context.Context, tx pgx.Tx, event Event) (int64, error) {
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}
	event.OccurredAt = event.OccurredAt.UTC().Truncate(time.Microsecond)
	if event.Detail == nil {
		event.Detail = map[string]any{}
	}
	detail, err := json.Marshal(event.Detail)
	if err != nil {
		return 0, fmt.Errorf("encode audit detail: %w", err)
	}
	var prevHash []byte
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", chainLock); err != nil {
		return 0, fmt.Errorf("lock audit chain: %w", err)
	}
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if errors.Is(err, pgx.ErrNoRows) {
		prevHash = make([]byte, sha256.Size)
	} else if err != nil {
		return 0, fmt.Errorf("read previous audit hash: %w", err)
	}
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('audit_events', 'seq')::regclass)`).Scan(&seq); err != nil {
		return 0, fmt.Errorf("allocate audit sequence: %w", err)
	}
	record := hashRecord{
		Seq:        seq,
		OccurredAt: event.OccurredAt.Format(time.RFC3339Nano),
		ActorType:  event.ActorType,
		ActorID:    event.ActorID,
		Action:     event.Action,
		TargetType: event.TargetType,
		TargetID:   event.TargetID,
		Outcome:    event.Outcome,
		Detail:     detail,
	}
	canonical, err := json.Marshal(record)
	if err != nil {
		return 0, fmt.Errorf("encode audit event: %w", err)
	}
	hash := hashEvent(prevHash, canonical)
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events(
			seq, occurred_at, actor_type, actor_id, action, target_type, target_id,
			outcome, detail, prev_hash, hash
		)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
	`, seq, event.OccurredAt, event.ActorType, event.ActorID, event.Action,
		event.TargetType, event.TargetID, event.Outcome, string(detail), prevHash, hash[:])
	if err != nil {
		return 0, fmt.Errorf("append audit event: %w", err)
	}
	return seq, nil
}

func AppendStandalone(ctx context.Context, pool *pgxpool.Pool, event Event) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin audit transaction: %w", err)
	}
	if _, err := Append(ctx, tx, event); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit audit event: %w", err)
	}
	return nil
}

func Verify(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT seq, occurred_at, actor_type, actor_id, action, target_type, target_id,
		       outcome, detail::text, prev_hash, hash
		FROM audit_events ORDER BY seq
	`)
	if err != nil {
		return fmt.Errorf("read audit chain: %w", err)
	}
	defer rows.Close()
	prevHash := make([]byte, sha256.Size)
	for rows.Next() {
		var (
			record     hashRecord
			occurredAt time.Time
			detail     []byte
			storedPrev []byte
			storedHash []byte
		)
		if err := rows.Scan(
			&record.Seq, &occurredAt, &record.ActorType, &record.ActorID, &record.Action,
			&record.TargetType, &record.TargetID, &record.Outcome, &detail, &storedPrev, &storedHash,
		); err != nil {
			return fmt.Errorf("read audit event: %w", err)
		}
		canonicalDetail, err := CanonicalJSON(detail)
		if err != nil {
			return fmt.Errorf("canonicalize audit event %d: %w", record.Seq, err)
		}
		record.OccurredAt = occurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		record.Detail = canonicalDetail
		canonical, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode audit event %d: %w", record.Seq, err)
		}
		expected := hashEvent(prevHash, canonical)
		if !bytes.Equal(storedPrev, prevHash) || !bytes.Equal(storedHash, expected[:]) {
			return fmt.Errorf("audit chain verification failed at seq %d", record.Seq)
		}
		prevHash = append(prevHash[:0], storedHash...)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate audit chain: %w", err)
	}
	return nil
}

func CanonicalJSON(data []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func hashEvent(prevHash, canonical []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write(prevHash)
	_, _ = hash.Write(canonical)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}
