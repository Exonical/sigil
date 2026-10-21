package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type EscrowSecret struct {
	ID          string
	TokenID     string
	Kind        string
	Algorithm   string
	Version     int
	State       string
	KEKID       string
	DEKNonce    []byte
	WrappedDEK  []byte
	Nonce       []byte
	Ciphertext  []byte
	GrantID     string
	StationID   string
	CreatedAt   time.Time
	ActivatedAt *time.Time
}

type NewEscrowSecret struct {
	TokenID    string
	Kind       string
	Algorithm  string
	Version    int
	KEKID      string
	DEKNonce   []byte
	WrappedDEK []byte
	Nonce      []byte
	Ciphertext []byte
	GrantID    string
	StationID  string
}

func LockToken(ctx context.Context, tx pgx.Tx, vendor, serial string) (Token, error) {
	var token Token
	err := tx.QueryRow(ctx, `
		SELECT id::text, vendor, model, serial, firmware, form_factor,
		       nickname, assigned_user_id::text, status
		FROM tokens WHERE vendor=$1 AND serial=$2
		FOR UPDATE
	`, vendor, serial).Scan(
		&token.ID, &token.Vendor, &token.Model, &token.Serial, &token.Firmware,
		&token.FormFactor, &token.Nickname, &token.AssignedUserID, &token.Status,
	)
	if err != nil {
		return Token{}, err
	}
	return token, nil
}

func ActiveEscrowSecret(ctx context.Context, tx pgx.Tx, tokenID, kind string) (EscrowSecret, error) {
	return scanEscrowSecret(tx.QueryRow(ctx, `
		SELECT id::text, token_id::text, kind, algorithm, version, state, kek_id,
		       dek_nonce, wrapped_dek, nonce, ciphertext, grant_id, station_id,
		       created_at, activated_at
		FROM escrowed_secrets
		WHERE token_id=$1::uuid AND kind=$2 AND state='active'
		FOR UPDATE
	`, tokenID, kind))
}

func MarkPendingEscrowUnconfirmed(ctx context.Context, tx pgx.Tx, tokenID, kind string) ([]int, error) {
	rows, err := tx.Query(ctx, `
		UPDATE escrowed_secrets SET state='unconfirmed'
		WHERE token_id=$1::uuid AND kind=$2 AND state='pending'
		RETURNING version
	`, tokenID, kind)
	if err != nil {
		return nil, fmt.Errorf("mark pending escrow unconfirmed: %w", err)
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("read unconfirmed escrow version: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unconfirmed escrow versions: %w", err)
	}
	return versions, nil
}

func NextEscrowVersion(ctx context.Context, tx pgx.Tx, tokenID, kind string) (int, error) {
	var version int
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) + 1
		FROM escrowed_secrets
		WHERE token_id=$1::uuid AND kind=$2
	`, tokenID, kind).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("read next escrow version: %w", err)
	}
	return version, nil
}

func InsertEscrowSecret(ctx context.Context, tx pgx.Tx, secret NewEscrowSecret) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO escrowed_secrets(
			token_id, kind, algorithm, version, state, kek_id, dek_nonce,
			wrapped_dek, nonce, ciphertext, grant_id, station_id
		)
		VALUES($1::uuid, $2, $3, $4, 'pending', $5, $6, $7, $8, $9, $10, $11)
	`, secret.TokenID, secret.Kind, secret.Algorithm, secret.Version, secret.KEKID,
		secret.DEKNonce, secret.WrappedDEK, secret.Nonce, secret.Ciphertext,
		secret.GrantID, secret.StationID)
	if err != nil {
		return fmt.Errorf("insert pending escrow secret: %w", err)
	}
	return nil
}

func EscrowRotation(ctx context.Context, tx pgx.Tx, rotationID string) ([]EscrowSecret, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, token_id::text, kind, algorithm, version, state, kek_id,
		       dek_nonce, wrapped_dek, nonce, ciphertext, grant_id, station_id,
		       created_at, activated_at
		FROM escrowed_secrets
		WHERE grant_id=$1
		ORDER BY kind, version
		FOR UPDATE
	`, rotationID)
	if err != nil {
		return nil, fmt.Errorf("read escrow rotation: %w", err)
	}
	defer rows.Close()
	var secrets []EscrowSecret
	for rows.Next() {
		secret, err := scanEscrowSecret(rows)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate escrow rotation: %w", err)
	}
	return secrets, nil
}

func ActivateEscrowRotation(ctx context.Context, tx pgx.Tx, secrets []EscrowSecret) error {
	for _, secret := range secrets {
		if _, err := tx.Exec(ctx, `
			UPDATE escrowed_secrets SET state='superseded'
			WHERE token_id=$1::uuid AND kind=$2 AND state='active'
		`, secret.TokenID, secret.Kind); err != nil {
			return fmt.Errorf("supersede active escrow secret: %w", err)
		}
		tag, err := tx.Exec(ctx, `
			UPDATE escrowed_secrets SET state='active', activated_at=now()
			WHERE id=$1::uuid AND state='pending'
		`, secret.ID)
		if err != nil {
			return fmt.Errorf("activate pending escrow secret: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("pending escrow secret %q changed during completion", secret.ID)
		}
	}
	return nil
}

func UpdateEscrowRotationState(ctx context.Context, tx pgx.Tx, rotationID, from, to string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE escrowed_secrets SET state=$3
		WHERE grant_id=$1 AND state=$2
	`, rotationID, from, to)
	if err != nil {
		return fmt.Errorf("update escrow rotation state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no escrow rows transitioned from %s to %s", from, to)
	}
	return nil
}

func LockStationAuditCursor(ctx context.Context, tx pgx.Tx, stationID string) (int64, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO station_audit_cursor(station_id, last_sequence)
		VALUES($1, 0)
		ON CONFLICT(station_id) DO NOTHING
	`, stationID); err != nil {
		return 0, fmt.Errorf("create station audit cursor: %w", err)
	}
	var sequence int64
	if err := tx.QueryRow(ctx, `
		SELECT last_sequence FROM station_audit_cursor WHERE station_id=$1 FOR UPDATE
	`, stationID).Scan(&sequence); err != nil {
		return 0, fmt.Errorf("lock station audit cursor: %w", err)
	}
	return sequence, nil
}

func SetStationAuditCursor(ctx context.Context, tx pgx.Tx, stationID string, sequence int64) error {
	if _, err := tx.Exec(ctx, `
		UPDATE station_audit_cursor SET last_sequence=$2 WHERE station_id=$1
	`, stationID, sequence); err != nil {
		return fmt.Errorf("update station audit cursor: %w", err)
	}
	return nil
}

type escrowScanner interface {
	Scan(...any) error
}

func scanEscrowSecret(scanner escrowScanner) (EscrowSecret, error) {
	var secret EscrowSecret
	var activatedAt sql.NullTime
	if err := scanner.Scan(
		&secret.ID, &secret.TokenID, &secret.Kind, &secret.Algorithm, &secret.Version,
		&secret.State, &secret.KEKID, &secret.DEKNonce, &secret.WrappedDEK,
		&secret.Nonce, &secret.Ciphertext, &secret.GrantID, &secret.StationID,
		&secret.CreatedAt, &activatedAt,
	); err != nil {
		return EscrowSecret{}, fmt.Errorf("scan escrow secret: %w", err)
	}
	if activatedAt.Valid {
		secret.ActivatedAt = &activatedAt.Time
	}
	return secret, nil
}
