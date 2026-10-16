package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrEnrollmentNotFound is returned when no enrollment challenge matches.
var ErrEnrollmentNotFound = errors.New("enrollment challenge not found")

// EnrollmentChallenge is a one-time SCEP enrollment. Only the SHA-256 of the challenge is stored.
type EnrollmentChallenge struct {
	ID              string
	TokenID         string
	Profile         string
	UserID          string
	StationID       string
	PrincipalUserID string
	ChallengeSHA256 []byte
	CSRSPKI         []byte
	State           string
	Expired         bool
}

// InsertEnrollmentChallenge records an issued challenge. The expiry is set by the database clock, and the
// returned expiry is the Unix time at which the challenge stops being valid.
func (s *Store) InsertEnrollmentChallenge(ctx context.Context, tx pgx.Tx, record EnrollmentChallenge, lifetimeMinutes int) (string, int64, error) {
	var id string
	var expires int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO enrollment_challenges(token_id, profile, user_id, station_id, principal_user_id,
		                                  challenge_sha256, state, expires_at)
		VALUES($1::uuid, $2, $3::uuid, $4, $5::uuid, $6, 'issued', now() + make_interval(mins => $7))
		RETURNING id::text, extract(epoch FROM expires_at)::bigint
	`, record.TokenID, record.Profile, record.UserID, record.StationID, record.PrincipalUserID,
		record.ChallengeSHA256, lifetimeMinutes).Scan(&id, &expires); err != nil {
		return "", 0, fmt.Errorf("insert enrollment challenge: %w", err)
	}
	return id, expires, nil
}

// EnrollmentByID reads an enrollment challenge by id, without its challenge value.
func (s *Store) EnrollmentByID(ctx context.Context, tx pgx.Tx, id string) (EnrollmentChallenge, error) {
	var record EnrollmentChallenge
	err := tx.QueryRow(ctx, `
		SELECT id::text, token_id::text, profile, user_id::text, station_id, principal_user_id::text,
		       challenge_sha256, csr_spki, state, expires_at <= now()
		FROM enrollment_challenges WHERE id = $1::uuid
	`, id).Scan(&record.ID, &record.TokenID, &record.Profile, &record.UserID, &record.StationID,
		&record.PrincipalUserID, &record.ChallengeSHA256, &record.CSRSPKI, &record.State, &record.Expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollmentChallenge{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("read enrollment challenge: %w", err)
	}
	return record, nil
}

// SubmitEnrollment moves an issued challenge to submitted and binds it to the CSR key. It is conditional on the state
// and the expiry, so a record that changed under the caller is not submitted.
func (s *Store) SubmitEnrollment(ctx context.Context, tx pgx.Tx, id string, csrSPKI []byte) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE enrollment_challenges
		SET state = 'submitted', csr_spki = $2, submitted_at = now()
		WHERE id = $1::uuid AND state = 'issued' AND expires_at > now()
	`, id, csrSPKI)
	if err != nil {
		return false, fmt.Errorf("submit enrollment challenge: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ConsumeEnrollment atomically consumes a submitted challenge for the CSR key and one of the allowed profiles. It
// returns false when no record matches, so a challenge is accepted at most once.
func (s *Store) ConsumeEnrollment(ctx context.Context, challengeSHA256, csrSPKI []byte, profiles []string) (string, string, bool, error) {
	var id, profile string
	err := s.Pool.QueryRow(ctx, `
		UPDATE enrollment_challenges
		SET state = 'consumed', consumed_at = now()
		WHERE challenge_sha256 = $1 AND state = 'submitted' AND expires_at > now()
		  AND csr_spki = $2 AND profile = ANY($3)
		RETURNING id::text, profile
	`, challengeSHA256, csrSPKI, profiles).Scan(&id, &profile)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("consume enrollment challenge: %w", err)
	}
	return id, profile, true, nil
}

// EnrollmentByChallenge reads the record for a challenge hash, for audit detail when a consume is refused.
func (s *Store) EnrollmentByChallenge(ctx context.Context, challengeSHA256 []byte) (EnrollmentChallenge, error) {
	var record EnrollmentChallenge
	err := s.Pool.QueryRow(ctx, `
		SELECT id::text, token_id::text, profile, user_id::text, station_id, principal_user_id::text,
		       challenge_sha256, csr_spki, state, expires_at <= now()
		FROM enrollment_challenges WHERE challenge_sha256 = $1
	`, challengeSHA256).Scan(&record.ID, &record.TokenID, &record.Profile, &record.UserID, &record.StationID,
		&record.PrincipalUserID, &record.ChallengeSHA256, &record.CSRSPKI, &record.State, &record.Expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollmentChallenge{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("read enrollment challenge: %w", err)
	}
	return record, nil
}
