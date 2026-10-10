package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// User is an authenticated person, used to build certificate subjects.
type User struct {
	ID          string
	Issuer      string
	Subject     string
	Username    string
	Email       string
	DisplayName string
}

// CertificateRecord is an issued certificate. DER holds the leaf certificate only.
type CertificateRecord struct {
	TokenID         string
	Slot            string
	Profile         string
	UserID          string
	SerialNumber    string
	Subject         string
	NotBefore       time.Time
	NotAfter        time.Time
	IssuedByStation string
	DER             []byte
}

// UserByID returns the user row for a token's assigned user.
func (s *Store) UserByID(ctx context.Context, tx pgx.Tx, id string) (User, error) {
	var user User
	err := tx.QueryRow(ctx, `
		SELECT id::text, issuer, subject, username, email, display_name
		FROM users WHERE id = $1
	`, id).Scan(&user.ID, &user.Issuer, &user.Subject, &user.Username, &user.Email, &user.DisplayName)
	if err != nil {
		return User{}, fmt.Errorf("read user: %w", err)
	}
	return user, nil
}

// InsertCertificate records a newly issued certificate and supersedes the previously active certificate
// for the same token and slot, in the caller's transaction.
func (s *Store) InsertCertificate(ctx context.Context, tx pgx.Tx, record CertificateRecord) (string, error) {
	if _, err := tx.Exec(ctx, `
		UPDATE certificates SET status = 'superseded'
		WHERE token_id = $1 AND slot = $2 AND status = 'active'
	`, record.TokenID, record.Slot); err != nil {
		return "", fmt.Errorf("supersede previous certificate: %w", err)
	}
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO certificates(token_id, slot, profile, user_id, serial_number, subject,
		                         not_before, not_after, status, issued_by_station, der)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10)
		RETURNING id::text
	`, record.TokenID, record.Slot, record.Profile, record.UserID, record.SerialNumber, record.Subject,
		record.NotBefore, record.NotAfter, record.IssuedByStation, record.DER).Scan(&id); err != nil {
		return "", fmt.Errorf("insert certificate: %w", err)
	}
	return id, nil
}

// ActiveCertificate returns the active certificate for a token slot, if any.
func (s *Store) ActiveCertificate(ctx context.Context, tokenID, slot string) (CertificateRecord, bool, error) {
	var record CertificateRecord
	err := s.Pool.QueryRow(ctx, `
		SELECT token_id::text, slot, profile, user_id::text, serial_number, subject, not_before, not_after,
		       issued_by_station, der
		FROM certificates WHERE token_id = $1 AND slot = $2 AND status = 'active'
	`, tokenID, slot).Scan(&record.TokenID, &record.Slot, &record.Profile, &record.UserID, &record.SerialNumber,
		&record.Subject, &record.NotBefore, &record.NotAfter, &record.IssuedByStation, &record.DER)
	if err == pgx.ErrNoRows {
		return CertificateRecord{}, false, nil
	}
	if err != nil {
		return CertificateRecord{}, false, fmt.Errorf("read active certificate: %w", err)
	}
	return record, true, nil
}
