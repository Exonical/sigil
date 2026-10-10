package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type Station struct {
	ID          string
	DNSName     string
	DisplayName string
	Mode        string
	Status      string
}

type Token struct {
	ID             string
	Vendor         string
	Model          string
	Serial         string
	Firmware       string
	FormFactor     string
	Nickname       *string
	AssignedUserID *string
	Status         string
}

type ObservedToken struct {
	Vendor     string
	Model      string
	Serial     string
	Firmware   string
	FormFactor string
	Connection string
}

type GrantRecord struct {
	ID           string
	Operation    string
	UserID       string
	StationID    string
	TokenSerial  string
	PIVSlot      uint32
	CallerOSUser string
	NotBefore    int64
	ExpiresAt    int64
	KeyID        string
}

func (s *Store) UpsertUser(ctx context.Context, issuer, subject, username, email, displayName string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO users(issuer, subject, username, email, display_name)
		VALUES($1, $2, $3, $4, $5)
		ON CONFLICT(issuer, subject) DO UPDATE
		SET username=EXCLUDED.username, email=EXCLUDED.email, display_name=EXCLUDED.display_name, last_seen_at=now()
		RETURNING id::text
	`, issuer, subject, username, email, displayName).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert authenticated user: %w", err)
	}
	return id, nil
}

func (s *Store) ActiveStationsByDNSNames(ctx context.Context, names []string) ([]Station, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, dns_name, display_name, mode, status
		FROM stations
		WHERE status='active' AND dns_name = ANY($1::text[])
	`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stations := make([]Station, 0)
	for rows.Next() {
		var station Station
		if err := rows.Scan(&station.ID, &station.DNSName, &station.DisplayName, &station.Mode, &station.Status); err != nil {
			return nil, err
		}
		stations = append(stations, station)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return stations, nil
}

func (s *Store) TokenByVendorSerial(ctx context.Context, vendor, serial string) (Token, error) {
	var token Token
	err := s.Pool.QueryRow(ctx, `
		SELECT id::text, vendor, model, serial, firmware, form_factor,
		       nickname, assigned_user_id::text, status
		FROM tokens WHERE vendor=$1 AND serial=$2
	`, vendor, serial).Scan(
		&token.ID, &token.Vendor, &token.Model, &token.Serial, &token.Firmware,
		&token.FormFactor, &token.Nickname, &token.AssignedUserID, &token.Status,
	)
	if err != nil {
		return Token{}, err
	}
	return token, nil
}

func InsertObservedToken(ctx context.Context, tx pgx.Tx, stationID string, token ObservedToken) error {
	if token.Vendor == "" || token.Serial == "" {
		return errors.New("observed token requires vendor and serial")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO tokens(vendor, model, serial, firmware, form_factor, last_station_id)
		VALUES($1, $2, $3, $4, $5, $6)
		ON CONFLICT(vendor, serial) DO UPDATE SET
			model=EXCLUDED.model,
			firmware=EXCLUDED.firmware,
			form_factor=EXCLUDED.form_factor,
			last_seen_at=now(),
			last_station_id=EXCLUDED.last_station_id
	`, token.Vendor, token.Model, token.Serial, token.Firmware, token.FormFactor, stationID)
	if err != nil {
		return fmt.Errorf("upsert observed token: %w", err)
	}
	return nil
}

func InsertGrant(ctx context.Context, tx pgx.Tx, grant GrantRecord) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO grants(
			grant_id, operation, user_id, station_id, token_serial, piv_slot,
			caller_os_user, not_before, expires_at, key_id
		)
		VALUES($1, $2, $3::uuid, $4, $5, $6, $7,
		       to_timestamp($8), to_timestamp($9), $10)
	`, grant.ID, grant.Operation, grant.UserID, grant.StationID, grant.TokenSerial,
		grant.PIVSlot, grant.CallerOSUser, grant.NotBefore, grant.ExpiresAt, grant.KeyID)
	if err != nil {
		return fmt.Errorf("record issued grant: %w", err)
	}
	return nil
}

func (s *Store) AddStation(ctx context.Context, tx pgx.Tx, station Station) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO stations(id, dns_name, display_name, mode, status)
		VALUES($1, $2, $3, $4, 'active')
	`, station.ID, station.DNSName, station.DisplayName, station.Mode)
	if err != nil {
		return fmt.Errorf("add station: %w", err)
	}
	return nil
}

func (s *Store) DisableStation(ctx context.Context, tx pgx.Tx, id string) error {
	tag, err := tx.Exec(ctx, `UPDATE stations SET status='disabled' WHERE id=$1 AND status='active'`, id)
	if err != nil {
		return fmt.Errorf("disable station: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
