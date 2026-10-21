package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// FindUserByName returns the single user whose username or email matches. Users appear here after
// their first authenticated call, so an admin cannot assign a token to someone who has never signed in.
func (s *Store) FindUserByName(ctx context.Context, tx pgx.Tx, name string) (string, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text FROM users
		WHERE lower(username) = lower($1) OR lower(email) = lower($1)
	`, name)
	if err != nil {
		return "", fmt.Errorf("find user: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", fmt.Errorf("scan user: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read users: %w", err)
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("no user %q has signed in yet", name)
	case 1:
		return ids[0], nil
	default:
		return "", fmt.Errorf("user %q matches more than one account", name)
	}
}

// AssignToken sets the token's assigned user and marks it active. Lost and retired tokens cannot be assigned.
func (s *Store) AssignToken(ctx context.Context, tx pgx.Tx, vendor, serial, userID string) (string, error) {
	var id, status string
	err := tx.QueryRow(ctx, `
		SELECT id::text, status FROM tokens WHERE vendor = $1 AND serial = $2 FOR UPDATE
	`, vendor, serial).Scan(&id, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("token %s %s is not in inventory; a station must report it first", vendor, serial)
	}
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	if status == "lost" || status == "retired" {
		return "", fmt.Errorf("token status %q cannot be assigned", status)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE tokens SET assigned_user_id = $2, status = 'active' WHERE id = $1
	`, id, userID); err != nil {
		return "", fmt.Errorf("assign token: %w", err)
	}
	return id, nil
}

// UnassignToken clears the assigned user and returns the token to the unassigned state.
func (s *Store) UnassignToken(ctx context.Context, tx pgx.Tx, vendor, serial string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		UPDATE tokens SET assigned_user_id = NULL, status = 'unassigned'
		WHERE vendor = $1 AND serial = $2 AND status IN ('active', 'unassigned')
		RETURNING id::text
	`, vendor, serial).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("token %s %s is not in inventory or is lost or retired", vendor, serial)
	}
	if err != nil {
		return "", fmt.Errorf("unassign token: %w", err)
	}
	return id, nil
}
