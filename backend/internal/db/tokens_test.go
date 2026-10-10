package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Exonical/sigil/backend/internal/testdb"
)

func TestTokenAssignmentRequiresASignedInUserAndWritesStatus(t *testing.T) {
	store, cleanup, err := testdb.Open(context.Background())
	if errors.Is(err, testdb.ErrNotConfigured) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO tokens(vendor, serial) VALUES('Yubico', '39192733')`); err != nil {
		t.Fatal(err)
	}

	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindUserByName(ctx, tx, "admin1"); err == nil {
		t.Fatal("a user who has never signed in must not be assignable")
	}
	_ = tx.Rollback(ctx)

	userID, err := store.UpsertUser(ctx, "https://idp.example/", "subject-admin1", "admin1", "admin1@example.test", "Admin One")
	if err != nil {
		t.Fatal(err)
	}
	tx, err = store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found, err := store.FindUserByName(ctx, tx, "Admin1")
	if err != nil || found != userID {
		t.Fatalf("FindUserByName = %q, %v; want %q", found, err, userID)
	}
	if _, err := store.AssignToken(ctx, tx, "Yubico", "39192733", userID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	var assigned *string
	if err := store.Pool.QueryRow(ctx, `SELECT status, assigned_user_id::text FROM tokens WHERE serial = '39192733'`).Scan(&status, &assigned); err != nil {
		t.Fatal(err)
	}
	if status != "active" || assigned == nil || *assigned != userID {
		t.Fatalf("after assign: status=%q assigned=%v", status, assigned)
	}

	tx, err = store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UnassignToken(ctx, tx, "Yubico", "39192733"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status, assigned_user_id::text FROM tokens WHERE serial = '39192733'`).Scan(&status, &assigned); err != nil {
		t.Fatal(err)
	}
	if status != "unassigned" || assigned != nil {
		t.Fatalf("after unassign: status=%q assigned=%v", status, assigned)
	}
}
