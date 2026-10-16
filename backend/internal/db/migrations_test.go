package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Exonical/sigil/backend/internal/testdb"
)

func TestMigrationsAreIdempotent(t *testing.T) {
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
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("migration count = %d, want 4", count)
	}
}
