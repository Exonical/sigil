package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotConfigured = errors.New("SIGIL_TEST_DATABASE_URL is unset")

func Open(ctx context.Context) (*db.Store, func(), error) {
	connectionString := os.Getenv("SIGIL_TEST_DATABASE_URL")
	if connectionString == "" {
		return nil, nil, ErrNotConfigured
	}
	admin, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to test database: %w", err)
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		admin.Close()
		return nil, nil, fmt.Errorf("generate test schema name: %w", err)
	}
	schema := "sigil_test_" + hex.EncodeToString(random[:])
	if _, err := admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		admin.Close()
		return nil, nil, fmt.Errorf("create isolated test schema: %w", err)
	}
	cleanup := func() {
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`)
		admin.Close()
	}
	poolConfig, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("parse test database URL: %w", err)
	}
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("open isolated test database pool: %w", err)
	}
	store := &db.Store{Pool: pool}
	if err := store.Migrate(ctx); err != nil {
		pool.Close()
		cleanup()
		return nil, nil, fmt.Errorf("migrate isolated test schema: %w", err)
	}
	cleanup = func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`)
		admin.Close()
	}
	return store, cleanup, nil
}
