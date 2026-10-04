package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const migrationLock int64 = 0x534947494c4d4947

type Store struct {
	Pool *pgxpool.Pool
}

func Open(ctx context.Context, connectionString string) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("could not initialize database pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database connection failed")
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() {
	s.Pool.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire database connection for migrations: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return fmt.Errorf("lock database migrations: %w", err)
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLock)
	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version integer PRIMARY KEY,
			name text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, name := range files {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		var applied bool
		err = conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", version).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if applied {
			continue
		}
		sql, err := migrationFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if _, err := tx.Conn().PgConn().Exec(ctx, string(sql)).ReadAll(); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version, name) VALUES($1, $2)", version, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

func migrationVersion(name string) (int, error) {
	base := strings.TrimPrefix(name, "migrations/")
	prefix, _, ok := strings.Cut(base, "_")
	if !ok {
		return 0, fmt.Errorf("invalid migration name %q", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("invalid migration version in %q", name)
	}
	return version, nil
}

func InTx(ctx context.Context, pool *pgxpool.Pool, operation func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
