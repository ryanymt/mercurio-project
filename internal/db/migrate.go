// Package db connects to foreman's Postgres database and applies its migrations.
package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver (D2)
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/ryanymt/mercurio-project/migrations"
)

// Open connects to the database at url, a postgres:// URL, and checks that it answers.
func Open(ctx context.Context, url string) (*sql.DB, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return db, nil
}

// newProvider returns a goose provider over the embedded migrations (D3). Its Postgres session
// lock serialises concurrent runners; goose's package-level functions take no lock, so two of them
// would race on the DDL and on goose's version table. Each migration runs in its own transaction.
func newProvider(db *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, fmt.Errorf("migration lock: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithSessionLocker(locker), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return nil, fmt.Errorf("load migrations: %w", err)
	}
	return p, nil
}

// Up applies every pending migration, oldest first, and returns what it applied: nothing when the
// database is already current. It does not close db.
func Up(ctx context.Context, db *sql.DB) ([]*goose.MigrationResult, error) {
	p, err := newProvider(db)
	if err != nil {
		return nil, err
	}
	res, err := p.Up(ctx)
	if err != nil {
		return res, fmt.Errorf("apply migrations: %w", err)
	}
	return res, nil
}

// Status lists every migration and whether it has been applied.
func Status(ctx context.Context, db *sql.DB) ([]*goose.MigrationStatus, error) {
	p, err := newProvider(db)
	if err != nil {
		return nil, err
	}
	st, err := p.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("migration status: %w", err)
	}
	return st, nil
}

// Version returns the highest migration version applied to db, or 0 if none has been.
func Version(ctx context.Context, db *sql.DB) (int64, error) {
	p, err := newProvider(db)
	if err != nil {
		return 0, err
	}
	v, err := p.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("migration version: %w", err)
	}
	return v, nil
}
