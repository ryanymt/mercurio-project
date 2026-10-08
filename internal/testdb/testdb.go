// Package testdb gives each test its own fresh Postgres database.
//
// The server is the one DATABASE_URL points at, a postgres:// URL; `make test` provides one
// (scripts/dev/testdb.sh). A test that asks for a database and finds no DATABASE_URL fails. It
// never skips: a skipped constraint test is a silently weakened suite (D6).
//
//	New(t) *sql.DB                  a fresh database with every migration applied, seed rows included
//	NewAsApp(t) (owner, app *sql.DB) the same, with a second pool connected as `app`, the deployed
//	                                 components' user, which holds only the rights 00007 grants
//	NewAsViewer(t) (owner, viewer *sql.DB) the same, connected as `viewer`, the viewer's read-only
//	                                 user, which holds only the rights 00008 grants
//	Empty(t) string                 the URL of a fresh, empty database, for testing the migration runner
//
// Both are dropped when the test ends. New's databases are clones of a template built once from
// the embedded migrations. Because `go test ./...` runs packages as parallel processes against the
// same server, the template is built under a Postgres advisory lock; afterwards it refuses
// connections, which cloning requires. Its name carries a hash of the migrations, so a changed
// schema gets a new template.
package testdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/migrations"
)

// The role the deployed components connect as (P05 D11). It is created on the test server, where
// roles are shared by every database, before the template is migrated, so migration 00007's grants
// reach every clone; its password is a fixed value for tests only.
const (
	appRole     = "app"
	appPassword = "foreman-test-app"
	// The viewer's read-only user (P06 D7), created the same way for migration 00008's grants.
	viewerRole     = "viewer"
	viewerPassword = "foreman-test-viewer"
	// setupVersion is part of the template's name: a template built by an older testdb, before the
	// roles existed, is never reused.
	setupVersion = "3"
)

// buildLockKey is the advisory lock taken while a template is built. Any constant works, as long
// as nothing else on the test server uses it.
const buildLockKey int64 = 0x666f72656d616e // "foreman"

var (
	setup    sync.Once
	admin    *sql.DB // connection pool to DATABASE_URL's own database, for CREATE/DROP DATABASE
	base     string  // DATABASE_URL
	template string  // name of the migrated template database
	setupErr error
)

// New returns a connection pool to a new database holding every migration and the seed rows.
func New(tb testing.TB) *sql.DB {
	tb.Helper()
	start(tb)
	name := uniqueName("foreman_test")
	createDatabase(tb, name, template)
	return openFor(tb, name)
}

// NewAsApp returns a new database like New's, with two pools: the test server's own user, which owns
// everything, and `app`, which holds only the rights migration 00007 grants.
func NewAsApp(tb testing.TB) (owner, app *sql.DB) {
	tb.Helper()
	start(tb)
	name := uniqueName("foreman_test")
	createDatabase(tb, name, template)
	u, err := url.Parse(withDatabase(base, name))
	if err != nil {
		tb.Fatalf("testdb: %v", err)
	}
	u.User = url.UserPassword(appRole, appPassword)
	return openFor(tb, name), openURL(tb, u.String())
}

// NewAsViewer returns a new database like New's, with two pools: the test server's own user, and
// `viewer`, which holds only the rights migration 00008 grants. ViewerURL gives the second's URL.
func NewAsViewer(tb testing.TB) (owner, viewer *sql.DB) {
	tb.Helper()
	owner, u := NewViewerURL(tb)
	return owner, openURL(tb, u)
}

// NewViewerURL returns a new database like New's: a pool as the server's own user, and the URL that
// connects as `viewer`, for a command that opens its own pool.
func NewViewerURL(tb testing.TB) (owner *sql.DB, viewerURL string) {
	tb.Helper()
	start(tb)
	name := uniqueName("foreman_test")
	createDatabase(tb, name, template)
	u, err := url.Parse(withDatabase(base, name))
	if err != nil {
		tb.Fatalf("testdb: %v", err)
	}
	u.User = url.UserPassword(viewerRole, viewerPassword)
	return openFor(tb, name), u.String()
}

// Empty returns the URL of a new, empty database: no schema, no goose version table.
func Empty(tb testing.TB) string {
	tb.Helper()
	start(tb)
	name := uniqueName("foreman_empty")
	createDatabase(tb, name, "template0")
	return withDatabase(base, name)
}

// start reads DATABASE_URL and, once per test process, builds or finds the template.
func start(tb testing.TB) {
	tb.Helper()
	raw := os.Getenv("DATABASE_URL")
	if raw == "" {
		tb.Fatal("testdb: DATABASE_URL is not set. Run the tests with `make test`, which starts a " +
			"Postgres for them, or point DATABASE_URL at one.")
	}
	if u, err := url.Parse(raw); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		tb.Fatal("testdb: DATABASE_URL must be a postgres:// URL")
	}
	setup.Do(func() {
		base = raw
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if admin, setupErr = db.Open(ctx, base); setupErr == nil {
			template, setupErr = buildTemplate(ctx)
		}
	})
	if setupErr != nil {
		tb.Fatalf("testdb: %v", setupErr)
	}
}

// buildTemplate returns the template's name, building it first unless a finished one exists.
func buildTemplate(ctx context.Context) (string, error) {
	name, err := templateName()
	if err != nil {
		return "", err
	}
	// Advisory locks belong to a session, so lock and unlock on one dedicated connection.
	conn, err := admin.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", buildLockKey); err != nil {
		return "", fmt.Errorf("lock template build: %w", err)
	}
	defer conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", buildLockKey)

	// The app and viewer roles, before any template is migrated; idempotent, and under the lock,
	// since test processes of every package share the server.
	for _, r := range []struct{ role, password string }{{appRole, appPassword}, {viewerRole, viewerPassword}} {
		if _, err := conn.ExecContext(ctx, `DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '`+r.role+`') THEN
				CREATE ROLE `+r.role+` LOGIN PASSWORD '`+r.password+`';
			END IF;
		END $$`); err != nil {
			return "", fmt.Errorf("create the %s role: %w", r.role, err)
		}
	}

	var done bool
	err = conn.QueryRowContext(ctx, "SELECT datistemplate FROM pg_database WHERE datname = $1", name).Scan(&done)
	switch {
	case err == nil && done:
		return name, nil // another test process built it
	case err == nil: // left half-built by a process that died; start again
		if _, err := conn.ExecContext(ctx, "DROP DATABASE "+quote(name)+" WITH (FORCE)"); err != nil {
			return "", fmt.Errorf("drop half-built template: %w", err)
		}
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("look for template: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "CREATE DATABASE "+quote(name)+" TEMPLATE template0"); err != nil {
		return "", fmt.Errorf("create template: %w", err)
	}
	tdb, err := db.Open(ctx, withDatabase(base, name))
	if err != nil {
		return "", err
	}
	_, err = db.Up(ctx, tdb)
	tdb.Close()
	if err != nil {
		return "", fmt.Errorf("migrate template: %w", err)
	}
	// Cloning needs a template nobody is connected to: forbid new connections, end stragglers.
	if _, err := conn.ExecContext(ctx, "ALTER DATABASE "+quote(name)+" WITH ALLOW_CONNECTIONS false IS_TEMPLATE true"); err != nil {
		return "", fmt.Errorf("seal template: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", name); err != nil {
		return "", fmt.Errorf("close template connections: %w", err)
	}
	return name, nil
}

// createDatabase creates name from the given template and drops it when the test ends.
func createDatabase(tb testing.TB, name, from string) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stmt := "CREATE DATABASE " + quote(name) + " TEMPLATE " + quote(from)
	for attempt := 1; ; attempt++ {
		_, err := admin.ExecContext(ctx, stmt)
		if err == nil {
			break
		}
		// 55006: a connection to the template is still closing. Brief; retry.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55006" && attempt < 50 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		tb.Fatalf("testdb: create database %s: %v", name, err)
	}
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quote(name)+" WITH (FORCE)"); err != nil {
			tb.Errorf("testdb: drop database %s: %v", name, err)
		}
	})
}

// openFor opens a pool to the named database, closed when the test ends (before the drop).
func openFor(tb testing.TB, name string) *sql.DB {
	tb.Helper()
	return openURL(tb, withDatabase(base, name))
}

// openURL opens a pool to a database URL, closed when the test ends.
func openURL(tb testing.TB, rawURL string) *sql.DB {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := db.Open(ctx, rawURL)
	if err != nil {
		tb.Fatalf("testdb: %v", err)
	}
	tb.Cleanup(func() { conn.Close() })
	return conn
}

// templateName is foreman_tmpl_ plus a hash of every embedded migration, names and contents.
func templateName() (string, error) {
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	h := sha256.New()
	fmt.Fprintf(h, "testdb setup %s\x00", setupVersion)
	for _, n := range names {
		b, err := fs.ReadFile(migrations.FS, n)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(b))
		h.Write(b)
	}
	return "foreman_tmpl_" + hex.EncodeToString(h.Sum(nil))[:12], nil
}

// withDatabase returns rawURL pointing at another database on the same server.
func withDatabase(rawURL, name string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" {
		panic(fmt.Sprintf("testdb: DATABASE_URL must be a postgres:// URL: %v", err))
	}
	u.Path = "/" + name
	return u.String()
}

func uniqueName(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func quote(name string) string { return pgx.Identifier{name}.Sanitize() }
