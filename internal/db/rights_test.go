package db_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// The deployed components connect as `app`, which may read and change rows and nothing more
// (migration 00007; P05 D11). Tests connect as the server's superuser, so without these a missing
// grant would pass `make test` and fail in production.

func refusedAsApp(t *testing.T, app *sql.DB, stmt string, args ...any) {
	t.Helper()
	_, err := app.ExecContext(context.Background(), stmt, args...)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "42501" {
		t.Fatalf("%s as app: %v, want a permission refusal (42501)", stmt, err)
	}
}

func TestAppHasRowRightsOnly(t *testing.T) {
	ctx := context.Background()
	_, app := testdb.NewAsApp(t)

	var id int64
	if err := app.QueryRowContext(ctx,
		`INSERT INTO tickets (project_id, title) VALUES ('foreman', 'written as app') RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("insert as app: %v", err)
	}
	if _, err := app.ExecContext(ctx, `UPDATE tickets SET title = 'updated as app' WHERE id = $1`, id); err != nil {
		t.Fatalf("update as app: %v", err)
	}
	for _, table := range []string{"projects", "tickets", "ticket_events", "budget", "attempts", "promotions", "artifacts", "api_requests"} {
		if _, err := app.ExecContext(ctx, `SELECT 1 FROM `+table+` LIMIT 1`); err != nil {
			t.Errorf("select from %s as app: %v", table, err)
		}
	}
	if _, err := app.ExecContext(ctx, `SELECT 1 FROM projects WHERE id = 'foreman' FOR NO KEY UPDATE`); err != nil {
		t.Errorf("the tick's project lock as app: %v", err)
	}
	refusedAsApp(t, app, `DELETE FROM tickets WHERE id = $1`, id)
	refusedAsApp(t, app, `SELECT 1 FROM goose_db_version`)
	refusedAsApp(t, app, `CREATE TABLE public.made_by_app (id int)`)
}

// Tables a later migration creates are usable by `app` without a grant of their own: the default
// privileges cover them and their sequences.
func TestLaterTablesReachApp(t *testing.T) {
	ctx := context.Background()
	owner, app := testdb.NewAsApp(t)
	if _, err := owner.ExecContext(ctx, `CREATE TABLE public.later_table (id BIGSERIAL PRIMARY KEY, note TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ExecContext(ctx, `INSERT INTO later_table (note) VALUES ('as app')`); err != nil {
		t.Fatalf("insert into a later table as app: %v", err)
	}
}

// `foreman db rights` reports what the connected user can do, changing nothing. The control: the
// test server's superuser may create a table, and the report says so.
func TestRightsReport(t *testing.T) {
	ctx := context.Background()
	owner, app := testdb.NewAsApp(t)

	r, err := db.ReportRights(ctx, app)
	if err != nil {
		t.Fatal(err)
	}
	if r.User != "app" || r.CloudSQLSuperuser || r.CreateRole || r.CreateDB || !r.CreateTableRefused {
		t.Fatalf("report as app: %+v", r)
	}
	o, err := db.ReportRights(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if o.CreateTableRefused {
		t.Fatalf("control: the report says the superuser cannot create a table: %+v", o)
	}
	var n int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM pg_tables WHERE tablename LIKE 'foreman_rights_probe%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the report left %d probe tables behind (%v)", n, err)
	}
}
