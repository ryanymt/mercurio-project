package db_test

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// The viewer reads as `viewer`, which may SELECT five tables and nothing else (migration 00008;
// P06 D7): projects, ticket_events and artifacts whole, and tickets and attempts column by column,
// without claim_token, which holds a live lease's fence. Nothing on api_requests, whose stored
// responses hold claim tokens too, and no default privileges, so a later table or column is
// readable only by its own grant.

// viewerColumns are the columns of tickets and attempts the viewer may read: every one but
// claim_token, written out here so a new column needs a decision in this test and in 00008.
var viewerColumns = map[string][]string{
	"tickets": {"id", "project_id", "state", "title", "body", "acceptance_criteria", "parent_ticket_id", "depth",
		"priority", "branch", "base_sha", "merge_commit_sha", "claimed_by", "claimed_at", "lease_expires_at",
		"attempt_count", "risk_verdict", "qa_report_path", "escalated_at", "escalation_reason", "parked",
		"parked_reason", "parked_until", "failure_reason", "retained_until", "created_at", "updated_at",
		"parent_depth", "head_sha"},
	"attempts": {"id", "ticket_id", "attempt", "role", "provider", "model", "tier", "started_at", "ended_at",
		"outcome", "input_tokens", "output_tokens", "launch_id"},
}

var wholeTables = []string{"artifacts", "projects", "ticket_events"}

func refusedAsViewer(t *testing.T, viewer *sql.DB, stmt string) {
	t.Helper()
	_, err := viewer.ExecContext(context.Background(), stmt)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "42501" {
		t.Errorf("%s as viewer: %v, want a permission refusal (42501)", stmt, err)
	}
}

func TestTheViewerReadsOnlyWhatItIsGranted(t *testing.T) {
	ctx := context.Background()
	_, viewer := testdb.NewAsViewer(t)
	for _, table := range wholeTables {
		if _, err := viewer.ExecContext(ctx, `SELECT * FROM `+table+` LIMIT 1`); err != nil {
			t.Errorf("select * from %s as viewer: %v", table, err)
		}
	}
	for table, cols := range viewerColumns {
		if _, err := viewer.ExecContext(ctx, `SELECT `+strings.Join(cols, ", ")+` FROM `+table+` LIMIT 1`); err != nil {
			t.Errorf("select the granted columns of %s as viewer: %v", table, err)
		}
		refusedAsViewer(t, viewer, `SELECT claim_token FROM `+table)
		refusedAsViewer(t, viewer, `SELECT * FROM `+table)
	}
	for _, table := range []string{"api_requests", "budget", "promotions", "goose_db_version"} {
		refusedAsViewer(t, viewer, `SELECT 1 FROM `+table+` LIMIT 1`)
	}
	for _, table := range append(append([]string{}, wholeTables...), "tickets", "attempts") {
		refusedAsViewer(t, viewer, `UPDATE `+table+` SET id = id WHERE false`)
		refusedAsViewer(t, viewer, `DELETE FROM `+table+` WHERE false`)
	}
	refusedAsViewer(t, viewer, `INSERT INTO tickets (project_id, title) VALUES ('foreman', 'written as viewer')`)
	refusedAsViewer(t, viewer, `INSERT INTO ticket_events (ticket_id, to_state, actor) VALUES (1, 'draft', 'human')`)
	refusedAsViewer(t, viewer, `CREATE TABLE public.made_by_viewer (id int)`)
}

// The grants are exactly these: listed from the catalogue, so a grant added anywhere shows here.
func TestTheViewersGrantsAreExactly(t *testing.T) {
	ctx := context.Background()
	owner, _ := testdb.NewAsViewer(t)
	rows, err := owner.QueryContext(ctx, `
		SELECT table_name, privilege_type FROM information_schema.role_table_grants
		WHERE grantee = 'viewer' ORDER BY table_name, privilege_type`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table, priv string
		rows.Scan(&table, &priv)
		tables = append(tables, table+":"+priv)
	}
	rows.Close()
	want := []string{"artifacts:SELECT", "projects:SELECT", "ticket_events:SELECT"}
	if strings.Join(tables, " ") != strings.Join(want, " ") {
		t.Fatalf("table grants %v, want %v", tables, want)
	}
	for table, cols := range viewerColumns {
		rows, err := owner.QueryContext(ctx, `
			SELECT column_name FROM information_schema.column_privileges
			WHERE grantee = 'viewer' AND table_name = $1 AND privilege_type = 'SELECT'`, table)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var c string
			rows.Scan(&c)
			got = append(got, c)
		}
		rows.Close()
		sort.Strings(got)
		w := append([]string(nil), cols...)
		sort.Strings(w)
		if strings.Join(got, " ") != strings.Join(w, " ") {
			t.Errorf("%s columns granted %v, want %v", table, got, w)
		}
	}
	var others int
	owner.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.column_privileges
		WHERE grantee = 'viewer' AND privilege_type <> 'SELECT'`).Scan(&others)
	if others != 0 {
		t.Fatalf("%d column privileges other than SELECT", others)
	}
}

// A later table or column is not the viewer's: no default privileges carry to it.
func TestLaterTablesAndColumnsDoNotReachTheViewer(t *testing.T) {
	ctx := context.Background()
	owner, viewer := testdb.NewAsViewer(t)
	for _, stmt := range []string{
		`CREATE TABLE public.later_table (id BIGSERIAL PRIMARY KEY, note TEXT)`,
		`ALTER TABLE tickets ADD COLUMN later_note TEXT`,
	} {
		if _, err := owner.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	refusedAsViewer(t, viewer, `SELECT note FROM later_table`)
	refusedAsViewer(t, viewer, `SELECT later_note FROM tickets`)
}
