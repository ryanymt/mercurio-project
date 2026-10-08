package viewer_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/testdb"
	"github.com/ryanymt/mercurio-project/internal/viewer"
)

// At startup the viewer checks its own database rights and refuses to start when it could write
// anything, or cannot read one of its five tables (P06 D7; red team R7, R7#2). Cloud SQL silently
// adds cloudsqlsuperuser to a user whose roles are wrong, so this is checked where it runs.

func TestTheRightsCheckPassesForTheViewer(t *testing.T) {
	_, conn := testdb.NewAsViewer(t)
	got, err := viewer.CheckRights(context.Background(), conn)
	if err != nil {
		t.Fatalf("the viewer's own user refused: %v", err)
	}
	if got.User != "viewer" || len(got.Reads) != 5 || len(got.Writes) != 0 {
		t.Fatalf("report %+v", got)
	}
}

func TestTheRightsCheckRefusesAWriter(t *testing.T) {
	owner, app := testdb.NewAsApp(t)
	for name, conn := range map[string]*sql.DB{"the server's own user": owner, "app": app} {
		t.Run(name, func(t *testing.T) {
			got, err := viewer.CheckRights(context.Background(), conn)
			if err == nil || !strings.Contains(err.Error(), "write") || len(got.Writes) == 0 {
				t.Fatalf("a user that can write passed: %+v, %v", got, err)
			}
		})
	}
}

// Any write the user was granted, on any table or sequence, column by column or through PUBLIC, and
// the right to create tables, is refused at startup (the T8 mutation run: V5, V6, V10).
func TestTheRightsCheckRefusesEveryWriteGrant(t *testing.T) {
	for name, grant := range map[string]string{
		"INSERT on tickets":        `GRANT INSERT ON tickets TO viewer`,
		"UPDATE of one column":     `GRANT UPDATE (title) ON tickets TO viewer`,
		"INSERT of one column":     `GRANT INSERT (outcome) ON attempts TO viewer`,
		"DELETE on artifacts":      `GRANT DELETE ON artifacts TO viewer`,
		"TRUNCATE on projects":     `GRANT TRUNCATE ON projects TO viewer`,
		"TRIGGER on ticket_events": `GRANT TRIGGER ON ticket_events TO viewer`,
		"INSERT on api_requests":   `GRANT INSERT ON api_requests TO viewer`,
		"a sequence's USAGE":       `GRANT USAGE ON SEQUENCE tickets_id_seq TO viewer`,
		"DELETE through PUBLIC":    `GRANT DELETE ON budget TO PUBLIC`,
		"CREATE in the schema":     `GRANT CREATE ON SCHEMA public TO viewer`,
		"UPDATE on a later table":  `CREATE TABLE later (id int); GRANT UPDATE ON later TO viewer`,
		"INSERT on a later view":   `CREATE VIEW later_view AS SELECT id FROM projects; GRANT INSERT ON later_view TO viewer`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			owner, conn := testdb.NewAsViewer(t)
			if _, err := owner.ExecContext(ctx, grant); err != nil {
				t.Fatal(err)
			}
			got, err := viewer.CheckRights(ctx, conn)
			if err == nil || !strings.Contains(err.Error(), "write") || len(got.Writes) == 0 {
				t.Fatalf("%s passed: %+v, %v", grant, got, err)
			}
		})
	}
}

func TestTheRightsCheckRefusesAMissingRead(t *testing.T) {
	ctx := context.Background()
	owner, conn := testdb.NewAsViewer(t)
	if _, err := owner.ExecContext(ctx, `REVOKE SELECT ON artifacts FROM viewer`); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.CheckRights(ctx, conn); err == nil || !strings.Contains(err.Error(), "artifacts") {
		t.Fatalf("a viewer that cannot read artifacts passed: %v", err)
	}
}
