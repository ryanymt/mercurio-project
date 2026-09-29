package db_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

func activeProjects(t *testing.T, conn *sql.DB) []string {
	t.Helper()
	rows, err := conn.Query(`SELECT id FROM projects WHERE is_active ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids
}

// `foreman project activate` makes the named project the only active one, in both directions (the
// unique index checks row by row, so a single UPDATE fails one way round), and records when (P05
// D18).
func TestActivateProjectBothWays(t *testing.T) {
	ctx := context.Background()
	conn := testdb.New(t)
	for _, id := range []string{"sandbox", "foreman", "sandbox"} {
		if err := db.ActivateProject(ctx, conn, id); err != nil {
			t.Fatalf("activate %s: %v", id, err)
		}
		if got := activeProjects(t, conn); len(got) != 1 || got[0] != id {
			t.Fatalf("active after activating %s: %v", id, got)
		}
		var recent bool
		if err := conn.QueryRow(`SELECT last_activated_at > now() - interval '1 minute' FROM projects WHERE id = $1`, id).Scan(&recent); err != nil || !recent {
			t.Fatalf("%s's last_activated_at not set (%v)", id, err)
		}
	}
}

func TestActivateUnknownProjectChangesNothing(t *testing.T) {
	ctx := context.Background()
	conn := testdb.New(t)
	if err := db.ActivateProject(ctx, conn, "nowhere"); err == nil {
		t.Fatal("an unknown project was activated")
	}
	if got := activeProjects(t, conn); len(got) != 1 || got[0] != "foreman" {
		t.Fatalf("active after a refused activation: %v, want foreman still", got)
	}
}
