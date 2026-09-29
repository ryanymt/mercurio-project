package db_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// The seed migrations give every environment the same start (acceptance criterion 5): foreman as
// the meta-project and the active one, the sandbox (P05) inactive, and one budget row per model
// provider.
func TestSeed(t *testing.T) {
	ctx := context.Background()
	conn := testdb.New(t)

	type project struct {
		id           string
		meta, active bool
		repoURL      string
	}
	rows, err := conn.QueryContext(ctx, "SELECT id, is_meta, is_active, repo_url FROM projects ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var projects []project
	for rows.Next() {
		var p project
		if err := rows.Scan(&p.id, &p.meta, &p.active, &p.repoURL); err != nil {
			t.Fatal(err)
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []project{
		{"foreman", true, true, "https://github.com/ryanymt/mercurio-project"},
		{"sandbox", false, false, "https://github.com/your-org/sandbox-repo"},
	}
	if !reflect.DeepEqual(projects, want) {
		t.Errorf("projects = %+v, want %+v", projects, want)
	}

	var providers []string
	rows, err = conn.QueryContext(ctx, "SELECT provider FROM budget ORDER BY provider")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(providers, []string{"anthropic", "zai"}) {
		t.Errorf("budget providers = %v, want [anthropic zai]", providers)
	}
}
