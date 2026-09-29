package testdb_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

func TestNewIsMigratedAndSeeded(t *testing.T) {
	ctx := context.Background()
	conn := testdb.New(t)
	v, err := db.Version(ctx, conn)
	if err != nil || v == 0 {
		t.Fatalf("clone's migration version = %d, %v; want the latest", v, err)
	}
	var n int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM projects WHERE id = 'foreman'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("seeded foreman project: count %d, %v", n, err)
	}
}

// Each test's database is its own: a row written in one clone is absent from the next.
func TestClonesAreIsolated(t *testing.T) {
	ctx := context.Background()
	a, b := testdb.New(t), testdb.New(t)
	if _, err := a.ExecContext(ctx,
		"INSERT INTO projects (id, name, repo_url) VALUES ('only-in-a', 'a', 'https://example.invalid/a')"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := b.QueryRowContext(ctx, "SELECT count(*) FROM projects WHERE id = 'only-in-a'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("a row written in one test database is visible in another")
	}
}

func TestEmptyHasNoSchema(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, testdb.Empty(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRowContext(ctx,
		"SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("empty database has %d tables", n)
	}
}

// A test that needs a database and has no DATABASE_URL must fail, never skip. The check runs this
// test binary again, without DATABASE_URL, on a test that asks for a database.
func TestNewFailsWithoutDatabaseURL(t *testing.T) {
	if os.Getenv("TESTDB_CHILD") == "1" {
		testdb.New(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNewFailsWithoutDatabaseURL$", "-test.v", "-test.count=1")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DATABASE_URL=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "TESTDB_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the child test passed without DATABASE_URL; it must fail:\n%s", out)
	}
	for _, want := range []string{"--- FAIL: TestNewFailsWithoutDatabaseURL", "DATABASE_URL is not set"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("child output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Errorf("the child test skipped; it must fail:\n%s", out)
	}
}
