package db_test

import (
	"context"
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/internal/testdb"
	"github.com/ryanymt/mercurio-project/migrations"
)

// migrationVersions returns the version of every embedded migration file, in file order.
func migrationVersions(t *testing.T) []int64 {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil || len(names) == 0 {
		t.Fatalf("no embedded migrations: %v", err)
	}
	var vs []int64
	for _, n := range names {
		v, err := strconv.ParseInt(strings.SplitN(n, "_", 2)[0], 10, 64)
		if err != nil {
			t.Fatalf("migration %s has no numeric version prefix", n)
		}
		vs = append(vs, v)
	}
	return vs
}

func openURL(t *testing.T, url string) *sql.DB {
	t.Helper()
	conn, err := db.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestUpMigratesAnEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	conn := openURL(t, testdb.Empty(t))

	res, err := db.Up(ctx, conn)
	if err != nil {
		t.Fatalf("Up on an empty database: %v", err)
	}
	if got, want := len(res), len(migrationVersions(t)); got != want {
		t.Fatalf("Up applied %d migrations, want all %d", got, want)
	}
	for _, table := range []string{"projects", "tickets", "ticket_events", "budget", "attempts", "promotions", "artifacts"} {
		var found sql.NullString
		if err := conn.QueryRowContext(ctx, "SELECT to_regclass($1)::text", "public."+table).Scan(&found); err != nil || !found.Valid {
			t.Errorf("table %s missing after Up (err %v)", table, err)
		}
	}
}

func TestUpAgainAppliesNothing(t *testing.T) {
	ctx := context.Background()
	conn := openURL(t, testdb.Empty(t))
	if _, err := db.Up(ctx, conn); err != nil {
		t.Fatal(err)
	}
	res, err := db.Up(ctx, conn)
	if err != nil {
		t.Fatalf("second Up: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("second Up applied %d migrations, want none", len(res))
	}
}

func TestRecordedVersionIsTheHighestFile(t *testing.T) {
	ctx := context.Background()
	conn := openURL(t, testdb.Empty(t))
	if v, err := db.Version(ctx, conn); err != nil || v != 0 {
		t.Fatalf("version before Up = %d, %v; want 0", v, err)
	}
	if _, err := db.Up(ctx, conn); err != nil {
		t.Fatal(err)
	}
	vs := migrationVersions(t)
	want := vs[len(vs)-1]
	if got, err := db.Version(ctx, conn); err != nil || got != want {
		t.Fatalf("recorded version = %d, %v; want %d, the highest migration file", got, err, want)
	}
	st, err := db.Status(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range st {
		if s.AppliedAt.IsZero() {
			t.Errorf("status: migration %d not applied", s.Source.Version)
		}
	}
}

// Two runners start together against one empty database. The session lock makes one wait for
// the other, so both succeed and every migration is applied exactly once; without the lock the
// second would fail on objects the first had just created.
func TestConcurrentUpAppliesOnce(t *testing.T) {
	ctx := context.Background()
	url := testdb.Empty(t)
	conns := []*sql.DB{openURL(t, url), openURL(t, url)}

	var wg sync.WaitGroup
	start := make(chan struct{})
	applied := make([]int, len(conns))
	errs := make([]error, len(conns))
	for i, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := db.Up(ctx, c)
			applied[i], errs[i] = len(res), err
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("runner %d: %v", i, err)
		}
	}
	if got, want := applied[0]+applied[1], len(migrationVersions(t)); got != want {
		t.Errorf("runners applied %d + %d migrations, want %d in total", applied[0], applied[1], want)
	}
	var dup int
	if err := conns[0].QueryRowContext(ctx, `
		SELECT count(*) FROM (
		  SELECT version_id FROM goose_db_version WHERE version_id > 0
		  GROUP BY version_id HAVING count(*) > 1) d`).Scan(&dup); err != nil {
		t.Fatal(err)
	}
	if dup != 0 {
		t.Errorf("%d migrations recorded more than once", dup)
	}
}
