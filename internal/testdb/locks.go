package testdb

import (
	"database/sql"
	"testing"
	"time"
)

// Helpers for tests that make two transactions meet at a lock, the deterministic way to test a
// race (P02; moved here for the dispatcher's tests, P04 T4).

// BackendPID returns the server process of an open transaction.
func BackendPID(tb testing.TB, tx *sql.Tx) int {
	tb.Helper()
	var pid int
	if err := tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		tb.Fatal(err)
	}
	return pid
}

// IsBlocked reports whether the server process pid is waiting on a lock now.
func IsBlocked(db *sql.DB, pid int) bool {
	var waiting bool
	db.QueryRow(`SELECT coalesce(wait_event_type = 'Lock', false) FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&waiting)
	return waiting
}

// WaitBlocked waits until the server process pid is waiting on a lock, failing the test after
// ten seconds.
func WaitBlocked(tb testing.TB, db *sql.DB, pid int) {
	tb.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if IsBlocked(db, pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	tb.Fatalf("process %d never blocked on a lock", pid)
}
