package callbackapi_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// The three claims, and the call each runner makes first: a dev runner starts its session; QA and
// integration claims go straight into their working states, so those runners heartbeat first.
var firstCalls = []struct {
	from, to callbackapi.State
	owner    callbackapi.Caller
}{
	{sReady, sClaimed, dev}, {sAwaiting, sInQA, qa}, {sApproved, sMerging, integrator},
}

// claim makes the dispatcher's claim of a ticket in from, and returns its claim token.
func claim(t *testing.T, conn *sql.DB, id int64, from, to callbackapi.State) string {
	t.Helper()
	req := request(id, from, to, dispatcherCaller, chCore)
	if from == sReady {
		req.Branch = branchFor(id, 2)
	}
	return mustDo(t, newEngine(nil), conn, req).ClaimToken
}

// firstCall makes the runner's first call after a claim into to.
func firstCall(t *testing.T, conn *sql.DB, id int64, to callbackapi.State, owner callbackapi.Caller, token string) error {
	t.Helper()
	if to == sClaimed {
		req := request(id, sClaimed, sInProgress, owner, chHTTP)
		req.ClaimToken = token
		_, err := do(t, newEngine(nil), conn, req)
		return err
	}
	_, err := doHeartbeat(t, conn, heartbeat(id, owner, token))
	return err
}

// backdate moves a ticket's claim and lease d into the past, as if the claim had been made d ago.
func backdate(t *testing.T, conn *sql.DB, id int64, d time.Duration) {
	t.Helper()
	if _, err := conn.Exec(`
		UPDATE tickets SET claimed_at = claimed_at - $2 * interval '1 millisecond',
		  lease_expires_at = lease_expires_at - $2 * interval '1 millisecond'
		WHERE id = $1`, id, d.Milliseconds()); err != nil {
		t.Fatal(err)
	}
}

// leaseLeft is how long the ticket's lease runs past the database's clock.
func leaseLeft(t *testing.T, conn *sql.DB, id int64) time.Duration {
	t.Helper()
	var secs float64
	if err := conn.QueryRow(`SELECT extract(epoch FROM lease_expires_at - clock_timestamp()) FROM tickets WHERE id = $1`,
		id).Scan(&secs); err != nil {
		t.Fatal(err)
	}
	return time.Duration(secs * float64(time.Second))
}

// leaseEnd is the ticket's lease_expires_at.
func leaseEnd(t *testing.T, conn *sql.DB, id int64) time.Time {
	t.Helper()
	var end time.Time
	if err := conn.QueryRow(`SELECT lease_expires_at FROM tickets WHERE id = $1`, id).Scan(&end); err != nil {
		t.Fatal(err)
	}
	return end
}

// Every claim opens a 10-minute first window, for a Cloud Run job's start (P06 D2).
func TestEveryClaimOpensATenMinuteWindow(t *testing.T) {
	for _, c := range firstCalls {
		t.Run(fmt.Sprintf("%s->%s", c.from, c.to), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: c.from, attempts: 1})
			claim(t, conn, id, c.from, c.to)
			var secs float64
			if err := conn.QueryRow(`SELECT extract(epoch FROM lease_expires_at - claimed_at) FROM tickets WHERE id = $1`,
				id).Scan(&secs); err != nil {
				t.Fatal(err)
			}
			if secs != 600 {
				t.Fatalf("the claim's lease runs %vs past its claim, want 600", secs)
			}
		})
	}
}

// A runner's first call 9 minutes after its claim is inside the window; one 10 minutes after is
// refused, and changes nothing.
func TestFirstCallInsideTheFirstWindow(t *testing.T) {
	for _, c := range firstCalls {
		for _, late := range []struct {
			after time.Duration
			ok    bool
		}{{9 * time.Minute, true}, {10 * time.Minute, false}} {
			t.Run(fmt.Sprintf("%s after %s", c.to, late.after), func(t *testing.T) {
				conn := fresh(t)
				id := seed(t, conn, fixture{state: c.from, attempts: 1})
				token := claim(t, conn, id, c.from, c.to)
				backdate(t, conn, id, late.after)
				before, events := snapshot(t, conn, id), eventCount(t, conn, id)
				requests := count(t, conn, `SELECT count(*) FROM api_requests`)
				err := firstCall(t, conn, id, c.to, c.owner, token)
				if late.ok {
					if err != nil {
						t.Fatalf("a first call %s after the claim was refused: %v", late.after, err)
					}
					return
				}
				wantStatus(t, err, 409)
				assertUnchanged(t, conn, id, before, events, requests)
			})
		}
	}
}

// A dev runner's session start keeps the later of the lease's end and five minutes from the clock
// (red team R11): an early start does not cut the first window short, and a late one is not left
// seconds.
func TestStartingKeepsTheLaterLeaseEnd(t *testing.T) {
	t.Run("early", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sReady, attempts: 1})
		token := claim(t, conn, id, sReady, sClaimed)
		end := leaseEnd(t, conn, id)
		if err := firstCall(t, conn, id, sClaimed, dev, token); err != nil {
			t.Fatal(err)
		}
		if got := leaseEnd(t, conn, id); !got.Equal(end) {
			t.Fatalf("an early start moved the lease from %s to %s, want it kept", end, got)
		}
	})
	t.Run("late", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sReady, attempts: 1})
		token := claim(t, conn, id, sReady, sClaimed)
		backdate(t, conn, id, 9*time.Minute+30*time.Second)
		if err := firstCall(t, conn, id, sClaimed, dev, token); err != nil {
			t.Fatal(err)
		}
		if left := leaseLeft(t, conn, id); left < 5*time.Minute-5*time.Second || left > 5*time.Minute {
			t.Fatalf("a late start left the lease %s, want five minutes from the clock", left)
		}
	})
}

// A heartbeat still sets the lease five minutes from the clock, inside the first window too, so a
// runner that heartbeats at once gives the rest of the window up (the runner contract).
func TestHeartbeatInTheFirstWindowSetsFiveMinutes(t *testing.T) {
	for _, c := range firstCalls {
		t.Run(string(c.to), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: c.from, attempts: 1})
			token := claim(t, conn, id, c.from, c.to)
			if _, err := doHeartbeat(t, conn, heartbeat(id, c.owner, token)); err != nil {
				t.Fatal(err)
			}
			if left := leaseLeft(t, conn, id); left < 5*time.Minute-5*time.Second || left > 5*time.Minute {
				t.Fatalf("a heartbeat left the lease %s, want five minutes from the clock", left)
			}
		})
	}
}

// A late start extends from the clock when it runs, not from its transaction's start.
func TestLateStartExtendsFromTheClock(t *testing.T) {
	conn := fresh(t)
	ctx := context.Background()
	id := seed(t, conn, fixture{state: sReady, attempts: 1})
	token := claim(t, conn, id, sReady, sClaimed)
	backdate(t, conn, id, 9*time.Minute+30*time.Second)

	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var start time.Time
	if err := tx.QueryRow(`SELECT now()`).Scan(&start); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	req := request(id, sClaimed, sInProgress, dev, chHTTP)
	req.ClaimToken = token
	if _, err := newEngine(nil).Transition(ctx, tx, req); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if min := start.Add(5*time.Minute + time.Second); leaseEnd(t, conn, id).Before(min) {
		t.Fatalf("lease extended to %s, want at least %s (five minutes from the start, not the transaction's)",
			leaseEnd(t, conn, id), min)
	}
}
