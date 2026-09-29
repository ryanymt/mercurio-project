package callbackapi_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// What the transition core does for the dispatcher (P04; docs/state-machine.md, "Reaps and failed
// launches", "An expired lease is final", "Three returns in a row", "Atomic claim").

// claimThrough claims a ticket through the core, as the dispatcher, and returns the new token. A
// new-work claim names the attempt it starts.
func claimThrough(t *testing.T, e *callbackapi.Engine, conn *sql.DB, id int64, from, to callbackapi.State) string {
	t.Helper()
	req := request(id, from, to, dispatcherCaller, chCore)
	if from == sReady {
		req.Branch = branchFor(id, cols(t, conn, id).Attempts+1)
	}
	return mustDo(t, e, conn, req).ClaimToken
}

// launchFailed is the dispatcher's return of a ticket whose launch definitely did not start.
func launchFailed(id int64, from, to callbackapi.State, token string) callbackapi.TransitionRequest {
	req := request(id, from, to, dispatcherCaller, chCore)
	req.Return, req.ClaimToken = callbackapi.ReturnLaunchFailed, token
	return req
}

func payloadOf(t *testing.T, ev event) map[string]any {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- the new-work claim: branch and base_sha ---------------------------------------------------

func TestNewWorkClaimRecordsBranchAndBase(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sReady, attempts: 1})
	req := request(id, sReady, sClaimed, dispatcherCaller, chCore)
	req.Branch = branchFor(id, 2)
	mustDo(t, newEngine(nil), conn, req)
	var branch, base string
	if err := conn.QueryRow(`SELECT branch, base_sha FROM tickets WHERE id = $1`, id).Scan(&branch, &base); err != nil {
		t.Fatal(err)
	}
	if branch != branchFor(id, 2) || base != baseFixtureSHA {
		t.Fatalf("branch %q, base_sha %q; want %q, %q", branch, base, branchFor(id, 2), baseFixtureSHA)
	}
}

func TestNewWorkClaimNeedsBranchAndBase(t *testing.T) {
	cases := map[string]func(r *callbackapi.TransitionRequest, id int64){
		"no base_sha":          func(r *callbackapi.TransitionRequest, id int64) { r.BaseSHA = "" },
		"abbreviated base_sha": func(r *callbackapi.TransitionRequest, id int64) { r.BaseSHA = "2222222" },
		"upper-case base_sha": func(r *callbackapi.TransitionRequest, id int64) {
			r.BaseSHA = "ABCDEF2222222222222222222222222222222222"
		},
		"no branch":                  func(r *callbackapi.TransitionRequest, id int64) { r.Branch = "" },
		"branch outside foreman":     func(r *callbackapi.TransitionRequest, id int64) { r.Branch = "feature/x" },
		"another ticket's branch":    func(r *callbackapi.TransitionRequest, id int64) { r.Branch = branchFor(id+1, 2) },
		"the attempt already used":   func(r *callbackapi.TransitionRequest, id int64) { r.Branch = branchFor(id, 1) },
		"an attempt beyond the next": func(r *callbackapi.TransitionRequest, id int64) { r.Branch = branchFor(id, 3) },
		"a suffix":                   func(r *callbackapi.TransitionRequest, id int64) { r.Branch = branchFor(id, 2) + "/x" },
		"a leading zero":             func(r *callbackapi.TransitionRequest, id int64) { r.Branch = fmt.Sprintf("foreman/0%d/2", id) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sReady, attempts: 1}) // the claim starts attempt 2
			before := snapshot(t, conn, id)
			req := request(id, sReady, sClaimed, dispatcherCaller, chCore)
			req.Branch = branchFor(id, 2)
			mutate(&req, id)
			_, err := do(t, newEngine(nil), conn, req)
			wantStatus(t, err, 400)
			assertUnchanged(t, conn, id, before, 0, 0)
		})
	}
}

// Branch and base_sha belong to the new-work claim alone.
func TestBranchAndBaseOnlyOnTheNewWorkClaim(t *testing.T) {
	conn := fresh(t)
	qaClaim := seed(t, conn, fixture{state: sAwaiting, attempts: 1})
	req := request(qaClaim, sAwaiting, sInQA, dispatcherCaller, chCore)
	req.BaseSHA = baseFixtureSHA
	_, err := do(t, newEngine(nil), conn, req)
	wantStatus(t, err, 400)

	start := seed(t, conn, fixture{state: sClaimed})
	req = request(start, sClaimed, sInProgress, dev, chHTTP)
	req.Branch = branchFor(start, 1)
	_, err = do(t, newEngine(nil), conn, req)
	wantStatus(t, err, 400)
}

// --- the return kinds (D9) --------------------------------------------------------------------

func TestDispatcherReturnNeedsAKnownKind(t *testing.T) {
	for _, kind := range []callbackapi.ReturnKind{"", "reap", "LEASE_EXPIRED"} {
		t.Run(fmt.Sprintf("%q", kind), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sClaimed, expired: true})
			before := snapshot(t, conn, id)
			req := request(id, sClaimed, sReady, dispatcherCaller, chCore)
			req.Return = kind
			_, err := do(t, newEngine(nil), conn, req)
			wantStatus(t, err, 400)
			assertUnchanged(t, conn, id, before, 0, 0)
		})
	}
}

// A kind names a dispatcher return and nothing else.
func TestReturnKindOnlyOnADispatcherReturn(t *testing.T) {
	conn := fresh(t)
	claim := seed(t, conn, fixture{state: sAwaiting, attempts: 1})
	req := request(claim, sAwaiting, sInQA, dispatcherCaller, chCore)
	req.Return = callbackapi.ReturnLeaseExpired
	_, err := do(t, newEngine(nil), conn, req)
	wantStatus(t, err, 400)

	giveUp := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req = request(giveUp, sInProgress, sReady, dev, chHTTP)
	req.Return = callbackapi.ReturnLaunchFailed
	_, err = do(t, newEngine(nil), conn, req)
	wantStatus(t, err, 400)
}

func TestReapRecordsItsKind(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sClaimed, expired: true})
	mustDo(t, newEngine(nil), conn, request(id, sClaimed, sReady, dispatcherCaller, chCore))
	if p := payloadOf(t, lastEvent(t, conn, id)); p["return"] != string(callbackapi.ReturnLeaseExpired) {
		t.Fatalf("reap event payload %v, want return=lease_expired", p)
	}
}

// A reap re-checks under the row lock that the lease has expired: a live lease is a 409 with
// nothing changed, on every return row.
func TestReapOfALiveLeaseIs409(t *testing.T) {
	for _, r := range []struct{ from, to callbackapi.State }{
		{sClaimed, sReady}, {sInProgress, sReady}, {sInQA, sAwaiting}, {sMerging, sApproved},
	} {
		t.Run(fmt.Sprintf("%s->%s", r.from, r.to), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: r.from, attempts: 1})
			before := snapshot(t, conn, id)
			_, err := do(t, newEngine(nil), conn, request(id, r.from, r.to, dispatcherCaller, chCore))
			wantStatus(t, err, 409)
			assertUnchanged(t, conn, id, before, 0, 0)
		})
	}
}

// A launch that definitely did not start returns the ticket at once, without waiting out the
// lease, from each of the three claimed states.
func TestFailedLaunchReturnsAtOnce(t *testing.T) {
	for _, c := range []struct{ from, to callbackapi.State }{
		{sReady, sClaimed}, {sAwaiting, sInQA}, {sApproved, sMerging},
	} {
		t.Run(string(c.to), func(t *testing.T) {
			conn := fresh(t)
			e := newEngine(nil)
			id := seed(t, conn, fixture{state: c.from, attempts: 1})
			token := claimThrough(t, e, conn, id, c.from, c.to)
			res := mustDo(t, e, conn, launchFailed(id, c.to, c.from, token))
			if res.State != c.from || state(t, conn, id) != c.from {
				t.Fatalf("state %s, want %s", state(t, conn, id), c.from)
			}
			if p := payloadOf(t, lastEvent(t, conn, id)); p["return"] != string(callbackapi.ReturnLaunchFailed) {
				t.Fatalf("event payload %v, want return=launch_failed", p)
			}
			if k := cols(t, conn, id); k.ClaimToken.Valid || k.Lease.Valid {
				t.Fatalf("a failed launch's return left a lease: %+v", k)
			}
		})
	}
}

// A failed-launch return is fenced: it needs the token the claim just issued, only while that claim
// is the ticket's latest event, and never from in_progress, where a runner is working.
func TestFailedLaunchIsFenced(t *testing.T) {
	t.Run("no token", func(t *testing.T) {
		conn := fresh(t)
		e := newEngine(nil)
		id := seed(t, conn, fixture{state: sReady})
		claimThrough(t, e, conn, id, sReady, sClaimed)
		before, events := snapshot(t, conn, id), eventCount(t, conn, id)
		_, err := do(t, e, conn, launchFailed(id, sClaimed, sReady, ""))
		wantStatus(t, err, 409)
		assertUnchanged(t, conn, id, before, events, 1)
	})
	t.Run("another token", func(t *testing.T) {
		conn := fresh(t)
		e := newEngine(nil)
		id := seed(t, conn, fixture{state: sReady})
		claimThrough(t, e, conn, id, sReady, sClaimed)
		before, events := snapshot(t, conn, id), eventCount(t, conn, id)
		_, err := do(t, e, conn, launchFailed(id, sClaimed, sReady, liveToken))
		wantStatus(t, err, 409)
		assertUnchanged(t, conn, id, before, events, 1)
	})
	t.Run("after a heartbeat", func(t *testing.T) {
		conn := fresh(t)
		e := newEngine(nil)
		id := seed(t, conn, fixture{state: sReady})
		token := claimThrough(t, e, conn, id, sReady, sClaimed)
		if _, err := doHeartbeat(t, conn, heartbeat(id, dev, token)); err != nil {
			t.Fatal(err)
		}
		_, err := do(t, e, conn, launchFailed(id, sClaimed, sReady, token))
		wantStatus(t, err, 409)
		if state(t, conn, id) != sClaimed {
			t.Fatal("a run that heartbeated was returned as never started")
		}
	})
	t.Run("from in_progress", func(t *testing.T) {
		conn := fresh(t)
		e := newEngine(nil)
		id := seed(t, conn, fixture{state: sReady})
		token := claimThrough(t, e, conn, id, sReady, sClaimed)
		start := request(id, sClaimed, sInProgress, dev, chHTTP)
		start.ClaimToken = token
		mustDo(t, e, conn, start)
		before, events := snapshot(t, conn, id), eventCount(t, conn, id)
		_, err := do(t, e, conn, launchFailed(id, sInProgress, sReady, token))
		wantStatus(t, err, 409)
		assertUnchanged(t, conn, id, before, events, 2)
	})
}

// Defence in depth: no dispatcher row enters in_progress, so the latest-event rule alone already
// refuses a failed-launch return from it. Even with an event log that made the dispatcher's claim
// look like the latest event, the return is refused, because a runner is working there.
func TestFailedLaunchNeverFromInProgress(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	if _, err := conn.Exec(`INSERT INTO ticket_events (ticket_id, from_state, to_state, actor, actor_id)
		VALUES ($1, 'ready', 'in_progress', 'dispatcher', $2)`, id, dispatcherCaller.Email); err != nil {
		t.Fatal(err)
	}
	before, events := snapshot(t, conn, id), eventCount(t, conn, id)
	_, err := do(t, newEngine(nil), conn, launchFailed(id, sInProgress, sReady, liveToken))
	wantStatus(t, err, 409)
	assertUnchanged(t, conn, id, before, events, 0)
}

// --- an expired lease is final (D14) ----------------------------------------------------------

func doArtifact(t *testing.T, conn *sql.DB, id int64, c callbackapi.Caller, token string) error {
	t.Helper()
	ctx := context.Background()
	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newEngine(nil).RegisterArtifact(ctx, tx, callbackapi.ArtifactRequest{
		TicketID: id, Caller: c, Kind: "log", GCSPath: fmt.Sprintf("foreman/%d/%d/run.log", id, cols(t, conn, id).Attempts),
		RequestID: newRequestID(), ClaimToken: token, Method: "POST", Path: fmt.Sprintf("/v1/tickets/%d/artifacts", id),
	})
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Once its lease has expired, the runner can no longer heartbeat, move the ticket or register an
// artifact; the dispatcher's reap goes through.
func TestExpiredLeaseRefusesTheRunner(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1, expired: true})
	before, events := snapshot(t, conn, id), eventCount(t, conn, id)

	_, err := doHeartbeat(t, conn, heartbeat(id, dev, liveToken))
	wantStatus(t, err, 409)
	_, err = do(t, e, conn, request(id, sInProgress, sAwaiting, dev, chHTTP))
	wantStatus(t, err, 409)
	wantStatus(t, doArtifact(t, conn, id, dev, liveToken), 409)
	assertUnchanged(t, conn, id, before, events, 0)
	if n := count(t, conn, `SELECT count(*) FROM artifacts WHERE ticket_id = $1`, id); n != 0 {
		t.Fatalf("%d artifacts registered on an expired lease", n)
	}

	mustDo(t, e, conn, request(id, sInProgress, sReady, dispatcherCaller, chCore))
	if s := state(t, conn, id); s != sReady {
		t.Fatalf("state %s after the reap, want ready", s)
	}
}

// setLease puts a ticket's lease a given time from the database's clock.
func setLease(t *testing.T, conn *sql.DB, id int64, d time.Duration) {
	t.Helper()
	if _, err := conn.Exec(`UPDATE tickets SET lease_expires_at = clock_timestamp() + $2 * interval '1 millisecond' WHERE id = $1`,
		id, d.Milliseconds()); err != nil {
		t.Fatal(err)
	}
}

// A runner request whose transaction began before the lease expired is judged when the check runs,
// not when the transaction began. The control shows the scenario tells the two apart: in the same
// transaction, the lease compared with now() still reads as live.
func TestExpiryIsJudgedNowNotAtTheTransactionsStart(t *testing.T) {
	conn := fresh(t)
	ctx := context.Background()
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	setLease(t, conn, id, time.Second)

	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var start time.Time
	if err := tx.QueryRow(`SELECT now()`).Scan(&start); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)

	var liveByNow bool
	if err := tx.QueryRow(`SELECT lease_expires_at > now() FROM tickets WHERE id = $1`, id).Scan(&liveByNow); err != nil {
		t.Fatal(err)
	}
	if !liveByNow {
		t.Fatal("control: compared with now() the lease already reads as expired, so this test cannot catch a check against now()")
	}
	_, err = newEngine(nil).Heartbeat(ctx, tx, heartbeat(id, dev, liveToken))
	wantStatus(t, err, 409)
}

// A heartbeat issued before expiry that waits behind a shared lock across the expiry is judged
// after the wait. The control shows why the check must be its own statement after the lock: the
// same comparison inside the waiting FOR UPDATE reads its clock before the wait, and calls the
// lease live.
func TestExpiryIsJudgedAfterTheLockWait(t *testing.T) {
	conn := fresh(t)
	ctx := context.Background()
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	setLease(t, conn, id, time.Second)

	holder, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.Exec(`SELECT 1 FROM tickets WHERE id = $1 FOR SHARE`, id); err != nil {
		t.Fatal(err)
	}

	control, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Rollback()
	controlPID := backendPID(t, control)
	controlLive := make(chan bool, 1)
	go func() {
		var live bool
		control.QueryRow(`SELECT lease_expires_at > clock_timestamp() FROM tickets WHERE id = $1 FOR UPDATE`, id).Scan(&live)
		controlLive <- live
	}()
	waitBlocked(t, conn, controlPID)

	hb, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer hb.Rollback()
	hbPID := backendPID(t, hb)
	hbErr := make(chan error, 1)
	go func() {
		_, err := newEngine(nil).Heartbeat(ctx, hb, heartbeat(id, dev, liveToken))
		hbErr <- err
	}()
	waitBlocked(t, conn, hbPID)

	time.Sleep(1500 * time.Millisecond) // the lease expires while both wait
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	if !<-controlLive {
		t.Fatal("control: the check inside the locking statement called the lease expired, so this test cannot tell the placements apart")
	}
	control.Rollback()
	wantStatus(t, <-hbErr, 409)
}

// A heartbeat extends the lease five minutes from the clock when it runs, not from its
// transaction's start.
func TestHeartbeatExtendsFromTheClock(t *testing.T) {
	conn := fresh(t)
	ctx := context.Background()
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
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
	res, err := newEngine(nil).Heartbeat(ctx, tx, heartbeat(id, dev, liveToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if min := start.Add(5*time.Minute + time.Second); res.LeaseExpiresAt.Before(min) {
		t.Fatalf("lease extended to %s, want at least %s (five minutes from the heartbeat, not the transaction's start)",
			res.LeaseExpiresAt, min)
	}
}

// --- three returns in a row (D8) --------------------------------------------------------------

// The third dispatcher return in a row escalates as the callback API's, from each claimed state.
func TestThirdReturnInARowEscalates(t *testing.T) {
	for _, c := range []struct{ from, to callbackapi.State }{
		{sReady, sClaimed}, {sAwaiting, sInQA}, {sApproved, sMerging},
	} {
		t.Run(string(c.to), func(t *testing.T) {
			conn := fresh(t)
			e := newEngine(nil)
			id := seed(t, conn, fixture{state: c.from, attempts: 1})
			for i := 1; i <= 3; i++ {
				token := claimThrough(t, e, conn, id, c.from, c.to)
				res := mustDo(t, e, conn, launchFailed(id, c.to, c.from, token))
				if i < 3 && res.State != c.from {
					t.Fatalf("return %d: state %s, want %s", i, res.State, c.from)
				}
			}
			if s := state(t, conn, id); s != sEscalated {
				t.Fatalf("state %s after three returns in a row, want escalated", s)
			}
			ev := lastEvent(t, conn, id)
			p := payloadOf(t, ev)
			if ev.Actor != string(callbackapi.RoleCallbackAPI) || ev.ActorID != dispatcherCaller.Email ||
				ev.From.String != string(c.to) || p["requested_to"] != string(c.from) || p["returns"] != float64(3) ||
				p["return"] != string(callbackapi.ReturnLaunchFailed) || p["reason"] == nil {
				t.Fatalf("escalation event %+v, payload %v", ev, p)
			}
			if k := cols(t, conn, id); !k.EscalatedAt.Valid || !k.EscalationReason.Valid || k.ClaimToken.Valid || k.Lease.Valid {
				t.Fatalf("escalated ticket columns %+v", k)
			}
		})
	}
}

// Returns count across leased states and kinds: a reaped dev session followed by two failed
// launches is three returns in a row (critique 2, G3).
func TestReturnsCountAcrossStatesAndKinds(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1, expired: true})
	mustDo(t, e, conn, request(id, sInProgress, sReady, dispatcherCaller, chCore))
	for i := 2; i <= 3; i++ {
		token := claimThrough(t, e, conn, id, sReady, sClaimed)
		mustDo(t, e, conn, launchFailed(id, sClaimed, sReady, token))
	}
	if s := state(t, conn, id); s != sEscalated {
		t.Fatalf("state %s, want escalated", s)
	}
}

// A runner's heartbeats are not transitions: they never reset the count.
func TestHeartbeatsDoNotResetTheCount(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sReady})
	for i := 1; i <= 3; i++ {
		token := claimThrough(t, e, conn, id, sReady, sClaimed)
		if _, err := doHeartbeat(t, conn, heartbeat(id, dev, token)); err != nil {
			t.Fatal(err)
		}
		expire(t, conn, id)
		res := mustDo(t, e, conn, request(id, sClaimed, sReady, dispatcherCaller, chCore))
		if want := map[bool]callbackapi.State{true: sEscalated, false: sReady}[i == 3]; res.State != want {
			t.Fatalf("reap %d: state %s, want %s", i, res.State, want)
		}
	}
}

// A transition a runner makes resets the count: two reaps, a dev session started and reaped (one),
// then two failed launches escalate only at the third since the runner's move.
func TestARunnersTransitionResetsTheCount(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sReady})
	for i := 0; i < 2; i++ {
		claimThrough(t, e, conn, id, sReady, sClaimed)
		expire(t, conn, id)
		mustDo(t, e, conn, request(id, sClaimed, sReady, dispatcherCaller, chCore))
	}
	token := claimThrough(t, e, conn, id, sReady, sClaimed)
	start := request(id, sClaimed, sInProgress, dev, chHTTP)
	start.ClaimToken = token
	mustDo(t, e, conn, start)
	expire(t, conn, id)
	if res := mustDo(t, e, conn, request(id, sInProgress, sReady, dispatcherCaller, chCore)); res.State != sReady {
		t.Fatalf("state %s after the first return since the runner's move, want ready", res.State)
	}
	token = claimThrough(t, e, conn, id, sReady, sClaimed)
	if res := mustDo(t, e, conn, launchFailed(id, sClaimed, sReady, token)); res.State != sReady {
		t.Fatalf("state %s after the second, want ready", res.State)
	}
	token = claimThrough(t, e, conn, id, sReady, sClaimed)
	if res := mustDo(t, e, conn, launchFailed(id, sClaimed, sReady, token)); res.State != sEscalated {
		t.Fatalf("state %s after the third, want escalated", res.State)
	}
}

// A human's event resets the count: after an escalation and a human's return to ready, it takes
// three more returns to escalate again.
func TestAHumansEventResetsTheCount(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sReady})
	returnOnce := func() callbackapi.State {
		token := claimThrough(t, e, conn, id, sReady, sClaimed)
		return mustDo(t, e, conn, launchFailed(id, sClaimed, sReady, token)).State
	}
	for i := 0; i < 3; i++ {
		returnOnce()
	}
	if s := state(t, conn, id); s != sEscalated {
		t.Fatalf("state %s, want escalated", s)
	}
	mustDo(t, e, conn, request(id, sEscalated, sReady, humanCaller, chHTTP))
	for i := 1; i <= 3; i++ {
		if got, want := returnOnce(), map[bool]callbackapi.State{true: sEscalated, false: sReady}[i == 3]; got != want {
			t.Fatalf("return %d after the human's move: state %s, want %s", i, got, want)
		}
	}
}

// --- back to QA (D17) ---------------------------------------------------------------------------

func TestHumanSendsAnEscalatedTicketBackToQA(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1, parked: true})
	mustDo(t, e, conn, request(id, sEscalated, sAwaiting, humanCaller, chHTTP))
	if s := state(t, conn, id); s != sAwaiting {
		t.Fatalf("state %s, want awaiting_review", s)
	}
	if k := cols(t, conn, id); k.Parked {
		t.Fatal("leaving escalated must clear parked")
	}

	noCommit := seed(t, conn, fixture{state: sEscalated, attempts: 1, noHead: true})
	before := snapshot(t, conn, noCommit)
	_, err := do(t, e, conn, request(noCommit, sEscalated, sAwaiting, humanCaller, chHTTP))
	wantStatus(t, err, 409)
	assertUnchanged(t, conn, noCommit, before, 0, 1)

	parent := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	seed(t, conn, fixture{state: sDone, parent: parent})
	before = snapshot(t, conn, parent)
	_, err = do(t, e, conn, request(parent, sEscalated, sAwaiting, humanCaller, chHTTP))
	wantStatus(t, err, 409)
	assertUnchanged(t, conn, parent, before, 0, 1)
}

// --- the attempt ends with its lease --------------------------------------------------------------

// insertAttempt writes the attempts row a launch would, for the lease holding token.
func insertAttempt(t *testing.T, conn *sql.DB, id int64, role callbackapi.Role, token string) {
	t.Helper()
	var provider, model, tier any = "anthropic", "claude-opus-5-5", "qa-1"
	if role == callbackapi.RoleIntegrator {
		provider, model, tier = nil, nil, nil
	}
	if _, err := conn.Exec(`INSERT INTO attempts (ticket_id, attempt, role, provider, model, tier, claim_token)
		VALUES ($1, 1, $2, $3, $4, $5, $6)`, id, string(role), provider, model, tier, token); err != nil {
		t.Fatal(err)
	}
}

func attemptEnd(t *testing.T, conn *sql.DB, token string) (ended bool, outcome sql.NullString) {
	t.Helper()
	if err := conn.QueryRow(`SELECT ended_at IS NOT NULL, outcome FROM attempts WHERE claim_token = $1`, token).
		Scan(&ended, &outcome); err != nil {
		t.Fatal(err)
	}
	return ended, outcome
}

// Wherever the core clears a claim token, it ends that lease's attempt, with the outcome the
// caller's move gives it.
func TestLeavingTheLeaseEndsTheAttempt(t *testing.T) {
	cases := []struct {
		name     string
		from, to callbackapi.State
		caller   callbackapi.Caller
		ch       callbackapi.Channel
		role     callbackapi.Role
		expired  bool
		want     string
	}{
		{"dev submits", sInProgress, sAwaiting, dev, chHTTP, callbackapi.RoleDev, false, "completed"},
		{"dev gives up", sInProgress, sReady, dev, chHTTP, callbackapi.RoleDev, false, "failed"},
		{"dev escalates", sInProgress, sEscalated, dev, chHTTP, callbackapi.RoleDev, false, "failed"},
		{"QA fails the work", sInQA, sReady, qa, chHTTP, callbackapi.RoleQA, false, "completed"},
		{"QA approves, diverted", sInQA, sApproved, qa, chHTTP, callbackapi.RoleQA, false, "completed"},
		{"integrator merges", sMerging, sMerged, integrator, chHTTP, callbackapi.RoleIntegrator, false, "completed"},
		{"integrator hits a conflict", sMerging, sReady, integrator, chHTTP, callbackapi.RoleIntegrator, false, "failed"},
		{"dispatcher reaps", sClaimed, sReady, dispatcherCaller, chCore, callbackapi.RoleDev, true, "reaped"},
		{"human abandons", sInProgress, sAbandoned, humanCaller, chHTTP, callbackapi.RoleDev, false, "abandoned"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: c.from, attempts: 1, expired: c.expired})
			insertAttempt(t, conn, id, c.role, liveToken)
			mustDo(t, newEngine(nil), conn, request(id, c.from, c.to, c.caller, c.ch))
			if ended, outcome := attemptEnd(t, conn, liveToken); !ended || outcome.String != c.want {
				t.Fatalf("attempt ended=%v outcome=%v, want ended with %s", ended, outcome, c.want)
			}
		})
	}
}

func TestFailedLaunchEndsTheAttempt(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sAwaiting, attempts: 1})
	token := claimThrough(t, e, conn, id, sAwaiting, sInQA)
	insertAttempt(t, conn, id, callbackapi.RoleQA, token)
	mustDo(t, e, conn, launchFailed(id, sInQA, sAwaiting, token))
	if ended, outcome := attemptEnd(t, conn, token); !ended || outcome.String != "launch_failed" {
		t.Fatalf("attempt ended=%v outcome=%v, want ended with launch_failed", ended, outcome)
	}
}

// An outcome already recorded (a rate limit the runner reported) is kept; the attempt still ends.
func TestAnOutcomeAlreadySetIsKept(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1, expired: true})
	insertAttempt(t, conn, id, callbackapi.RoleDev, liveToken)
	if _, err := conn.Exec(`UPDATE attempts SET outcome = 'rate_limited' WHERE claim_token = $1`, liveToken); err != nil {
		t.Fatal(err)
	}
	mustDo(t, newEngine(nil), conn, request(id, sInProgress, sReady, dispatcherCaller, chCore))
	if ended, outcome := attemptEnd(t, conn, liveToken); !ended || outcome.String != "rate_limited" {
		t.Fatalf("attempt ended=%v outcome=%v, want ended, still rate_limited", ended, outcome)
	}
}

// Starting the dev session keeps the lease, so the attempt stays open.
func TestStartingTheSessionKeepsTheAttemptOpen(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sClaimed})
	insertAttempt(t, conn, id, callbackapi.RoleDev, liveToken)
	mustDo(t, newEngine(nil), conn, request(id, sClaimed, sInProgress, dev, chHTTP))
	if ended, outcome := attemptEnd(t, conn, liveToken); ended || outcome.Valid {
		t.Fatalf("attempt ended=%v outcome=%v on claimed -> in_progress, want still open", ended, outcome)
	}
}
