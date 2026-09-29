package callbackapi_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

var (
	dev        = runner(callbackapi.RoleDev, "foreman")
	qa         = runner(callbackapi.RoleQA, "foreman")
	integrator = runner(callbackapi.RoleIntegrator, "foreman")
	spec       = runner(callbackapi.RoleSpec, "foreman")
)

const (
	sReady      = callbackapi.StateReady
	sDraft      = callbackapi.StateDraft
	sClaimed    = callbackapi.StateClaimed
	sInProgress = callbackapi.StateInProgress
	sAwaiting   = callbackapi.StateAwaitingReview
	sInQA       = callbackapi.StateInQA
	sApproved   = callbackapi.StateApproved
	sMerging    = callbackapi.StateMerging
	sMerged     = callbackapi.StateMerged
	sDone       = callbackapi.StateDone
	sEscalated  = callbackapi.StateEscalated
	sFailed     = callbackapi.StateFailed
	sAbandoned  = callbackapi.StateAbandoned
	sDecomposed = callbackapi.StateDecomposed
	chHTTP      = callbackapi.ChannelHTTP
	chCore      = callbackapi.ChannelCore
)

type columns struct {
	Attempts              int
	ClaimToken, ClaimedBy sql.NullString
	Lease, ClaimedAt      sql.NullTime
	EscalatedAt           sql.NullTime
	EscalationReason      sql.NullString
	FailureReason         sql.NullString
	RetainedUntil         sql.NullTime
	RiskVerdict           []byte
	Parked                bool
	ParkedReason          sql.NullString
	AC                    []byte
}

func cols(t *testing.T, conn *sql.DB, id int64) columns {
	t.Helper()
	var c columns
	err := conn.QueryRow(`
		SELECT attempt_count, claim_token, claimed_by, lease_expires_at, claimed_at, escalated_at,
		  escalation_reason, failure_reason, retained_until, coalesce(risk_verdict, 'null'::jsonb),
		  parked, parked_reason, coalesce(acceptance_criteria, 'null'::jsonb)
		FROM tickets WHERE id = $1`, id).
		Scan(&c.Attempts, &c.ClaimToken, &c.ClaimedBy, &c.Lease, &c.ClaimedAt, &c.EscalatedAt,
			&c.EscalationReason, &c.FailureReason, &c.RetainedUntil, &c.RiskVerdict, &c.Parked,
			&c.ParkedReason, &c.AC)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// --- the order of checks ---------------------------------------------------------------------

// A runner of the wrong role on a leased ticket, with no claim token, is refused because it is
// not its transition (403), not because of the fence (409): authorization comes first and
// does not read the ticket's state.
func TestWrongRoleOnLeasedTicketIs403Not409(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := request(id, sInProgress, sAwaiting, qa, chHTTP)
	req.ClaimToken = ""
	_, err := do(t, newEngine(nil), conn, req)
	wantStatus(t, err, 403)
}

// The right role naming a `from` the ticket has already left gets 409.
func TestStaleFromIs409(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sAwaiting, attempts: 1})
	before := snapshot(t, conn, id)
	_, err := do(t, newEngine(nil), conn, request(id, sInProgress, sAwaiting, dev, chHTTP))
	wantStatus(t, err, 409)
	assertUnchanged(t, conn, id, before, 0, 0)
}

func TestUnknownTicketIs404(t *testing.T) {
	conn := fresh(t)
	_, err := do(t, newEngine(nil), conn, request(999999, sReady, sClaimed, dispatcherCaller, chCore))
	wantStatus(t, err, 404)
	_, err = do(t, newEngine(nil), conn, request(999999, sInProgress, sAwaiting, dev, chHTTP))
	wantStatus(t, err, 404)
}

// A runner acting on another project's ticket is refused; a human acts across projects.
func TestProjectScope(t *testing.T) {
	conn := fresh(t)
	addProject(t, conn, "other")
	id := seed(t, conn, fixture{project: "other", state: sInProgress, attempts: 1})
	_, err := do(t, newEngine(nil), conn, request(id, sInProgress, sAwaiting, dev, chHTTP))
	wantStatus(t, err, 403)

	esc := seed(t, conn, fixture{project: "other", state: sEscalated, attempts: 1})
	mustDo(t, newEngine(nil), conn, request(esc, sEscalated, sReady, humanCaller, chHTTP))
}

func TestMalformedRequestsAre400(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	before := snapshot(t, conn, id)
	for name, mutate := range map[string]func(*callbackapi.TransitionRequest){
		"request id not a uuid": func(r *callbackapi.TransitionRequest) { r.RequestID = "req-1" },
		"unknown state":         func(r *callbackapi.TransitionRequest) { r.To = "blocked" },
		"payload not an object": func(r *callbackapi.TransitionRequest) { r.Payload = json.RawMessage(`[1]`) },
	} {
		t.Run(name, func(t *testing.T) {
			req := request(id, sInProgress, sAwaiting, dev, chHTTP)
			mutate(&req)
			_, err := do(t, newEngine(nil), conn, req)
			wantStatus(t, err, 400)
			assertUnchanged(t, conn, id, before, 0, 0)
		})
	}
}

// --- isolation --------------------------------------------------------------------------------

// The roll-up and the request log are correct only under READ COMMITTED; any other level is
// refused before anything is read.
func TestOnlyReadCommitted(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	tx, err := conn.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = newEngine(nil).Transition(context.Background(), tx, request(id, sInProgress, sAwaiting, dev, chHTTP))
	if err == nil {
		t.Fatal("a REPEATABLE READ transaction was accepted")
	}
	if s := state(t, conn, id); s != sInProgress {
		t.Fatalf("state %s after a refused transaction", s)
	}
}

// --- attempt accounting and the cap ------------------------------------------------------------

func TestOnlyStartingADevSessionUsesAnAttempt(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sClaimed, attempts: 0})
	mustDo(t, e, conn, request(id, sClaimed, sInProgress, dev, chHTTP))
	if c := cols(t, conn, id); c.Attempts != 1 {
		t.Fatalf("attempts = %d after claimed -> in_progress, want 1", c.Attempts)
	}
	mustDo(t, e, conn, request(id, sInProgress, sAwaiting, dev, chHTTP))
	mustDo(t, e, conn, request(id, sAwaiting, sInQA, dispatcherCaller, chCore))
	expire(t, conn, id)
	mustDo(t, e, conn, request(id, sInQA, sAwaiting, dispatcherCaller, chCore)) // a QA reap
	qaClaim := mustDo(t, e, conn, request(id, sAwaiting, sInQA, dispatcherCaller, chCore))
	fail := request(id, sInQA, sReady, qa, chHTTP) // QA failed, with the token its claim issued
	fail.ClaimToken = qaClaim.ClaimToken
	mustDo(t, e, conn, fail)
	if c := cols(t, conn, id); c.Attempts != 1 {
		t.Fatalf("attempts = %d after reaps and a QA failure, want still 1", c.Attempts)
	}
}

// A return to ready by a ticket that has used both attempts lands in failed, recorded as the
// callback API's, naming the caller and what it asked for.
func TestReturnToReadyAtTheCapFails(t *testing.T) {
	cases := []struct {
		name   string
		from   callbackapi.State
		caller callbackapi.Caller
		ch     callbackapi.Channel
	}{
		{"dev gives up", sInProgress, dev, chHTTP},
		{"dispatcher reaps", sInProgress, dispatcherCaller, chCore},
		{"QA fails it", sInQA, qa, chHTTP},
		{"rebase conflict", sMerging, integrator, chHTTP},
		{"human retries", sEscalated, humanCaller, chHTTP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: c.from, attempts: callbackapi.AttemptCap, expired: c.caller.Role == callbackapi.RoleDispatcher})
			res := mustDo(t, newEngine(nil), conn, request(id, c.from, sReady, c.caller, c.ch))
			if res.State != sFailed || state(t, conn, id) != sFailed {
				t.Fatalf("state %s, want failed", state(t, conn, id))
			}
			if n := eventCount(t, conn, id); n != 1 {
				t.Fatalf("%d events, want exactly 1", n)
			}
			ev := lastEvent(t, conn, id)
			if ev.Actor != string(callbackapi.RoleCallbackAPI) || ev.ActorID != c.caller.Email {
				t.Fatalf("event %+v: want actor callback_api, actor_id %s", ev, c.caller.Email)
			}
			var p map[string]any
			json.Unmarshal(ev.Payload, &p)
			if p["requested_to"] != string(sReady) {
				t.Fatalf("payload %s lacks requested_to=ready", ev.Payload)
			}
			k := cols(t, conn, id)
			if !k.FailureReason.Valid || !k.RetainedUntil.Valid || k.ClaimToken.Valid || k.Lease.Valid {
				t.Fatalf("failed ticket columns %+v: want failure_reason, retained_until, no lease", k)
			}
		})
	}
}

// --- leases and the claim token ---------------------------------------------------------------

func TestClaimTokenLifecycle(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sReady})

	claim := mustDo(t, e, conn, request(id, sReady, sClaimed, dispatcherCaller, chCore))
	c := cols(t, conn, id)
	if claim.ClaimToken == "" || c.ClaimToken.String != claim.ClaimToken || !c.Lease.Valid || !c.ClaimedAt.Valid || !c.ClaimedBy.Valid {
		t.Fatalf("a claim must set the token, lease and claimant: result %+v, columns %+v", claim, c)
	}

	start := request(id, sClaimed, sInProgress, dev, chHTTP)
	start.ClaimToken = claim.ClaimToken
	mustDo(t, e, conn, start)
	if k := cols(t, conn, id); k.ClaimToken.String != claim.ClaimToken || !k.Lease.Valid {
		t.Fatalf("claimed -> in_progress must keep the token and lease: %+v", k)
	}

	// A reap clears them, and the next claim issues a different token.
	expire(t, conn, id)
	mustDo(t, e, conn, request(id, sInProgress, sReady, dispatcherCaller, chCore))
	if k := cols(t, conn, id); k.ClaimToken.Valid || k.Lease.Valid || k.ClaimedBy.Valid {
		t.Fatalf("a reap must clear the lease and token: %+v", k)
	}
	claimAgain := request(id, sReady, sClaimed, dispatcherCaller, chCore)
	claimAgain.Branch = branchFor(id, 2) // the first session used an attempt
	again := mustDo(t, e, conn, claimAgain)
	if again.ClaimToken == claim.ClaimToken {
		t.Fatal("a new claim reused the previous token")
	}

	// The reaped runner's old token no longer works.
	stale := request(id, sClaimed, sInProgress, dev, chHTTP)
	stale.ClaimToken = claim.ClaimToken
	_, err := do(t, e, conn, stale)
	wantStatus(t, err, 409)

	// Leaving the leased set clears them.
	start2 := request(id, sClaimed, sInProgress, dev, chHTTP)
	start2.ClaimToken = again.ClaimToken
	mustDo(t, e, conn, start2)
	done := request(id, sInProgress, sAwaiting, dev, chHTTP)
	done.ClaimToken = again.ClaimToken
	mustDo(t, e, conn, done)
	if k := cols(t, conn, id); k.ClaimToken.Valid || k.Lease.Valid {
		t.Fatalf("leaving the leased set must clear the lease and token: %+v", k)
	}
}

func TestFenceRefusesMissingOrWrongToken(t *testing.T) {
	for name, token := range map[string]string{"missing": "", "wrong": "not-the-token"} {
		t.Run(name, func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
			before := snapshot(t, conn, id)
			req := request(id, sInProgress, sAwaiting, dev, chHTTP)
			req.ClaimToken = token
			_, err := do(t, newEngine(nil), conn, req)
			wantStatus(t, err, 409)
			assertUnchanged(t, conn, id, before, 0, 0)
		})
	}
}

// A leased ticket whose token is NULL refuses every runner call, so a missing header can never
// match a missing token.
func TestNullTokenRefusesRunners(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1, noToken: true})
	req := request(id, sInProgress, sAwaiting, dev, chHTTP)
	req.ClaimToken = ""
	_, err := do(t, newEngine(nil), conn, req)
	wantStatus(t, err, 409)
}

// --- escalation bookkeeping, parking, tickets with children -----------------------------------

func TestEscalationBookkeepingAndParkingCleared(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	esc := request(id, sInProgress, sEscalated, dev, chHTTP)
	esc.Payload = json.RawMessage(`{"reason":"the spec contradicts itself"}`)
	mustDo(t, e, conn, esc)
	if k := cols(t, conn, id); !k.EscalatedAt.Valid || !k.EscalationReason.Valid || k.ClaimToken.Valid {
		t.Fatalf("a move to escalated must set escalated_at and a reason and end the lease: %+v", k)
	}
	if _, err := conn.Exec(`UPDATE tickets SET parked = true, parked_reason = 'later' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	mustDo(t, e, conn, request(id, sEscalated, sReady, humanCaller, chHTTP))
	if k := cols(t, conn, id); k.Parked || k.ParkedReason.Valid {
		t.Fatalf("leaving escalated must clear parking (D21): %+v", k)
	}
}

// A ticket with children leaves escalated only for done, failed or abandoned (D19).
func TestTicketWithChildrenLeavesEscalatedOnlyToAnEnd(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	parent := seed(t, conn, fixture{state: sEscalated})
	seed(t, conn, fixture{state: sFailed, parent: parent})
	for _, to := range []callbackapi.State{sReady, sApproved} {
		_, err := do(t, e, conn, request(parent, sEscalated, to, humanCaller, chHTTP))
		wantStatus(t, err, 409)
	}
	mustDo(t, e, conn, request(parent, sEscalated, sDone, humanCaller, chHTTP))
}

func TestDraftToReadyNeedsAcceptanceCriteria(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sDraft})
	for name, ac := range map[string][]callbackapi.Criterion{
		"none":       nil,
		"empty text": {{ID: "AC1", Text: " "}},
		"no id":      {{ID: "", Text: "it works"}},
	} {
		t.Run(name, func(t *testing.T) {
			req := request(id, sDraft, sReady, spec, chHTTP)
			req.AcceptanceCriteria = ac
			_, err := do(t, e, conn, req)
			wantStatus(t, err, 400)
		})
	}
	req := request(id, sDraft, sReady, spec, chHTTP)
	req.AcceptanceCriteria = []callbackapi.Criterion{{ID: "AC1", Text: "it works"}, {ID: "AC2", Text: "it is tested"}}
	mustDo(t, e, conn, req)
	var ac []callbackapi.Criterion
	json.Unmarshal(cols(t, conn, id).AC, &ac)
	if len(ac) != 2 || ac[1].ID != "AC2" {
		t.Fatalf("acceptance criteria written = %+v", ac)
	}
}

// --- atomicity and races ------------------------------------------------------------------------

// A failure after the ticket is updated (here the event insert, made to fail by a trigger) rolls
// back the update too: never a state change without its event.
func TestFailureAfterUpdateRollsBackBoth(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	if _, err := conn.Exec(`
		CREATE FUNCTION refuse_event() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'event insert refused by test'; END $$;
		CREATE TRIGGER refuse_event BEFORE INSERT ON ticket_events FOR EACH ROW EXECUTE FUNCTION refuse_event();`); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, conn, id)
	_, err := do(t, newEngine(nil), conn, request(id, sInProgress, sAwaiting, dev, chHTTP))
	if err == nil {
		t.Fatal("the transition succeeded although its event could not be written")
	}
	assertUnchanged(t, conn, id, before, 0, 0)
}

// Two transitions racing on one ticket are evaluated one after the other. B blocks on A's row
// lock; when A commits, B finds the ticket no longer in its `from` and gets 409. Nothing is lost.
func TestRacingTransitionsSerialise(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	ctx := context.Background()
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})

	txA, _ := callbackapi.BeginTx(ctx, conn)
	if _, err := e.Transition(ctx, txA, request(id, sInProgress, sAwaiting, dev, chHTTP)); err != nil {
		t.Fatal(err)
	}
	txB, _ := callbackapi.BeginTx(ctx, conn)
	pidB := backendPID(t, txB)
	errB := make(chan error, 1)
	go func() {
		_, err := e.Transition(ctx, txB, request(id, sInProgress, sEscalated, dev, chHTTP))
		errB <- err
	}()
	waitBlocked(t, conn, pidB)
	if err := txA.Commit(); err != nil {
		t.Fatal(err)
	}
	err := <-errB
	txB.Rollback()
	wantStatus(t, err, 409)
	if s := state(t, conn, id); s != sAwaiting {
		t.Fatalf("state %s, want A's awaiting_review", s)
	}
	if n := eventCount(t, conn, id); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
}

// Every claim issues a fresh token and lease, and every reap clears them: all three queues'
// claims and all four reaps (the Anchor's leases criterion, row by row).
func TestEveryClaimAndReapHandlesTheToken(t *testing.T) {
	claims := []struct{ from, to callbackapi.State }{
		{sReady, sClaimed}, {sAwaiting, sInQA}, {sApproved, sMerging},
	}
	for _, c := range claims {
		t.Run(fmt.Sprintf("claim %s->%s", c.from, c.to), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: c.from, attempts: 1})
			req := request(id, c.from, c.to, dispatcherCaller, chCore)
			if c.from == sReady {
				req.Branch = branchFor(id, 2)
			}
			res := mustDo(t, newEngine(nil), conn, req)
			k := cols(t, conn, id)
			if res.ClaimToken == "" || k.ClaimToken.String != res.ClaimToken || !k.Lease.Valid || !k.ClaimedBy.Valid {
				t.Fatalf("claim did not set a token and lease: result %+v, columns %+v", res, k)
			}
		})
	}
	reaps := []struct{ from, to callbackapi.State }{
		{sClaimed, sReady}, {sInProgress, sReady}, {sInQA, sAwaiting}, {sMerging, sApproved},
	}
	for _, r := range reaps {
		t.Run(fmt.Sprintf("reap %s->%s", r.from, r.to), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: r.from, attempts: 1, expired: true})
			mustDo(t, newEngine(nil), conn, request(id, r.from, r.to, dispatcherCaller, chCore))
			if k := cols(t, conn, id); k.ClaimToken.Valid || k.Lease.Valid || k.ClaimedBy.Valid || k.ClaimedAt.Valid {
				t.Fatalf("reap left a lease behind: %+v", k)
			}
		})
	}
}
