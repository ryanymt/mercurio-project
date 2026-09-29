package dispatcher_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ryanymt/mercurio-project/internal/dispatcher"
)

// Tests added at P04's close, holding clauses of the Anchor that the build's tests covered less
// than they said (evidence/close-tests.md).

// "A claim, its lease, claim token, event, request log, budget charge and attempts row commit in
// one transaction before the launcher is called": all of them are there after a claim, and none
// of them when that transaction's commit fails.
func TestAClaimIsOneTransaction(t *testing.T) {
	e := newEnv(t)
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	if out := e.tick(); out.Claimed != qa {
		t.Fatalf("claimed %d, want %d", out.Claimed, qa)
	}
	if n := e.count(`SELECT count(*) FROM ticket_events WHERE ticket_id = $1 AND actor = 'dispatcher' AND to_state = 'in_qa'`, qa); n != 1 {
		t.Fatalf("%d claim events, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM api_requests WHERE caller = $1`, dispatcher.DispatcherAccount); n != 1 {
		t.Fatalf("%d request-log rows, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM tickets WHERE id = $1 AND claim_token IS NOT NULL AND lease_expires_at > now()`, qa); n != 1 ||
		e.count(`SELECT count(*) FROM attempts WHERE ticket_id = $1`, qa) != 1 || e.consumed("anthropic") != 1 {
		t.Fatal("the claim's lease, token, attempt or charge is missing")
	}

	// The same claim, its commit made to fail: the connection is cut just before it.
	e2 := newEnv(t)
	qa2 := e2.seed(fixture{state: sAwaiting, attempts: 1})
	var pid int
	dispatcher.SetHooks(e2.d, dispatcher.Hooks{
		TxStarted: func(p int) { pid = p },
		BeforeCommit: func() {
			if _, err := e2.db.Exec(`SELECT pg_terminate_backend($1)`, pid); err != nil {
				t.Error(err)
			}
			time.Sleep(200 * time.Millisecond)
		},
	})
	if _, err := e2.d.Tick(context.Background()); err == nil {
		t.Fatal("the tick succeeded with its commit cut off")
	}
	if e2.state(qa2) != sAwaiting || e2.count(`SELECT count(*) FROM ticket_events WHERE ticket_id = $1`, qa2) != 0 ||
		e2.count(`SELECT count(*) FROM api_requests`) != 0 || e2.count(`SELECT count(*) FROM attempts`) != 0 ||
		e2.consumed("anthropic") != 0 || len(e2.launcher.launched()) != 0 {
		t.Fatal("part of a claim whose transaction failed was kept, or something launched")
	}
}

// D7: the project's row is locked FOR NO KEY UPDATE, which the key-share lock of a new ticket's
// insert does not conflict with: creating a ticket never waits for a tick.
func TestTicketCreationNeverWaitsForATick(t *testing.T) {
	e := newEnv(t)
	e.seed(fixture{state: sAwaiting, attempts: 1})
	a := holdBeforeCommit(t, e.d)
	done := make(chan error, 1)
	go func() {
		_, err := e.db.Exec(`INSERT INTO tickets (project_id, title) VALUES ('foreman', 'created during a tick')`)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		a.finish(t)
		t.Fatal("creating a ticket waited for the tick's lock on the project")
	}
	a.finish(t)
}

// "No reap ... refunds a unit": the budgets are the same after every leased state is reaped.
func TestNoReapRefundsAUnit(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE projects SET is_active = false`)
	e.exec(`UPDATE budget SET consumed_estimate = 5`)
	for _, s := range []fixture{
		{state: sClaimed, expired: true}, {state: sInProgress, attempts: 1, expired: true},
		{state: sInQA, attempts: 1, expired: true}, {state: sMerging, attempts: 1, expired: true},
	} {
		e.seed(s)
	}
	if out := e.tick(); len(out.Reaped) != 4 {
		t.Fatalf("reaped %v, want four", out.Reaped)
	}
	if e.consumed("zai") != 5 || e.consumed("anthropic") != 5 {
		t.Fatalf("budgets zai %v anthropic %v after reaps, want both still 5", e.consumed("zai"), e.consumed("anthropic"))
	}
}

// "parked_until ... read in the query, never written back": a passed date blocks new work, and the
// escalation's parking is left exactly as the human set it.
func TestParkedUntilIsNeverWrittenBack(t *testing.T) {
	e := newEnv(t)
	esc := e.seed(fixture{state: sEscalated, attempts: 1, parked: true, until: "now() - interval '1 minute'"})
	var before string
	e.db.QueryRow(`SELECT parked::text || coalesce(parked_reason, '') || parked_until::text FROM tickets WHERE id = $1`, esc).Scan(&before)
	e.seed(fixture{state: sReady})
	if out := e.tick(); out.Claimed != 0 {
		t.Fatal("new work claimed under an escalation parked until a date that has passed")
	}
	var after string
	e.db.QueryRow(`SELECT parked::text || coalesce(parked_reason, '') || parked_until::text FROM tickets WHERE id = $1`, esc).Scan(&after)
	if after != before {
		t.Fatalf("the tick wrote the parking back: %q, was %q", after, before)
	}
}

// A failed QA launch returns in_qa -> awaiting_review at once and refunds Claude's unit, as the
// Anchor names for each of the three claimed states.
func TestAFailedQALaunchIsReturnedAndRefunded(t *testing.T) {
	e := newEnv(t)
	e.launcher.fail = func(r dispatcher.LaunchRequest) bool { return true }
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	out := e.tick()
	if !out.LaunchFailed || e.state(qa) != sAwaiting || e.consumed("anthropic") != 0 {
		t.Fatalf("outcome %+v, state %s, anthropic %v: want returned at once and refunded", out, e.state(qa), e.consumed("anthropic"))
	}
}

// "With no model call anywhere in it": the dispatcher's package imports no HTTP client or model
// SDK. Its one outside call is git, as a process, through the risk evaluator's runner.
func TestTheDispatcherCallsNoModel(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, "github.com/ryanymt/mercurio-project/internal/dispatcher").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Fields(string(out)) {
		if strings.HasPrefix(imp, "net") || strings.Contains(imp, "anthropic") || strings.Contains(imp, "openai") ||
			strings.Contains(imp, "genai") || strings.Contains(imp, "grpc") {
			t.Errorf("the dispatcher imports %s", imp)
		}
	}
}
