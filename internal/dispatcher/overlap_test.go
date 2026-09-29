package dispatcher_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// Overlaps forced with the tick's hooks, never left to timing (P04 T4; red team 3, R1). Each
// mechanism is armed where it alone holds its property; evidence/T4-mutations.md shows each test
// failing with its mechanism removed.

type tickResult struct {
	out dispatcher.Outcome
	err error
}

// heldTick runs a tick that stops just before its claim commits, until released.
type heldTick struct {
	release chan struct{}
	done    chan tickResult
}

func holdBeforeCommit(t *testing.T, d *dispatcher.Dispatcher) *heldTick {
	t.Helper()
	h := &heldTick{release: make(chan struct{}), done: make(chan tickResult, 1)}
	reached := make(chan struct{})
	var once sync.Once
	dispatcher.SetHooks(d, dispatcher.Hooks{BeforeCommit: func() {
		once.Do(func() { close(reached); <-h.release })
	}})
	go func() {
		out, err := d.Tick(context.Background())
		h.done <- tickResult{out, err}
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the held tick never reached its commit")
	}
	return h
}

func (h *heldTick) finish(t *testing.T) dispatcher.Outcome {
	t.Helper()
	close(h.release)
	r := <-h.done
	if r.err != nil {
		t.Fatalf("held tick: %v", r.err)
	}
	return r.out
}

// startTick runs a tick in the background, reporting the server process of each transaction it
// begins, so the test can wait until one of them is blocked.
func startTick(d *dispatcher.Dispatcher) (pids chan int, done chan tickResult) {
	pids, done = make(chan int, 16), make(chan tickResult, 1)
	dispatcher.SetHooks(d, dispatcher.Hooks{TxStarted: func(pid int) { pids <- pid }})
	go func() {
		out, err := d.Tick(context.Background())
		done <- tickResult{out, err}
	}()
	return pids, done
}

// waitTickBlocked waits until one of a tick's transactions is waiting on a lock.
func waitTickBlocked(t *testing.T, db *sql.DB, pids chan int, done chan tickResult) {
	t.Helper()
	var seen []int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case p := <-pids:
			seen = append(seen, p)
		case r := <-done:
			t.Fatalf("the tick finished (%+v, %v) without ever waiting on a lock", r.out, r.err)
		default:
		}
		for _, p := range seen {
			if testdb.IsBlocked(db, p) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the tick never blocked on a lock")
}

// Two ticks overlapping never exceed one lease per role, never claim the same ticket and never
// start two integrations: the second waits on the project's row, then finds the role's slot
// taken. Repeated.
func TestOverlappingTicksKeepOneLeasePerRole(t *testing.T) {
	for _, c := range []struct {
		name   string
		from   callbackapi.State
		leased []callbackapi.State
	}{
		{"dev", sReady, []callbackapi.State{sClaimed, sInProgress}},
		{"integrator", sApproved, []callbackapi.State{sMerging}},
	} {
		for i := 0; i < 3; i++ {
			t.Run(c.name, func(t *testing.T) {
				e := newEnv(t)
				first := e.seed(fixture{state: c.from, attempts: 1, priority: 9})
				second := e.seed(fixture{state: c.from, attempts: 1})
				a := holdBeforeCommit(t, e.d)
				b := e.dispatcher()
				pids, done := startTick(b)
				waitTickBlocked(t, e.db, pids, done)
				outA := a.finish(t)
				r := <-done
				if r.err != nil {
					t.Fatal(r.err)
				}
				if outA.Claimed != first || r.out.Claimed != 0 {
					t.Fatalf("tick A claimed %d, tick B %d; want A %d and B nothing", outA.Claimed, r.out.Claimed, first)
				}
				if n := e.liveLeases(c.leased...); n != 1 || e.state(second) != c.from {
					t.Fatalf("%d live %s leases, want 1", n, c.name)
				}
			})
		}
	}
}

// The gate never waits on a runner: a leased ticket it cannot lock is held by a request in flight
// and counts as a live lease, even with its lease expired. The tick claims nothing for that role
// and finishes while the runner's transaction is still open.
func TestTheGateCountsARunnerInFlight(t *testing.T) {
	e := newEnv(t)
	busy := e.seed(fixture{state: sInProgress, attempts: 1})
	work := e.seed(fixture{state: sReady})
	var runner *sql.Tx
	dispatcher.SetHooks(e.d, dispatcher.Hooks{AfterReap: func() { // on the tick's goroutine: t.Error, never t.Fatal
		if _, err := e.db.Exec(`UPDATE tickets SET lease_expires_at = now() - interval '1 second' WHERE id = $1`, busy); err != nil {
			t.Error(err)
		}
		var err error
		if runner, err = e.db.Begin(); err != nil {
			t.Error(err)
			return
		}
		if _, err := runner.Exec(`SELECT 1 FROM tickets WHERE id = $1 FOR UPDATE`, busy); err != nil {
			t.Error(err)
		}
	}})
	done := make(chan tickResult, 1)
	go func() { out, err := e.d.Tick(context.Background()); done <- tickResult{out, err} }()
	select {
	case r := <-done:
		if r.err != nil || r.out.Claimed != 0 || e.state(work) != sReady {
			t.Fatalf("outcome %+v, %v: want nothing claimed while the dev slot's runner is in flight", r.out, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the tick waited on a runner's transaction")
	}
	runner.Rollback()
}

// A ticket a human's open transaction holds is passed over, not waited on: the tick claims the
// next one.
func TestACandidateHeldElsewhereIsPassedOver(t *testing.T) {
	e := newEnv(t)
	dispatcher.SetLockTimeout(e.d, 2000)
	held := e.seed(fixture{state: sReady, priority: 9})
	next := e.seed(fixture{state: sReady})
	human, err := e.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer human.Rollback()
	if _, err := human.Exec(`SELECT 1 FROM tickets WHERE id = $1 FOR UPDATE`, held); err != nil {
		t.Fatal(err)
	}
	if out := e.tick(); out.Claimed != next {
		t.Fatalf("claimed %d, want %d past the held ticket %d", out.Claimed, next, held)
	}
}

// A provider paused between the tick's unlocked read of the budgets and its lock on the budget row
// is not charged: the tick looks again without it and claims a ticket on the other provider.
func TestAPauseBetweenReadAndLockIsHonoured(t *testing.T) {
	e := newEnv(t)
	first := e.seed(fixture{state: sReady, priority: 9})  // attempt 1: GLM
	second := e.seed(fixture{state: sReady, attempts: 1}) // attempt 2: Claude Sonnet
	var once sync.Once
	dispatcher.SetHooks(e.d, dispatcher.Hooks{BeforeBudgetLock: func() {
		once.Do(func() { e.exec(`UPDATE budget SET paused_until = now() + interval '1 hour' WHERE provider = 'zai'`) })
	}})
	if out := e.tick(); out.Claimed != second || e.state(first) != sReady {
		t.Fatalf("claimed %d, want %d on Claude after GLM was paused", out.Claimed, second)
	}
	if e.consumed("zai") != 0 {
		t.Fatal("the paused provider was charged")
	}
}

// Never overdrawn under overlap: with room for exactly one unit of Claude, tick A claims QA, and
// tick B, overlapping, does not charge Claude again for new work on its second attempt.
func TestNeverOverdrawnUnderOverlap(t *testing.T) {
	for i := 0; i < 3; i++ {
		e := newEnv(t)
		e.exec(`UPDATE budget SET window_capacity = 1.2 WHERE provider = 'anthropic'`) // 1.02 above the reserve
		qa := e.seed(fixture{state: sAwaiting, attempts: 1, priority: 9})
		work := e.seed(fixture{state: sReady, attempts: 1}) // attempt 2: Claude Sonnet
		a := holdBeforeCommit(t, e.d)
		b := e.dispatcher()
		pids, done := startTick(b)
		waitTickBlocked(t, e.db, pids, done)
		if out := a.finish(t); out.Claimed != qa {
			t.Fatalf("tick A claimed %d, want QA %d", out.Claimed, qa)
		}
		if r := <-done; r.err != nil || r.out.Claimed != 0 {
			t.Fatalf("tick B: %+v, %v; want nothing claimed", r.out, r.err)
		}
		if c := e.consumed("anthropic"); c != 1 || e.state(work) != sReady {
			t.Fatalf("anthropic consumed %v, want 1", c)
		}
	}
}

// A lock timeout bounds every tick transaction: a reap stuck behind a stalled session skips that
// ticket, and a pick stuck on a budget row claims nothing; the tick finishes either way.
func TestALockTimeoutEndsAStuckTick(t *testing.T) {
	e := newEnv(t)
	dispatcher.SetLockTimeout(e.d, 300)
	stuck := e.seed(fixture{state: sInProgress, attempts: 1, expired: true})
	stalled, err := e.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stalled.Exec(`SELECT 1 FROM tickets WHERE id = $1 FOR UPDATE`, stuck); err != nil {
		t.Fatal(err)
	}
	e.exec(`UPDATE projects SET is_active = false`)
	start := time.Now()
	if out := e.tick(); len(out.Reaped) != 0 || e.state(stuck) != sInProgress {
		t.Fatalf("outcome %+v: want the stuck ticket skipped", out)
	}
	stalled.Rollback()
	e.exec(`UPDATE projects SET is_active = true WHERE id = 'foreman'`)
	e.exec(`UPDATE tickets SET state = 'done', claim_token = NULL, claimed_by = NULL, claimed_at = NULL, lease_expires_at = NULL WHERE id = $1`, stuck)

	work := e.seed(fixture{state: sReady})
	budget, err := e.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Rollback()
	if _, err := budget.Exec(`SELECT 1 FROM budget WHERE provider = 'zai' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	if out := e.tick(); out.Claimed != 0 || e.state(work) != sReady || e.consumed("zai") != 0 {
		t.Fatalf("outcome %+v: want nothing claimed behind a locked budget row", out)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("two stuck ticks took %s", took)
	}
}
