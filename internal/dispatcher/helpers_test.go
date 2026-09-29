package dispatcher_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

const baseSHA = "3333333333333333333333333333333333333333"

// fakeRemote stands in for git ls-remote, counting its calls; onCall runs inside the call, after
// the first transaction and before the second.
type fakeRemote struct {
	mu     sync.Mutex
	calls  int
	sha    string
	err    error
	onCall func()
}

func (f *fakeRemote) LsRemote(ctx context.Context, url, branch string) (string, error) {
	f.mu.Lock()
	f.calls++
	onCall := f.onCall
	f.mu.Unlock()
	if onCall != nil {
		onCall()
	}
	return f.sha, f.err
}

func (f *fakeRemote) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeLauncher records every request; fail makes a launch report that nothing started.
type fakeLauncher struct {
	mu       sync.Mutex
	requests []dispatcher.LaunchRequest
	fail     func(dispatcher.LaunchRequest) bool
	onLaunch func(dispatcher.LaunchRequest)
	roles    []callbackapi.Role // the roles it can start; every runner role when nil
}

// Roles names the roles it can start for any project (P05 D8, D20).
func (f *fakeLauncher) Roles(project string) []callbackapi.Role {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.roles != nil {
		return f.roles
	}
	return []callbackapi.Role{callbackapi.RoleDev, callbackapi.RoleQA, callbackapi.RoleIntegrator, callbackapi.RoleSpec, callbackapi.RoleArchitect}
}

func (f *fakeLauncher) Launch(ctx context.Context, req dispatcher.LaunchRequest) (string, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	fail, on := f.fail, f.onLaunch
	f.mu.Unlock()
	if on != nil {
		on(req)
	}
	if fail != nil && fail(req) {
		return "", errors.New("the runner did not start")
	}
	return "launch-" + randomHex(4), nil
}

func (f *fakeLauncher) launched() []dispatcher.LaunchRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dispatcher.LaunchRequest(nil), f.requests...)
}

type env struct {
	t        *testing.T
	db       *sql.DB
	remote   *fakeRemote
	launcher *fakeLauncher
	d        *dispatcher.Dispatcher
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newEnv is a fresh database (foreman active, both budgets seeded) and a dispatcher over it, with
// a fake remote at baseSHA and a launcher that records.
func newEnv(t *testing.T) *env {
	t.Helper()
	db := testdb.New(t)
	e := &env{t: t, db: db, remote: &fakeRemote{sha: baseSHA}, launcher: &fakeLauncher{}}
	e.d = e.dispatcher()
	return e
}

// dispatcher builds another dispatcher over the same database, remote and launcher: a second tick
// process.
func (e *env) dispatcher() *dispatcher.Dispatcher {
	e.t.Helper()
	tiers, err := dispatcher.EmbeddedTiers()
	if err != nil {
		e.t.Fatal(err)
	}
	return dispatcher.New(e.db, callbackapi.NewEngine(nil, quietLog()), tiers, e.remote, e.launcher, quietLog())
}

func (e *env) tick() dispatcher.Outcome {
	e.t.Helper()
	out, err := e.d.Tick(context.Background())
	if err != nil {
		e.t.Fatalf("tick: %v", err)
	}
	return out
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// fixture is a ticket inserted directly, in any state.
type fixture struct {
	project  string // default foreman
	state    callbackapi.State
	attempts int
	parent   int64
	priority int
	expired  bool // a leased ticket whose lease has expired
	parked   bool
	until    string // parked_until, as SQL: "now() + interval '1 hour'"
}

func (e *env) seed(f fixture) int64 {
	e.t.Helper()
	if f.project == "" {
		f.project = "foreman"
	}
	var parent sql.NullInt64
	depth := 0
	if f.parent != 0 {
		parent, depth = sql.NullInt64{Int64: f.parent, Valid: true}, 1
	}
	leased := callbackapi.IsLeased(f.state)
	var token sql.NullString
	if leased {
		token = sql.NullString{String: randomHex(16), Valid: true}
	}
	lease := "NULL"
	switch {
	case leased && f.expired:
		lease = "now() - interval '1 minute'"
	case leased:
		lease = "now() + interval '5 minutes'"
	}
	until := "NULL"
	if f.until != "" {
		until = f.until
	}
	var head sql.NullString
	switch f.state {
	case callbackapi.StateAwaitingReview, callbackapi.StateInQA, callbackapi.StateApproved, callbackapi.StateMerging, callbackapi.StateEscalated:
		head = sql.NullString{String: "4444444444444444444444444444444444444444", Valid: true}
	}
	var id int64
	err := e.db.QueryRow(`
		INSERT INTO tickets (project_id, title, state, attempt_count, parent_ticket_id, depth, priority,
		  claim_token, claimed_by, claimed_at, lease_expires_at, parked, parked_reason, parked_until,
		  acceptance_criteria, escalated_at, base_sha, head_sha)
		VALUES ($1, 'fixture', $2, $3, $4, $5, $6, $7, CASE WHEN $8 THEN 'runner' END, CASE WHEN $8 THEN now() END,
		  `+lease+`, $9, CASE WHEN $9 THEN 'parked by fixture' END, `+until+`,
		  '[{"id":"AC1","text":"it works"}]', CASE WHEN $10 THEN now() END,
		  CASE WHEN $11 THEN '5555555555555555555555555555555555555555' END, $12)
		RETURNING id`,
		f.project, string(f.state), f.attempts, parent, depth, f.priority, token, leased, f.parked,
		f.state == callbackapi.StateEscalated, f.state != callbackapi.StateReady && f.state != callbackapi.StateDraft, head,
	).Scan(&id)
	if err != nil {
		e.t.Fatalf("seed %+v: %v", f, err)
	}
	return id
}

func (e *env) state(id int64) callbackapi.State {
	e.t.Helper()
	var s string
	if err := e.db.QueryRow(`SELECT state FROM tickets WHERE id = $1`, id).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return callbackapi.State(s)
}

func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// liveLeases counts the tickets of foreman in a role's leased states with a lease not yet expired.
func (e *env) liveLeases(states ...callbackapi.State) int {
	e.t.Helper()
	ss := make([]string, len(states))
	for i, s := range states {
		ss[i] = string(s)
	}
	n := 0
	for _, s := range ss {
		n += e.count(`SELECT count(*) FROM tickets WHERE project_id = 'foreman' AND state = $1 AND lease_expires_at > now()`, s)
	}
	return n
}

func (e *env) consumed(provider string) float64 {
	e.t.Helper()
	var c float64
	if err := e.db.QueryRow(`SELECT consumed_estimate FROM budget WHERE provider = $1`, provider).Scan(&c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(query, args...); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
}

// attempt is the attempts row a claim wrote for a ticket, the latest.
type attempt struct {
	Attempt                         int
	Role                            string
	Provider, Model, Tier, LaunchID sql.NullString
	Outcome                         sql.NullString
	Token                           string
	Ended                           bool
}

func (e *env) attempt(id int64) attempt {
	e.t.Helper()
	var a attempt
	err := e.db.QueryRow(`
		SELECT attempt, role, provider, model, tier, launch_id, outcome, claim_token, ended_at IS NOT NULL
		FROM attempts WHERE ticket_id = $1 ORDER BY id DESC LIMIT 1`, id).
		Scan(&a.Attempt, &a.Role, &a.Provider, &a.Model, &a.Tier, &a.LaunchID, &a.Outcome, &a.Token, &a.Ended)
	if err != nil {
		e.t.Fatalf("attempt of ticket %d: %v", id, err)
	}
	return a
}
