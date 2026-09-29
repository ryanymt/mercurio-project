package callbackapi_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// Callers as the identity layer (T4) would hand them to the core.
var (
	humanCaller      = callbackapi.Caller{Email: "operator@example.com", Role: callbackapi.RoleHuman}
	dispatcherCaller = callbackapi.Caller{Email: "dispatcher@your-project-id.iam.gserviceaccount.com", Role: callbackapi.RoleDispatcher}
)

func runner(role callbackapi.Role, project string) callbackapi.Caller {
	name := map[callbackapi.Role]string{
		callbackapi.RoleSpec: "spec", callbackapi.RoleArchitect: "architect", callbackapi.RoleDev: "dev",
		callbackapi.RoleQA: "qa", callbackapi.RoleIntegrator: "integrator",
	}[role]
	return callbackapi.Caller{
		Email:   fmt.Sprintf("%s-%s@your-project-id.iam.gserviceaccount.com", name, project),
		Role:    role,
		Project: project,
	}
}

// The seven roles that can call in; the internal actors (callback_api, risk_evaluator) never do.
var callerRoles = []callbackapi.Role{
	callbackapi.RoleDispatcher, callbackapi.RoleSpec, callbackapi.RoleArchitect, callbackapi.RoleDev,
	callbackapi.RoleQA, callbackapi.RoleIntegrator, callbackapi.RoleHuman,
}

// callerFor returns the foreman-project caller for a role, and the channel it calls through.
func callerFor(role callbackapi.Role) (callbackapi.Caller, callbackapi.Channel) {
	switch role {
	case callbackapi.RoleHuman:
		return humanCaller, callbackapi.ChannelHTTP
	case callbackapi.RoleDispatcher:
		return dispatcherCaller, callbackapi.ChannelCore
	default:
		return runner(role, "foreman"), callbackapi.ChannelHTTP
	}
}

const liveToken = "claim-token-live"

// fixtureSHA is the submitted commit seeded on tickets past submission, and the one the request
// helper names on the two transitions that carry a commit (P03 D10).
const fixtureSHA = "1111111111111111111111111111111111111111"

// fixture describes a ticket inserted directly, bypassing the engine, in any state.
type fixture struct {
	project  string // default "foreman"
	state    callbackapi.State
	attempts int
	parent   int64 // makes it a depth-1 child
	parked   bool
	noToken  bool // a leased ticket with a NULL claim token
	withAC   bool
	baseSHA  string
	headSHA  string // default fixtureSHA for states past submission, unless noHead
	noHead   bool   // a ticket with no submitted commit (P03 D14)
	expired  bool   // a leased ticket whose lease has already expired, so the dispatcher may reap it
}

// pastSubmission are the states a ticket reaches only after the dev runner named its commit.
func pastSubmission(s callbackapi.State) bool {
	switch s {
	case callbackapi.StateAwaitingReview, callbackapi.StateInQA, callbackapi.StateApproved,
		callbackapi.StateMerging, callbackapi.StateMerged, callbackapi.StateEscalated:
		return true
	}
	return false
}

func seed(t *testing.T, conn *sql.DB, f fixture) int64 {
	t.Helper()
	if f.project == "" {
		f.project = "foreman"
	}
	var parent sql.NullInt64
	depth := 0
	if f.parent != 0 {
		parent, depth = sql.NullInt64{Int64: f.parent, Valid: true}, 1
	}
	leased := callbackapi.IsLeased(f.state)
	var token, claimedBy sql.NullString
	if leased {
		claimedBy = sql.NullString{String: "runner-1", Valid: true}
		if !f.noToken {
			token = sql.NullString{String: liveToken, Valid: true}
		}
	}
	ac := sql.NullString{}
	if f.withAC || f.state != callbackapi.StateDraft {
		ac = sql.NullString{String: `[{"id":"AC1","text":"it works"}]`, Valid: true}
	}
	var base, head sql.NullString
	if f.baseSHA != "" {
		base = sql.NullString{String: f.baseSHA, Valid: true}
	}
	switch {
	case f.noHead:
	case f.headSHA != "":
		head = sql.NullString{String: f.headSHA, Valid: true}
	case pastSubmission(f.state):
		head = sql.NullString{String: fixtureSHA, Valid: true}
	}
	var id int64
	err := conn.QueryRow(`
		INSERT INTO tickets (project_id, title, state, attempt_count, parent_ticket_id, depth,
		  claim_token, claimed_by, claimed_at, lease_expires_at, parked, parked_reason,
		  acceptance_criteria, escalated_at, base_sha, head_sha)
		VALUES ($1, 'fixture', $2, $3, $4, $5, $6, $7,
		  CASE WHEN $8 THEN now() END, CASE WHEN $8 THEN now() + interval '5 minutes' END,
		  $9, CASE WHEN $9 THEN 'parked by fixture' END, $10::jsonb,
		  CASE WHEN $11 THEN now() END, $12, $13)
		RETURNING id`,
		f.project, string(f.state), f.attempts, parent, depth, token, claimedBy, leased, f.parked, ac,
		f.state == callbackapi.StateEscalated, base, head,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed %+v: %v", f, err)
	}
	if f.expired {
		expire(t, conn, id)
	}
	return id
}

// expire moves a ticket's lease into the past: only then may the dispatcher reap it (P04 D9).
func expire(t *testing.T, conn *sql.DB, id int64) {
	t.Helper()
	if _, err := conn.Exec(`UPDATE tickets SET lease_expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

// baseFixtureSHA is the default branch's head a new-work claim records (P04 D4).
const baseFixtureSHA = "2222222222222222222222222222222222222222"

// branchFor is the branch a new-work claim records: the ticket and the dev attempt it starts.
func branchFor(id int64, attempt int) string { return fmt.Sprintf("foreman/%d/%d", id, attempt) }

// dispatcherReturn reports whether (from, to) is one of the dispatcher's return rows: out of a
// leased state, to a state outside the set.
func dispatcherReturn(from, to callbackapi.State) bool {
	for _, r := range callbackapi.Table() {
		if r.From == from && r.To == to && r.Actor == callbackapi.RoleDispatcher &&
			callbackapi.IsLeased(from) && !callbackapi.IsLeased(to) {
			return true
		}
	}
	return false
}

func addProject(t *testing.T, conn *sql.DB, id string) {
	t.Helper()
	if _, err := conn.Exec(`INSERT INTO projects (id, name, repo_url) VALUES ($1, $1, 'https://example.invalid/'||$1)`, id); err != nil {
		t.Fatal(err)
	}
}

func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func request(id int64, from, to callbackapi.State, c callbackapi.Caller, ch callbackapi.Channel) callbackapi.TransitionRequest {
	req := callbackapi.TransitionRequest{
		TicketID: id, From: from, To: to, Caller: c, Channel: ch, RequestID: newRequestID(),
		Method: "POST", Path: fmt.Sprintf("/v1/tickets/%d/transitions", id),
	}
	if c.Role != callbackapi.RoleHuman && c.Role != callbackapi.RoleDispatcher {
		req.ClaimToken = liveToken
	}
	if from == callbackapi.StateDraft && to == callbackapi.StateReady {
		req.AcceptanceCriteria = []callbackapi.Criterion{{ID: "AC1", Text: "it works"}}
	}
	if carriesCommit(from, to) {
		req.HeadSHA = fixtureSHA
	}
	// The dispatcher's new-work claim names the branch and base (a ticket's first attempt unless the
	// test sets another), and its returns their kind: a reap unless the test says otherwise (P04).
	if c.Role == callbackapi.RoleDispatcher && from == callbackapi.StateReady && to == callbackapi.StateClaimed {
		req.Branch, req.BaseSHA = branchFor(id, 1), baseFixtureSHA
	}
	if c.Role == callbackapi.RoleDispatcher && dispatcherReturn(from, to) {
		req.Return = callbackapi.ReturnLeaseExpired
	}
	return req
}

// carriesCommit: the dev runner's submission and QA's approval name a commit (P03 D10).
func carriesCommit(from, to callbackapi.State) bool {
	return (from == callbackapi.StateInProgress && to == callbackapi.StateAwaitingReview) ||
		(from == callbackapi.StateInQA && to == callbackapi.StateApproved)
}

// do runs one transition in its own READ COMMITTED transaction: commit on success, roll back on
// any error, as every caller of the core must.
func do(t *testing.T, e *callbackapi.Engine, conn *sql.DB, req callbackapi.TransitionRequest) (callbackapi.Result, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Transition(ctx, tx, req)
	if err != nil {
		tx.Rollback()
		return res, err
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return res, nil
}

func mustDo(t *testing.T, e *callbackapi.Engine, conn *sql.DB, req callbackapi.TransitionRequest) callbackapi.Result {
	t.Helper()
	res, err := do(t, e, conn, req)
	if err != nil {
		t.Fatalf("%s -> %s by %s: %v", req.From, req.To, req.Caller.Role, err)
	}
	return res
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	var e *callbackapi.Error
	if !errors.As(err, &e) {
		t.Fatalf("want a refusal with status %d, got %v", status, err)
	}
	if e.Status != status {
		t.Fatalf("want status %d, got %d (%s)", status, e.Status, e.Reason)
	}
}

// ticketRow is every column of a ticket, for asserting that a refusal changed nothing.
type ticketRow map[string]any

func snapshot(t *testing.T, conn *sql.DB, id int64) ticketRow {
	t.Helper()
	rows, err := conn.Query(`SELECT * FROM tickets WHERE id = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	if !rows.Next() {
		t.Fatalf("ticket %d not found", id)
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		t.Fatal(err)
	}
	row := ticketRow{}
	for i, c := range cols {
		row[c] = vals[i]
	}
	return row
}

func count(t *testing.T, conn *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func eventCount(t *testing.T, conn *sql.DB, id int64) int {
	return count(t, conn, `SELECT count(*) FROM ticket_events WHERE ticket_id = $1`, id)
}

// assertUnchanged checks that a refused request left the ticket, its events and the request log
// exactly as they were.
func assertUnchanged(t *testing.T, conn *sql.DB, id int64, before ticketRow, events, requests int) {
	t.Helper()
	if after := snapshot(t, conn, id); !reflect.DeepEqual(before, after) {
		t.Errorf("ticket %d changed on a refusal:\nbefore %v\nafter  %v", id, before, after)
	}
	if n := eventCount(t, conn, id); n != events {
		t.Errorf("ticket %d: %d events after a refusal, want %d", id, n, events)
	}
	if n := count(t, conn, `SELECT count(*) FROM api_requests`); n != requests {
		t.Errorf("%d request-log rows after a refusal, want %d", n, requests)
	}
}

type event struct {
	From, To  sql.NullString
	Actor     string
	ActorID   string
	RequestID sql.NullString
	Payload   []byte
}

func lastEvent(t *testing.T, conn *sql.DB, id int64) event {
	t.Helper()
	var ev event
	err := conn.QueryRow(`
		SELECT from_state, to_state, actor, actor_id, request_id, coalesce(payload, 'null'::jsonb)
		FROM ticket_events WHERE ticket_id = $1 ORDER BY id DESC LIMIT 1`, id).
		Scan(&ev.From, &ev.To, &ev.Actor, &ev.ActorID, &ev.RequestID, &ev.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func state(t *testing.T, conn *sql.DB, id int64) callbackapi.State {
	t.Helper()
	var s string
	if err := conn.QueryRow(`SELECT state FROM tickets WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return callbackapi.State(s)
}

func newEngine(ev callbackapi.Evaluator) *callbackapi.Engine {
	if ev == nil {
		ev = callbackapi.FailClosed{}
	}
	return callbackapi.NewEngine(ev, nil)
}

// backendPID and waitBlocked are testdb's (moved there in P04, for the dispatcher's tests too).
func backendPID(t *testing.T, tx *sql.Tx) int { return testdb.BackendPID(t, tx) }

func waitBlocked(t *testing.T, conn *sql.DB, pid int) { testdb.WaitBlocked(t, conn, pid) }

func fresh(t *testing.T) *sql.DB { return testdb.New(t) }
