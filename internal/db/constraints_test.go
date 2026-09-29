package db_test

// These tests write invalid rows straight through database/sql and assert that the server itself
// refuses them, naming the SQLSTATE and the constraint the later phases' error handling keys off.
// A row that broke two CHECKs at once would be reported as whichever Postgres reaches first, so
// every rejected row here breaks exactly one constraint: the depth cases give the ticket a real
// parent, and the parent cases keep depth legal.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// accept asserts a statement succeeds. Every row a rejection case depends on goes through it, so a
// case can never pass because its own setup failed to insert.
func accept(t *testing.T, conn *sql.DB, stmt string, args ...any) {
	t.Helper()
	if _, err := conn.ExecContext(context.Background(), stmt, args...); err != nil {
		t.Fatalf("want the statement accepted, got error: %v\n  statement: %s", err, stmt)
	}
}

// acceptID asserts an INSERT ... RETURNING id succeeds and returns the generated id.
func acceptID(t *testing.T, conn *sql.DB, stmt string, args ...any) int64 {
	t.Helper()
	var id int64
	if err := conn.QueryRowContext(context.Background(), stmt, args...).Scan(&id); err != nil {
		t.Fatalf("want the statement accepted, got error: %v\n  statement: %s", err, stmt)
	}
	return id
}

// reject asserts a statement is refused with exactly the given SQLSTATE on exactly the given
// constraint: no error, a non-Postgres error, another SQLSTATE, or another constraint all fail it.
func reject(t *testing.T, conn *sql.DB, code, constraint, stmt string, args ...any) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(), stmt, args...)
	if err == nil {
		t.Fatalf("want SQLSTATE %s on %s, got no error\n  statement: %s", code, constraint, stmt)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("want SQLSTATE %s on %s, got a non-Postgres error: %v\n  statement: %s",
			code, constraint, err, stmt)
	}
	if pgErr.Code != code || pgErr.ConstraintName != constraint {
		t.Fatalf("rejected with SQLSTATE %s on constraint %q, want SQLSTATE %s on constraint %q\n  statement: %s",
			pgErr.Code, pgErr.ConstraintName, code, constraint, stmt)
	}
}

// Rejection 1: one_active_project, the partial unique index that lets exactly one project be
// active at a time. The seed makes foreman that project; a test that deactivates it runs in its
// own database, so no other test sees foreman stood down.
func TestOnlyOneProjectMayBeActive(t *testing.T) {
	ctx := context.Background()
	conn := testdb.New(t)

	// Without the seeded active row there is no conflict to hit, so check it is really there.
	var active bool
	err := conn.QueryRowContext(ctx, "SELECT is_active FROM projects WHERE id = 'foreman'").Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatal("the seed did not insert the foreman project; one_active_project is not exercised")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("the seeded foreman project is not active; one_active_project is not exercised")
	}

	// A project that is not active takes no part in the index, so a second project may exist.
	accept(t, conn, `INSERT INTO projects (id, name, repo_url, is_active)
		VALUES ('side-project', 'side project', 'https://example.invalid/side', false)`)

	reject(t, conn, "23505", "one_active_project", `INSERT INTO projects (id, name, repo_url, is_active)
		VALUES ('rival', 'rival', 'https://example.invalid/rival', true)`)

	// Stood down, foreman frees the slot for the next active project.
	upd, err := conn.ExecContext(ctx, "UPDATE projects SET is_active = false WHERE id = 'foreman'")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := upd.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("deactivating foreman touched %d rows, %v; want 1", n, err)
	}
	accept(t, conn, `INSERT INTO projects (id, name, repo_url, is_active)
		VALUES ('rival', 'rival', 'https://example.invalid/rival', true)`)
}

// Rejection 2: depth_capped. Decomposition stops at depth 1, so a grandchild is refused -- with a
// real parent, since an orphan would be refused by child_has_parent first instead.
func TestTicketDepthIsCapped(t *testing.T) {
	conn := testdb.New(t)

	parent := acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth) VALUES ('foreman', 'parent', 0) RETURNING id")
	acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'child', 1, $1) RETURNING id",
		parent)

	reject(t, conn, "23514", "depth_capped",
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'grandchild', 2, $1)",
		parent)
}

// Rejections 3a and 3b: child_has_parent, which pins depth and parent to each other -- a ticket at
// depth 1 has a parent, a ticket at depth 0 has none. Each rejected row keeps the other side of
// that pairing legal, so child_has_parent is the constraint that fails.
func TestChildTicketHasAParent(t *testing.T) {
	conn := testdb.New(t)

	parent := acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth) VALUES ('foreman', 'parent', 0) RETURNING id")

	// The two legal shapes: a top-level ticket with no parent, and a child of a real one.
	acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth) VALUES ('foreman', 'top-level', 0) RETURNING id")
	acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'child', 1, $1) RETURNING id",
		parent)

	// A child without a parent.
	reject(t, conn, "23514", "child_has_parent",
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'orphan', 1, NULL)")

	// A depth-0 ticket that nevertheless has a parent.
	reject(t, conn, "23514", "child_has_parent",
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'misparented', 0, $1)",
		parent)
}

// Rejection 4: attempts_bounded. A ticket gets at most two dev sessions, so 0, 1 and 2 are legal
// and anything outside them is refused.
func TestTicketAttemptsAreBounded(t *testing.T) {
	conn := testdb.New(t)

	for _, n := range []int{0, 1, 2} {
		accept(t, conn,
			"INSERT INTO tickets (project_id, title, attempt_count) VALUES ('foreman', $1, $2)",
			fmt.Sprintf("attempts %d", n), n)
	}
	for _, n := range []int{3, -1} {
		reject(t, conn, "23514", "attempts_bounded",
			"INSERT INTO tickets (project_id, title, attempt_count) VALUES ('foreman', $1, $2)",
			fmt.Sprintf("attempts %d", n), n)
	}
}

// Rejection 5: ticket_events_idempotent, the partial unique index that makes a retried request
// land on the row it already wrote. Only non-NULL request ids take part in it, so an event with
// no request id is never a duplicate, and the same id on two tickets is two different requests.
func TestTicketEventsAreIdempotentPerRequest(t *testing.T) {
	conn := testdb.New(t)

	ticket := acceptID(t, conn,
		"INSERT INTO tickets (project_id, title) VALUES ('foreman', 'evented') RETURNING id")

	// The first write of a request id is the one the index allows.
	accept(t, conn,
		"INSERT INTO ticket_events (ticket_id, to_state, actor, request_id) VALUES ($1, 'ready', 'dev', $2)",
		ticket, "req-dup")

	reject(t, conn, "23505", "ticket_events_idempotent",
		"INSERT INTO ticket_events (ticket_id, to_state, actor, request_id) VALUES ($1, 'ready', 'dev', $2)",
		ticket, "req-dup")

	// Distinct request ids on one ticket are distinct requests.
	for _, id := range []string{"req-a", "req-b"} {
		accept(t, conn,
			"INSERT INTO ticket_events (ticket_id, to_state, actor, request_id) VALUES ($1, 'ready', 'dev', $2)",
			ticket, id)
	}

	// A NULL request id is outside the index, so two of them never collide.
	for i := 0; i < 2; i++ {
		accept(t, conn,
			"INSERT INTO ticket_events (ticket_id, to_state, actor, request_id) VALUES ($1, 'ready', 'dev', NULL)",
			ticket)
	}

	// The index keys on the ticket too: one request id, two tickets, two rows.
	other := acceptID(t, conn,
		"INSERT INTO tickets (project_id, title) VALUES ('foreman', 'also evented') RETURNING id")
	accept(t, conn,
		"INSERT INTO ticket_events (ticket_id, to_state, actor, request_id) VALUES ($1, 'ready', 'dev', $2)",
		ticket, "req-shared")
	accept(t, conn,
		"INSERT INTO ticket_events (ticket_id, to_state, actor, request_id) VALUES ($1, 'ready', 'dev', $2)",
		other, "req-shared")
}

// Rejection 6: one_current_promotion_per_component. Promotion is a human act recorded per
// component, and exactly one recorded promotion for a component is the current one.
func TestOnlyOneCurrentPromotionPerComponent(t *testing.T) {
	conn := testdb.New(t)

	accept(t, conn, `INSERT INTO promotions (component, image_digest, git_sha, promoted_by)
		VALUES ('dispatcher', 'sha256:1111', 'aaaaaaa', 'ci-operator')`)

	// A second current promotion for a component already promoted is refused.
	reject(t, conn, "23505", "one_current_promotion_per_component", `INSERT INTO promotions
		(component, image_digest, git_sha, promoted_by, is_current)
		VALUES ('dispatcher', 'sha256:2222', 'bbbbbbb', 'ci-operator', true)`)

	// An older promotion kept for the record is not current, so it may sit beside the first.
	accept(t, conn, `INSERT INTO promotions (component, image_digest, git_sha, promoted_by, is_current)
		VALUES ('dispatcher', 'sha256:2222', 'bbbbbbb', 'ci-operator', false)`)

	// Another component has a current promotion of its own.
	accept(t, conn, `INSERT INTO promotions (component, image_digest, git_sha, promoted_by, is_current)
		VALUES ('integrator', 'sha256:3333', 'ccccccc', 'ci-operator', true)`)

	// Once the first stands down, a new current promotion for the same component takes over.
	accept(t, conn, "UPDATE promotions SET is_current = false WHERE component = 'dispatcher' AND is_current")
	accept(t, conn, `INSERT INTO promotions (component, image_digest, git_sha, promoted_by, is_current)
		VALUES ('dispatcher', 'sha256:4444', 'ddddddd', 'ci-operator', true)`)
}

// Rejection 7 (P02, D16): parent_at_depth_0. Depth is capped at 1 in the database itself, not only
// in the API: a child's parent must be a top-level ticket, whoever writes the row. The grandchild
// here is at depth 1, which passes every CHECK, so only the foreign key can refuse it.
func TestChildParentMustBeTopLevel(t *testing.T) {
	conn := testdb.New(t)

	parent := acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth) VALUES ('foreman', 'parent', 0) RETURNING id")
	child := acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'child', 1, $1) RETURNING id",
		parent)

	reject(t, conn, "23503", "parent_at_depth_0",
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'grandchild', 1, $1)",
		child)

	// Re-parenting an existing child under another child is refused the same way.
	sibling := acceptID(t, conn,
		"INSERT INTO tickets (project_id, title, depth, parent_ticket_id) VALUES ('foreman', 'sibling', 1, $1) RETURNING id",
		parent)
	reject(t, conn, "23503", "parent_at_depth_0",
		"UPDATE tickets SET parent_ticket_id = $1 WHERE id = $2", child, sibling)
}

// The submitted commit is a full SHA-1 in lowercase hex, or nothing (P03 D10).
func TestHeadShaIsAFullLowercaseSha(t *testing.T) {
	conn := testdb.New(t)
	id := acceptID(t, conn, "INSERT INTO tickets (project_id, title) VALUES ('foreman', 't') RETURNING id")

	accept(t, conn, "UPDATE tickets SET head_sha = $1 WHERE id = $2", "0123456789abcdef0123456789abcdef01234567", id)
	accept(t, conn, "UPDATE tickets SET head_sha = NULL WHERE id = $1", id)
	for _, bad := range []string{
		"0123456789ABCDEF0123456789ABCDEF01234567",                         // upper case
		"0123456789abcdef",                                                 // abbreviated
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // SHA-256 length
		"0123456789abcdef0123456789abcdef0123456g",                         // not hex
		"",
		" 0123456789abcdef0123456789abcdef01234567",
	} {
		reject(t, conn, "23514", "head_sha_format", "UPDATE tickets SET head_sha = $1 WHERE id = $2", bad, id)
	}
}

// attemptTicket inserts a ticket for the attempts cases to hang their rows on.
func attemptTicket(t *testing.T, conn *sql.DB) int64 {
	t.Helper()
	return acceptID(t, conn, "INSERT INTO tickets (project_id, title) VALUES ('foreman', 'attempts') RETURNING id")
}

// An attempt names its provider, model and tier, all three, except the integrator's, which uses no
// model and names none (P04, red team 1 R4).
func TestAttemptNamesItsModelUnlessIntegrator(t *testing.T) {
	conn := testdb.New(t)
	id := attemptTicket(t, conn)
	const insert = `INSERT INTO attempts (ticket_id, attempt, role, provider, model, tier)
		VALUES ($1, 1, $2, $3, $4, $5)`

	accept(t, conn, insert, id, "dev", "zai", "glm-5.3-flash", "dev-1")
	accept(t, conn, insert, id, "qa", "anthropic", "claude-opus-5-5", "qa-1")
	accept(t, conn, insert, id, "integrator", nil, nil, nil)
	for _, c := range []struct {
		role                  string
		provider, model, tier any
	}{
		{"integrator", "anthropic", nil, nil},
		{"integrator", nil, "claude-opus-5-5", nil},
		{"integrator", nil, nil, "qa-1"},
		{"dev", nil, nil, nil},
		{"dev", "zai", nil, "dev-1"},
		{"qa", "anthropic", "claude-opus-5-5", nil},
	} {
		reject(t, conn, "23514", "attempts_model_by_role", insert, id, c.role, c.provider, c.model, c.tier)
	}
}

// Every launch's claim token is its own: the rate-limit endpoint and the core find an attempt by it
// (P04 D13, red team 1 R4).
func TestAttemptClaimTokensAreUnique(t *testing.T) {
	conn := testdb.New(t)
	id := attemptTicket(t, conn)
	const insert = `INSERT INTO attempts (ticket_id, attempt, role, provider, model, tier, claim_token)
		VALUES ($1, 1, 'dev', 'zai', 'glm-5.3-flash', 'dev-1', $2)`

	accept(t, conn, insert, id, "token-a")
	accept(t, conn, insert, id, "token-b")
	accept(t, conn, insert, id, nil)
	accept(t, conn, insert, id, nil)
	reject(t, conn, "23505", "attempts_claim_token_unique", insert, id, "token-a")
}

// An attempt's outcome is one the dispatcher and the core write, or not yet set (P04, red team 2).
func TestAttemptOutcomeIsKnown(t *testing.T) {
	conn := testdb.New(t)
	id := attemptTicket(t, conn)
	const insert = `INSERT INTO attempts (ticket_id, attempt, role, provider, model, tier, outcome)
		VALUES ($1, 1, 'dev', 'zai', 'glm-5.3-flash', 'dev-1', $2)`

	for _, o := range []any{nil, "completed", "failed", "rate_limited", "reaped", "launch_failed", "abandoned"} {
		accept(t, conn, insert, id, o)
	}
	for _, o := range []string{"", "COMPLETED", "succeeded", "timeout"} {
		reject(t, conn, "23514", "attempts_outcome_known", insert, id, o)
	}
}

// A ticket in a leased state has a lease expiry; one without would never be reaped (P04, red
// team 1 R4).
func TestLeasedTicketHasALeaseExpiry(t *testing.T) {
	conn := testdb.New(t)
	id := attemptTicket(t, conn)

	for _, s := range []string{"claimed", "in_progress", "in_qa", "merging"} {
		accept(t, conn, "UPDATE tickets SET state = $1, lease_expires_at = now() + interval '5 minutes' WHERE id = $2", s, id)
		reject(t, conn, "23514", "leased_has_expiry",
			"UPDATE tickets SET state = $1, lease_expires_at = NULL WHERE id = $2", s, id)
	}
	for _, s := range []string{"ready", "awaiting_review", "approved", "escalated"} {
		accept(t, conn, "UPDATE tickets SET state = $1, lease_expires_at = NULL WHERE id = $2", s, id)
	}
}
