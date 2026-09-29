package callbackapi_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// A runner reports a rate limit, which pauses its own provider (P04 Approach 7, D5; the Anchor's
// "Rate limits").

func rateLimit(id int64, c callbackapi.Caller, token string, reset time.Time) callbackapi.RateLimitRequest {
	return callbackapi.RateLimitRequest{
		TicketID: id, Caller: c, RequestID: newRequestID(), ClaimToken: token, ResetAt: reset,
		Method: "POST", Path: fmt.Sprintf("/v1/tickets/%d/rate-limit", id),
	}
}

func doRateLimit(t *testing.T, conn *sql.DB, req callbackapi.RateLimitRequest) (callbackapi.RateLimitResult, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	res, err := newEngine(nil).RateLimit(ctx, tx, req)
	if err != nil {
		tx.Rollback()
		return res, err
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return res, nil
}

// dbTime is the database's clock, which every pause is measured by.
func dbTime(t *testing.T, conn *sql.DB) time.Time {
	t.Helper()
	var now time.Time
	if err := conn.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now
}

func pausedUntil(t *testing.T, conn *sql.DB, provider string) sql.NullTime {
	t.Helper()
	var p sql.NullTime
	if err := conn.QueryRow(`SELECT paused_until FROM budget WHERE provider = $1`, provider).Scan(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

// The report pauses the provider of the caller's own attempt until the reset time, and marks the
// attempt rate_limited; the other provider is untouched.
func TestRateLimitPausesTheCallersOwnProvider(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	insertAttempt(t, conn, id, callbackapi.RoleDev, liveToken) // its provider: anthropic
	reset := dbTime(t, conn).Add(10 * time.Minute).Truncate(time.Microsecond)
	res, err := doRateLimit(t, conn, rateLimit(id, dev, liveToken, reset))
	if err != nil {
		t.Fatal(err)
	}
	if p := pausedUntil(t, conn, "anthropic"); !p.Valid || !p.Time.Equal(reset) || res.Provider != "anthropic" || !res.PausedUntil.Equal(reset) {
		t.Fatalf("anthropic paused until %v (result %+v), want %s", p, res, reset)
	}
	if p := pausedUntil(t, conn, "zai"); p.Valid {
		t.Fatalf("zai paused until %v: the report paused a provider that was not the caller's", p.Time)
	}
	if ended, outcome := attemptEnd(t, conn, liveToken); ended || outcome.String != "rate_limited" {
		t.Fatalf("attempt ended=%v outcome=%v, want still open, rate_limited", ended, outcome)
	}
	if state(t, conn, id) != sInProgress {
		t.Fatal("a rate-limit report changed the ticket's state")
	}
}

// A reset time that is not in the future is a 400, with nothing changed.
func TestRateLimitResetMustBeInTheFuture(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	insertAttempt(t, conn, id, callbackapi.RoleDev, liveToken)
	for _, reset := range []time.Time{{}, dbTime(t, conn).Add(-time.Second)} {
		_, err := doRateLimit(t, conn, rateLimit(id, dev, liveToken, reset))
		wantStatus(t, err, 400)
	}
	if p := pausedUntil(t, conn, "anthropic"); p.Valid {
		t.Fatal("a refused report paused the provider")
	}
}

// A pause is at most 24 hours ahead, and a report never shortens a longer pause already there.
func TestRateLimitPauseIsClampedAndNeverShortened(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	insertAttempt(t, conn, id, callbackapi.RoleDev, liveToken)
	now := dbTime(t, conn)
	if _, err := doRateLimit(t, conn, rateLimit(id, dev, liveToken, now.Add(48*time.Hour))); err != nil {
		t.Fatal(err)
	}
	p := pausedUntil(t, conn, "anthropic")
	if d := p.Time.Sub(now); d < 24*time.Hour-time.Minute || d > 24*time.Hour+time.Minute {
		t.Fatalf("paused %s ahead, want 24 hours", d)
	}
	if _, err := doRateLimit(t, conn, rateLimit(id, dev, liveToken, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if q := pausedUntil(t, conn, "anthropic"); !q.Time.Equal(p.Time) {
		t.Fatalf("a shorter report moved the pause from %s to %s", p.Time, q.Time)
	}
}

// Who may report: the runner holding the ticket's lease, in its project, with its token, while the
// lease lasts, and with a provider to pause.
func TestRateLimitRefusals(t *testing.T) {
	reset := func(conn *sql.DB) time.Time { return dbTime(t, conn).Add(time.Hour) }
	cases := []struct {
		name   string
		f      fixture
		role   callbackapi.Role // the attempt's
		caller callbackapi.Caller
		token  string
		status int
	}{
		{"the integrator, which uses no provider", fixture{state: sMerging, attempts: 1}, callbackapi.RoleIntegrator, integrator, liveToken, 409},
		{"a spec runner", fixture{state: sInProgress, attempts: 1}, callbackapi.RoleDev, spec, liveToken, 403},
		{"a human", fixture{state: sInProgress, attempts: 1}, callbackapi.RoleDev, humanCaller, "", 403},
		{"the dispatcher", fixture{state: sInProgress, attempts: 1}, callbackapi.RoleDev, dispatcherCaller, "", 403},
		{"QA on a dev lease", fixture{state: sInProgress, attempts: 1}, callbackapi.RoleDev, qa, liveToken, 409},
		{"a stale token", fixture{state: sInProgress, attempts: 1}, callbackapi.RoleDev, dev, "claim-token-stale", 409},
		{"an expired lease", fixture{state: sInProgress, attempts: 1, expired: true}, callbackapi.RoleDev, dev, liveToken, 409},
		{"another project", fixture{state: sInProgress, attempts: 1}, callbackapi.RoleDev, runner(callbackapi.RoleDev, "other"), liveToken, 403},
		{"no lease", fixture{state: sAwaiting, attempts: 1}, callbackapi.RoleDev, dev, liveToken, 409},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := fresh(t)
			addProject(t, conn, "other")
			id := seed(t, conn, c.f)
			insertAttempt(t, conn, id, c.role, liveToken)
			_, err := doRateLimit(t, conn, rateLimit(id, c.caller, c.token, reset(conn)))
			wantStatus(t, err, c.status)
			for _, p := range []string{"anthropic", "zai"} {
				if pausedUntil(t, conn, p).Valid {
					t.Fatalf("a refused report paused %s", p)
				}
			}
		})
	}
	// A lease with no attempt recorded (a ticket claimed before the dispatcher wrote attempts).
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	_, err := doRateLimit(t, conn, rateLimit(id, dev, liveToken, reset(conn)))
	wantStatus(t, err, 409)
}

// A replayed report returns the recorded result and changes nothing again.
func TestRateLimitReplayIsIdempotent(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	insertAttempt(t, conn, id, callbackapi.RoleDev, liveToken)
	req := rateLimit(id, dev, liveToken, dbTime(t, conn).Add(time.Hour))
	first, err := doRateLimit(t, conn, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE budget SET paused_until = NULL`); err != nil {
		t.Fatal(err)
	}
	again, err := doRateLimit(t, conn, req)
	if err != nil || !again.Replayed || again.Provider != first.Provider || !again.PausedUntil.Equal(first.PausedUntil) {
		t.Fatalf("replay = %+v, %v; want the recorded %+v", again, err, first)
	}
	if pausedUntil(t, conn, "anthropic").Valid {
		t.Fatal("a replay paused the provider again")
	}
}

// Over HTTP: the route, the claim token header, and a body that names only the reset time.
func TestHTTPRateLimit(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	insertAttempt(t, a.conn, id, callbackapi.RoleDev, liveToken)
	path := fmt.Sprintf("/v1/tickets/%d/rate-limit", id)
	reset := dbTime(t, a.conn).Add(time.Hour).UTC().Format(time.RFC3339Nano)

	st, b := a.do(call{method: "POST", path: path, token: a.tokenFor(dev.Email), key: newRequestID(), claim: liveToken,
		body: map[string]any{"reset_at": reset, "provider": "zai"}})
	wantHTTP(t, st, 400, b) // the provider is never the caller's to name
	st, b = a.do(call{method: "POST", path: path, token: a.tokenFor(dev.Email), key: newRequestID(), claim: liveToken,
		body: map[string]any{"reset_at": reset}})
	wantHTTP(t, st, 200, b)
	if b["provider"] != "anthropic" || b["paused_until"] == nil {
		t.Fatalf("response %v", b)
	}
	st, b = a.do(call{method: "POST", path: path, token: a.tokenFor(humanCaller.Email), key: newRequestID(),
		body: map[string]any{"reset_at": reset}})
	wantHTTP(t, st, 403, b)
}
