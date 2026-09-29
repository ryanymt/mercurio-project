package dispatcher_test

import (
	"context"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

func uuid() string {
	h := randomHex(16)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

// A QA runner's rate-limit report pauses Claude: the next tick passes over new work whose tier is
// Claude, and once the pause ends by itself, a tick claims it (P04 T5).
func TestARateLimitStopsItsProviderUntilTheReset(t *testing.T) {
	e := newEnv(t)
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	work := e.seed(fixture{state: sReady, attempts: 1}) // attempt 2: Claude Sonnet
	if out := e.tick(); out.Claimed != qa {
		t.Fatalf("claimed %d, want QA %d", out.Claimed, qa)
	}
	var token string
	var reset time.Time
	if err := e.db.QueryRow(`SELECT claim_token, clock_timestamp() + interval '1500 milliseconds' FROM tickets WHERE id = $1`, qa).
		Scan(&token, &reset); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx, err := callbackapi.BeginTx(ctx, e.db)
	if err != nil {
		t.Fatal(err)
	}
	qaRunner := callbackapi.Caller{Email: "qa-foreman@your-project-id.iam.gserviceaccount.com", Role: callbackapi.RoleQA, Project: "foreman"}
	if _, err := callbackapi.NewEngine(nil, quietLog()).RateLimit(ctx, tx, callbackapi.RateLimitRequest{
		TicketID: qa, Caller: qaRunner, RequestID: uuid(), ClaimToken: token, ResetAt: reset,
		Method: "POST", Path: "/v1/tickets/rate-limit",
	}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if out := e.tick(); out.Claimed != 0 || e.state(work) != sReady {
		t.Fatalf("claimed %d while Claude is paused", out.Claimed)
	}
	time.Sleep(time.Until(reset) + 500*time.Millisecond)
	if out := e.tick(); out.Claimed != work {
		t.Fatalf("claimed %d after the pause ended, want %d", out.Claimed, work)
	}
}
