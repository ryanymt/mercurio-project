package callbackapi_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

func digest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
func gitSHA(c byte) string { return strings.Repeat(string(c), 40) }

func promote(c callbackapi.Caller, component, d, sha string) callbackapi.PromotionRequest {
	return callbackapi.PromotionRequest{
		Caller: c, Component: component, ImageDigest: d, GitSHA: sha, RequestID: newRequestID(),
		Method: "POST", Path: "/v1/promotions",
	}
}

func doPromote(t *testing.T, conn *sql.DB, req callbackapi.PromotionRequest) (callbackapi.PromotionResult, error) {
	return inTx(t, conn, func(ctx context.Context, tx *sql.Tx) (callbackapi.PromotionResult, error) {
		return newEngine(nil).Promote(ctx, tx, req)
	})
}

func current(t *testing.T, conn *sql.DB, component string) (digest, by string) {
	t.Helper()
	err := conn.QueryRow(`SELECT image_digest, promoted_by FROM promotions WHERE component = $1 AND is_current`, component).
		Scan(&digest, &by)
	if err != nil {
		t.Fatalf("current promotion of %s: %v", component, err)
	}
	return digest, by
}

// A promotion retires the component's current row, then inserts the new one: the partial unique
// index is checked immediately, so the other order would refuse every second promotion.
func TestPromotionReplacesTheCurrentOne(t *testing.T) {
	conn := fresh(t)
	first, err := doPromote(t, conn, promote(humanCaller, "dispatcher", digest('a'), gitSHA('1')))
	if err != nil {
		t.Fatal(err)
	}
	second, err := doPromote(t, conn, promote(humanCaller, "dispatcher", digest('b'), gitSHA('2')))
	if err != nil {
		t.Fatal(err)
	}
	if second.Retired != first.PromotionID {
		t.Fatalf("second promotion retired %d, want %d", second.Retired, first.PromotionID)
	}
	d, by := current(t, conn, "dispatcher")
	if d != digest('b') || by != humanCaller.Email {
		t.Fatalf("current = %s by %s", d, by)
	}
	if n := count(t, conn, `SELECT count(*) FROM promotions WHERE component = 'dispatcher'`); n != 2 {
		t.Fatalf("%d promotion rows, want 2 (history kept)", n)
	}
}

func TestPromotionFormats(t *testing.T) {
	conn := fresh(t)
	for name, req := range map[string]callbackapi.PromotionRequest{
		"digest without sha256:": promote(humanCaller, "dispatcher", strings.Repeat("a", 64), gitSHA('1')),
		"short digest":           promote(humanCaller, "dispatcher", "sha256:abc", gitSHA('1')),
		"short git sha":          promote(humanCaller, "dispatcher", digest('a'), "abc123"),
		"no component":           promote(humanCaller, "", digest('a'), gitSHA('1')),
		"odd component":          promote(humanCaller, "Dispatcher; DROP", digest('a'), gitSHA('1')),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := doPromote(t, conn, req)
			wantStatus(t, err, 400)
		})
	}
}

// Promotion is a human act: every agent identity is refused.
func TestNoAgentPromotes(t *testing.T) {
	for _, role := range agentRoles {
		t.Run(string(role), func(t *testing.T) {
			conn := fresh(t)
			c, _ := callerFor(role)
			_, err := doPromote(t, conn, promote(c, "dispatcher", digest('a'), gitSHA('1')))
			wantStatus(t, err, 403)
			if n := count(t, conn, `SELECT count(*) FROM promotions`); n != 0 {
				t.Fatalf("%d promotions after a refusal", n)
			}
		})
	}
}

// Two promotions of one component at once: the second waits, then finds the first's new current
// row and is refused with 409, not a 500.
func TestConcurrentPromotionsConflict(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	ctx := context.Background()
	if _, err := doPromote(t, conn, promote(humanCaller, "integrator", digest('a'), gitSHA('1'))); err != nil {
		t.Fatal(err)
	}
	txA, _ := callbackapi.BeginTx(ctx, conn)
	if _, err := e.Promote(ctx, txA, promote(humanCaller, "integrator", digest('b'), gitSHA('2'))); err != nil {
		t.Fatal(err)
	}
	txB, _ := callbackapi.BeginTx(ctx, conn)
	pidB := backendPID(t, txB)
	errB := make(chan error, 1)
	go func() {
		_, err := e.Promote(ctx, txB, promote(humanCaller, "integrator", digest('c'), gitSHA('3')))
		errB <- err
	}()
	waitBlocked(t, conn, pidB)
	if err := txA.Commit(); err != nil {
		t.Fatal(err)
	}
	err := <-errB
	txB.Rollback()
	wantStatus(t, err, 409)
	if d, _ := current(t, conn, "integrator"); d != digest('b') {
		t.Fatalf("current %s, want A's", d)
	}
}
