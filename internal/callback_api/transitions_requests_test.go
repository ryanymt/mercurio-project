package callbackapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// The same request replayed returns the recorded result and writes nothing twice, even after the
// ticket has moved on, and even though the ticket is no longer in the replay's `from`.
func TestReplayReturnsTheRecordedResult(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := request(id, sInProgress, sAwaiting, dev, chHTTP)
	first := mustDo(t, e, conn, req)

	again := mustDo(t, e, conn, req)
	if !again.Replayed || again.State != first.State || again.EventID != first.EventID {
		t.Fatalf("replay = %+v, want the recorded %+v", again, first)
	}
	if n := eventCount(t, conn, id); n != 1 {
		t.Fatalf("%d events after a replay, want 1", n)
	}

	// The ticket moves on; a late replay still gets the recorded result, not a 409.
	mustDo(t, e, conn, request(id, sAwaiting, sInQA, dispatcherCaller, chCore))
	late := mustDo(t, e, conn, req)
	if !late.Replayed || late.State != sAwaiting {
		t.Fatalf("late replay = %+v", late)
	}
}

// The same key with a different request is a conflict.
func TestConflictingReplayIs409(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := request(id, sInProgress, sAwaiting, dev, chHTTP)
	mustDo(t, e, conn, req)

	other := req
	other.Payload = json.RawMessage(`{"note":"different"}`)
	_, err := do(t, e, conn, other)
	wantStatus(t, err, 409)

	// A different claim token is a different request too (a reaped runner and its successor
	// share a service account and could share a deterministic key).
	tok := req
	tok.ClaimToken = "someone-else"
	_, err = do(t, e, conn, tok)
	wantStatus(t, err, 409)
}

// A refusal of any kind rolls back and leaves no request-log row, so a corrected retry under the
// same key is evaluated afresh and succeeds.
func TestRefusalsAreNeverRecorded(t *testing.T) {
	cases := []struct {
		name    string
		fx      fixture
		refused func(id int64) callbackapi.TransitionRequest
		fixed   func(r callbackapi.TransitionRequest) callbackapi.TransitionRequest
		status  int
	}{
		{"400: no acceptance criteria", fixture{state: sDraft},
			func(id int64) callbackapi.TransitionRequest {
				r := request(id, sDraft, sReady, spec, chHTTP)
				r.AcceptanceCriteria = nil
				return r
			},
			func(r callbackapi.TransitionRequest) callbackapi.TransitionRequest {
				r.AcceptanceCriteria = []callbackapi.Criterion{{ID: "AC1", Text: "it works"}}
				return r
			}, 400},
		{"409: missing claim token", fixture{state: sInProgress, attempts: 1},
			func(id int64) callbackapi.TransitionRequest {
				r := request(id, sInProgress, sAwaiting, dev, chHTTP)
				r.ClaimToken = ""
				return r
			},
			func(r callbackapi.TransitionRequest) callbackapi.TransitionRequest {
				r.ClaimToken = liveToken
				return r
			}, 409},
		{"409: stale from", fixture{state: sInProgress, attempts: 1},
			func(id int64) callbackapi.TransitionRequest { return request(id, sClaimed, sInProgress, dev, chHTTP) },
			func(r callbackapi.TransitionRequest) callbackapi.TransitionRequest {
				r.From, r.To, r.HeadSHA = sInProgress, sAwaiting, fixtureSHA
				return r
			}, 409},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := fresh(t)
			e := newEngine(nil)
			id := seed(t, conn, c.fx)
			refused := c.refused(id)
			_, err := do(t, e, conn, refused)
			wantStatus(t, err, c.status)
			if n := count(t, conn, `SELECT count(*) FROM api_requests`); n != 0 {
				t.Fatalf("%d request-log rows after a refusal, want 0", n)
			}
			mustDo(t, e, conn, c.fixed(refused)) // same request id
		})
	}
	// A 403 never touches the log at all: authorization comes before the key is claimed.
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	_, err := do(t, newEngine(nil), conn, request(id, sInProgress, sAwaiting, qa, chHTTP))
	wantStatus(t, err, 403)
	if n := count(t, conn, `SELECT count(*) FROM api_requests`); n != 0 {
		t.Fatalf("%d request-log rows after a 403, want 0", n)
	}
}

// A duplicate sent while the first is still in flight waits on the key, then replays the first
// one's committed result: deterministic interleaving, not luck.
func TestConcurrentDuplicateReplays(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	ctx := context.Background()
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := request(id, sInProgress, sAwaiting, dev, chHTTP)

	txA, _ := callbackapi.BeginTx(ctx, conn)
	first, err := e.Transition(ctx, txA, req)
	if err != nil {
		t.Fatal(err)
	}
	txB, _ := callbackapi.BeginTx(ctx, conn)
	pidB := backendPID(t, txB)
	type out struct {
		res callbackapi.Result
		err error
	}
	got := make(chan out, 1)
	go func() {
		res, err := e.Transition(ctx, txB, req)
		got <- out{res, err}
	}()
	waitBlocked(t, conn, pidB)
	if err := txA.Commit(); err != nil {
		t.Fatal(err)
	}
	o := <-got
	if o.err != nil {
		txB.Rollback()
		t.Fatalf("the duplicate failed instead of replaying: %v", o.err)
	}
	txB.Commit()
	if !o.res.Replayed || o.res.EventID != first.EventID {
		t.Fatalf("duplicate = %+v, want a replay of %+v", o.res, first)
	}
	if n := eventCount(t, conn, id); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
}

// If the first request rolls back, the waiting duplicate is evaluated on its own.
func TestDuplicateAfterRollbackIsEvaluatedAfresh(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	ctx := context.Background()
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := request(id, sInProgress, sAwaiting, dev, chHTTP)

	txA, _ := callbackapi.BeginTx(ctx, conn)
	if _, err := e.Transition(ctx, txA, req); err != nil {
		t.Fatal(err)
	}
	txB, _ := callbackapi.BeginTx(ctx, conn)
	pidB := backendPID(t, txB)
	got := make(chan error, 1)
	go func() {
		_, err := e.Transition(ctx, txB, req)
		got <- err
	}()
	waitBlocked(t, conn, pidB)
	txA.Rollback()
	if err := <-got; err != nil {
		txB.Rollback()
		t.Fatalf("duplicate after a rollback: %v", err)
	}
	txB.Commit()
	if s := state(t, conn, id); s != sAwaiting {
		t.Fatalf("state %s, want awaiting_review", s)
	}
}

// A request-log row without a stored response is never replayed: it is an internal error.
func TestRowWithoutResponseIsNeverReplayed(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := request(id, sInProgress, sAwaiting, dev, chHTTP)
	if _, err := conn.Exec(`INSERT INTO api_requests (caller, request_id, request_hash) VALUES ($1, $2, 'x')`,
		dev.Email, req.RequestID); err != nil {
		t.Fatal(err)
	}
	_, err := do(t, newEngine(nil), conn, req)
	var e *callbackapi.Error
	if err == nil || (errors.As(err, &e) && e.Status < 500) {
		t.Fatalf("want an internal error, got %v", err)
	}
	if s := state(t, conn, id); s != sInProgress {
		t.Fatalf("state %s: a row without a response was acted on", s)
	}
}
