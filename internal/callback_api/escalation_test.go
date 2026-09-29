package callbackapi_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

type stubEvaluator struct {
	verdict callbackapi.Verdict
	err     error
	panics  bool
}

func (s stubEvaluator) Evaluate(ctx context.Context, subject callbackapi.Subject) (callbackapi.Verdict, error) {
	if s.panics {
		panic("evaluator exploded")
	}
	return s.verdict, s.err
}

func riskVerdict(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		t.Fatalf("risk_verdict %s is not an object", raw)
	}
	return v
}

// D3: until P03 plugs in the real evaluator, every approval escalates, recorded as the risk
// evaluator's, naming QA and what it asked for.
func TestFailClosedEscalatesEveryApproval(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInQA, attempts: 1})
	res := mustDo(t, newEngine(callbackapi.FailClosed{}), conn, request(id, sInQA, sApproved, qa, chHTTP))
	if res.State != sEscalated || state(t, conn, id) != sEscalated {
		t.Fatalf("state %s, want escalated", state(t, conn, id))
	}
	if n := eventCount(t, conn, id); n != 1 {
		t.Fatalf("%d events, want exactly 1", n)
	}
	ev := lastEvent(t, conn, id)
	if ev.Actor != string(callbackapi.RoleRiskEvaluator) || ev.ActorID != qa.Email {
		t.Fatalf("event %+v: want actor risk_evaluator, actor_id %s", ev, qa.Email)
	}
	var p map[string]any
	json.Unmarshal(ev.Payload, &p)
	if p["requested_to"] != string(sApproved) {
		t.Fatalf("payload %s lacks requested_to=approved", ev.Payload)
	}
	k := cols(t, conn, id)
	if !k.EscalationReason.Valid || !k.EscalatedAt.Valid || riskVerdict(t, k.RiskVerdict)["cleared"] != false {
		t.Fatalf("columns %+v: want a reason, escalated_at and an uncleared verdict", k)
	}
}

// The plug point works both ways now, so P03 is not its first user: a clear verdict approves,
// and an error or a panic escalates (never a 500 that leaves the ticket in in_qa).
func TestEvaluatorVerdicts(t *testing.T) {
	cases := []struct {
		name string
		ev   callbackapi.Evaluator
		want callbackapi.State
	}{
		{"clears", stubEvaluator{verdict: callbackapi.Verdict{Cleared: true}}, sApproved},
		{"escalates", stubEvaluator{verdict: callbackapi.Verdict{MatchedRules: []string{"protected_paths"}}}, sEscalated},
		{"errors", stubEvaluator{err: errors.New("policy unreadable")}, sEscalated},
		{"panics", stubEvaluator{panics: true}, sEscalated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sInQA, attempts: 1})
			res, err := do(t, newEngine(c.ev), conn, request(id, sInQA, sApproved, qa, chHTTP))
			if err != nil {
				t.Fatalf("the evaluator's failure became an error: %v", err)
			}
			if res.State != c.want || state(t, conn, id) != c.want {
				t.Fatalf("state %s, want %s", state(t, conn, id), c.want)
			}
			v := riskVerdict(t, cols(t, conn, id).RiskVerdict)
			if v["cleared"] != (c.want == sApproved) {
				t.Fatalf("risk_verdict %v", v)
			}
		})
	}
}

// --- roll-up -------------------------------------------------------------------------------------

// decomposedWith seeds a decomposed parent with n children in childState.
func decomposedWith(t *testing.T, n int, childState callbackapi.State) (conn *sql.DB, parent int64, children []int64) {
	t.Helper()
	conn = fresh(t)
	parent = seed(t, conn, fixture{state: sDecomposed})
	for i := 0; i < n; i++ {
		children = append(children, seed(t, conn, fixture{state: childState, parent: parent, attempts: 1}))
	}
	return conn, parent, children
}

func TestRollUpToDone(t *testing.T) {
	conn, parent, kids := decomposedWith(t, 2, sMerged)
	e := newEngine(nil)
	mustDo(t, e, conn, request(kids[0], sMerged, sDone, integrator, chHTTP))
	if s := state(t, conn, parent); s != sDecomposed {
		t.Fatalf("parent %s after one of two children finished", s)
	}
	last := request(kids[1], sMerged, sDone, integrator, chHTTP)
	mustDo(t, e, conn, last)
	if s := state(t, conn, parent); s != sDone {
		t.Fatalf("parent %s after every child is done, want done", s)
	}
	if p, c := eventCount(t, conn, parent), eventCount(t, conn, kids[1]); p != 1 || c != 1 {
		t.Fatalf("%d parent and %d child events, want exactly 1 each", p, c)
	}
	ev := lastEvent(t, conn, parent)
	if ev.Actor != string(callbackapi.RoleCallbackAPI) || ev.ActorID != integrator.Email || ev.RequestID.Valid {
		t.Fatalf("roll-up event %+v: want callback_api, the child's caller, no request id of its own", ev)
	}
	var p map[string]any
	json.Unmarshal(ev.Payload, &p)
	if p["child_request_id"] != last.RequestID {
		t.Fatalf("roll-up payload %s lacks the child's request id", ev.Payload)
	}
}

// D18: a failed or an abandoned child sends the parent to escalated, not done.
func TestRollUpToEscalated(t *testing.T) {
	t.Run("failed child", func(t *testing.T) {
		conn, parent, kids := decomposedWith(t, 2, sMerged)
		e := newEngine(nil)
		mustDo(t, e, conn, request(kids[0], sMerged, sDone, integrator, chHTTP))
		if _, err := conn.Exec(`UPDATE tickets SET state = 'in_progress', claim_token = $2,
			claimed_by = 'r', lease_expires_at = now() + interval '5 minutes', attempt_count = 2 WHERE id = $1`,
			kids[1], liveToken); err != nil {
			t.Fatal(err)
		}
		mustDo(t, e, conn, request(kids[1], sInProgress, sReady, dev, chHTTP)) // at the cap: failed
		if s := state(t, conn, parent); s != sEscalated {
			t.Fatalf("parent %s, want escalated", s)
		}
		if p, c := eventCount(t, conn, parent), eventCount(t, conn, kids[1]); p != 1 || c != 1 {
			t.Fatalf("%d parent and %d child events, want exactly 1 each", p, c)
		}
		if k := cols(t, conn, parent); !k.EscalationReason.Valid || !k.EscalatedAt.Valid {
			t.Fatalf("escalated parent without reason or time: %+v", k)
		}
	})
	t.Run("abandoned child", func(t *testing.T) {
		conn, parent, kids := decomposedWith(t, 2, sMerged)
		e := newEngine(nil)
		mustDo(t, e, conn, request(kids[0], sMerged, sDone, integrator, chHTTP))
		// merged can't be abandoned (D19), so the second child is still awaiting review.
		if _, err := conn.Exec(`UPDATE tickets SET state = 'awaiting_review' WHERE id = $1`, kids[1]); err != nil {
			t.Fatal(err)
		}
		mustDo(t, e, conn, request(kids[1], sAwaiting, sAbandoned, humanCaller, chHTTP))
		if s := state(t, conn, parent); s != sEscalated {
			t.Fatalf("parent %s, want escalated", s)
		}
		if n := eventCount(t, conn, parent); n != 1 {
			t.Fatalf("%d parent events, want exactly 1", n)
		}
	})
}

// If a human has already moved the parent out of decomposed, the roll-up does nothing and the
// child's own transition still commits.
func TestRollUpWithAbandonedParentIsANoOp(t *testing.T) {
	conn, parent, kids := decomposedWith(t, 1, sMerged)
	e := newEngine(nil)
	mustDo(t, e, conn, request(parent, sDecomposed, sAbandoned, humanCaller, chHTTP))
	mustDo(t, e, conn, request(kids[0], sMerged, sDone, integrator, chHTTP))
	if s := state(t, conn, kids[0]); s != sDone {
		t.Fatalf("child %s, want done", s)
	}
	if s := state(t, conn, parent); s != sAbandoned {
		t.Fatalf("parent %s, want still abandoned", s)
	}
}

// Two children finishing at once: A holds the parent's lock; B waits for it; when A commits, B
// counts the siblings afresh and rolls the parent up. A broken count (inside the locking
// statement, or under REPEATABLE READ) would leave the parent decomposed for ever.
func TestRollUpWhenTwoChildrenFinishTogether(t *testing.T) {
	conn, parent, kids := decomposedWith(t, 2, sMerged)
	e := newEngine(nil)
	ctx := context.Background()

	txA, _ := callbackapi.BeginTx(ctx, conn)
	if _, err := e.Transition(ctx, txA, request(kids[0], sMerged, sDone, integrator, chHTTP)); err != nil {
		t.Fatal(err)
	}
	txB, _ := callbackapi.BeginTx(ctx, conn)
	pidB := backendPID(t, txB)
	errB := make(chan error, 1)
	go func() {
		_, err := e.Transition(ctx, txB, request(kids[1], sMerged, sDone, integrator, chHTTP))
		errB <- err
	}()
	waitBlocked(t, conn, pidB)
	if err := txA.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-errB; err != nil {
		txB.Rollback()
		t.Fatal(err)
	}
	if err := txB.Commit(); err != nil {
		t.Fatal(err)
	}
	if s := state(t, conn, parent); s != sDone {
		t.Fatalf("parent %s after both children finished together, want done", s)
	}
}
