package callbackapi_test

import (
	"fmt"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

type pair struct{ from, to callbackapi.State }

// pairs returns every (from, to) in the ownership table, with the roles allowed on it.
func pairs() map[pair][]callbackapi.Row {
	out := map[pair][]callbackapi.Row{}
	for _, r := range callbackapi.Table() {
		p := pair{r.From, r.To}
		out[p] = append(out[p], r)
	}
	return out
}

// Acceptance criterion 1: every row driven by a caller, in both directions, against the seven
// roles. The allowed actor, through its own channel, gets the expected state and exactly one
// event naming it; every other role, through its natural channel, gets 403 and changes nothing.
// `ready -> decomposed` goes through /decompose (T3) and internal rows are nobody's to request;
// both are only in the refusal half here.
func TestEveryRowInBothDirections(t *testing.T) {
	for p, rows := range pairs() {
		allowed := map[callbackapi.Role]callbackapi.Row{}
		for _, r := range rows {
			if r.Channel == callbackapi.ChannelHTTP || r.Channel == callbackapi.ChannelCore {
				allowed[r.Actor] = r
			}
		}
		for _, role := range callerRoles {
			name := fmt.Sprintf("%s->%s/%s", p.from, p.to, role)
			if r, ok := allowed[role]; ok {
				t.Run(name+"/allowed", func(t *testing.T) { rowAllowed(t, r) })
			} else {
				t.Run(name+"/refused", func(t *testing.T) { rowRefused(t, p, role) })
			}
		}
	}
}

func rowAllowed(t *testing.T, r callbackapi.Row) {
	conn := fresh(t)
	e := newEngine(nil)
	// A reap needs an expired lease; a new-work claim names the attempt it starts (P04).
	id := seed(t, conn, fixture{state: r.From, attempts: 1, expired: r.Actor == callbackapi.RoleDispatcher && dispatcherReturn(r.From, r.To)})
	c, ch := callerFor(r.Actor)
	req := request(id, r.From, r.To, c, ch)
	if r.Actor == callbackapi.RoleDispatcher && r.From == callbackapi.StateReady {
		req.Branch = branchFor(id, 2)
	}
	res := mustDo(t, e, conn, req)

	want := r.To
	if r.From == callbackapi.StateInQA && r.To == callbackapi.StateApproved {
		want = callbackapi.StateEscalated // fail closed until P03 (D3)
	}
	if got := state(t, conn, id); got != want || res.State != want {
		t.Fatalf("state = %s (result %s), want %s", got, res.State, want)
	}
	if n := eventCount(t, conn, id); n != 1 {
		t.Fatalf("%d events, want exactly 1", n)
	}
	ev := lastEvent(t, conn, id)
	if ev.ActorID != c.Email || ev.From.String != string(r.From) || ev.To.String != string(want) {
		t.Fatalf("event = %+v, want %s -> %s by %s", ev, r.From, want, c.Email)
	}
	if want == r.To && ev.Actor != string(r.Actor) {
		t.Fatalf("event actor = %s, want %s", ev.Actor, r.Actor)
	}
	wantAttempts := 1
	if r.From == callbackapi.StateClaimed && r.To == callbackapi.StateInProgress {
		wantAttempts = 2 // starting a dev session is the only row that uses an attempt
	}
	if c := cols(t, conn, id); c.Attempts != wantAttempts {
		t.Fatalf("attempts = %d, want %d", c.Attempts, wantAttempts)
	}
}

func rowRefused(t *testing.T, p pair, role callbackapi.Role) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: p.from, attempts: 1})
	before, events := snapshot(t, conn, id), eventCount(t, conn, id)
	c, ch := callerFor(role)
	_, err := do(t, e, conn, request(id, p.from, p.to, c, ch))
	wantStatus(t, err, 403)
	assertUnchanged(t, conn, id, before, events, 0)
}

// A row requested through the wrong channel is refused like a row that isn't there: the
// dispatcher's reaps are not reachable over HTTP, a runner's rows are not reachable by the
// dispatcher's direct calls, and `ready -> decomposed` only through /decompose.
func TestRowsOnlyThroughTheirChannel(t *testing.T) {
	for _, r := range callbackapi.Table() {
		if r.Channel == callbackapi.ChannelInternal {
			continue
		}
		for _, ch := range []callbackapi.Channel{callbackapi.ChannelHTTP, callbackapi.ChannelCore, callbackapi.ChannelDecompose} {
			if ch == r.Channel {
				continue
			}
			t.Run(fmt.Sprintf("%s->%s/%s/via-%s", r.From, r.To, r.Actor, ch), func(t *testing.T) {
				conn := fresh(t)
				id := seed(t, conn, fixture{state: r.From, attempts: 1})
				before := snapshot(t, conn, id)
				c, _ := callerFor(r.Actor)
				_, err := do(t, newEngine(nil), conn, request(id, r.From, r.To, c, ch))
				wantStatus(t, err, 403)
				assertUnchanged(t, conn, id, before, 0, 0)
			})
		}
	}
}

// The internal rows exist, and no caller can request them through any channel.
func TestInternalRowsAreNobodysToRequest(t *testing.T) {
	var internal []callbackapi.Row
	for _, r := range callbackapi.Table() {
		if r.Channel == callbackapi.ChannelInternal {
			internal = append(internal, r)
		}
	}
	want := map[pair]callbackapi.Role{
		{callbackapi.StateReady, callbackapi.StateEscalated}:      callbackapi.RoleCallbackAPI,
		{callbackapi.StateDecomposed, callbackapi.StateDone}:      callbackapi.RoleCallbackAPI,
		{callbackapi.StateDecomposed, callbackapi.StateEscalated}: callbackapi.RoleCallbackAPI,
		{callbackapi.StateInQA, callbackapi.StateEscalated}:       callbackapi.RoleRiskEvaluator,
	}
	for _, r := range internal {
		if want[pair{r.From, r.To}] != r.Actor {
			t.Errorf("unexpected internal row %+v", r)
		}
		delete(want, pair{r.From, r.To})
	}
	for p, a := range want {
		t.Errorf("internal row %s -> %s (%s) missing from the table", p.from, p.to, a)
	}
}

// D19: `escalated` leaves only for ready, approved, awaiting_review (P04 D17), done or failed (and
// abandoned), never for a leased state, draft, decomposed or merged; abandoned is reachable from every state except
// done, failed, abandoned and merged.
func TestOpenEndedRowsAreEnumerated(t *testing.T) {
	out := map[callbackapi.State]bool{}
	into := map[callbackapi.State]bool{}
	for _, r := range callbackapi.Table() {
		if r.From == callbackapi.StateEscalated && r.To != callbackapi.StateAbandoned {
			if r.Actor != callbackapi.RoleHuman {
				t.Errorf("escalated -> %s by %s: only a human may leave escalated", r.To, r.Actor)
			}
			out[r.To] = true
		}
		if r.To == callbackapi.StateAbandoned {
			if r.Actor != callbackapi.RoleHuman {
				t.Errorf("%s -> abandoned by %s: only a human may abandon", r.From, r.Actor)
			}
			into[r.From] = true
		}
	}
	for _, s := range []callbackapi.State{callbackapi.StateReady, callbackapi.StateApproved, callbackapi.StateAwaitingReview, callbackapi.StateDone, callbackapi.StateFailed} {
		if !out[s] {
			t.Errorf("escalated -> %s missing", s)
		}
		delete(out, s)
	}
	for s := range out {
		t.Errorf("escalated -> %s must not exist", s)
	}
	for _, s := range callbackapi.States() {
		terminalOrMerged := s == callbackapi.StateDone || s == callbackapi.StateFailed ||
			s == callbackapi.StateAbandoned || s == callbackapi.StateMerged
		if into[s] == terminalOrMerged {
			t.Errorf("%s -> abandoned: present=%v, want %v", s, into[s], !terminalOrMerged)
		}
	}
}
