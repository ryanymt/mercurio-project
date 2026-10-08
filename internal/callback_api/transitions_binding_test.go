package callbackapi_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// A person's decision lands only on the escalation and the commit they saw (P06 D5, D19, D21): every
// move out of escalated, and parking, names the escalated_at the page showed, and an approval also
// the head_sha. The fixtures' escalations happened at fixtureEscalatedAt.

// decisions are a person's moves out of escalated: every row the table has for them.
var decisions = []callbackapi.State{sReady, sApproved, sAwaiting, sDone, sFailed, sAbandoned}

func decision(id int64, to callbackapi.State) callbackapi.TransitionRequest {
	return request(id, sEscalated, to, humanCaller, chHTTP)
}

func escalatedAtOf(t *testing.T, conn *sql.DB, id int64) time.Time {
	t.Helper()
	var at time.Time
	if err := conn.QueryRow(`SELECT escalated_at FROM tickets WHERE id = $1`, id).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// --- the escalation -------------------------------------------------------------------------------

// Every decision out of escalated, abandoning included, needs the escalation's time: without it 400,
// another escalation's 409 with nothing changed, its own applied.
func TestEveryDecisionIsBoundToTheEscalation(t *testing.T) {
	for _, to := range decisions {
		t.Run(string(to), func(t *testing.T) {
			conn := fresh(t)
			e := newEngine(nil)
			id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
			before := snapshot(t, conn, id)

			none := decision(id, to)
			none.EscalatedAt = nil
			_, err := do(t, e, conn, none)
			wantStatus(t, err, 400)

			other := decision(id, to)
			later := fixtureEscalatedAt.Add(time.Second)
			other.EscalatedAt = &later
			_, err = do(t, e, conn, other)
			wantStatus(t, err, 409)
			assertUnchanged(t, conn, id, before, 0, 0)

			mustDo(t, e, conn, decision(id, to))
		})
	}
}

// Parking and unparking are decisions on the escalation too (red team R8#2).
func TestParkingIsBoundToTheEscalation(t *testing.T) {
	for _, parked := range []bool{true, false} {
		t.Run(fmt.Sprint("parked=", parked), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sEscalated, attempts: 1, parked: !parked})
			before, events := snapshot(t, conn, id), eventCount(t, conn, id)
			reason := ""
			if parked {
				reason = "waiting"
			}
			none := park(id, humanCaller, parked, reason, nil)
			none.EscalatedAt = nil
			_, err := doPark(t, conn, none)
			wantStatus(t, err, 400)

			other := park(id, humanCaller, parked, reason, nil)
			earlier := fixtureEscalatedAt.Add(-time.Minute)
			other.EscalatedAt = &earlier
			_, err = doPark(t, conn, other)
			wantStatus(t, err, 409)
			assertUnchanged(t, conn, id, before, events, 0)

			if _, err := doPark(t, conn, park(id, humanCaller, parked, reason, nil)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A ticket escalated again after the page was loaded refuses the page's decision: the case D19
// exists for. The second escalation's own time is accepted.
func TestADecisionOnALaterEscalationIsRefused(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	shown := escalatedAtOf(t, conn, id)
	mustDo(t, e, conn, decision(id, sReady))
	// The ticket runs again and its runner escalates: a new escalation.
	if _, err := conn.Exec(`UPDATE tickets SET state = 'in_progress', claim_token = $2, claimed_by = 'r',
		claimed_at = now(), lease_expires_at = now() + interval '5 minutes' WHERE id = $1`, id, liveToken); err != nil {
		t.Fatal(err)
	}
	mustDo(t, e, conn, request(id, sInProgress, sEscalated, dev, chHTTP))
	again := escalatedAtOf(t, conn, id)
	if again.Equal(shown) {
		t.Fatal("the second escalation kept the first one's time")
	}
	stale := decision(id, sDone)
	stale.EscalatedAt = &shown
	before, events := snapshot(t, conn, id), eventCount(t, conn, id)
	requests := count(t, conn, `SELECT count(*) FROM api_requests`)
	_, err := do(t, e, conn, stale)
	wantStatus(t, err, 409)
	assertUnchanged(t, conn, id, before, events, requests)
	current := decision(id, sDone)
	current.EscalatedAt = &again
	mustDo(t, e, conn, current)
}

// escalated_at is compared exactly, at the stored microseconds: the same instant in another zone is
// accepted, the value truncated to the second or carrying extra nanoseconds is not.
func TestEscalatedAtIsComparedExactly(t *testing.T) {
	if fixtureEscalatedAt.Nanosecond()%1000 != 0 || fixtureEscalatedAt.Nanosecond() == 0 {
		t.Fatal("the fixture's escalation must carry microseconds and nothing finer")
	}
	for name, c := range map[string]struct {
		at time.Time
		ok bool
	}{
		"as stored":             {fixtureEscalatedAt, true},
		"another zone":          {fixtureEscalatedAt.In(time.FixedZone("+08", 8*3600)), true},
		"truncated to a second": {fixtureEscalatedAt.Truncate(time.Second), false},
		"truncated to a milli":  {fixtureEscalatedAt.Truncate(time.Millisecond), false},
		"a nanosecond later":    {fixtureEscalatedAt.Add(time.Nanosecond), false},
		"a microsecond earlier": {fixtureEscalatedAt.Add(-time.Microsecond), false},
	} {
		t.Run(name, func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
			if got := escalatedAtOf(t, conn, id); !got.Equal(fixtureEscalatedAt) {
				t.Fatalf("seeded escalated_at %v, want %v", got, fixtureEscalatedAt)
			}
			req := decision(id, sReady)
			at := c.at
			req.EscalatedAt = &at
			_, err := do(t, newEngine(nil), conn, req)
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok {
				wantStatus(t, err, 409)
			}
		})
	}
}

// escalated_at belongs only to a decision out of escalated: on any other transition, abandoning from
// another state among them, it is a 400. Abandoning from another state needs none (its from binds it).
func TestEscalatedAtOnlyOutOfEscalated(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	at := fixtureEscalatedAt
	for _, c := range []struct {
		from, to callbackapi.State
		caller   callbackapi.Caller
		ch       callbackapi.Channel
	}{
		{sInProgress, sAwaiting, dev, chHTTP},
		{sInProgress, sEscalated, dev, chHTTP},
		{sReady, sClaimed, dispatcherCaller, chCore},
		{sDraft, sReady, spec, chHTTP},
		{sReady, sAbandoned, humanCaller, chHTTP},
		{sInQA, sApproved, qa, chHTTP},
	} {
		id := seed(t, conn, fixture{state: c.from, attempts: 1})
		req := request(id, c.from, c.to, c.caller, c.ch)
		req.EscalatedAt = &at
		_, err := do(t, e, conn, req)
		if err == nil || callbackapi.StatusOf(err) != 400 {
			t.Errorf("%s -> %s by %s with escalated_at: %v, want 400", c.from, c.to, c.caller.Role, err)
		}
	}
	id := seed(t, conn, fixture{state: sReady, attempts: 1})
	mustDo(t, e, conn, request(id, sReady, sAbandoned, humanCaller, chHTTP))
}

// --- the commit -----------------------------------------------------------------------------------

// An approval, and a return to QA, name the head the page showed: without it 400, another 409 with
// nothing changed, the ticket's own applied (P06 D5; [P04/feedback]).
func TestApprovalsNameTheCommit(t *testing.T) {
	for _, to := range []callbackapi.State{sApproved, sAwaiting} {
		t.Run(string(to), func(t *testing.T) {
			conn := fresh(t)
			e := newEngine(nil)
			id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
			before := snapshot(t, conn, id)

			none := decision(id, to)
			none.HeadSHA = ""
			_, err := do(t, e, conn, none)
			wantStatus(t, err, 400)

			short := decision(id, to)
			short.HeadSHA = fixtureSHA[:12]
			_, err = do(t, e, conn, short)
			wantStatus(t, err, 400)

			moved := decision(id, to)
			moved.HeadSHA = gitSHA('9')
			_, err = do(t, e, conn, moved)
			wantStatus(t, err, 409)
			assertUnchanged(t, conn, id, before, 0, 0)

			mustDo(t, e, conn, decision(id, to))
			if s := state(t, conn, id); s != to {
				t.Fatalf("state %s, want %s", s, to)
			}
		})
	}
}

// head_sha is refused on a decision that is not about a commit.
func TestOtherDecisionsTakeNoCommit(t *testing.T) {
	for _, to := range []callbackapi.State{sReady, sDone, sFailed, sAbandoned} {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
		req := decision(id, to)
		req.HeadSHA = fixtureSHA
		_, err := do(t, newEngine(nil), conn, req)
		if err == nil || callbackapi.StatusOf(err) != 400 {
			t.Errorf("escalated -> %s with head_sha: %v, want 400", to, err)
		}
	}
}

// A dev runner that must stop after pushing escalates naming its commit, which becomes the ticket's
// head; without one the head stays as it was. A head_sha that is not a full SHA is a 400 (P06 D21).
func TestARunnersEscalationMayNameItsCommit(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	head := func(id int64) sql.NullString {
		var h sql.NullString
		conn.QueryRow(`SELECT head_sha FROM tickets WHERE id = $1`, id).Scan(&h)
		return h
	}

	named := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := request(named, sInProgress, sEscalated, dev, chHTTP)
	req.HeadSHA = gitSHA('7')
	mustDo(t, e, conn, req)
	if h := head(named); h.String != gitSHA('7') {
		t.Fatalf("head %v after escalating with a commit, want %s", h, gitSHA('7'))
	}
	// And a person approves exactly that commit.
	approve := decision(named, sApproved)
	approve.EscalatedAt = ptr(escalatedAtOf(t, conn, named))
	approve.HeadSHA = gitSHA('7')
	mustDo(t, e, conn, approve)

	plain := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	mustDo(t, e, conn, request(plain, sInProgress, sEscalated, dev, chHTTP))
	if h := head(plain); h.Valid {
		t.Fatalf("head %v after escalating without a commit, want none", h)
	}

	for _, bad := range []string{fixtureSHA[:7], "ABCDEF" + fixtureSHA[6:], fixtureSHA + "0", "not a sha"} {
		id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
		r := request(id, sInProgress, sEscalated, dev, chHTTP)
		r.HeadSHA = bad
		_, err := do(t, e, conn, r)
		wantStatus(t, err, 400)
	}
}

func ptr[T any](v T) *T { return &v }

// --- idempotency and the record -------------------------------------------------------------------

// A reused key with the same decision replays; with another escalated_at or head_sha it is a 409,
// not a replay (red team R8#2). Parking likewise.
func TestAReusedKeyMustNameTheSameBinding(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	first := decision(id, sApproved)
	res := mustDo(t, e, conn, first)
	again, err := do(t, e, conn, first)
	if err != nil || again.EventID != res.EventID || eventCount(t, conn, id) != 1 {
		t.Fatalf("replay: %+v, %v, %d events", again, err, eventCount(t, conn, id))
	}
	otherAt := first
	later := fixtureEscalatedAt.Add(time.Microsecond)
	otherAt.EscalatedAt = &later
	_, err = do(t, e, conn, otherAt)
	wantStatus(t, err, 409)
	otherHead := first
	otherHead.HeadSHA = gitSHA('8')
	_, err = do(t, e, conn, otherHead)
	wantStatus(t, err, 409)

	parked := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	p := park(parked, humanCaller, true, "later", nil)
	if _, err := doPark(t, conn, p); err != nil {
		t.Fatal(err)
	}
	p.EscalatedAt = &later
	_, err = doPark(t, conn, p)
	wantStatus(t, err, 409)
}

// The decision's event records what it was bound to, over anything of that name in the payload the
// person sent: a payload cannot imitate a binding.
func TestTheEventRecordsTheBinding(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	want := fixtureEscalatedAt.UTC().Format(time.RFC3339Nano)
	imitation := json.RawMessage(`{"reason": "looks fine", "bound_to": {"escalated_at": "2000-01-01T00:00:00Z", "head_sha": "` +
		gitSHA('6') + `"}}`)

	approved := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	req := decision(approved, sApproved)
	req.Payload = imitation
	mustDo(t, e, conn, req)

	done := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	req = decision(done, sDone)
	req.Payload = imitation
	mustDo(t, e, conn, req)

	parked := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	if _, err := doPark(t, conn, park(parked, humanCaller, true, "later", nil)); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		id   int64
		head string
	}{"approved": {approved, fixtureSHA}, "done": {done, ""}, "parked": {parked, ""}} {
		var p struct {
			Reason  string            `json:"reason"`
			BoundTo map[string]string `json:"bound_to"`
		}
		ev := lastEvent(t, conn, c.id)
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.BoundTo["escalated_at"] != want || p.BoundTo["head_sha"] != c.head {
			t.Errorf("%s: bound_to %v, want escalated_at %s and head_sha %q", name, p.BoundTo, want, c.head)
		}
		if name != "parked" && p.Reason != "looks fine" {
			t.Errorf("%s: the person's own reason was lost: %s", name, ev.Payload)
		}
	}
}

// The binding is one instant however it is written: the event records it in UTC, and a retry with
// the same key naming the same instant in another zone replays the decision rather than being
// refused as a different request.
func TestTheBindingIsOneInstantInAnyZone(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	req := decision(id, sDone)
	inZone := fixtureEscalatedAt.In(time.FixedZone("+08", 8*3600))
	req.EscalatedAt = &inZone
	res := mustDo(t, e, conn, req)
	var p struct {
		BoundTo map[string]string `json:"bound_to"`
	}
	json.Unmarshal(lastEvent(t, conn, id).Payload, &p)
	if want := fixtureEscalatedAt.UTC().Format(time.RFC3339Nano); p.BoundTo["escalated_at"] != want {
		t.Fatalf("bound_to escalated_at %q, want %q in UTC", p.BoundTo["escalated_at"], want)
	}
	retry := req
	utc := fixtureEscalatedAt.UTC()
	retry.EscalatedAt = &utc
	again, err := do(t, e, conn, retry)
	if err != nil || again.EventID != res.EventID {
		t.Fatalf("a retry naming the same instant in UTC: %+v, %v, want the first decision replayed", again, err)
	}
}

// Leaving escalated keeps escalated_at and escalation_reason as the last escalation (D13), whichever
// way it leaves.
func TestTheEscalationStaysAsHistory(t *testing.T) {
	for _, to := range decisions {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
		if _, err := conn.Exec(`UPDATE tickets SET escalation_reason = 'needs a person' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		mustDo(t, newEngine(nil), conn, decision(id, to))
		k := cols(t, conn, id)
		if !k.EscalatedAt.Valid || !k.EscalatedAt.Time.Equal(fixtureEscalatedAt) || k.EscalationReason.String != "needs a person" {
			t.Errorf("after escalated -> %s: escalated_at %v, reason %v", to, k.EscalatedAt, k.EscalationReason)
		}
	}
}

// --- over HTTP ------------------------------------------------------------------------------------

// The relayed decision carries escalated_at and head_sha in its body, decoded strictly: the value as
// RFC 3339 with its microseconds lands, the same truncated to the second does not.
func TestHTTPDecisionsCarryWhatWasShown(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sEscalated, attempts: 1})
	path := fmt.Sprintf("/v1/tickets/%d/transitions", id)
	body := func(at string) map[string]any {
		return map[string]any{"from": sEscalated, "to": sApproved, "escalated_at": at, "head_sha": fixtureSHA}
	}
	st, b := a.do(call{method: "POST", path: path, as: humanEmail, key: newRequestID(),
		body: body(fixtureEscalatedAt.Format(time.RFC3339))})
	wantHTTP(t, st, 409, b)
	st, b = a.do(call{method: "POST", path: path, as: humanEmail, key: newRequestID(),
		body: body("yesterday")})
	wantHTTP(t, st, 400, b)
	st, b = a.do(call{method: "POST", path: path, as: humanEmail, key: newRequestID(),
		body: body(fixtureEscalatedAt.Format(time.RFC3339Nano))})
	wantHTTP(t, st, 200, b)

	parked := seed(t, a.conn, fixture{state: sEscalated, attempts: 1})
	st, b = a.do(call{method: "PUT", path: fmt.Sprintf("/v1/tickets/%d/parking", parked), as: humanEmail,
		key: newRequestID(), body: map[string]any{"parked": true, "reason": "later",
			"escalated_at": fixtureEscalatedAt.Format(time.RFC3339Nano)}})
	wantHTTP(t, st, 200, b)
}
