package callbackapi_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// park asks to park or unpark id, naming the seeded escalation (P06 D19).
func park(id int64, c callbackapi.Caller, parked bool, reason string, until *time.Time) callbackapi.ParkingRequest {
	at := fixtureEscalatedAt
	return callbackapi.ParkingRequest{
		TicketID: id, Caller: c, Parked: parked, Reason: reason, Until: until, EscalatedAt: &at,
		RequestID: newRequestID(), Method: "PUT", Path: fmt.Sprintf("/v1/tickets/%d/parking", id),
	}
}

func doPark(t *testing.T, conn *sql.DB, req callbackapi.ParkingRequest) (callbackapi.ParkingResult, error) {
	return inTx(t, conn, func(ctx context.Context, tx *sql.Tx) (callbackapi.ParkingResult, error) {
		return newEngine(nil).Park(ctx, tx, req)
	})
}

func TestHumanParksAnEscalation(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	until := time.Now().Add(48 * time.Hour)
	res, err := doPark(t, conn, park(id, humanCaller, true, "waiting on a vendor", &until))
	if err != nil {
		t.Fatal(err)
	}
	var parked bool
	var reason sql.NullString
	var pu sql.NullTime
	conn.QueryRow(`SELECT parked, parked_reason, parked_until FROM tickets WHERE id = $1`, id).Scan(&parked, &reason, &pu)
	if !parked || reason.String != "waiting on a vendor" || !pu.Valid || !res.Parked {
		t.Fatalf("parked=%v reason=%v until=%v", parked, reason, pu)
	}
	ev := lastEvent(t, conn, id)
	if ev.From.String != string(sEscalated) || ev.To.String != string(sEscalated) || ev.ActorID != humanCaller.Email {
		t.Fatalf("parking event %+v: want a same-state event by the human", ev)
	}
	var p map[string]any
	json.Unmarshal(ev.Payload, &p)
	if p["parked"] != true {
		t.Fatalf("parking payload %s", ev.Payload)
	}

	// Unparking clears all three fields.
	if _, err := doPark(t, conn, park(id, humanCaller, false, "", nil)); err != nil {
		t.Fatal(err)
	}
	conn.QueryRow(`SELECT parked, parked_reason, parked_until FROM tickets WHERE id = $1`, id).Scan(&parked, &reason, &pu)
	if parked || reason.Valid || pu.Valid {
		t.Fatalf("after unparking: parked=%v reason=%v until=%v", parked, reason, pu)
	}
}

// Parking belongs to an escalation (D21): a ticket in any other state cannot be parked, so a flag
// set in advance can never exempt a future escalation.
func TestOnlyAnEscalatedTicketIsParked(t *testing.T) {
	for _, s := range []callbackapi.State{sReady, sInProgress, sAwaiting, sDone} {
		t.Run(string(s), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: s, attempts: 1})
			before := snapshot(t, conn, id)
			_, err := doPark(t, conn, park(id, humanCaller, true, "in advance", nil))
			wantStatus(t, err, 409)
			assertUnchanged(t, conn, id, before, 0, 0)
		})
	}
}

// parked_until must be in the future, judged by the database's clock.
func TestParkedUntilMustBeInTheFuture(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	before := snapshot(t, conn, id)
	past := time.Now().Add(-time.Minute)
	_, err := doPark(t, conn, park(id, humanCaller, true, "too late", &past))
	wantStatus(t, err, 400)
	assertUnchanged(t, conn, id, before, 0, 0)
}

func TestParkingNeedsAReason(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	_, err := doPark(t, conn, park(id, humanCaller, true, " ", nil))
	wantStatus(t, err, 400)
}

// No agent may ever write parked.
func TestNoAgentParks(t *testing.T) {
	for _, role := range agentRoles {
		t.Run(string(role), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sEscalated, attempts: 1})
			before := snapshot(t, conn, id)
			c, _ := callerFor(role)
			_, err := doPark(t, conn, park(id, c, true, "an agent tries", nil))
			wantStatus(t, err, 403)
			assertUnchanged(t, conn, id, before, 0, 0)
		})
	}
}
