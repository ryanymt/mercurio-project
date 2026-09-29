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

func heartbeat(id int64, c callbackapi.Caller, token string) callbackapi.HeartbeatRequest {
	return callbackapi.HeartbeatRequest{
		TicketID: id, Caller: c, RequestID: newRequestID(), ClaimToken: token,
		Method: "POST", Path: fmt.Sprintf("/v1/tickets/%d/heartbeat", id),
	}
}

func doHeartbeat(t *testing.T, conn *sql.DB, req callbackapi.HeartbeatRequest) (callbackapi.HeartbeatResult, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	res, err := newEngine(nil).Heartbeat(ctx, tx, req)
	if err != nil {
		tx.Rollback()
		return res, err
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return res, nil
}

// The owner of the current leased state extends the lease, in database time, and the heartbeat
// is recorded as an event (D22).
func TestHeartbeatExtendsTheLeaseAndIsAnEvent(t *testing.T) {
	owners := map[callbackapi.State]callbackapi.Caller{
		sClaimed: dev, sInProgress: dev, sInQA: qa, sMerging: integrator,
	}
	for st, owner := range owners {
		t.Run(string(st), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: st, attempts: 1})
			if _, err := conn.Exec(`UPDATE tickets SET lease_expires_at = now() + interval '10 seconds' WHERE id = $1`, id); err != nil {
				t.Fatal(err)
			}
			res, err := doHeartbeat(t, conn, heartbeat(id, owner, liveToken))
			if err != nil {
				t.Fatal(err)
			}
			var remaining time.Duration
			var secs float64
			conn.QueryRow(`SELECT extract(epoch FROM lease_expires_at - now()) FROM tickets WHERE id = $1`, id).Scan(&secs)
			remaining = time.Duration(secs * float64(time.Second))
			if remaining < 4*time.Minute || remaining > 5*time.Minute+time.Second {
				t.Fatalf("lease has %s left after a heartbeat, want about five minutes", remaining)
			}
			if state(t, conn, id) != st {
				t.Fatal("a heartbeat changed the state")
			}
			ev := lastEvent(t, conn, id)
			if ev.From.String != string(st) || ev.To.String != string(st) || ev.ActorID != owner.Email || res.EventID == 0 {
				t.Fatalf("heartbeat event %+v", ev)
			}
			var p map[string]any
			json.Unmarshal(ev.Payload, &p)
			if p["heartbeat"] != true || p["lease_expires_at"] == nil {
				t.Fatalf("heartbeat payload %s", ev.Payload)
			}
		})
	}
}

func TestHeartbeatRefusals(t *testing.T) {
	cases := []struct {
		name   string
		fx     fixture
		caller callbackapi.Caller
		token  string
		status int
	}{
		{"not a leasing role", fixture{state: sInProgress, attempts: 1}, humanCaller, "", 403},
		{"dispatcher", fixture{state: sInProgress, attempts: 1}, dispatcherCaller, "", 403},
		{"spec runner", fixture{state: sInProgress, attempts: 1}, spec, liveToken, 403},
		{"another project", fixture{project: "other", state: sInProgress, attempts: 1}, dev, liveToken, 403},
		{"role does not own this state", fixture{state: sInQA, attempts: 1}, dev, liveToken, 409},
		{"state not leased", fixture{state: sAwaiting, attempts: 1}, dev, liveToken, 409},
		{"missing token", fixture{state: sInProgress, attempts: 1}, dev, "", 409},
		{"wrong token", fixture{state: sInProgress, attempts: 1}, dev, "stale", 409},
		{"null token", fixture{state: sInProgress, attempts: 1, noToken: true}, dev, "", 409},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := fresh(t)
			if c.fx.project == "other" {
				addProject(t, conn, "other")
			}
			id := seed(t, conn, c.fx)
			before, events := snapshot(t, conn, id), eventCount(t, conn, id)
			_, err := doHeartbeat(t, conn, heartbeat(id, c.caller, c.token))
			wantStatus(t, err, c.status)
			assertUnchanged(t, conn, id, before, events, 0)
		})
	}
}

// A heartbeat replayed under the same key is recorded once.
func TestHeartbeatIsIdempotent(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	req := heartbeat(id, dev, liveToken)
	if _, err := doHeartbeat(t, conn, req); err != nil {
		t.Fatal(err)
	}
	if _, err := doHeartbeat(t, conn, req); err != nil {
		t.Fatal(err)
	}
	if n := eventCount(t, conn, id); n != 1 {
		t.Fatalf("%d heartbeat events for one key, want 1", n)
	}
}
