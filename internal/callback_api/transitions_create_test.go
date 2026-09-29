package callbackapi_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// inTx runs fn in its own READ COMMITTED transaction: commit on success, roll back on error.
func inTx[T any](t *testing.T, conn *sql.DB, fn func(ctx context.Context, tx *sql.Tx) (T, error)) (T, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	res, err := fn(ctx, tx)
	if err != nil {
		tx.Rollback()
		return res, err
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return res, nil
}

var agentRoles = []callbackapi.Role{
	callbackapi.RoleDispatcher, callbackapi.RoleSpec, callbackapi.RoleArchitect,
	callbackapi.RoleDev, callbackapi.RoleQA, callbackapi.RoleIntegrator,
}

func create(c callbackapi.Caller, project, title string, ac []callbackapi.Criterion) callbackapi.CreateRequest {
	return callbackapi.CreateRequest{
		Caller: c, Project: project, Title: title, Body: "body", Priority: 1,
		AcceptanceCriteria: ac, RequestID: newRequestID(), Method: "POST", Path: "/v1/tickets",
	}
}

func doCreate(t *testing.T, conn *sql.DB, req callbackapi.CreateRequest) (callbackapi.CreateResult, error) {
	return inTx(t, conn, func(ctx context.Context, tx *sql.Tx) (callbackapi.CreateResult, error) {
		return newEngine(nil).Create(ctx, tx, req)
	})
}

var oneAC = []callbackapi.Criterion{{ID: "AC1", Text: "it works"}}

func TestHumanCreatesInANamedProject(t *testing.T) {
	conn := fresh(t)
	addProject(t, conn, "other")

	draft, err := doCreate(t, conn, create(humanCaller, "other", "a draft", nil))
	if err != nil {
		t.Fatal(err)
	}
	if draft.State != sDraft || draft.Project != "other" {
		t.Fatalf("created %+v, want a draft in other", draft)
	}
	ready, err := doCreate(t, conn, create(humanCaller, "foreman", "specified", oneAC))
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != sReady || state(t, conn, ready.TicketID) != sReady {
		t.Fatalf("created %+v, want ready (acceptance criteria given)", ready)
	}
	ev := lastEvent(t, conn, ready.TicketID)
	if ev.From.Valid || ev.To.String != string(sReady) || ev.Actor != "human" || ev.ActorID != humanCaller.Email {
		t.Fatalf("creation event %+v: want no from-state, to ready, by the human", ev)
	}
	var depth int
	var parent sql.NullInt64
	conn.QueryRow(`SELECT depth, parent_ticket_id FROM tickets WHERE id = $1`, ready.TicketID).Scan(&depth, &parent)
	if depth != 0 || parent.Valid {
		t.Fatal("a created ticket must be top level: children come only from /decompose")
	}
}

func TestSpecRunnerCreatesOnlyInItsOwnProject(t *testing.T) {
	conn := fresh(t)
	addProject(t, conn, "other")
	own, err := doCreate(t, conn, create(spec, "", "own project implied", nil))
	if err != nil {
		t.Fatal(err)
	}
	if own.Project != "foreman" {
		t.Fatalf("project %s, want the spec runner's own", own.Project)
	}
	if _, err := doCreate(t, conn, create(spec, "foreman", "own project named", nil)); err != nil {
		t.Fatal(err)
	}
	_, err = doCreate(t, conn, create(spec, "other", "someone else's", nil))
	wantStatus(t, err, 403)
}

func TestOnlyHumansAndSpecRunnersCreate(t *testing.T) {
	for _, role := range agentRoles {
		if role == callbackapi.RoleSpec {
			continue
		}
		t.Run(string(role), func(t *testing.T) {
			conn := fresh(t)
			c, _ := callerFor(role)
			_, err := doCreate(t, conn, create(c, "foreman", "not mine to create", nil))
			wantStatus(t, err, 403)
			if n := count(t, conn, `SELECT count(*) FROM tickets`); n != 0 {
				t.Fatalf("%d tickets after a refused creation", n)
			}
		})
	}
}

func TestCreationRefusals(t *testing.T) {
	conn := fresh(t)
	cases := map[string]struct {
		req    callbackapi.CreateRequest
		status int
	}{
		"human names no project": {create(humanCaller, "", "where?", nil), 400},
		"unknown project":        {create(humanCaller, "nowhere", "lost", nil), 404},
		"no title":               {create(humanCaller, "foreman", " ", nil), 400},
		"criterion without text": {create(humanCaller, "foreman", "t", []callbackapi.Criterion{{ID: "AC1"}}), 400},
		"bad idempotency key": {func() callbackapi.CreateRequest {
			r := create(humanCaller, "foreman", "t", nil)
			r.RequestID = "one"
			return r
		}(), 400},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := doCreate(t, conn, c.req)
			wantStatus(t, err, c.status)
		})
	}
	if n := count(t, conn, `SELECT count(*) FROM tickets`); n != 0 {
		t.Fatalf("%d tickets after refused creations", n)
	}
}

func TestCreationIsIdempotent(t *testing.T) {
	conn := fresh(t)
	req := create(humanCaller, "foreman", "once", oneAC)
	first, err := doCreate(t, conn, req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := doCreate(t, conn, req)
	if err != nil || !again.Replayed || again.TicketID != first.TicketID {
		t.Fatalf("replay = %+v, %v; want the first ticket again", again, err)
	}
	if n := count(t, conn, `SELECT count(*) FROM tickets`); n != 1 {
		t.Fatalf("%d tickets for one key", n)
	}
	other := req
	other.Title = "twice"
	_, err = doCreate(t, conn, other)
	wantStatus(t, err, 409)
}

func TestCreatedAcceptanceCriteriaAreStored(t *testing.T) {
	conn := fresh(t)
	res, err := doCreate(t, conn, create(humanCaller, "foreman", "t", []callbackapi.Criterion{{ID: "AC1", Text: "a"}, {ID: "AC2", Text: "b"}}))
	if err != nil {
		t.Fatal(err)
	}
	var ac []callbackapi.Criterion
	json.Unmarshal(cols(t, conn, res.TicketID).AC, &ac)
	if len(ac) != 2 {
		t.Fatalf("stored acceptance criteria %+v", ac)
	}
}
