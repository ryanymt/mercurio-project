package callbackapi_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

func children(n int) []callbackapi.ChildSpec {
	var out []callbackapi.ChildSpec
	for i := 1; i <= n; i++ {
		out = append(out, callbackapi.ChildSpec{
			Title: fmt.Sprintf("child %d", i), Priority: i,
			AcceptanceCriteria: []callbackapi.Criterion{{ID: "AC1", Text: fmt.Sprintf("part %d works", i)}},
		})
	}
	return out
}

func decompose(id int64, c callbackapi.Caller, kids []callbackapi.ChildSpec) callbackapi.DecomposeRequest {
	return callbackapi.DecomposeRequest{
		TicketID: id, Caller: c, Children: kids, RequestID: newRequestID(),
		Method: "POST", Path: fmt.Sprintf("/v1/tickets/%d/decompose", id),
	}
}

func doDecompose(t *testing.T, conn *sql.DB, req callbackapi.DecomposeRequest) (callbackapi.DecomposeResult, error) {
	return inTx(t, conn, func(ctx context.Context, tx *sql.Tx) (callbackapi.DecomposeResult, error) {
		return newEngine(nil).Decompose(ctx, tx, req)
	})
}

func TestDecomposeIntoOneToFive(t *testing.T) {
	for _, n := range []int{1, 5} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			conn := fresh(t)
			parent := seed(t, conn, fixture{state: sReady})
			req := decompose(parent, spec, children(n))
			res, err := doDecompose(t, conn, req)
			if err != nil {
				t.Fatal(err)
			}
			if res.State != sDecomposed || state(t, conn, parent) != sDecomposed || len(res.Children) != n {
				t.Fatalf("result %+v, parent %s: want decomposed with %d children", res, state(t, conn, parent), n)
			}
			for _, kid := range res.Children {
				var depth int
				var p int64
				var project string
				var ac sql.NullString
				conn.QueryRow(`SELECT depth, parent_ticket_id, project_id, acceptance_criteria FROM tickets WHERE id = $1`, kid).
					Scan(&depth, &p, &project, &ac)
				if state(t, conn, kid) != sReady || depth != 1 || p != parent || project != "foreman" || !ac.Valid {
					t.Fatalf("child %d: want ready, depth 1, the parent's project, with criteria", kid)
				}
				if ev := lastEvent(t, conn, kid); ev.From.Valid || ev.To.String != string(sReady) || ev.ActorID != spec.Email {
					t.Fatalf("child creation event %+v", ev)
				}
				if c := eventCount(t, conn, kid); c != 1 {
					t.Fatalf("child %d has %d events, want exactly 1", kid, c)
				}
			}
			if c := eventCount(t, conn, parent); c != 1 {
				t.Fatalf("parent has %d events, want exactly 1", c)
			}
			ev := lastEvent(t, conn, parent)
			if ev.From.String != string(sReady) || ev.To.String != string(sDecomposed) || ev.Actor != "spec" {
				t.Fatalf("parent event %+v", ev)
			}
		})
	}
}

// The split is one transaction: when the parent's own event fails, after every child, its event
// and the parent's update are written, none of them remains.
func TestDecomposeFailureWritesNothing(t *testing.T) {
	conn := fresh(t)
	parent := seed(t, conn, fixture{state: sReady})
	if _, err := conn.Exec(`
		CREATE FUNCTION refuse_split() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'split event refused by test'; END $$;
		CREATE TRIGGER refuse_split BEFORE INSERT ON ticket_events FOR EACH ROW
		  WHEN (NEW.to_state = 'decomposed') EXECUTE FUNCTION refuse_split();`); err != nil {
		t.Fatal(err)
	}
	before, total := snapshot(t, conn, parent), count(t, conn, `SELECT count(*) FROM tickets`)
	if _, err := doDecompose(t, conn, decompose(parent, spec, children(3))); err == nil {
		t.Fatal("the split succeeded although the parent's event could not be written")
	}
	assertUnchanged(t, conn, parent, before, 0, 0)
	if n := count(t, conn, `SELECT count(*) FROM tickets`); n != total {
		t.Fatalf("%d tickets, want %d: children outlived a failed split", n, total)
	}
	if n := count(t, conn, `SELECT count(*) FROM ticket_events`); n != 0 {
		t.Fatalf("%d events after a failed split, want 0", n)
	}
}

func TestDecomposeZeroChildrenIs400(t *testing.T) {
	conn := fresh(t)
	parent := seed(t, conn, fixture{state: sReady})
	before := snapshot(t, conn, parent)
	_, err := doDecompose(t, conn, decompose(parent, spec, nil))
	wantStatus(t, err, 400)
	assertUnchanged(t, conn, parent, before, 0, 0)
}

// Six or more children escalate the parent instead: nothing is created, and the answer is a
// success (200) carrying the escalated ticket, since the escalation is recorded.
func TestDecomposeSixOrMoreEscalates(t *testing.T) {
	conn := fresh(t)
	parent := seed(t, conn, fixture{state: sReady})
	res, err := doDecompose(t, conn, decompose(parent, spec, children(6)))
	if err != nil {
		t.Fatalf("six children: want a recorded escalation, got %v", err)
	}
	if res.State != sEscalated || len(res.Children) != 0 || state(t, conn, parent) != sEscalated {
		t.Fatalf("result %+v: want the parent escalated and no children", res)
	}
	if n := count(t, conn, `SELECT count(*) FROM tickets WHERE parent_ticket_id = $1`, parent); n != 0 {
		t.Fatalf("%d children created by an escalated split", n)
	}
	if n := eventCount(t, conn, parent); n != 1 {
		t.Fatalf("%d events, want exactly 1", n)
	}
	ev := lastEvent(t, conn, parent)
	if ev.Actor != string(callbackapi.RoleCallbackAPI) || ev.ActorID != spec.Email || ev.To.String != string(sEscalated) {
		t.Fatalf("escalation event %+v", ev)
	}
	if k := cols(t, conn, parent); !k.EscalationReason.Valid || !k.EscalatedAt.Valid {
		t.Fatalf("escalated parent without reason: %+v", k)
	}
}

// A child is never decomposed, whatever the count: nothing is written.
func TestDecomposeADepthOneTicketIsRefused(t *testing.T) {
	for _, n := range []int{0, 1, 6} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			conn := fresh(t)
			parent := seed(t, conn, fixture{state: sDecomposed})
			kid := seed(t, conn, fixture{state: sReady, parent: parent})
			before, total := snapshot(t, conn, kid), count(t, conn, `SELECT count(*) FROM tickets`)
			_, err := doDecompose(t, conn, decompose(kid, spec, children(n)))
			want := 409
			if n == 0 {
				want = 400
			}
			wantStatus(t, err, want)
			assertUnchanged(t, conn, kid, before, 0, 0)
			if c := count(t, conn, `SELECT count(*) FROM tickets`); c != total {
				t.Fatalf("%d tickets, want %d: a refused split created something", c, total)
			}
		})
	}
}

// A parent that already has children is not split again (it would loop).
func TestDecomposeAParentWithChildrenIsRefused(t *testing.T) {
	conn := fresh(t)
	parent := seed(t, conn, fixture{state: sReady})
	seed(t, conn, fixture{state: sFailed, parent: parent})
	_, err := doDecompose(t, conn, decompose(parent, spec, children(1)))
	wantStatus(t, err, 409)
}

func TestDecomposeRefusals(t *testing.T) {
	t.Run("not ready", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sDraft})
		_, err := doDecompose(t, conn, decompose(id, spec, children(2)))
		wantStatus(t, err, 409)
	})
	t.Run("a child without criteria", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sReady})
		kids := children(2)
		kids[1].AcceptanceCriteria = nil
		_, err := doDecompose(t, conn, decompose(id, spec, kids))
		wantStatus(t, err, 400)
	})
	t.Run("another project", func(t *testing.T) {
		conn := fresh(t)
		addProject(t, conn, "other")
		id := seed(t, conn, fixture{project: "other", state: sReady})
		_, err := doDecompose(t, conn, decompose(id, spec, children(2)))
		wantStatus(t, err, 403)
	})
	for _, role := range callerRoles {
		if role == callbackapi.RoleSpec {
			continue
		}
		t.Run("role "+string(role), func(t *testing.T) {
			conn := fresh(t)
			id := seed(t, conn, fixture{state: sReady})
			c, _ := callerFor(role)
			_, err := doDecompose(t, conn, decompose(id, c, children(2)))
			wantStatus(t, err, 403)
		})
	}
}

func TestDecomposeIsIdempotent(t *testing.T) {
	conn := fresh(t)
	parent := seed(t, conn, fixture{state: sReady})
	req := decompose(parent, spec, children(2))
	first, err := doDecompose(t, conn, req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := doDecompose(t, conn, req)
	if err != nil || !again.Replayed || len(again.Children) != 2 || again.Children[0] != first.Children[0] {
		t.Fatalf("replay = %+v, %v", again, err)
	}
	if n := count(t, conn, `SELECT count(*) FROM tickets WHERE parent_ticket_id = $1`, parent); n != 2 {
		t.Fatalf("%d children after a replay, want 2", n)
	}
}
