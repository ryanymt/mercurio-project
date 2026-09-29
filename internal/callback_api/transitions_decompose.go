package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// MaxChildren is the most children a decomposition proceeds with; more escalate to a human.
const MaxChildren = 5

// ChildSpec is one child of a decomposition. Every child needs its own acceptance criteria.
type ChildSpec struct {
	Title              string      `json:"title"`
	Body               string      `json:"body,omitempty"`
	Priority           int         `json:"priority,omitempty"`
	AcceptanceCriteria []Criterion `json:"acceptance_criteria"`
}

// DecomposeRequest splits a ready, top-level ticket into children.
type DecomposeRequest struct {
	TicketID     int64
	Caller       Caller
	Children     []ChildSpec
	RequestID    string
	Method, Path string
}

// DecomposeResult is what a decomposition did; also its recorded response.
type DecomposeResult struct {
	TicketID int64   `json:"ticket_id"`
	State    State   `json:"state"` // decomposed, or escalated for six or more children
	Children []int64 `json:"children"`
	EventID  int64   `json:"event_id"`
	Replayed bool    `json:"-"`
}

// Decompose is the only way to `ready -> decomposed` (the row's channel is `decompose`). In one
// transaction, a spec runner's `ready`, top-level ticket in its own project, with no children yet,
// gets 1 to 5 `ready` depth-1 children (each with a creation event) and moves to decomposed. Zero
// children is 400; six or more move the parent `ready -> escalated` (the callback API's own row)
// and create nothing. A child, or a parent that already has children, is refused with 409 whatever
// the count, before the count is looked at.
func (e *Engine) Decompose(ctx context.Context, tx *sql.Tx, req DecomposeRequest) (DecomposeResult, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return DecomposeResult{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return DecomposeResult{}, err
	}
	if req.TicketID <= 0 || !validRequestID(req.RequestID) {
		return DecomposeResult{}, refuse(400, "a ticket id and a UUID idempotency key are required")
	}
	if len(req.Children) == 0 {
		return DecomposeResult{}, refuse(400, "a decomposition needs at least one child")
	}
	for i, c := range req.Children {
		if strings.TrimSpace(c.Title) == "" || !validPriority(c.Priority) {
			return DecomposeResult{}, refuse(400, "child %d needs a title and a priority in range", i+1)
		}
		if err := validateCriteria(c.AcceptanceCriteria); err != nil {
			return DecomposeResult{}, refuse(400, "child %d: a split without its own acceptance criteria is arbitrary", i+1)
		}
	}
	row, ok := lookup(StateReady, StateDecomposed, req.Caller.Role)
	if !ok || row.Channel != ChannelDecompose {
		return DecomposeResult{}, refuse(403, "%s may not decompose tickets", req.Caller.Role)
	}
	if err := checkProject(ctx, tx, req.TicketID, req.Caller.Project); err != nil {
		return DecomposeResult{}, err
	}

	hash := requestHash(map[string]any{"method": req.Method, "path": req.Path, "ticket": req.TicketID,
		"children": req.Children})
	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, hash)
	if err != nil {
		return DecomposeResult{}, err
	}
	if replay != nil {
		var res DecomposeResult
		if err := json.Unmarshal(replay, &res); err != nil {
			return DecomposeResult{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	t, err := lockTicket(ctx, tx, req.TicketID)
	if err != nil {
		return DecomposeResult{}, err
	}
	switch {
	case t.Parent.Valid:
		return DecomposeResult{}, refuse(409, "ticket %d is a child: depth is capped at 1", t.ID)
	case t.State != StateReady:
		return DecomposeResult{}, refuse(409, "ticket %d is %s, not ready", t.ID, t.State)
	case t.HasChildren:
		return DecomposeResult{}, refuse(409, "ticket %d already has children", t.ID)
	}

	from := StateReady
	var res DecomposeResult
	if len(req.Children) > MaxChildren {
		reason := fmt.Sprintf("a split into %d children needs a human (more than %d)", len(req.Children), MaxChildren)
		u := newUpdate(t.ID)
		u.set("state = %s", string(StateEscalated))
		u.setExpr("escalated_at = now()")
		u.set("escalation_reason = %s", reason)
		if _, err := u.exec(ctx, tx); err != nil {
			return DecomposeResult{}, err
		}
		eventID, err := insertEvent(ctx, tx, event{
			ticket: t.ID, from: &from, to: StateEscalated, actor: RoleCallbackAPI, actorID: req.Caller.Email,
			requestID: req.RequestID,
			payload:   map[string]any{"requested_to": string(StateDecomposed), "reason": reason, "children": len(req.Children)},
		})
		if err != nil {
			return DecomposeResult{}, err
		}
		res = DecomposeResult{TicketID: t.ID, State: StateEscalated, Children: []int64{}, EventID: eventID}
	} else {
		var kids []int64
		for _, c := range req.Children {
			ac, _ := json.Marshal(c.AcceptanceCriteria)
			id, err := insertTicket(ctx, tx, newTicket{
				project: t.Project, title: c.Title, body: c.Body, priority: c.Priority,
				state: StateReady, ac: string(ac), parent: t.ID,
			})
			if err != nil {
				return DecomposeResult{}, err
			}
			if _, err := insertEvent(ctx, tx, event{
				ticket: id, to: StateReady, actor: req.Caller.Role, actorID: req.Caller.Email,
				requestID: req.RequestID, payload: map[string]any{"created": true, "parent_ticket_id": t.ID},
			}); err != nil {
				return DecomposeResult{}, err
			}
			kids = append(kids, id)
		}
		u := newUpdate(t.ID)
		u.set("state = %s", string(StateDecomposed))
		if _, err := u.exec(ctx, tx); err != nil {
			return DecomposeResult{}, err
		}
		eventID, err := insertEvent(ctx, tx, event{
			ticket: t.ID, from: &from, to: StateDecomposed, actor: req.Caller.Role, actorID: req.Caller.Email,
			requestID: req.RequestID, payload: map[string]any{"children": kids},
		})
		if err != nil {
			return DecomposeResult{}, err
		}
		res = DecomposeResult{TicketID: t.ID, State: StateDecomposed, Children: kids, EventID: eventID}
	}
	e.log.Info("ticket decomposition", "ticket", t.ID, "project", t.Project, "from", from, "to", res.State,
		"children", len(res.Children), "actor_id", req.Caller.Email)
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 200, res); err != nil {
		return DecomposeResult{}, err
	}
	return res, nil
}
