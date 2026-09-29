package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"strings"
)

// CreateRequest creates a ticket. Its fields are the allowlist: no parent, depth, state, attempt
// count, parking or lease field can be named, so no child exists outside /decompose.
type CreateRequest struct {
	Caller             Caller
	Project            string // a human names it; a spec runner's is its own
	Title, Body        string
	Priority           int
	AcceptanceCriteria []Criterion // given: the ticket starts ready; else draft
	RequestID          string
	Method, Path       string
}

// CreateResult is what a creation did; also its recorded response.
type CreateResult struct {
	TicketID int64  `json:"ticket_id"`
	Project  string `json:"project"`
	State    State  `json:"state"`
	EventID  int64  `json:"event_id"`
	Replayed bool   `json:"-"`
}

// validateCriteria checks a non-empty list of acceptance criteria.
func validateCriteria(ac []Criterion) error {
	if len(ac) == 0 {
		return refuse(400, "acceptance criteria are required")
	}
	for _, c := range ac {
		if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Text) == "" {
			return refuse(400, "every acceptance criterion needs an id and a text")
		}
	}
	return nil
}

func validPriority(p int) bool { return p >= math.MinInt16 && p <= math.MaxInt16 }

// Create makes a top-level ticket, in `draft`, or `ready` when acceptance criteria are given,
// with a creation event. A human creates in the project it names (the Anchor's "project comes
// from the mapping" is about the caller's authority; the new ticket's project is data); a spec
// runner only in its own.
func (e *Engine) Create(ctx context.Context, tx *sql.Tx, req CreateRequest) (CreateResult, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return CreateResult{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return CreateResult{}, err
	}
	if !validRequestID(req.RequestID) {
		return CreateResult{}, refuse(400, "the idempotency key must be a UUID")
	}
	if strings.TrimSpace(req.Title) == "" {
		return CreateResult{}, refuse(400, "a title is required")
	}
	if !validPriority(req.Priority) {
		return CreateResult{}, refuse(400, "priority out of range")
	}
	if len(req.AcceptanceCriteria) > 0 {
		if err := validateCriteria(req.AcceptanceCriteria); err != nil {
			return CreateResult{}, err
		}
	}
	project := req.Project
	switch req.Caller.Role {
	case RoleHuman:
		if project == "" {
			return CreateResult{}, refuse(400, "name the project the ticket belongs to")
		}
	case RoleSpec:
		if project == "" {
			project = req.Caller.Project
		}
		if project != req.Caller.Project {
			return CreateResult{}, refuse(403, "a spec runner creates tickets only in its own project")
		}
	default:
		return CreateResult{}, refuse(403, "%s may not create tickets", req.Caller.Role)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1)`, project).Scan(&exists); err != nil {
		return CreateResult{}, internal("look up project", err)
	}
	if !exists {
		return CreateResult{}, refuse(404, "project %s not found", project)
	}

	hash := requestHash(map[string]any{"method": req.Method, "path": req.Path, "project": project,
		"title": req.Title, "body": req.Body, "priority": req.Priority, "acceptance_criteria": req.AcceptanceCriteria})
	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, hash)
	if err != nil {
		return CreateResult{}, err
	}
	if replay != nil {
		var res CreateResult
		if err := json.Unmarshal(replay, &res); err != nil {
			return CreateResult{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	st := StateDraft
	var ac any
	if len(req.AcceptanceCriteria) > 0 {
		st = StateReady
		b, _ := json.Marshal(req.AcceptanceCriteria)
		ac = string(b)
	}
	id, err := insertTicket(ctx, tx, newTicket{
		project: project, title: req.Title, body: req.Body, priority: req.Priority, state: st, ac: ac,
	})
	if err != nil {
		return CreateResult{}, err
	}
	eventID, err := insertEvent(ctx, tx, event{
		ticket: id, to: st, actor: req.Caller.Role, actorID: req.Caller.Email, requestID: req.RequestID,
		payload: map[string]any{"created": true},
	})
	if err != nil {
		return CreateResult{}, err
	}
	e.log.Info("ticket created", "ticket", id, "project", project, "to", st,
		"actor", req.Caller.Role, "actor_id", req.Caller.Email)
	res := CreateResult{TicketID: id, Project: project, State: st, EventID: eventID}
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 201, res); err != nil {
		return CreateResult{}, err
	}
	return res, nil
}

type newTicket struct {
	project, title, body string
	priority             int
	state                State
	ac                   any // JSON text, or nil
	parent               int64
}

func insertTicket(ctx context.Context, tx *sql.Tx, t newTicket) (int64, error) {
	var parent sql.NullInt64
	depth := 0
	if t.parent != 0 {
		parent, depth = sql.NullInt64{Int64: t.parent, Valid: true}, 1
	}
	var body sql.NullString
	if t.body != "" {
		body = sql.NullString{String: t.body, Valid: true}
	}
	var id int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO tickets (project_id, title, body, priority, state, acceptance_criteria, parent_ticket_id, depth)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8) RETURNING id`,
		t.project, t.title, body, t.priority, string(t.state), t.ac, parent, depth).Scan(&id)
	if err != nil {
		return 0, internal("insert ticket", err)
	}
	return id, nil
}
