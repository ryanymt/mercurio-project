package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Parking (docs/state-machine.md, "Parking"; P02 D21). Only a human parks, only an escalated
// ticket, and the human's own move out of escalated clears the flag (transitions_engine.go), so a
// flag never outlives the escalation it was set for. Nothing clears it automatically.

// ParkingRequest sets or clears parking on an escalated ticket.
type ParkingRequest struct {
	TicketID     int64
	Caller       Caller
	Parked       bool
	Reason       string     // required when parking
	Until        *time.Time // optional; must be in the future by the database's clock
	EscalatedAt  *time.Time // required: the escalation the page showed (P06 D19)
	RequestID    string
	Method, Path string
}

// ParkingResult is what a parking change did; also its recorded response.
type ParkingResult struct {
	TicketID int64 `json:"ticket_id"`
	Parked   bool  `json:"parked"`
	EventID  int64 `json:"event_id"`
	Replayed bool  `json:"-"`
}

// Park sets or clears `parked`, `parked_reason` and `parked_until`, with a same-state event.
func (e *Engine) Park(ctx context.Context, tx *sql.Tx, req ParkingRequest) (ParkingResult, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return ParkingResult{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return ParkingResult{}, err
	}
	if req.TicketID <= 0 || !validRequestID(req.RequestID) {
		return ParkingResult{}, refuse(400, "a ticket id and a UUID idempotency key are required")
	}
	if req.Parked && strings.TrimSpace(req.Reason) == "" {
		return ParkingResult{}, refuse(400, "parking needs a reason")
	}
	if !req.Parked && (req.Reason != "" || req.Until != nil) {
		return ParkingResult{}, refuse(400, "unparking takes no reason or date")
	}
	if req.EscalatedAt == nil {
		return ParkingResult{}, refuse(400, "parking names the escalation it decides: escalated_at")
	}
	if req.Caller.Role != RoleHuman {
		return ParkingResult{}, refuse(403, "only a human may park or unpark a ticket")
	}

	var until any
	if req.Until != nil {
		until = req.Until.UTC()
	}
	hash := requestHash(map[string]any{"method": req.Method, "path": req.Path, "ticket": req.TicketID,
		"parked": req.Parked, "reason": req.Reason, "until": until, "escalated_at": escalationKey(req.EscalatedAt)})
	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, hash)
	if err != nil {
		return ParkingResult{}, err
	}
	if replay != nil {
		var res ParkingResult
		if err := json.Unmarshal(replay, &res); err != nil {
			return ParkingResult{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	t, err := lockTicket(ctx, tx, req.TicketID)
	if err != nil {
		return ParkingResult{}, err
	}
	if t.State != StateEscalated {
		return ParkingResult{}, refuse(409, "ticket %d is %s: only an escalated ticket is parked", t.ID, t.State)
	}
	if err := sameEscalation(t, *req.EscalatedAt); err != nil {
		return ParkingResult{}, err
	}
	var reason any
	if req.Parked {
		reason = req.Reason
	}
	// The future check is part of the statement, in the database's time (a CHECK constraint
	// cannot use now()).
	var id int64
	err = tx.QueryRowContext(ctx, `
		UPDATE tickets SET parked = $2, parked_reason = $3, parked_until = $4, updated_at = now()
		WHERE id = $1 AND ($4::timestamptz IS NULL OR $4::timestamptz > now())
		RETURNING id`, t.ID, req.Parked, reason, until).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ParkingResult{}, refuse(400, "parked_until must be in the future")
	}
	if err != nil {
		return ParkingResult{}, internal("park ticket", err)
	}
	payload := map[string]any{"parked": req.Parked, "bound_to": map[string]any{"escalated_at": escalationKey(req.EscalatedAt)}}
	if req.Parked {
		payload["reason"] = req.Reason
		if req.Until != nil {
			payload["parked_until"] = req.Until.UTC().Format(time.RFC3339)
		}
	}
	eventID, err := insertEvent(ctx, tx, event{
		ticket: t.ID, from: &t.State, to: t.State, actor: RoleHuman, actorID: req.Caller.Email,
		requestID: req.RequestID, payload: payload,
	})
	if err != nil {
		return ParkingResult{}, err
	}
	e.log.Info("ticket parking", "ticket", t.ID, "project", t.Project, "parked", req.Parked, "actor_id", req.Caller.Email)
	res := ParkingResult{TicketID: t.ID, Parked: req.Parked, EventID: eventID}
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 200, res); err != nil {
		return ParkingResult{}, err
	}
	return res, nil
}
