package callbackapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// The claim token fences runners (P02 D15). Runners of one role share a service account, so the
// account cannot tell a live runner from one that was reaped and replaced: every claim sets a
// fresh random token, every runner call about a leased ticket must present it, and every reap and
// every move out of the leased set clears it. It is a fence, not a credential.

func newClaimToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// fence refuses a runner acting on a leased ticket without the current token. A NULL token on a
// leased ticket refuses every runner, so a missing header never matches a missing token.
func fence(t ticket, c Caller, presented string) error {
	if !c.Role.IsRunner() || !IsLeased(t.State) {
		return nil
	}
	if !t.ClaimToken.Valid || presented == "" ||
		subtle.ConstantTimeCompare([]byte(t.ClaimToken.String), []byte(presented)) != 1 {
		return refuse(409, "ticket %d is leased to another runner, or the lease has ended", t.ID)
	}
	return nil
}

// leaseLive refuses a runner whose lease has expired (P04 D14): once expired, a lease is final,
// and only the dispatcher's reap may act on the ticket. Every runner call about a leased ticket
// makes this check after the ticket's row lock is held, in a statement of its own, against the
// clock when it runs: the transaction's now() is its start, and a clock read inside the locking
// statement is read before any wait for the lock. So at most one of a reap and a late runner acts.
func leaseLive(ctx context.Context, tx *sql.Tx, t ticket, c Caller) error {
	if !c.Role.IsRunner() || !IsLeased(t.State) {
		return nil
	}
	var live bool
	if err := tx.QueryRowContext(ctx,
		`SELECT coalesce(lease_expires_at > clock_timestamp(), false) FROM tickets WHERE id = $1`, t.ID).Scan(&live); err != nil {
		return internal("read the lease", err)
	}
	if !live {
		return refuse(409, "ticket %d: the lease has expired", t.ID)
	}
	return nil
}

// checkReturn holds the dispatcher's return from a leased state to its kind (P04 D9). A reap only
// once the lease has expired, re-checked under the row lock, so a runner that heartbeated in time
// is never clobbered. A failed launch only from a claimed state (never in_progress, where a runner
// is working), with the token the claim issued, and only while that claim is the ticket's latest
// event: a heartbeat or a runner's move since means the run did start.
func checkReturn(ctx context.Context, tx *sql.Tx, t ticket, req TransitionRequest) error {
	switch req.Return {
	case ReturnLeaseExpired:
		var expired bool
		if err := tx.QueryRowContext(ctx,
			`SELECT lease_expires_at IS NULL OR lease_expires_at <= now() FROM tickets WHERE id = $1`, t.ID).Scan(&expired); err != nil {
			return internal("read the lease", err)
		}
		if !expired {
			return refuse(409, "ticket %d's lease has not expired", t.ID)
		}
	case ReturnLaunchFailed:
		if t.State == StateInProgress {
			return refuse(409, "ticket %d is in_progress: its runner started, so it is reaped, not returned", t.ID)
		}
		if !t.ClaimToken.Valid || req.ClaimToken == "" ||
			subtle.ConstantTimeCompare([]byte(t.ClaimToken.String), []byte(req.ClaimToken)) != 1 {
			return refuse(409, "ticket %d: a failed launch's return needs the token its claim issued", t.ID)
		}
		var actor, to string
		var from sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT actor, from_state, to_state FROM ticket_events WHERE ticket_id = $1 ORDER BY id DESC LIMIT 1`, t.ID).
			Scan(&actor, &from, &to)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return internal("read the latest event", err)
		}
		claimLatest := err == nil && actor == string(RoleDispatcher) && State(to) == t.State &&
			from.Valid && !IsLeased(State(from.String))
		if !claimLatest {
			return refuse(409, "ticket %d has moved since its claim: the run started, so it is reaped, not returned", t.ID)
		}
	}
	return nil
}

// endAttempt ends the attempt of the lease whose token a transition clears (P04; red team 2, R4):
// ended_at and the outcome, each only where not yet set, so a rate limit the runner reported is
// kept. A ticket claimed before migration 00005 has no such row, and nothing happens.
func endAttempt(ctx context.Context, tx *sql.Tx, token, outcome string) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE attempts SET ended_at = coalesce(ended_at, now()), outcome = coalesce(outcome, $2)
		WHERE claim_token = $1`, token, outcome); err != nil {
		return internal("end the attempt", err)
	}
	return nil
}

// attemptOutcome is how the move that ends a lease ends its attempt, by who asked: the runner's
// own move completed the work (the dev's submission, any verdict QA asked for, even one the risk
// evaluator diverts, the integrator's merge) or failed it; the dispatcher reaped it or its launch
// failed; a human abandoned it.
func attemptOutcome(req TransitionRequest) string {
	switch {
	case req.Caller.Role == RoleDispatcher && req.Return == ReturnLaunchFailed:
		return "launch_failed"
	case req.Caller.Role == RoleDispatcher:
		return "reaped"
	case req.Caller.Role == RoleHuman:
		return "abandoned"
	case (req.From == StateInProgress && req.To == StateAwaitingReview) || req.From == StateInQA || req.To == StateMerged:
		return "completed"
	}
	return "failed"
}

// HeartbeatRequest extends the lease on a ticket the caller's runner is working.
type HeartbeatRequest struct {
	TicketID     int64
	Caller       Caller
	RequestID    string // the Idempotency-Key: a UUID
	ClaimToken   string
	Method, Path string
}

// HeartbeatResult is what a heartbeat did; also its recorded response.
type HeartbeatResult struct {
	TicketID       int64     `json:"ticket_id"`
	State          State     `json:"state"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	EventID        int64     `json:"event_id"`
	Replayed       bool      `json:"-"`
}

// Heartbeat extends the lease to five minutes from the database's clock when it runs, only for the
// role that owns the ticket's current leased state, in its own project, with the claim token, and
// never once the lease has expired (P04 D14). It is a ticket change, so it writes a same-state
// event (D22) and goes through the request log. Same order as Transition: authorization without
// state (403), request log, lock, then state (409).
func (e *Engine) Heartbeat(ctx context.Context, tx *sql.Tx, req HeartbeatRequest) (HeartbeatResult, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return HeartbeatResult{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return HeartbeatResult{}, err
	}
	if req.TicketID <= 0 || !validRequestID(req.RequestID) {
		return HeartbeatResult{}, refuse(400, "a ticket id and a UUID idempotency key are required")
	}
	switch req.Caller.Role {
	case RoleDev, RoleQA, RoleIntegrator:
	default:
		return HeartbeatResult{}, refuse(403, "%s never holds a lease", req.Caller.Role)
	}
	if err := checkProject(ctx, tx, req.TicketID, req.Caller.Project); err != nil {
		return HeartbeatResult{}, err
	}

	hash := requestHash(map[string]any{"method": req.Method, "path": req.Path, "ticket": req.TicketID,
		"heartbeat": true, "claim_token": req.ClaimToken})
	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, hash)
	if err != nil {
		return HeartbeatResult{}, err
	}
	if replay != nil {
		var res HeartbeatResult
		if err := json.Unmarshal(replay, &res); err != nil {
			return HeartbeatResult{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	t, err := lockTicket(ctx, tx, req.TicketID)
	if err != nil {
		return HeartbeatResult{}, err
	}
	if !IsLeased(t.State) || leaseOwner(t.State) != req.Caller.Role {
		return HeartbeatResult{}, refuse(409, "ticket %d is %s: no lease of a %s runner to extend", t.ID, t.State, req.Caller.Role)
	}
	if err := fence(t, req.Caller, req.ClaimToken); err != nil {
		return HeartbeatResult{}, err
	}
	if err := leaseLive(ctx, tx, t, req.Caller); err != nil {
		return HeartbeatResult{}, err
	}

	var expires time.Time
	if err := tx.QueryRowContext(ctx, `
		UPDATE tickets SET lease_expires_at = clock_timestamp() + interval '5 minutes', updated_at = now()
		WHERE id = $1 RETURNING lease_expires_at`, t.ID).Scan(&expires); err != nil {
		return HeartbeatResult{}, internal("extend lease", err)
	}
	eventID, err := insertEvent(ctx, tx, event{
		ticket: t.ID, from: &t.State, to: t.State, actor: req.Caller.Role, actorID: req.Caller.Email,
		requestID: req.RequestID,
		payload:   map[string]any{"heartbeat": true, "lease_expires_at": expires.UTC().Format(time.RFC3339Nano)},
	})
	if err != nil {
		return HeartbeatResult{}, err
	}
	res := HeartbeatResult{TicketID: t.ID, State: t.State, LeaseExpiresAt: expires, EventID: eventID}
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 200, res); err != nil {
		return HeartbeatResult{}, err
	}
	return res, nil
}
