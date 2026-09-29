package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// The rate-limit report (P04 Approach 7, D5): a runner holding a lease says its provider limited
// it, and the callback API pauses that provider (the one in the attempts row written for the
// caller's lease, never one the request names) until the reset time, clamped to 24 hours ahead. A
// paused provider stops its own tiers in the dispatcher and nothing else, and the pause ends by
// itself. It changes no ticket, so it writes no ticket event; the request log records it. What the
// runner then does with its ticket is P07's.

// RateLimitRequest reports a rate limit on the caller's lease.
type RateLimitRequest struct {
	TicketID     int64
	Caller       Caller
	RequestID    string // the Idempotency-Key: a UUID
	ClaimToken   string
	ResetAt      time.Time // when the provider says the limit resets; must be in the future
	Method, Path string
}

// RateLimitResult is what a report did; also its recorded response.
type RateLimitResult struct {
	TicketID    int64     `json:"ticket_id"`
	Provider    string    `json:"provider"`
	PausedUntil time.Time `json:"paused_until"`
	Replayed    bool      `json:"-"`
}

// RateLimit pauses the provider of the caller's own attempt. Same order as Transition: validation
// (400), a lease-holding role in its own project (403), the request log, the lock, the lease owner,
// the fence and the lease's expiry (409), the attempt's provider (409 when there is none: the
// integrator), the reset time against the database's clock (400).
func (e *Engine) RateLimit(ctx context.Context, tx *sql.Tx, req RateLimitRequest) (RateLimitResult, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return RateLimitResult{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return RateLimitResult{}, err
	}
	if req.TicketID <= 0 || !validRequestID(req.RequestID) {
		return RateLimitResult{}, refuse(400, "a ticket id and a UUID idempotency key are required")
	}
	if req.ResetAt.IsZero() {
		return RateLimitResult{}, refuse(400, "reset_at, when the provider's limit resets, is required")
	}
	switch req.Caller.Role {
	case RoleDev, RoleQA, RoleIntegrator:
	default:
		return RateLimitResult{}, refuse(403, "%s never holds a lease, so it reports no rate limit", req.Caller.Role)
	}
	if err := checkProject(ctx, tx, req.TicketID, req.Caller.Project); err != nil {
		return RateLimitResult{}, err
	}

	hash := requestHash(map[string]any{"method": req.Method, "path": req.Path, "ticket": req.TicketID,
		"rate_limit": true, "claim_token": req.ClaimToken, "reset_at": req.ResetAt.UTC().Format(time.RFC3339Nano)})
	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, hash)
	if err != nil {
		return RateLimitResult{}, err
	}
	if replay != nil {
		var res RateLimitResult
		if err := json.Unmarshal(replay, &res); err != nil {
			return RateLimitResult{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	t, err := lockTicket(ctx, tx, req.TicketID)
	if err != nil {
		return RateLimitResult{}, err
	}
	if !IsLeased(t.State) || leaseOwner(t.State) != req.Caller.Role {
		return RateLimitResult{}, refuse(409, "ticket %d is %s: no lease of a %s runner", t.ID, t.State, req.Caller.Role)
	}
	if err := fence(t, req.Caller, req.ClaimToken); err != nil {
		return RateLimitResult{}, err
	}
	if err := leaseLive(ctx, tx, t, req.Caller); err != nil {
		return RateLimitResult{}, err
	}
	var provider sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT provider FROM attempts WHERE claim_token = $1`, t.ClaimToken.String).Scan(&provider)
	if errors.Is(err, sql.ErrNoRows) {
		return RateLimitResult{}, refuse(409, "ticket %d: no attempt is recorded for this lease", t.ID)
	}
	if err != nil {
		return RateLimitResult{}, internal("read the attempt", err)
	}
	if !provider.Valid {
		return RateLimitResult{}, refuse(409, "ticket %d: the integrator uses no provider to pause", t.ID)
	}
	var future bool
	if err := tx.QueryRowContext(ctx, `SELECT $1::timestamptz > now()`, req.ResetAt).Scan(&future); err != nil {
		return RateLimitResult{}, internal("compare the reset time", err)
	}
	if !future {
		return RateLimitResult{}, refuse(400, "reset_at must be in the future")
	}

	// The later of the pause already there and this one, never more than 24 hours ahead.
	var until time.Time
	if err := tx.QueryRowContext(ctx, `
		UPDATE budget SET paused_until = greatest(coalesce(paused_until, '-infinity'), least($2::timestamptz, now() + interval '24 hours')),
		  updated_at = now()
		WHERE provider = $1 RETURNING paused_until`, provider.String, req.ResetAt).Scan(&until); err != nil {
		return RateLimitResult{}, internal("pause the provider", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE attempts SET outcome = coalesce(outcome, 'rate_limited') WHERE claim_token = $1`, t.ClaimToken.String); err != nil {
		return RateLimitResult{}, internal("record the rate limit on the attempt", err)
	}
	e.log.Info("provider paused", "provider", provider.String, "until", until, "ticket", t.ID, "project", t.Project,
		"actor_id", req.Caller.Email)
	res := RateLimitResult{TicketID: t.ID, Provider: provider.String, PausedUntil: until}
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 200, res); err != nil {
		return RateLimitResult{}, err
	}
	return res, nil
}
