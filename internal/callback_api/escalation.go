package callbackapi

import (
	"context"
	"database/sql"
	"fmt"
)

// The engine's escalating and failing diversions, and the decomposition roll-up
// (docs/state-machine.md: "Retry semantics", "Three returns in a row", "Decomposition"). The risk
// diversion's evaluator is in escalation_evaluator.go.

type diversion struct {
	to     State
	actor  Role
	reason string
}

// capDiversion: a return to ready by a ticket that has used every attempt lands in failed,
// decided by the callback API, whoever asked (a runner, the dispatcher's reap, or a human).
func capDiversion(t ticket, to State) (diversion, bool) {
	if to != StateReady || t.Attempts < AttemptCap {
		return diversion{}, false
	}
	return diversion{
		to:     StateFailed,
		actor:  RoleCallbackAPI,
		reason: fmt.Sprintf("returned to ready after %d of %d attempts: the attempt cap", t.Attempts, AttemptCap),
	}, true
}

// ReturnsBeforeEscalation is how many dispatcher returns in a row escalate a ticket instead of
// returning it (P04 D8, open item 13).
const ReturnsBeforeEscalation = 3

// returnsDiversion: the dispatcher's third return of a ticket in a row, from any leased state, by
// reap or by a failed launch, escalates, decided by the callback API. Without it a runner that
// cannot start (a broken image, a missing secret) is claimed again on every tick, ahead of
// everything behind it. The count comes from the event log: the dispatcher's returns since the
// last transition a runner made on the ticket or its last event by a human. A heartbeat is a
// same-state event, not a transition, so a runner's own heartbeats never reset it. Every event on
// a ticket is written under its row lock, which the caller holds, so the count is stable. It
// returns this return's number in the run. The state lists are IsLeased's.
func returnsDiversion(ctx context.Context, tx *sql.Tx, t ticket) (diversion, int, bool, error) {
	var prior int
	err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM ticket_events e
		WHERE e.ticket_id = $1 AND e.actor = 'dispatcher'
		  AND e.from_state IN ('claimed', 'in_progress', 'in_qa', 'merging')
		  AND e.to_state NOT IN ('claimed', 'in_progress', 'in_qa', 'merging')
		  AND e.id > coalesce((
		    SELECT max(r.id) FROM ticket_events r
		    WHERE r.ticket_id = $1
		      AND (r.actor = 'human'
		        OR (r.actor IN ('spec', 'architect', 'dev', 'qa', 'integrator')
		          AND r.from_state IS DISTINCT FROM r.to_state))), 0)`, t.ID).Scan(&prior)
	if err != nil {
		return diversion{}, 0, false, internal("count the dispatcher's returns", err)
	}
	n := prior + 1
	if n < ReturnsBeforeEscalation {
		return diversion{}, n, false, nil
	}
	return diversion{
		to:    StateEscalated,
		actor: RoleCallbackAPI,
		reason: fmt.Sprintf("returned by the dispatcher %d times in a row with no runner's move between: "+
			"its runner may be unable to start", n),
	}, n, true, nil
}

// rollUp runs when a child's transition has just left it in a terminal state. It locks the parent
// first and only then counts the siblings, in a separate statement: under READ COMMITTED that
// statement sees every sibling's committed state, so two children finishing at once cannot both
// miss the last step (the second waits for the first's parent lock). The lock order is always the
// child, then the parent. If a human has already moved the parent out of decomposed, nothing
// happens and the child's transition still commits.
func (e *Engine) rollUp(ctx context.Context, tx *sql.Tx, parent, child int64, c Caller, childRequestID string) error {
	var s, project string
	err := tx.QueryRowContext(ctx, `SELECT state, project_id FROM tickets WHERE id = $1 FOR UPDATE`, parent).Scan(&s, &project)
	if err != nil {
		return internal("lock parent", err)
	}
	from := State(s)
	if from != StateDecomposed {
		return nil
	}
	var open, total, unfinished int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE state NOT IN ('done', 'failed', 'abandoned')),
		       count(*),
		       count(*) FILTER (WHERE state IN ('failed', 'abandoned'))
		FROM tickets WHERE parent_ticket_id = $1`, parent).Scan(&open, &total, &unfinished); err != nil {
		return internal("count children", err)
	}
	if open > 0 {
		return nil
	}

	to, reason := StateDone, fmt.Sprintf("all %d children are done", total)
	u := newUpdate(parent)
	u.set("state = %s", string(StateDone))
	if unfinished > 0 {
		to = StateEscalated
		reason = fmt.Sprintf("%d of %d children failed or were abandoned: a human decides whether partial completion is acceptable", unfinished, total)
		u = newUpdate(parent)
		u.set("state = %s", string(StateEscalated))
		u.setExpr("escalated_at = now()")
		u.set("escalation_reason = %s", reason)
	}
	if _, err := u.exec(ctx, tx); err != nil {
		return err
	}
	if _, err := insertEvent(ctx, tx, event{
		ticket: parent, from: &from, to: to, actor: RoleCallbackAPI, actorID: c.Email,
		payload: map[string]any{"reason": reason, "child_ticket_id": child, "child_request_id": childRequestID},
	}); err != nil {
		return err
	}
	e.log.Info("ticket roll-up", "ticket", parent, "project", project, "from", from, "to", to,
		"actor", RoleCallbackAPI, "actor_id", c.Email, "child", child)
	return nil
}
