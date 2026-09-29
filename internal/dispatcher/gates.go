package dispatcher

import (
	"context"
	"database/sql"
	"errors"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// The gates (P04 Approach 4), each read inside the pick's transaction with the project's row
// locked. Locks are taken in one order: the project, then tickets (the shared locks on leased
// tickets, then the candidate), then a provider's budget row.

type project struct {
	id, repoURL, branch string
}

// lockProject locks the active project's row, so two ticks serialise on it (D7). FOR NO KEY
// UPDATE does not conflict with the key-share lock a new ticket's insert takes on its project.
func lockProject(ctx context.Context, tx *sql.Tx) (project, bool, error) {
	var p project
	err := tx.QueryRowContext(ctx, `
		SELECT id, repo_url, default_branch FROM projects WHERE is_active FOR NO KEY UPDATE`).Scan(&p.id, &p.repoURL, &p.branch)
	if errors.Is(err, sql.ErrNoRows) {
		return p, false, nil
	}
	return p, err == nil, err
}

// liveLeases reports, per role, whether the role holds a lease in the project: a ticket in one of
// its leased states whose lease has not expired. The tick takes a shared lock on each such ticket
// it can (SKIP LOCKED); one it cannot lock is held by a runner's request in flight and counts as
// live, so the gate never waits on a runner and never misses one (D14; red team 3, R3). New leased
// tickets appear only through claims, which serialise on the project's row, so the set can only
// shrink while the tick holds it.
func liveLeases(ctx context.Context, tx *sql.Tx, projectID string) (map[callbackapi.Role]bool, error) {
	states := map[int64]callbackapi.State{}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, state FROM tickets
		WHERE project_id = $1 AND state IN ('claimed', 'in_progress', 'in_qa', 'merging')`, projectID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var s string
		if err := rows.Scan(&id, &s); err != nil {
			rows.Close()
			return nil, err
		}
		states[id] = callbackapi.State(s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	live := map[callbackapi.Role]bool{}
	locked := map[int64]bool{}
	rows, err = tx.QueryContext(ctx, `
		SELECT id, state, lease_expires_at > now() FROM tickets
		WHERE project_id = $1 AND state IN ('claimed', 'in_progress', 'in_qa', 'merging')
		FOR SHARE SKIP LOCKED`, projectID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var s string
		var unexpired bool
		if err := rows.Scan(&id, &s, &unexpired); err != nil {
			rows.Close()
			return nil, err
		}
		locked[id] = true
		if unexpired {
			live[roleOf(callbackapi.State(s))] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for id, s := range states {
		if !locked[id] {
			live[roleOf(s)] = true
		}
	}
	return live, nil
}

// roleOf is the role whose runner holds a leased state.
func roleOf(s callbackapi.State) callbackapi.Role {
	switch s {
	case callbackapi.StateClaimed, callbackapi.StateInProgress:
		return callbackapi.RoleDev
	case callbackapi.StateInQA:
		return callbackapi.RoleQA
	}
	return callbackapi.RoleIntegrator
}

// escalationBlocks reports whether an escalation in the project stops new work: one unparked, or
// parked with a parked_until that has passed, read here and never written back (D6; open item 11).
func escalationBlocks(ctx context.Context, tx *sql.Tx, projectID string) (bool, error) {
	var blocked bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM tickets WHERE project_id = $1 AND state = 'escalated'
		  AND (parked = false OR parked_until <= now()))`, projectID).Scan(&blocked)
	return blocked, err
}

// readBudgets reads every provider's budget without a lock, to choose candidates: a provider is
// usable when it is not paused and has a unit above its reserve, or its window's reset has passed.
// The chosen provider's row is locked and checked again before any charge (D16).
func readBudgets(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT provider,
		  (paused_until IS NULL OR paused_until <= now())
		  AND (window_resets_at <= now() OR consumed_estimate + 1 <= window_capacity * (1 - reserve_fraction))
		FROM budget`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	usable := map[string]bool{}
	for rows.Next() {
		var p string
		var ok bool
		if err := rows.Scan(&p, &ok); err != nil {
			return nil, err
		}
		usable[p] = ok
	}
	return usable, rows.Err()
}

// lockBudget locks a provider's budget row, rolls its window over if the reset has passed (a new
// window of the same length, starting now, consumed zero), and reports whether it still has a
// unit to charge: a rate-limit report may have paused it since the unlocked read.
func lockBudget(ctx context.Context, tx *sql.Tx, provider string) (bool, error) {
	var resetPassed bool
	if err := tx.QueryRowContext(ctx, `
		SELECT window_resets_at <= now() FROM budget WHERE provider = $1 FOR UPDATE`, provider).Scan(&resetPassed); err != nil {
		return false, err
	}
	if resetPassed {
		if _, err := tx.ExecContext(ctx, `
			UPDATE budget SET window_resets_at = now() + (window_resets_at - window_started_at),
			  window_started_at = now(), consumed_estimate = 0, updated_at = now()
			WHERE provider = $1`, provider); err != nil {
			return false, err
		}
	}
	var usable bool
	err := tx.QueryRowContext(ctx, `
		SELECT (paused_until IS NULL OR paused_until <= now())
		  AND consumed_estimate + 1 <= window_capacity * (1 - reserve_fraction)
		FROM budget WHERE provider = $1`, provider).Scan(&usable)
	return usable, err
}
