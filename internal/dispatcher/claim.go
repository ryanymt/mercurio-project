package dispatcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// The pick and the claim (P04 Approach 2, steps 3 to 6; D15, D16).

// queue is one of the three queues, in the order the tick tries them.
type queue struct {
	role     callbackapi.Role
	from, to callbackapi.State
}

var queues = []queue{
	{callbackapi.RoleIntegrator, callbackapi.StateApproved, callbackapi.StateMerging},
	{callbackapi.RoleQA, callbackapi.StateAwaitingReview, callbackapi.StateInQA},
	{callbackapi.RoleDev, callbackapi.StateReady, callbackapi.StateClaimed},
}

// head is the default branch's head read for new work, and the project it was read for.
type head struct {
	project project
	sha     string
}

// claim is a committed claim, what the launch needs.
type claim struct {
	ticket                   int64
	role                     callbackapi.Role
	from, to                 callbackapi.State
	project, repoURL         string
	branch, baseSHA, headSHA string
	title                    string
	token                    string
	attempt                  int
	tier                     *Tier // nil for the integrator
}

func (c *claim) tierName() string {
	if c.tier == nil {
		return ""
	}
	return c.tier.Name
}

func (c *claim) request() (LaunchRequest, error) {
	sa, err := ServiceAccount(c.role, c.project)
	if err != nil {
		return LaunchRequest{}, err
	}
	r := LaunchRequest{TicketID: c.ticket, Project: c.project, RepoURL: c.repoURL, Role: c.role, ServiceAccount: sa,
		Branch: c.branch, BaseSHA: c.baseSHA, HeadSHA: c.headSHA, ClaimToken: c.token, Attempt: c.attempt,
		Title: boundTitle(c.title)}
	if c.tier != nil {
		r.Provider, r.Model, r.Tier, r.Credential = c.tier.Provider, c.tier.Model, c.tier.Name, c.tier.Credential
	}
	return r, nil
}

// pick claims at most one ticket. Transaction 1 tries integration and QA; if neither claims and new
// work has a candidate, it rolls back, releasing every lock, the default branch's head is read with
// no lock held, and transaction 2 runs the whole pick again, in order, with the head in hand (D15).
func (d *Dispatcher) pick(ctx context.Context) (*claim, string, error) {
	c, next, note, err := d.pickOnce(ctx, nil)
	if err != nil || c != nil || next == nil {
		return c, note, err
	}
	if d.hooks.BetweenTx != nil {
		d.hooks.BetweenTx()
	}
	sha, err := d.remote.LsRemote(ctx, next.repoURL, next.branch)
	if err != nil {
		d.log.Warn("no new work this tick: the default branch's head could not be read", "project", next.id, "error", err)
		return nil, "no new work: ls-remote failed: " + err.Error(), nil
	}
	c, _, note, err = d.pickOnce(ctx, &head{project: *next, sha: sha})
	return c, note, err
}

// pickOnce is one pick transaction. Without a head it stops at new work, returning the project to
// read the head for when new work has a candidate. A lock wait that times out ends it with nothing
// claimed.
func (d *Dispatcher) pickOnce(ctx context.Context, h *head) (*claim, *project, string, error) {
	c, next, note, err := d.pickTx(ctx, h)
	if lockTimedOut(err) {
		d.log.Warn("the pick waited too long for a lock; nothing claimed this tick", "error", err)
		return nil, nil, "a lock wait timed out", nil
	}
	return c, next, note, err
}

func (d *Dispatcher) pickTx(ctx context.Context, h *head) (*claim, *project, string, error) {
	tx, err := d.begin(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	defer tx.Rollback()
	if d.hooks.TxStarted != nil {
		var pid int
		tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid)
		d.hooks.TxStarted(pid)
	}
	p, ok, err := lockProject(ctx, tx)
	if err != nil || !ok {
		return nil, nil, "no active project", err
	}
	if h != nil && h.project != p {
		return nil, nil, "the project changed while its head was read", nil
	}
	live, err := liveLeases(ctx, tx, p.id)
	if err != nil {
		return nil, nil, "", err
	}
	usable, err := readBudgets(ctx, tx)
	if err != nil {
		return nil, nil, "", err
	}
	launchable := map[callbackapi.Role]bool{}
	for _, r := range d.launcher.Roles(p.id) {
		launchable[r] = true
	}
	var held []string
	for _, q := range queues {
		if !launchable[q.role] {
			continue // nothing could start it: it rests where it is (P05 D8)
		}
		if live[q.role] {
			held = append(held, string(q.role))
			continue
		}
		if q.role == callbackapi.RoleDev {
			blocked, err := escalationBlocks(ctx, tx, p.id)
			if err != nil {
				return nil, nil, "", err
			}
			if blocked {
				return nil, nil, "an escalation blocks new work", nil
			}
			if h == nil {
				has, err := d.hasCandidate(ctx, tx, p.id, q, usable)
				if err != nil || !has {
					return nil, nil, nothingToClaim(held), err
				}
				return nil, &p, "", nil
			}
		}
		c, err := d.claimFrom(ctx, tx, p, q, usable, h)
		if err != nil {
			return nil, nil, "", err
		}
		if c != nil {
			if d.hooks.BeforeCommit != nil {
				d.hooks.BeforeCommit()
			}
			if err := tx.Commit(); err != nil {
				return nil, nil, "", err
			}
			return c, nil, "", nil
		}
	}
	return nil, nil, nothingToClaim(held), nil
}

// nothingToClaim names the roles whose slot was held, when that is part of why nothing was claimed.
func nothingToClaim(held []string) string {
	if len(held) == 0 {
		return "nothing to claim"
	}
	return "nothing to claim; a lease is held by " + strings.Join(held, ", ")
}

// attemptsFor lists the attempts a queue may claim: those whose tier's provider is usable and not
// excluded (dev: the attempt it starts; QA: the dev attempt it judges). The integrator has no tier:
// nil, meaning any.
func (d *Dispatcher) attemptsFor(role callbackapi.Role, usable, excluded map[string]bool) []int64 {
	if role == callbackapi.RoleIntegrator {
		return nil
	}
	out := []int64{}
	for a := 1; a <= callbackapi.AttemptCap; a++ {
		if t, ok := d.tiers.For(role, a); ok && usable[t.Provider] && !excluded[t.Provider] {
			out = append(out, int64(a))
		}
	}
	return out
}

// candidateSQL selects a queue's next ticket: children before unstarted parents, never a ticket
// with children, then priority and age. For dev the attempt filtered on is the one it starts, for
// QA the one it judges.
func candidateSQL(q queue, filtered bool, lock string) string {
	filter := ""
	switch {
	case filtered && q.role == callbackapi.RoleDev:
		filter = " AND t.attempt_count + 1 = ANY($3::int[])"
	case filtered:
		filter = " AND t.attempt_count = ANY($3::int[])"
	}
	return `SELECT t.id, t.attempt_count, coalesce(t.branch, ''), coalesce(t.base_sha, ''), coalesce(t.head_sha, ''), t.title
		FROM tickets t
		WHERE t.project_id = $1 AND t.state = $2` + filter + `
		  AND (t.parent_ticket_id IS NOT NULL OR NOT EXISTS (SELECT 1 FROM tickets c WHERE c.parent_ticket_id = t.id))
		ORDER BY (t.parent_ticket_id IS NULL), t.priority DESC, t.created_at ASC, t.id ASC ` + lock + ` LIMIT 1`
}

func candidateArgs(projectID string, q queue, attempts []int64) []any {
	args := []any{projectID, string(q.from)}
	if attempts != nil {
		args = append(args, attempts)
	}
	return args
}

// hasCandidate reports, without locking, whether new work has a ticket to claim on a usable
// provider, before the tick spends a network call on its head.
func (d *Dispatcher) hasCandidate(ctx context.Context, tx *sql.Tx, projectID string, q queue, usable map[string]bool) (bool, error) {
	attempts := d.attemptsFor(q.role, usable, nil)
	if len(attempts) == 0 {
		return false, nil
	}
	var id int64
	var n int
	var b, base, hd, title string
	err := tx.QueryRowContext(ctx, candidateSQL(q, true, ""), candidateArgs(projectID, q, attempts)...).Scan(&id, &n, &b, &base, &hd, &title)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// claimFrom claims a queue's next ticket whose tier's provider is usable. The ticket is locked
// first (FOR UPDATE SKIP LOCKED: a row a runner or a human holds is passed over, not waited on),
// then the provider's budget row, checked again; if a report paused the provider in between, the
// query runs again without it (D16). Then the claim goes through the core, one unit is charged and
// the attempt's row written, all in the caller's transaction.
func (d *Dispatcher) claimFrom(ctx context.Context, tx *sql.Tx, p project, q queue, usable map[string]bool, h *head) (*claim, error) {
	excluded := map[string]bool{}
	for {
		attempts := d.attemptsFor(q.role, usable, excluded)
		if attempts != nil && len(attempts) == 0 {
			return nil, nil
		}
		c := &claim{role: q.role, from: q.from, to: q.to, project: p.id, repoURL: p.repoURL}
		var count int
		err := tx.QueryRowContext(ctx, candidateSQL(q, attempts != nil, "FOR UPDATE SKIP LOCKED"), candidateArgs(p.id, q, attempts)...).
			Scan(&c.ticket, &count, &c.branch, &c.baseSHA, &c.headSHA, &c.title)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		c.attempt = count
		if q.role == callbackapi.RoleDev {
			c.attempt = count + 1
		}
		if q.role != callbackapi.RoleIntegrator {
			t, ok := d.tiers.For(q.role, c.attempt)
			if !ok { // the candidate query admits only attempts the table covers
				return nil, fmt.Errorf("ticket %d: no %s tier for attempt %d", c.ticket, q.role, c.attempt)
			}
			if d.hooks.BeforeBudgetLock != nil {
				d.hooks.BeforeBudgetLock()
			}
			ok, err := lockBudget(ctx, tx, t.Provider)
			if err != nil {
				return nil, err
			}
			if !ok {
				excluded[t.Provider] = true
				continue
			}
			c.tier = &t
		}

		req := callbackapi.TransitionRequest{
			TicketID: c.ticket, From: q.from, To: q.to, Caller: dispatcherCaller, Channel: callbackapi.ChannelCore,
			RequestID: newRequestID(), Method: "CORE", Path: fmt.Sprintf("dispatcher/tickets/%d/claim", c.ticket),
		}
		if q.role == callbackapi.RoleDev {
			c.branch, c.baseSHA = fmt.Sprintf("foreman/%d/%d", c.ticket, c.attempt), h.sha
			req.Branch, req.BaseSHA = c.branch, c.baseSHA
		}
		res, err := d.engine.Transition(ctx, tx, req)
		if err != nil {
			return nil, fmt.Errorf("claim ticket %d: %w", c.ticket, err)
		}
		c.token = res.ClaimToken

		var provider, model, tier any
		if c.tier != nil {
			provider, model, tier = c.tier.Provider, c.tier.Model, c.tier.Name
			if _, err := tx.ExecContext(ctx, `
				UPDATE budget SET consumed_estimate = consumed_estimate + 1, updated_at = now() WHERE provider = $1`,
				c.tier.Provider); err != nil {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO attempts (ticket_id, attempt, role, provider, model, tier, claim_token)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			c.ticket, c.attempt, string(q.role), provider, model, tier, c.token); err != nil {
			return nil, err
		}
		return c, nil
	}
}
