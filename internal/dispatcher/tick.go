package dispatcher

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// One tick (P04 Approach 2; docs/state-machine.md, "Atomic claim"): reap, check the budgets, pick
// in one or two transactions, launch, record, exit. No model anywhere: every decision is the
// database's state and the protected tier table.

// DispatcherAccount is the identity the dispatcher acts as in the transition core.
const DispatcherAccount = "dispatcher@" + serviceAccountDomain

var dispatcherCaller = callbackapi.Caller{Email: DispatcherAccount, Role: callbackapi.RoleDispatcher}

// defaultLockTimeoutMS bounds every lock wait of a tick's transactions: a stalled session can
// delay a tick, never hang it or the ticks behind it (red team 3, R3).
const defaultLockTimeoutMS = 5000

// Remote reads the head of a branch on a project's remote: riskevaluator's Git.LsRemote.
type Remote interface {
	LsRemote(ctx context.Context, url, branch string) (string, error)
}

// Dispatcher makes ticks. It keeps no state between them.
type Dispatcher struct {
	db            *sql.DB
	engine        *callbackapi.Engine
	tiers         *Tiers
	remote        Remote
	launcher      Launcher
	log           *slog.Logger
	lockTimeoutMS int
	hooks         hooks
}

// hooks hold a tick at a point, for the tests alone (export_test.go); production never sets them.
type hooks struct {
	TxStarted        func(pid int) // each pick transaction, once begun, with its server process
	AfterReap        func()
	BetweenTx        func() // after transaction 1 rolled back, before ls-remote
	BeforeBudgetLock func()
	BeforeCommit     func()      // before a pick transaction commits its claim
	AfterCommit      func() bool // true: stop before launching, as if the tick died there
}

// New returns a dispatcher.
func New(db *sql.DB, engine *callbackapi.Engine, tiers *Tiers, remote Remote, launcher Launcher, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	return &Dispatcher{db: db, engine: engine, tiers: tiers, remote: remote, launcher: launcher, log: log,
		lockTimeoutMS: defaultLockTimeoutMS}
}

// Outcome is what one tick did.
type Outcome struct {
	Reaped       []int64          // tickets a reap returned (or the core diverted: failed, escalated)
	Claimed      int64            // 0 when nothing was claimed
	Role         callbackapi.Role // the claimed ticket's runner
	LaunchID     string
	LaunchFailed bool   // the launch did not start: the ticket was returned and its unit refunded
	Stopped      bool   // a test hook stopped the tick after its commit
	Note         string // why nothing was claimed, when nothing was
}

// Tick makes one pass. It returns an error only when something is wrong that a person must fix (a
// provider with no budget row, a database error); everything else is in the Outcome and the log.
func (d *Dispatcher) Tick(ctx context.Context) (Outcome, error) {
	var out Outcome
	reaped, err := d.reap(ctx)
	out.Reaped = reaped
	if err != nil {
		return out, err
	}
	if d.hooks.AfterReap != nil {
		d.hooks.AfterReap()
	}
	if err := d.checkBudgetRows(ctx); err != nil {
		return out, err
	}
	c, note, err := d.pick(ctx)
	if err != nil {
		return out, err
	}
	if c == nil {
		out.Note = note
		d.log.Info("dispatch tick", "reaped", len(out.Reaped), "claimed", 0, "note", note)
		return out, nil
	}
	out.Claimed, out.Role = c.ticket, c.role
	if d.hooks.AfterCommit != nil && d.hooks.AfterCommit() {
		out.Stopped = true
		return out, nil
	}
	d.launch(ctx, c, &out)
	d.log.Info("dispatch tick", "reaped", len(out.Reaped), "claimed", c.ticket, "project", c.project,
		"role", c.role, "attempt", c.attempt, "tier", c.tierName(), "launch_id", out.LaunchID, "launch_failed", out.LaunchFailed)
	return out, nil
}

// begin opens a READ COMMITTED transaction whose lock waits are bounded.
func (d *Dispatcher) begin(ctx context.Context) (*sql.Tx, error) {
	tx, err := callbackapi.BeginTx(ctx, d.db)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", d.lockTimeoutMS)); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// lockTimedOut reports a lock wait that hit lock_timeout.
func lockTimedOut(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "55P03"
}

func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// reapTo is where a reap returns a ticket from each leased state.
var reapTo = map[callbackapi.State]callbackapi.State{
	callbackapi.StateClaimed:    callbackapi.StateReady,
	callbackapi.StateInProgress: callbackapi.StateReady,
	callbackapi.StateInQA:       callbackapi.StateAwaitingReview,
	callbackapi.StateMerging:    callbackapi.StateApproved,
}

// reap returns every expired lease, in every project, through the core, one transaction each. The
// core re-checks the expiry under the row lock, so a runner that heartbeated in time wins with a
// 409, which is ignored; so is a lock wait that timed out behind a stalled session. The core ends
// the lease's attempt, and diverts a third return in a row or a return at the cap.
func (d *Dispatcher) reap(ctx context.Context) ([]int64, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT id, state FROM tickets
		WHERE state IN ('claimed', 'in_progress', 'in_qa', 'merging') AND lease_expires_at <= now()
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("find expired leases: %w", err)
	}
	type expired struct {
		id    int64
		state callbackapi.State
	}
	var all []expired
	for rows.Next() {
		var x expired
		var s string
		if err := rows.Scan(&x.id, &s); err != nil {
			rows.Close()
			return nil, err
		}
		x.state = callbackapi.State(s)
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var reaped []int64
	for _, x := range all {
		tx, err := d.begin(ctx)
		if err != nil {
			return reaped, err
		}
		_, err = d.engine.Transition(ctx, tx, callbackapi.TransitionRequest{
			TicketID: x.id, From: x.state, To: reapTo[x.state], Caller: dispatcherCaller, Channel: callbackapi.ChannelCore,
			RequestID: newRequestID(), Return: callbackapi.ReturnLeaseExpired,
			Method: "CORE", Path: fmt.Sprintf("dispatcher/tickets/%d/reap", x.id),
		})
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			tx.Rollback()
			if callbackapi.StatusOf(err) == 409 || lockTimedOut(err) {
				d.log.Info("reap skipped", "ticket", x.id, "reason", err)
				continue
			}
			d.log.Warn("reap failed", "ticket", x.id, "error", err)
			continue
		}
		reaped = append(reaped, x.id)
	}
	return reaped, nil
}

// checkBudgetRows fails the tick when the tier table names a provider with no budget row: its
// tickets would otherwise be passed over without a word (red team 2, R7).
func (d *Dispatcher) checkBudgetRows(ctx context.Context) error {
	for _, p := range d.tiers.Providers() {
		var ok bool
		if err := d.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM budget WHERE provider = $1)`, p).Scan(&ok); err != nil {
			return fmt.Errorf("read the budget of %s: %w", p, err)
		}
		if !ok {
			return fmt.Errorf("the tier table names the provider %s, which has no budget row", p)
		}
	}
	return nil
}

// launch hands the claim to the launcher and records the launch id. A launch that definitely did
// not start returns the ticket at once and refunds its unit (D9, D10).
func (d *Dispatcher) launch(ctx context.Context, c *claim, out *Outcome) {
	req, err := c.request()
	var id string
	if err == nil {
		id, err = d.launcher.Launch(ctx, req)
	}
	if err != nil {
		out.LaunchFailed = true
		d.log.Warn("launch failed", "ticket", c.ticket, "role", c.role, "error", err)
		if rerr := d.returnFailedLaunch(ctx, c); rerr != nil {
			d.log.Warn("the failed launch's return was refused; the lease will be reaped", "ticket", c.ticket, "error", rerr)
		}
		return
	}
	out.LaunchID = id
	if _, err := d.db.ExecContext(ctx, `UPDATE attempts SET launch_id = $1 WHERE claim_token = $2`, id, c.token); err != nil {
		d.log.Warn("record the launch id", "ticket", c.ticket, "error", err)
	}
}

// returnFailedLaunch returns the ticket through the dispatcher's return row, fenced by the claim's
// token, and only if that succeeds refunds the unit to the attempt's provider, unless its window
// rolled over since the charge (red team 1, R13). The core ends the attempt.
func (d *Dispatcher) returnFailedLaunch(ctx context.Context, c *claim) error {
	tx, err := d.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := d.engine.Transition(ctx, tx, callbackapi.TransitionRequest{
		TicketID: c.ticket, From: c.to, To: c.from, Caller: dispatcherCaller, Channel: callbackapi.ChannelCore,
		RequestID: newRequestID(), Return: callbackapi.ReturnLaunchFailed, ClaimToken: c.token,
		Method: "CORE", Path: fmt.Sprintf("dispatcher/tickets/%d/launch-failed", c.ticket),
	}); err != nil {
		return err
	}
	if c.tier != nil {
		if _, err := tx.ExecContext(ctx, `
			UPDATE budget b SET consumed_estimate = b.consumed_estimate - 1, updated_at = now()
			FROM attempts a
			WHERE b.provider = $1 AND a.claim_token = $2 AND a.started_at >= b.window_started_at`,
			c.tier.Provider, c.token); err != nil {
			return err
		}
	}
	return tx.Commit()
}
