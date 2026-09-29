package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Caller is a verified identity: the email its token proved, the role and, for runners, the
// project the identity mapping gives it. Nothing in a request can supply these.
type Caller struct {
	Email   string
	Role    Role
	Project string // runners only; humans and the dispatcher act across projects
}

// Criterion is one acceptance criterion.
type Criterion struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// TransitionRequest asks to move one ticket from `From` to `To`.
type TransitionRequest struct {
	TicketID           int64
	From, To           State
	Caller             Caller
	Channel            Channel
	RequestID          string          // the Idempotency-Key: a UUID
	ClaimToken         string          // X-Foreman-Claim-Token; runners on a leased ticket
	Payload            json.RawMessage // optional JSON object, kept in the event
	AcceptanceCriteria []Criterion     // draft -> ready only
	HeadSHA            string          // the commit submitted (in_progress -> awaiting_review) or tested (in_qa -> approved)
	Branch             string          // the dispatcher's new-work claim: foreman/<ticket>/<attempt it starts>
	BaseSHA            string          // the dispatcher's new-work claim: the default branch's head
	Return             ReturnKind      // the dispatcher's returns from a leased state
	Method, Path       string          // name the request for the request log
}

// ReturnKind is how the dispatcher returns a ticket from a leased state (P04 D9).
type ReturnKind string

const (
	ReturnLeaseExpired ReturnKind = "lease_expired" // a reap: the lease must have expired
	ReturnLaunchFailed ReturnKind = "launch_failed" // the launcher reported the run definitely did not start
)

// Result is what a transition did. It is also the recorded response a replay returns.
type Result struct {
	TicketID     int64    `json:"ticket_id"`
	From         State    `json:"from"`
	State        State    `json:"state"`
	RequestedTo  State    `json:"requested_to,omitempty"` // set when the engine diverted the request
	Actor        Role     `json:"actor"`
	EventID      int64    `json:"event_id"`
	AttemptCount int      `json:"attempt_count"`
	ClaimToken   string   `json:"claim_token,omitempty"` // a claim's new token, for the dispatcher
	Verdict      *Verdict `json:"verdict,omitempty"`     // the risk verdict, on in_qa -> approved
	Replayed     bool     `json:"-"`
}

// Error is a refusal, carrying the HTTP status it maps to. Every refusal is an error, and the
// caller of the engine must roll its transaction back on any error.
type Error struct {
	Status int
	Reason string
	cause  error
}

func (e *Error) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Reason) }
func (e *Error) Unwrap() error { return e.cause }

func refuse(status int, format string, a ...any) *Error {
	return &Error{Status: status, Reason: fmt.Sprintf(format, a...)}
}

func internal(what string, err error) *Error {
	return &Error{Status: 500, Reason: what + ": " + err.Error(), cause: err}
}

func internalf(format string, a ...any) *Error {
	return &Error{Status: 500, Reason: fmt.Sprintf(format, a...)}
}

// StatusOf maps an error from the engine to an HTTP status.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 500
}

// Engine applies transitions. It is safe for concurrent use.
type Engine struct {
	evaluator Evaluator
	log       *slog.Logger
}

// NewEngine returns an engine using evaluator for `in_qa -> approved`; with none, FailClosed. The
// command passes the risk evaluator from riskevaluator.FromEnv.
func NewEngine(evaluator Evaluator, log *slog.Logger) *Engine {
	if evaluator == nil {
		evaluator = FailClosed{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Engine{evaluator: evaluator, log: log}
}

// BeginTx opens the READ COMMITTED transaction the engine requires.
func BeginTx(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	return db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
}

// requireReadCommitted refuses any other isolation level: the roll-up's sibling count and the
// request log's duplicate handling are correct only under READ COMMITTED. Fail closed.
func requireReadCommitted(ctx context.Context, tx *sql.Tx) error {
	var level string
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&level); err != nil {
		return internal("read isolation level", err)
	}
	if level != "read committed" {
		return internalf("the transition core requires READ COMMITTED, the transaction is %s", level)
	}
	return nil
}

// ticket is the locked row, as far as the engine needs it.
type ticket struct {
	ID          int64
	State       State
	Project     string
	Attempts    int
	ClaimToken  sql.NullString
	Parent      sql.NullInt64
	HasChildren bool
	BaseSHA     sql.NullString
	HeadSHA     sql.NullString
	IsMeta      bool // projects.is_meta, read without locking the project row
}

func lockTicket(ctx context.Context, tx *sql.Tx, id int64) (ticket, error) {
	t := ticket{ID: id}
	var s string
	err := tx.QueryRowContext(ctx, `
		SELECT t.state, t.project_id, t.attempt_count, t.claim_token, t.parent_ticket_id,
		  EXISTS (SELECT 1 FROM tickets c WHERE c.parent_ticket_id = t.id),
		  t.base_sha, t.head_sha, p.is_meta
		FROM tickets t JOIN projects p ON p.id = t.project_id WHERE t.id = $1 FOR UPDATE OF t`, id).
		Scan(&s, &t.Project, &t.Attempts, &t.ClaimToken, &t.Parent, &t.HasChildren, &t.BaseSHA, &t.HeadSHA, &t.IsMeta)
	if errors.Is(err, sql.ErrNoRows) {
		return t, refuse(404, "ticket %d not found", id)
	}
	if err != nil {
		return t, internal("lock ticket", err)
	}
	t.State = State(s)
	return t, nil
}

// checkProject holds a runner to its own project. The project never changes, so this reads the
// ticket without locking it and without looking at its state.
func checkProject(ctx context.Context, tx *sql.Tx, id int64, project string) error {
	var p string
	err := tx.QueryRowContext(ctx, `SELECT project_id FROM tickets WHERE id = $1`, id).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return refuse(404, "ticket %d not found", id)
	}
	if err != nil {
		return internal("read ticket project", err)
	}
	if p != project {
		return refuse(403, "ticket %d is not in project %s", id, project)
	}
	return nil
}

func (r TransitionRequest) validate() error {
	if r.TicketID <= 0 {
		return refuse(400, "a ticket id is required")
	}
	if !validRequestID(r.RequestID) {
		return refuse(400, "the idempotency key must be a UUID")
	}
	if !r.From.Valid() || !r.To.Valid() {
		return refuse(400, "unknown state in %q -> %q", r.From, r.To)
	}
	if len(r.Payload) > 0 {
		var obj map[string]any
		if json.Unmarshal(r.Payload, &obj) != nil || obj == nil {
			return refuse(400, "the payload must be a JSON object")
		}
	}
	if r.From == StateDraft && r.To == StateReady {
		if err := validateCriteria(r.AcceptanceCriteria); err != nil {
			return err
		}
	} else if len(r.AcceptanceCriteria) > 0 {
		return refuse(400, "acceptance criteria are accepted only on draft -> ready")
	}
	if carriesCommit(r.From, r.To) {
		if !shaPattern.MatchString(r.HeadSHA) {
			return refuse(400, "head_sha must name the commit: a full SHA-1 in lowercase hex")
		}
	} else if r.HeadSHA != "" {
		return refuse(400, "head_sha is accepted only on in_progress -> awaiting_review and in_qa -> approved")
	}
	return nil
}

// validateForRow checks the fields that belong to one row, once authorization has found it: the
// dispatcher's new-work claim names its branch and base, and its returns their kind; no other
// request carries either (P04 D4, D9). The branch's attempt is checked under the lock.
func (r TransitionRequest) validateForRow(row Row) error {
	if isNewWorkClaim(row) {
		if !shaPattern.MatchString(r.BaseSHA) {
			return refuse(400, "base_sha must name the default branch's head: a full SHA-1 in lowercase hex")
		}
		if m := branchPattern.FindStringSubmatch(r.Branch); m == nil || m[1] != strconv.FormatInt(r.TicketID, 10) {
			return refuse(400, "the branch must be foreman/%d/ and the attempt the claim starts", r.TicketID)
		}
	} else if r.Branch != "" || r.BaseSHA != "" {
		return refuse(400, "branch and base_sha are accepted only on the dispatcher's ready -> claimed")
	}
	if isReturn(row) {
		if r.Return != ReturnLeaseExpired && r.Return != ReturnLaunchFailed {
			return refuse(400, "the dispatcher's return needs its kind: %s or %s", ReturnLeaseExpired, ReturnLaunchFailed)
		}
	} else if r.Return != "" {
		return refuse(400, "a return kind is accepted only on the dispatcher's returns from a leased state")
	}
	return nil
}

var (
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	branchPattern = regexp.MustCompile(`^foreman/([1-9][0-9]*)/([1-9][0-9]*)$`)
)

// branchName is the branch of a ticket's dev attempt: every attempt starts on its own.
func branchName(ticket int64, attempt int) string {
	return fmt.Sprintf("foreman/%d/%d", ticket, attempt)
}

// carriesCommit: the dev runner's submission names the commit it submits, and QA's approval the
// commit it tested (P03 D10).
func carriesCommit(from, to State) bool {
	return (from == StateInProgress && to == StateAwaitingReview) || (from == StateInQA && to == StateApproved)
}

func (r TransitionRequest) hash() string {
	return requestHash(map[string]any{
		"method": r.Method, "path": r.Path, "ticket": r.TicketID, "from": r.From, "to": r.To,
		"payload": canonical(r.Payload), "acceptance_criteria": r.AcceptanceCriteria,
		"claim_token": r.ClaimToken, "head_sha": r.HeadSHA,
		"branch": r.Branch, "base_sha": r.BaseSHA, "return": r.Return,
	})
}

func validCaller(c Caller) error {
	if c.Email == "" || c.Role == "" || c.Role == RoleCallbackAPI || c.Role == RoleRiskEvaluator {
		return internalf("no verified caller")
	}
	if c.Role.IsRunner() && c.Project == "" {
		return internalf("runner %s has no project", c.Email)
	}
	return nil
}

// Transition applies one transition in the caller's transaction, in this order (P02 Approach 3):
// isolation; validation (400); authorization without reading state (403); the row's own fields
// (400); the request log (replay, or 409); the row lock and `from` (404, 409); preconditions (400, 409); the fence and the
// lease's expiry (409); diversions; bookkeeping; update; event; stored response; roll-up. Every refusal is an error, and
// the caller must roll back on any error, so a refusal leaves nothing behind.
func (e *Engine) Transition(ctx context.Context, tx *sql.Tx, req TransitionRequest) (Result, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return Result{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return Result{}, err
	}
	if err := req.validate(); err != nil {
		return Result{}, err
	}

	row, ok := lookup(req.From, req.To, req.Caller.Role)
	if !ok {
		return Result{}, refuse(403, "%s -> %s is not a transition %s may make", req.From, req.To, req.Caller.Role)
	}
	if row.Channel != req.Channel {
		return Result{}, refuse(403, "%s -> %s is not reachable through %s", req.From, req.To, req.Channel)
	}
	if err := req.validateForRow(row); err != nil {
		return Result{}, err
	}
	if req.Caller.Role.IsRunner() {
		if err := checkProject(ctx, tx, req.TicketID, req.Caller.Project); err != nil {
			return Result{}, err
		}
	}

	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, req.hash())
	if err != nil {
		return Result{}, err
	}
	if replay != nil {
		var res Result
		if err := json.Unmarshal(replay, &res); err != nil {
			return Result{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	t, err := lockTicket(ctx, tx, req.TicketID)
	if err != nil {
		return Result{}, err
	}
	if t.State != req.From {
		return Result{}, refuse(409, "ticket %d is %s, not %s", t.ID, t.State, req.From)
	}
	if req.From == StateEscalated && (req.To == StateReady || req.To == StateApproved || req.To == StateAwaitingReview) && t.HasChildren {
		return Result{}, refuse(409, "ticket %d has children: it leaves escalated only for done, failed or abandoned", t.ID)
	}
	if req.From == StateEscalated && req.To == StateApproved && !t.HeadSHA.Valid {
		return Result{}, refuse(409, "ticket %d has no submitted commit: an approved ticket must have one to land", t.ID)
	}
	if req.From == StateEscalated && req.To == StateAwaitingReview && !t.HeadSHA.Valid {
		return Result{}, refuse(409, "ticket %d has no submitted commit for QA to test", t.ID)
	}
	if isNewWorkClaim(row) && req.Branch != branchName(t.ID, t.Attempts+1) {
		return Result{}, refuse(400, "ticket %d has used %d attempts: the claim's branch is %s", t.ID, t.Attempts, branchName(t.ID, t.Attempts+1))
	}
	if isReturn(row) {
		if err := checkReturn(ctx, tx, t, req); err != nil {
			return Result{}, err
		}
	}
	if err := fence(t, req.Caller, req.ClaimToken); err != nil {
		return Result{}, err
	}
	if err := leaseLive(ctx, tx, t, req.Caller); err != nil {
		return Result{}, err
	}

	res, err := e.apply(ctx, tx, t, row, req)
	if err != nil {
		return Result{}, err
	}
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 200, res); err != nil {
		return Result{}, err
	}
	return res, nil
}

// apply works out what the transition really does (diversions and bookkeeping), writes the ticket
// and its one event, and rolls up the parent when a child ends.
func (e *Engine) apply(ctx context.Context, tx *sql.Tx, t ticket, row Row, req TransitionRequest) (Result, error) {
	payload := map[string]any{}
	if len(req.Payload) > 0 {
		json.Unmarshal(req.Payload, &payload)
	}
	reason, _ := payload["reason"].(string)

	u := newUpdate(t.ID)
	to, actor := req.To, req.Caller.Role
	var requestedTo State
	var verdict *Verdict

	// Diversions (escalation.go): a return to ready at the cap fails; the dispatcher's third return
	// in a row escalates (P04 D8); an approval asks the risk evaluator, and anything but a clear
	// verdict escalates. A tested commit that is not the submitted one escalates without asking it,
	// and clears head_sha (P03 D10, D14).
	if isReturn(row) {
		payload["return"] = string(req.Return)
	}
	if d, ok := capDiversion(t, req.To); ok {
		to, actor, requestedTo, reason = d.to, d.actor, req.To, d.reason
	} else if isReturn(row) {
		d, n, ok, err := returnsDiversion(ctx, tx, t)
		if err != nil {
			return Result{}, err
		}
		if ok {
			to, actor, requestedTo, reason = d.to, d.actor, req.To, d.reason
			payload["returns"] = n
		}
	} else if req.From == StateInQA && req.To == StateApproved {
		at, err := dbNow(ctx, tx)
		if err != nil {
			return Result{}, err
		}
		var v Verdict
		if req.HeadSHA != t.HeadSHA.String {
			v = qaMismatch(t.HeadSHA.String, req.HeadSHA)
			u.setExpr("head_sha = NULL")
		} else {
			v = e.evaluate(ctx, Subject{TicketID: t.ID, Project: t.Project, IsMeta: t.IsMeta,
				BaseSHA: t.BaseSHA.String, HeadSHA: t.HeadSHA.String})
		}
		v.EvaluatedAt, v.BaseSHA, v.HeadSHA, v.TestedSHA = at, t.BaseSHA.String, t.HeadSHA.String, req.HeadSHA
		if err := u.riskVerdict(v); err != nil {
			return Result{}, err
		}
		payload["risk_verdict"] = v
		verdict = &v
		if !v.Cleared {
			to, actor, requestedTo, reason = StateEscalated, RoleRiskEvaluator, req.To, v.Reason
		}
	}
	if requestedTo != "" {
		payload["requested_to"] = string(requestedTo)
		payload["reason"] = reason
	}

	// Bookkeeping.
	u.set("state = %s", string(to))
	if req.From == StateClaimed && to == StateInProgress {
		u.set("attempt_count = attempt_count + %s", 1)
	}
	var token string
	switch {
	case isClaim(row) && to == row.To:
		token = newClaimToken()
		u.set("claim_token = %s", token)
		u.set("claimed_by = %s", req.Caller.Email)
		u.setExpr("claimed_at = now()")
		u.setExpr("lease_expires_at = now() + interval '5 minutes'")
	case !IsLeased(to):
		u.setExpr("claim_token = NULL")
		u.setExpr("claimed_by = NULL")
		u.setExpr("claimed_at = NULL")
		u.setExpr("lease_expires_at = NULL")
		if t.ClaimToken.Valid {
			if err := endAttempt(ctx, tx, t.ClaimToken.String, attemptOutcome(req)); err != nil {
				return Result{}, err
			}
		}
	}
	if isNewWorkClaim(row) {
		u.set("branch = %s", req.Branch)
		u.set("base_sha = %s", req.BaseSHA)
	}
	if to == StateEscalated {
		if reason == "" {
			reason = fmt.Sprintf("escalated by %s", actor)
		}
		u.setExpr("escalated_at = now()")
		u.set("escalation_reason = %s", reason)
	}
	if req.From == StateEscalated {
		// Parking belongs to the escalation it was set for (D21).
		u.setExpr("parked = false")
		u.setExpr("parked_reason = NULL")
		u.setExpr("parked_until = NULL")
	}
	if to == StateFailed {
		if reason == "" {
			reason = fmt.Sprintf("failed by %s", actor)
		}
		u.set("failure_reason = %s", reason)
	}
	if to == StateFailed || to == StateAbandoned {
		u.setExpr("retained_until = now() + interval '30 days'")
	}
	if req.From == StateDraft && to == StateReady {
		ac, _ := json.Marshal(req.AcceptanceCriteria)
		u.set("acceptance_criteria = %s::jsonb", string(ac))
	}
	if req.From == StateInProgress && to == StateAwaitingReview {
		u.set("head_sha = %s", req.HeadSHA)
	}
	if to == StateReady {
		u.setExpr("head_sha = NULL") // a new attempt is a new commit
	}

	attempts, err := u.exec(ctx, tx)
	if err != nil {
		return Result{}, err
	}
	eventID, err := insertEvent(ctx, tx, event{
		ticket: t.ID, from: &t.State, to: to, actor: actor, actorID: req.Caller.Email,
		requestID: req.RequestID, payload: payload,
	})
	if err != nil {
		return Result{}, err
	}
	e.log.Info("ticket transition", "ticket", t.ID, "project", t.Project, "from", t.State, "to", to,
		"actor", actor, "actor_id", req.Caller.Email, "requested_to", requestedTo)

	if t.Parent.Valid && IsTerminal(to) {
		if err := e.rollUp(ctx, tx, t.Parent.Int64, t.ID, req.Caller, req.RequestID); err != nil {
			return Result{}, err
		}
	}
	return Result{
		TicketID: t.ID, From: t.State, State: to, RequestedTo: requestedTo, Actor: actor,
		EventID: eventID, AttemptCount: attempts, ClaimToken: token, Verdict: verdict,
	}, nil
}

// dbNow is the transaction's time, the same now() every statement in it sees: the verdict's time
// is then the event's.
func dbNow(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var at time.Time
	if err := tx.QueryRowContext(ctx, `SELECT now()`).Scan(&at); err != nil {
		return at, internal("read the transaction's time", err)
	}
	return at, nil
}

// update builds one UPDATE of a ticket from column assignments.
type update struct {
	id    int64
	sets  []string
	args  []any
	extra []string
}

func newUpdate(id int64) *update { return &update{id: id, args: []any{id}} }

// set adds `column = expr`, where %s stands for the value's placeholder.
func (u *update) set(assign string, v any) {
	u.args = append(u.args, v)
	u.sets = append(u.sets, fmt.Sprintf(assign, fmt.Sprintf("$%d", len(u.args))))
}

func (u *update) setExpr(assign string) { u.sets = append(u.sets, assign) }

func (u *update) riskVerdict(v Verdict) error {
	b, err := json.Marshal(v)
	if err != nil {
		return internal("encode the risk verdict", err)
	}
	u.set("risk_verdict = %s::jsonb", string(b))
	return nil
}

func (u *update) exec(ctx context.Context, tx *sql.Tx) (int, error) {
	q := "UPDATE tickets SET " + strings.Join(append(u.sets, "updated_at = now()"), ", ") +
		" WHERE id = $1 RETURNING attempt_count"
	var attempts int
	if err := tx.QueryRowContext(ctx, q, u.args...).Scan(&attempts); err != nil {
		return 0, internal("update ticket", err)
	}
	return attempts, nil
}

// event is one ticket_events row.
type event struct {
	ticket    int64
	from      *State // nil for a creation
	to        State
	actor     Role
	actorID   string
	requestID string // empty for a roll-up, which has none of its own
	payload   map[string]any
}

func insertEvent(ctx context.Context, tx *sql.Tx, ev event) (int64, error) {
	var from, reqID sql.NullString
	if ev.from != nil {
		from = sql.NullString{String: string(*ev.from), Valid: true}
	}
	if ev.requestID != "" {
		reqID = sql.NullString{String: ev.requestID, Valid: true}
	}
	var payload []byte
	if len(ev.payload) > 0 {
		payload, _ = json.Marshal(ev.payload)
	}
	var id int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO ticket_events (ticket_id, from_state, to_state, actor, actor_id, request_id, payload)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		ev.ticket, from, string(ev.to), string(ev.actor), ev.actorID, reqID, payload).Scan(&id)
	if err != nil {
		return 0, internal("write event", err)
	}
	return id, nil
}
