// Package callbackapi is foreman's callback API: the only writer to Postgres besides the
// dispatcher, and the place where the ticket state machine is enforced (docs/state-machine.md,
// docs/architecture.md). The dispatcher calls the same transition code directly.
//
// Every file that decides or enforces anything is named transitions*, escalation* or parking*,
// so the risk policy's protected-path matchers cover it (P02 D9). http.go holds routing only.
package callbackapi

// State is a ticket state (the ticket_state enum).
type State string

const (
	StateDraft          State = "draft"
	StateReady          State = "ready"
	StateClaimed        State = "claimed"
	StateInProgress     State = "in_progress"
	StateAwaitingReview State = "awaiting_review"
	StateInQA           State = "in_qa"
	StateApproved       State = "approved"
	StateMerging        State = "merging"
	StateMerged         State = "merged"
	StateDone           State = "done"
	StateDecomposed     State = "decomposed"
	StateEscalated      State = "escalated"
	StateFailed         State = "failed"
	StateAbandoned      State = "abandoned"
)

var allStates = []State{
	StateDraft, StateReady, StateClaimed, StateInProgress, StateAwaitingReview, StateInQA,
	StateApproved, StateMerging, StateMerged, StateDone, StateDecomposed, StateEscalated,
	StateFailed, StateAbandoned,
}

// States returns every ticket state.
func States() []State { return append([]State(nil), allStates...) }

// Valid reports whether s is a ticket state.
func (s State) Valid() bool {
	for _, x := range allStates {
		if s == x {
			return true
		}
	}
	return false
}

// IsLeased reports whether something runs in state s, and so holds a lease a reap can expire.
func IsLeased(s State) bool {
	return s == StateClaimed || s == StateInProgress || s == StateInQA || s == StateMerging
}

// IsTerminal reports whether s ends a ticket for the roll-up.
func IsTerminal(s State) bool {
	return s == StateDone || s == StateFailed || s == StateAbandoned
}

// leaseOwner is the role whose runner holds the lease in a leased state.
func leaseOwner(s State) Role {
	switch s {
	case StateClaimed, StateInProgress:
		return RoleDev
	case StateInQA:
		return RoleQA
	case StateMerging:
		return RoleIntegrator
	}
	return ""
}

// Role is an actor (the actor_role enum).
type Role string

const (
	RoleHuman         Role = "human"
	RoleDispatcher    Role = "dispatcher"
	RoleCallbackAPI   Role = "callback_api"
	RoleSpec          Role = "spec"
	RoleArchitect     Role = "architect"
	RoleDev           Role = "dev"
	RoleQA            Role = "qa"
	RoleRiskEvaluator Role = "risk_evaluator"
	RoleIntegrator    Role = "integrator"
	RoleHousekeeping  Role = "housekeeping"
	// RoleViewer is the viewer's service account (P06 D4). It is a caller only while relaying a
	// person's IAP assertion, and then the caller is that person: the engine refuses it as itself,
	// and it is never an event's actor.
	RoleViewer Role = "viewer"
)

// IsRunner reports whether r is a runner role: one scoped to a project and fenced by a claim token.
func (r Role) IsRunner() bool {
	switch r {
	case RoleSpec, RoleArchitect, RoleDev, RoleQA, RoleIntegrator:
		return true
	}
	return false
}

// Channel is how a transition may arrive.
type Channel string

const (
	ChannelHTTP      Channel = "http"      // runners and humans, on /transitions
	ChannelDecompose Channel = "decompose" // ready -> decomposed, only through /decompose
	ChannelCore      Channel = "core"      // the dispatcher's direct calls
	ChannelInternal  Channel = "internal"  // the callback API's own diversions; nobody requests these
)

// Row is one line of the ownership table: exactly one legal actor for a (from, to), reached
// through one channel.
type Row struct {
	From    State
	To      State
	Actor   Role
	Channel Channel
}

// AttemptCap is the number of dev sessions a ticket may start. A return to ready at the cap is
// diverted to failed.
const AttemptCap = 2

// The ownership table (docs/state-machine.md, "Transition ownership"). The cap diversion (a return
// to ready at the cap becomes failed) and the three-returns diversion (the dispatcher's third return
// in a row escalates) are rules of the engine, not rows.
var table = buildTable()

func buildTable() []Row {
	rows := []Row{
		{StateDraft, StateReady, RoleSpec, ChannelHTTP},
		{StateReady, StateDecomposed, RoleSpec, ChannelDecompose},
		{StateReady, StateClaimed, RoleDispatcher, ChannelCore},
		{StateClaimed, StateReady, RoleDispatcher, ChannelCore},
		{StateClaimed, StateInProgress, RoleDev, ChannelHTTP},
		{StateInProgress, StateReady, RoleDev, ChannelHTTP},
		{StateInProgress, StateReady, RoleDispatcher, ChannelCore},
		{StateInProgress, StateAwaitingReview, RoleDev, ChannelHTTP},
		{StateInProgress, StateEscalated, RoleDev, ChannelHTTP},
		{StateAwaitingReview, StateInQA, RoleDispatcher, ChannelCore},
		{StateInQA, StateAwaitingReview, RoleDispatcher, ChannelCore},
		{StateInQA, StateReady, RoleQA, ChannelHTTP},
		{StateInQA, StateApproved, RoleQA, ChannelHTTP},
		{StateInQA, StateEscalated, RoleRiskEvaluator, ChannelInternal},
		{StateApproved, StateMerging, RoleDispatcher, ChannelCore},
		{StateMerging, StateApproved, RoleDispatcher, ChannelCore},
		{StateMerging, StateMerged, RoleIntegrator, ChannelHTTP},
		{StateMerging, StateReady, RoleIntegrator, ChannelHTTP},
		{StateMerged, StateDone, RoleIntegrator, ChannelHTTP},
		{StateReady, StateEscalated, RoleCallbackAPI, ChannelInternal},
		{StateDecomposed, StateDone, RoleCallbackAPI, ChannelInternal},
		{StateDecomposed, StateEscalated, RoleCallbackAPI, ChannelInternal},
		// Out of escalated: a human only, never straight to a leased state, draft, decomposed or
		// merged (D19). A ticket with children has a further precondition in the engine, and so
		// does one without a submitted commit going to approved or back to QA (P04 D17).
		{StateEscalated, StateReady, RoleHuman, ChannelHTTP},
		{StateEscalated, StateApproved, RoleHuman, ChannelHTTP},
		{StateEscalated, StateAwaitingReview, RoleHuman, ChannelHTTP},
		{StateEscalated, StateDone, RoleHuman, ChannelHTTP},
		{StateEscalated, StateFailed, RoleHuman, ChannelHTTP},
	}
	// Into abandoned: a human only, from every state except done, failed, abandoned and merged.
	for _, s := range allStates {
		if !IsTerminal(s) && s != StateMerged {
			rows = append(rows, Row{s, StateAbandoned, RoleHuman, ChannelHTTP})
		}
	}
	return rows
}

// Table returns a copy of the ownership table.
func Table() []Row { return append([]Row(nil), table...) }

// lookup finds the row for (from, to, actor).
func lookup(from, to State, actor Role) (Row, bool) {
	for _, r := range table {
		if r.From == from && r.To == to && r.Actor == actor {
			return r, true
		}
	}
	return Row{}, false
}

// isClaim reports whether a dispatcher row takes a lease: into a leased state from outside one.
func isClaim(r Row) bool {
	return r.Actor == RoleDispatcher && IsLeased(r.To) && !IsLeased(r.From)
}

// isNewWorkClaim reports whether a row is the dispatcher's claim of new work, the one that records
// the ticket's branch and base_sha (P04 D4).
func isNewWorkClaim(r Row) bool {
	return r.Actor == RoleDispatcher && r.From == StateReady && r.To == StateClaimed
}

// isReturn reports whether a dispatcher row returns a ticket from a leased state: a reap or the
// return of a launch that failed (P04 D9).
func isReturn(r Row) bool {
	return r.Actor == RoleDispatcher && IsLeased(r.From) && !IsLeased(r.To)
}
