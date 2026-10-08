package dispatcher_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/gitfixture"
	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/riskevaltest"
)

// One tick of the dispatcher (P04 Approach 2; docs/state-machine.md, "Atomic claim").

const (
	sReady      = callbackapi.StateReady
	sClaimed    = callbackapi.StateClaimed
	sInProgress = callbackapi.StateInProgress
	sAwaiting   = callbackapi.StateAwaitingReview
	sInQA       = callbackapi.StateInQA
	sApproved   = callbackapi.StateApproved
	sMerging    = callbackapi.StateMerging
	sEscalated  = callbackapi.StateEscalated
	sDone       = callbackapi.StateDone
	sFailed     = callbackapi.StateFailed
	sDraft      = callbackapi.StateDraft
)

// --- gates ------------------------------------------------------------------------------------

func TestNoActiveProjectClaimsNothing(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE projects SET is_active = false`)
	id := e.seed(fixture{state: sReady})
	if out := e.tick(); out.Claimed != 0 || e.state(id) != sReady {
		t.Fatalf("claimed %d with no active project", out.Claimed)
	}
}

// Queues in order: integration, then QA, then new work; ls-remote only for new work.
func TestQueuesInOrder(t *testing.T) {
	e := newEnv(t)
	integ := e.seed(fixture{state: sApproved, attempts: 1})
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	work := e.seed(fixture{state: sReady})
	for i, want := range []struct {
		id    int64
		state callbackapi.State
	}{{integ, sMerging}, {qa, sInQA}, {work, sClaimed}} {
		out := e.tick()
		if out.Claimed != want.id || e.state(want.id) != want.state {
			t.Fatalf("tick %d claimed %d, want %d in %s", i+1, out.Claimed, want.id, want.state)
		}
		if wantCalls := map[bool]int{true: 1, false: 0}[i == 2]; e.remote.count() != wantCalls {
			t.Fatalf("tick %d: ls-remote called %d times, want %d", i+1, e.remote.count(), wantCalls)
		}
	}
}

// Children sort ahead of unstarted parents, and a ticket with children is never claimed.
func TestChildrenFirstAndParentsNever(t *testing.T) {
	e := newEnv(t)
	top := e.seed(fixture{state: sReady, priority: 5})
	parent := e.seed(fixture{state: sReady, priority: 9})
	child := e.seed(fixture{state: sReady, parent: parent})
	if out := e.tick(); out.Claimed != child {
		t.Fatalf("claimed %d, want the child %d ahead of %d", out.Claimed, child, top)
	}

	e2 := newEnv(t)
	parent2 := e2.seed(fixture{state: sReady, priority: 9})
	e2.seed(fixture{state: sDone, parent: parent2})
	other := e2.seed(fixture{state: sReady})
	if out := e2.tick(); out.Claimed != other || e2.state(parent2) != sReady {
		t.Fatalf("claimed %d, want %d: a ticket with children is never claimed", out.Claimed, other)
	}
}

// At most one lease per role: a live dev lease stops new work, not QA.
func TestOneLeasePerRole(t *testing.T) {
	e := newEnv(t)
	e.seed(fixture{state: sInProgress, attempts: 1})
	work := e.seed(fixture{state: sReady})
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	if out := e.tick(); out.Claimed != qa {
		t.Fatalf("claimed %d, want the QA ticket %d", out.Claimed, qa)
	}
	if out := e.tick(); out.Claimed != 0 || e.state(work) != sReady {
		t.Fatalf("claimed %d while a dev lease is live", out.Claimed)
	}
}

// An escalation blocks new work while unparked, or parked with a date that has passed; QA and
// integration drain meanwhile.
func TestEscalationBlocksNewWorkOnly(t *testing.T) {
	cases := []struct {
		name    string
		esc     fixture
		blocked bool
	}{
		{"unparked", fixture{state: sEscalated, attempts: 1}, true},
		{"parked with no date", fixture{state: sEscalated, attempts: 1, parked: true}, false},
		{"parked until later", fixture{state: sEscalated, attempts: 1, parked: true, until: "now() + interval '1 hour'"}, false},
		{"parked until a date that has passed", fixture{state: sEscalated, attempts: 1, parked: true, until: "now() - interval '1 minute'"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.seed(c.esc)
			work := e.seed(fixture{state: sReady})
			out := e.tick()
			if claimed := out.Claimed == work; claimed == c.blocked {
				t.Fatalf("new work claimed=%v, want %v", claimed, !c.blocked)
			}
		})
	}
	e := newEnv(t)
	e.seed(fixture{state: sEscalated, attempts: 1})
	integ := e.seed(fixture{state: sApproved, attempts: 1})
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	if a, b := e.tick().Claimed, e.tick().Claimed; a != integ || b != qa {
		t.Fatalf("claimed %d then %d during an escalation, want integration %d then QA %d", a, b, integ, qa)
	}
}

// --- reaping ----------------------------------------------------------------------------------

// Every leased state is reaped through the core, attempt_count untouched; a return to ready at the
// cap lands in failed; an outcome the runner reported is kept. The project is inactive, so the
// tick claims nothing after its reaps.
func TestReapsEveryLeasedState(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE projects SET is_active = false`)
	type seeded struct {
		state    callbackapi.State
		attempts int
	}
	want := map[int64]seeded{
		e.seed(fixture{state: sClaimed, attempts: 1, expired: true}):    {sReady, 1},
		e.seed(fixture{state: sInProgress, attempts: 1, expired: true}): {sReady, 1},
		e.seed(fixture{state: sInQA, attempts: 1, expired: true}):       {sAwaiting, 1},
		e.seed(fixture{state: sMerging, attempts: 1, expired: true}):    {sApproved, 1},
		e.seed(fixture{state: sInProgress, attempts: 2, expired: true}): {sFailed, 2},
		e.seed(fixture{state: sInProgress, attempts: 1}):                {sInProgress, 1}, // live
	}
	limited := e.seed(fixture{state: sInQA, attempts: 1, expired: true})
	want[limited] = seeded{sAwaiting, 1}
	e.exec(`INSERT INTO attempts (ticket_id, attempt, role, provider, model, tier, claim_token, outcome)
		SELECT id, 1, 'qa', 'anthropic', 'claude-opus-5-5', 'qa-opus', claim_token, 'rate_limited' FROM tickets WHERE id = $1`, limited)

	out := e.tick()
	for id, w := range want {
		if got := e.state(id); got != w.state {
			t.Errorf("ticket %d: %s, want %s", id, got, w.state)
		}
		if n := e.count(`SELECT attempt_count FROM tickets WHERE id = $1`, id); n != w.attempts {
			t.Errorf("ticket %d: attempt_count %d, want it untouched at %d", id, n, w.attempts)
		}
	}
	if len(out.Reaped) != 6 {
		t.Errorf("reaped %v, want six", out.Reaped)
	}
	if a := e.attempt(limited); !a.Ended || a.Outcome.String != "rate_limited" {
		t.Errorf("rate-limited attempt %+v: want ended, still rate_limited", a)
	}
}

// --- the provider per ticket ------------------------------------------------------------------

// A paused provider stops only its own tiers: with GLM paused, the ticket on its first attempt is
// passed over and the one on its second is claimed on Claude Sonnet.
func TestAPausedProviderStopsOnlyItsTiers(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE budget SET paused_until = now() + interval '1 hour' WHERE provider = 'zai'`)
	first := e.seed(fixture{state: sReady, priority: 9})
	second := e.seed(fixture{state: sReady, attempts: 1})
	out := e.tick()
	if out.Claimed != second || e.state(first) != sReady {
		t.Fatalf("claimed %d, want %d on its second attempt", out.Claimed, second)
	}
	a := e.attempt(second)
	if a.Attempt != 2 || a.Provider.String != "anthropic" || a.Model.String != "claude-sonnet-5" || a.Tier.String != "dev-sonnet" {
		t.Fatalf("attempt row %+v, want attempt 2 on claude-sonnet-5", a)
	}
	if e.consumed("zai") != 0 || e.consumed("anthropic") != 1 {
		t.Fatalf("budgets zai %v anthropic %v, want 0 and 1", e.consumed("zai"), e.consumed("anthropic"))
	}

	// Claude paused stops QA (both its tiers are Claude), not GLM's new work.
	e2 := newEnv(t)
	e2.exec(`UPDATE budget SET paused_until = now() + interval '1 hour' WHERE provider = 'anthropic'`)
	qa := e2.seed(fixture{state: sAwaiting, attempts: 1})
	work := e2.seed(fixture{state: sReady})
	if out := e2.tick(); out.Claimed != work || e2.state(qa) != sAwaiting {
		t.Fatalf("claimed %d, want new work %d on GLM while Claude is paused", out.Claimed, work)
	}

	// A pause ends by itself.
	e3 := newEnv(t)
	e3.exec(`UPDATE budget SET paused_until = now() - interval '1 second' WHERE provider = 'zai'`)
	w := e3.seed(fixture{state: sReady})
	if out := e3.tick(); out.Claimed != w {
		t.Fatal("a pause that has ended still stops its provider")
	}
}

// QA's tier is the one for the dev attempt it judges.
func TestQAsTierFollowsTheAttemptItJudges(t *testing.T) {
	e := newEnv(t)
	qa := e.seed(fixture{state: sAwaiting, attempts: 2})
	if out := e.tick(); out.Claimed != qa {
		t.Fatalf("claimed %d, want %d", out.Claimed, qa)
	}
	if a := e.attempt(qa); a.Attempt != 2 || a.Role != "qa" || a.Tier.String != "qa-opus" || a.Provider.String != "anthropic" {
		t.Fatalf("attempt row %+v, want QA's tier for attempt 2", a)
	}
}

// --- budgets ----------------------------------------------------------------------------------

// A window with no unit left above its reserve stops its provider; one whose reset has passed rolls
// over to a new window of the same length starting now, and admits the claim.
func TestBudgetWindows(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE budget SET consumed_estimate = 85 WHERE provider = 'zai'`) // capacity 100, reserve 0.15
	work := e.seed(fixture{state: sReady})
	if out := e.tick(); out.Claimed != 0 || e.state(work) != sReady {
		t.Fatal("claimed on a provider with no unit left above its reserve")
	}

	e.exec(`UPDATE budget SET consumed_estimate = 100, window_started_at = now() - interval '6 hours',
		window_resets_at = now() - interval '1 hour' WHERE provider = 'zai'`)
	before := time.Now().Add(-time.Second)
	if out := e.tick(); out.Claimed != work {
		t.Fatal("a window whose reset has passed did not admit the claim")
	}
	var started, resets time.Time
	var consumed float64
	if err := e.db.QueryRow(`SELECT window_started_at, window_resets_at, consumed_estimate FROM budget WHERE provider = 'zai'`).
		Scan(&started, &resets, &consumed); err != nil {
		t.Fatal(err)
	}
	if started.Before(before) || resets.Sub(started) != 5*time.Hour || consumed != 1 {
		t.Fatalf("window %s to %s, consumed %v: want a new five-hour window from now, one unit used", started, resets, consumed)
	}
}

// A launch that definitely did not start returns the ticket at once and refunds its unit; not after
// the window rolled over since the charge; never for the integrator, which used none.
func TestAFailedLaunchIsRefunded(t *testing.T) {
	e := newEnv(t)
	e.launcher.fail = func(dispatcher.LaunchRequest) bool { return true }
	work := e.seed(fixture{state: sReady})
	out := e.tick()
	if !out.LaunchFailed || e.state(work) != sReady || e.consumed("zai") != 0 {
		t.Fatalf("outcome %+v, state %s, zai %v: want returned at once and refunded", out, e.state(work), e.consumed("zai"))
	}
	if a := e.attempt(work); !a.Ended || a.Outcome.String != "launch_failed" {
		t.Fatalf("attempt %+v, want ended as launch_failed", a)
	}

	// Another tick rolled the window over between the charge and the failure: no refund, or the
	// new window would start at -1.
	e2 := newEnv(t)
	e2.launcher.onLaunch = func(dispatcher.LaunchRequest) {
		e2.exec(`UPDATE budget SET window_started_at = clock_timestamp(), window_resets_at = clock_timestamp() + interval '5 hours',
			consumed_estimate = 0 WHERE provider = 'zai'`)
	}
	e2.launcher.fail = func(dispatcher.LaunchRequest) bool { return true }
	e2.seed(fixture{state: sReady})
	e2.tick()
	if c := e2.consumed("zai"); c != 0 {
		t.Fatalf("zai consumed %v after a refund across a rollover, want 0", c)
	}

	e3 := newEnv(t)
	e3.launcher.fail = func(dispatcher.LaunchRequest) bool { return true }
	integ := e3.seed(fixture{state: sApproved, attempts: 1})
	if out := e3.tick(); !out.LaunchFailed || e3.state(integ) != sApproved {
		t.Fatalf("outcome %+v: want the integration returned", out)
	}
	if e3.consumed("zai") != 0 || e3.consumed("anthropic") != 0 {
		t.Fatal("an integrator launch touched a budget")
	}
	if a := e3.attempt(integ); a.Provider.Valid || a.Model.Valid || a.Tier.Valid {
		t.Fatalf("integrator attempt %+v names a model", a)
	}
}

// A tier's provider with no budget row fails the tick loudly, after its reaps.
func TestAProviderWithNoBudgetRowFailsTheTick(t *testing.T) {
	e := newEnv(t)
	e.exec(`DELETE FROM budget WHERE provider = 'zai'`)
	reaped := e.seed(fixture{state: sClaimed, expired: true})
	work := e.seed(fixture{state: sReady, priority: 9})
	if _, err := e.d.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "zai") {
		t.Fatalf("err = %v, want the missing budget row named", err)
	}
	if e.state(reaped) != sReady || e.state(work) != sReady || e.count(`SELECT count(*) FROM attempts`) != 0 {
		t.Fatal("want the reap done and nothing claimed")
	}
}

// --- ls-remote and the two transactions -------------------------------------------------------

// A new-work claim records the head the remote reports for the default branch, read with real git.
func TestNewWorkRecordsTheRemotesHead(t *testing.T) {
	e := newEnv(t)
	r := gitfixture.New(t, filepath.Join(t.TempDir(), "remote.git"))
	head := r.Commit(nil, "one", gitfixture.Text("README", "1\n"))
	r.Git("update-ref", "refs/heads/main", head)
	e.exec(`UPDATE projects SET repo_url = $1 WHERE id = 'foreman'`, r.Dir)
	tiers, _ := dispatcher.EmbeddedTiers()
	d := dispatcher.New(e.db, callbackapi.NewEngine(nil, quietLog()), tiers, riskevaltest.GitAllowingFile(t), e.launcher, quietLog())
	work := e.seed(fixture{state: sReady})
	if out, err := d.Tick(context.Background()); err != nil || out.Claimed != work {
		t.Fatalf("tick: %+v, %v", out, err)
	}
	var branch, base string
	if err := e.db.QueryRow(`SELECT branch, base_sha FROM tickets WHERE id = $1`, work).Scan(&branch, &base); err != nil {
		t.Fatal(err)
	}
	if base != head || branch != "foreman/"+itoa(work)+"/1" {
		t.Fatalf("branch %s, base %s; want foreman/%d/1 at %s", branch, base, work, head)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// With nothing new work could claim, the tick ends without a network call: here the only ready
// ticket needs GLM, which is paused.
func TestNoCandidateNoNetworkCall(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE budget SET paused_until = now() + interval '1 hour' WHERE provider = 'zai'`)
	e.seed(fixture{state: sReady})
	if out := e.tick(); out.Claimed != 0 || e.remote.count() != 0 {
		t.Fatalf("outcome %+v, ls-remote calls %d: want nothing claimed and no call", out, e.remote.count())
	}
}

// If ls-remote fails, no new work is claimed that tick; the other queues were tried first.
func TestLsRemoteFailingSkipsOnlyNewWork(t *testing.T) {
	e := newEnv(t)
	e.remote.err = errors.New("the remote is unreachable")
	work := e.seed(fixture{state: sReady})
	if out := e.tick(); out.Claimed != 0 || e.state(work) != sReady || e.remote.count() != 1 {
		t.Fatalf("outcome %+v with ls-remote failing", out)
	}
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	if out := e.tick(); out.Claimed != qa || e.remote.count() != 1 {
		t.Fatalf("claimed %d (ls-remote calls %d), want QA %d with no ls-remote", out.Claimed, e.remote.count(), qa)
	}
}

// Between the two transactions the project may change: a different active project, or a changed
// repo_url or default branch, and no new work is claimed on a head read for something else.
func TestTheProjectChangingBetweenTransactionsSkipsNewWork(t *testing.T) {
	for name, change := range map[string][]string{
		"another project active": {`UPDATE projects SET is_active = false WHERE id = 'foreman'`,
			`INSERT INTO projects (id, name, repo_url, is_active) VALUES ('other', 'other', 'https://example.invalid/other', true)`},
		"repo_url changed":       {`UPDATE projects SET repo_url = 'https://example.invalid/moved' WHERE id = 'foreman'`},
		"default branch changed": {`UPDATE projects SET default_branch = 'trunk' WHERE id = 'foreman'`},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			work := e.seed(fixture{state: sReady})
			e.remote.onCall = func() {
				for _, stmt := range change {
					e.exec(stmt)
				}
			}
			if out := e.tick(); out.Claimed != 0 || e.state(work) != sReady {
				t.Fatalf("claimed %d after the project changed under ls-remote", out.Claimed)
			}
		})
	}
}

// Transaction 2 runs the whole pick again: QA work that became claimable during ls-remote is
// claimed instead of new work, and the head read is discarded.
func TestTheSecondTransactionKeepsTheQueueOrder(t *testing.T) {
	e := newEnv(t)
	work := e.seed(fixture{state: sReady})
	late := e.seed(fixture{state: sDraft, attempts: 1})
	e.remote.onCall = func() {
		e.exec(`UPDATE tickets SET state = 'awaiting_review', head_sha = '4444444444444444444444444444444444444444' WHERE id = $1`, late)
	}
	if out := e.tick(); out.Claimed != late || e.state(work) != sReady {
		t.Fatalf("claimed %d, want the QA ticket %d that arrived during ls-remote", out.Claimed, late)
	}
}

// --- the launch -------------------------------------------------------------------------------

func TestTheLaunchRequest(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE projects SET repo_url = 'https://example.invalid/foreman.git' WHERE id = 'foreman'`)
	work := e.seed(fixture{state: sReady})
	out := e.tick()
	reqs := e.launcher.launched()
	if len(reqs) != 1 {
		t.Fatalf("%d launches", len(reqs))
	}
	var token string
	e.db.QueryRow(`SELECT claim_token FROM tickets WHERE id = $1`, work).Scan(&token)
	want := dispatcher.LaunchRequest{
		TicketID: work, Project: "foreman", RepoURL: "https://example.invalid/foreman.git",
		Role: callbackapi.RoleDev, ServiceAccount: "dev-foreman@your-project-id.iam.gserviceaccount.com",
		Branch: "foreman/" + itoa(work) + "/1", BaseSHA: baseSHA, ClaimToken: token, Attempt: 1,
		Provider: "zai", Model: "glm-5.3-flash", Tier: "dev-glm-flash", Credential: "zai-api-key", Title: "fixture",
	}
	if reqs[0] != want {
		t.Fatalf("launch request\n%+v\nwant\n%+v", reqs[0], want)
	}
	if a := e.attempt(work); a.LaunchID.String != out.LaunchID || out.LaunchID == "" || a.Token != token {
		t.Fatalf("attempt %+v, outcome %+v: want the launch id recorded", a, out)
	}

	e2 := newEnv(t)
	integ := e2.seed(fixture{state: sApproved, attempts: 1})
	e2.tick()
	r := e2.launcher.launched()[0]
	if r.TicketID != integ || r.Role != callbackapi.RoleIntegrator || r.Provider != "" || r.Credential != "" ||
		r.HeadSHA == "" || r.ServiceAccount != "integrator-foreman@your-project-id.iam.gserviceaccount.com" {
		t.Fatalf("integrator launch %+v", r)
	}
}

// The launch request carries the ticket's title, the echo runner's instruction (P06 D14), cut to
// dispatcher.MaxTitle characters: it travels in the execution's environment, and the API sets no
// limit. A title at the bound is whole; one past it is cut at a character, never inside one.
func TestTheLaunchRequestCarriesTheTitleBounded(t *testing.T) {
	for name, c := range map[string]struct{ title, want string }{
		"short":        {"[echo:escalate] stop here", "[echo:escalate] stop here"},
		"at the bound": {strings.Repeat("é", dispatcher.MaxTitle), strings.Repeat("é", dispatcher.MaxTitle)},
		"past it":      {strings.Repeat("é", dispatcher.MaxTitle) + "überlang", strings.Repeat("é", dispatcher.MaxTitle)},
		"far past it":  {strings.Repeat("x", 10*dispatcher.MaxTitle), strings.Repeat("x", dispatcher.MaxTitle)},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			id := e.seed(fixture{state: sReady})
			e.exec(`UPDATE tickets SET title = $1 WHERE id = $2`, c.title, id)
			e.tick()
			reqs := e.launcher.launched()
			if len(reqs) != 1 || reqs[0].Title != c.want || !utf8.ValidString(reqs[0].Title) {
				t.Fatalf("launched %d with title %q, want %q", len(reqs), firstTitle(reqs), c.want)
			}
		})
	}
	if dispatcher.MaxTitle < 100 || dispatcher.MaxTitle > 1000 {
		t.Fatalf("MaxTitle %d: a title must fit, and an environment override stay small", dispatcher.MaxTitle)
	}
}

func firstTitle(reqs []dispatcher.LaunchRequest) string {
	if len(reqs) == 0 {
		return ""
	}
	return reqs[0].Title
}

// Three failed launches in a row escalate: for new work, and for QA, whose next ticket is then
// claimed (an escalation stops new work only).
func TestThreeFailedLaunchesEscalate(t *testing.T) {
	e := newEnv(t)
	e.launcher.fail = func(dispatcher.LaunchRequest) bool { return true }
	work := e.seed(fixture{state: sReady})
	for i := 1; i <= 3; i++ {
		e.tick()
	}
	if s := e.state(work); s != sEscalated {
		t.Fatalf("state %s after three failed launches, want escalated", s)
	}

	e2 := newEnv(t)
	e2.launcher.fail = func(r dispatcher.LaunchRequest) bool { return r.Role == callbackapi.RoleQA }
	first := e2.seed(fixture{state: sAwaiting, attempts: 1, priority: 9})
	next := e2.seed(fixture{state: sAwaiting, attempts: 1})
	for i := 1; i <= 3; i++ {
		e2.tick()
	}
	if s := e2.state(first); s != sEscalated {
		t.Fatalf("QA ticket %s after three failed launches, want escalated", s)
	}
	if out := e2.tick(); out.Claimed != next {
		t.Fatalf("claimed %d, want the next QA ticket %d", out.Claimed, next)
	}
}

// If the tick dies after the claim commits, the lease expires and a later tick reaps it.
func TestATickKilledAfterTheCommitIsReaped(t *testing.T) {
	e := newEnv(t)
	dispatcher.SetHooks(e.d, dispatcher.Hooks{AfterCommit: func() bool { return true }})
	work := e.seed(fixture{state: sReady})
	if out := e.tick(); out.Claimed != work || len(e.launcher.launched()) != 0 || e.state(work) != sClaimed {
		t.Fatalf("outcome %+v, %d launches: want claimed and nothing launched", out, len(e.launcher.launched()))
	}
	dispatcher.SetHooks(e.d, dispatcher.Hooks{})
	e.exec(`UPDATE tickets SET lease_expires_at = now() - interval '1 second' WHERE id = $1`, work)
	e.exec(`UPDATE projects SET is_active = false`)
	if out := e.tick(); len(out.Reaped) != 1 || e.state(work) != sReady {
		t.Fatalf("outcome %+v, state %s: want the claim reaped", out, e.state(work))
	}
	if a := e.attempt(work); a.Outcome.String != "reaped" {
		t.Fatalf("attempt %+v, want reaped", a)
	}
}

// Only the roles the launcher can start for the project are claimed (P05 D8, D20): with dev alone,
// a QA ticket rests at awaiting_review while new work is claimed.
func TestOnlyLaunchableRolesAreClaimed(t *testing.T) {
	e := newEnv(t)
	e.launcher.roles = []callbackapi.Role{callbackapi.RoleDev}
	qa := e.seed(fixture{state: sAwaiting, attempts: 1})
	integ := e.seed(fixture{state: sApproved, attempts: 1})
	work := e.seed(fixture{state: sReady})
	if out := e.tick(); out.Claimed != work {
		t.Fatalf("claimed %d, want the new work %d", out.Claimed, work)
	}
	if e.state(qa) != sAwaiting || e.state(integ) != sApproved {
		t.Fatalf("a ticket whose role cannot be launched was claimed: QA %s, integration %s", e.state(qa), e.state(integ))
	}
	e2 := newEnv(t)
	e2.launcher.roles = []callbackapi.Role{callbackapi.RoleDev}
	e2.seed(fixture{state: sAwaiting, attempts: 1})
	if out := e2.tick(); out.Claimed != 0 || !strings.Contains(out.Note, "nothing to claim") {
		t.Fatalf("outcome %+v, want nothing claimed", out)
	}
}

// The recording launcher, for local runs, starts every runner role.
func TestTheRecordingLauncherStartsEveryRole(t *testing.T) {
	got := dispatcher.NewRecordingLauncher(io.Discard).Roles("any")
	want := map[callbackapi.Role]bool{callbackapi.RoleDev: true, callbackapi.RoleQA: true, callbackapi.RoleIntegrator: true,
		callbackapi.RoleSpec: true, callbackapi.RoleArchitect: true}
	if len(got) != len(want) {
		t.Fatalf("roles %v", got)
	}
	for _, r := range got {
		if !want[r] {
			t.Fatalf("roles %v", got)
		}
	}
}
