package callbackapi_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	riskevaluator "github.com/ryanymt/mercurio-project/internal/risk_evaluator"
	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/gitfixture"
	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/riskevaltest"
)

// The risk evaluator behind `in_qa -> approved` (P03 T5): real git repositories, the real
// evaluator, the real engine, and over HTTP the real handler.

// A test policy with the three rules evaluated in P03 and none of the late ones.
const earlyPolicy = `version: 1
fail_closed: true
rules:
  - id: protected_paths
    reason: "Touches a path that requires human review"
    match:
      any_path: ["auth/**", "infra/**"]
  - id: size
    reason: "Change is large enough to warrant a human read"
    match:
      files_changed_gt: 15
      lines_changed_gt: 600
  - id: dependency_change
    reason: "Adds, removes, or bumps a dependency"
    match:
      any_path: ["**/go.mod", "**/go.sum"]
`

// history is a repository with a base commit and heads built on it.
type history struct {
	repos string
	repo  *gitfixture.Repo
	base  string
}

func newHistory(t *testing.T) history {
	t.Helper()
	repos := t.TempDir()
	r := gitfixture.New(t, filepath.Join(repos, "foreman.git"))
	base := r.Commit(nil, "base", gitfixture.Text("README", "one\n"), gitfixture.Text("pkg/util.go", "package pkg\n"))
	return history{repos: repos, repo: r, base: base}
}

// head commits the base's files plus changes on top of the base.
func (h history) head(t *testing.T, files ...gitfixture.File) string {
	t.Helper()
	all := []gitfixture.File{gitfixture.Text("README", "one\n"), gitfixture.Text("pkg/util.go", "package pkg\n")}
	for _, f := range files {
		all = slices.DeleteFunc(all, func(g gitfixture.File) bool { return g.Path == f.Path })
		all = append(all, f)
	}
	return h.repo.Commit([]string{h.base}, "head", all...)
}

func riskEngine(t *testing.T, repos string) *callbackapi.Engine {
	t.Helper()
	return callbackapi.NewEngine(riskevaltest.Evaluator(t, repos, riskevaltest.Policy(t, "foreman", earlyPolicy)), nil)
}

func approveAs(id int64, c callbackapi.Caller, sha string) callbackapi.TransitionRequest {
	r := request(id, sInQA, sApproved, c, chHTTP)
	r.HeadSHA = sha
	return r
}

type storedVerdict struct {
	Cleared      bool              `json:"cleared"`
	MatchedRules []string          `json:"matched_rules"`
	Reasons      map[string]string `json:"reasons"`
	Reason       string            `json:"reason"`
	EvaluatedAt  time.Time         `json:"evaluated_at"`
	BaseSHA      string            `json:"base_sha"`
	HeadSHA      string            `json:"head_sha"`
	TestedSHA    string            `json:"tested_sha"`
	Policy       *struct {
		Project string `json:"project"`
		SHA256  string `json:"sha256"`
	} `json:"policy"`
}

func verdictOf(t *testing.T, conn *sql.DB, id int64) storedVerdict {
	t.Helper()
	var raw []byte
	if err := conn.QueryRow(`SELECT risk_verdict FROM tickets WHERE id = $1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var v storedVerdict
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("risk_verdict %s: %v", raw, err)
	}
	return v
}

func headOf(t *testing.T, conn *sql.DB, id int64) sql.NullString {
	t.Helper()
	var h sql.NullString
	if err := conn.QueryRow(`SELECT head_sha FROM tickets WHERE id = $1`, id).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

// A protected path escalates, and the verdict is in the row, the event and the answer, stamped
// with the transaction's time.
func TestRiskProtectedChangeEscalates(t *testing.T) {
	h := newHistory(t)
	head := h.head(t, gitfixture.Text("auth/login.py", "x = 1\n"))
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInQA, attempts: 1, baseSHA: h.base, headSHA: head})

	res := mustDo(t, riskEngine(t, h.repos), conn, approveAs(id, qa, head))
	if res.State != sEscalated || res.Actor != callbackapi.RoleRiskEvaluator || res.Verdict == nil || res.Verdict.Cleared {
		t.Fatalf("result %+v", res)
	}
	v := verdictOf(t, conn, id)
	if v.Cleared || !slices.Contains(v.MatchedRules, "protected_paths") || !strings.Contains(v.Reasons["protected_paths"], "auth/login.py") ||
		v.BaseSHA != h.base || v.HeadSHA != head || v.Policy == nil || v.Policy.Project != "foreman" || len(v.Policy.SHA256) != 64 {
		t.Fatalf("stored verdict %+v", v)
	}
	ev := lastEvent(t, conn, id)
	var payload struct {
		Verdict storedVerdict `json:"risk_verdict"`
	}
	if err := json.Unmarshal(ev.Payload, &payload); err != nil || !slices.Equal(payload.Verdict.MatchedRules, v.MatchedRules) {
		t.Fatalf("event payload %s: %v", ev.Payload, err)
	}
	var created time.Time
	if err := conn.QueryRow(`SELECT created_at FROM ticket_events WHERE ticket_id = $1 ORDER BY id DESC LIMIT 1`, id).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if !v.EvaluatedAt.Equal(created) || !res.Verdict.EvaluatedAt.Equal(created) {
		t.Fatalf("evaluated_at %s (answer %s), event at %s: want the transaction's time",
			v.EvaluatedAt, res.Verdict.EvaluatedAt, created)
	}
	if k := cols(t, conn, id); !k.EscalationReason.Valid || !strings.Contains(k.EscalationReason.String, "protected_paths") {
		t.Fatalf("escalation reason %+v", k.EscalationReason)
	}
}

// A one-line change outside every protected path clears, under a test policy.
func TestRiskOneLineChangeClears(t *testing.T) {
	h := newHistory(t)
	head := h.head(t, gitfixture.Text("pkg/util.go", "package pkg\n\nvar x = 1\n"))
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInQA, attempts: 1, baseSHA: h.base, headSHA: head})
	res := mustDo(t, riskEngine(t, h.repos), conn, approveAs(id, qa, head))
	if res.State != sApproved || res.Actor != callbackapi.RoleQA || res.Verdict == nil || !res.Verdict.Cleared {
		t.Fatalf("result %+v", res)
	}
	if v := verdictOf(t, conn, id); !v.Cleared || len(v.MatchedRules) != 0 || v.EvaluatedAt.IsZero() {
		t.Fatalf("stored verdict %+v", v)
	}
}

// The same two, over HTTP: the verdict is in the 200 answer.
func TestRiskOverHTTP(t *testing.T) {
	h := newHistory(t)
	protected := h.head(t, gitfixture.Text("infra/main.tf", "x\n"))
	clean := h.head(t, gitfixture.Text("pkg/util.go", "package pkg\n\nvar y = 2\n"))
	a := newAPIWith(t, riskEngine(t, h.repos))
	for _, c := range []struct {
		head, want string
		cleared    bool
	}{{protected, "escalated", false}, {clean, "approved", true}} {
		id := seed(t, a.conn, fixture{state: sInQA, attempts: 1, baseSHA: h.base, headSHA: c.head})
		st, b := a.do(call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/transitions", id), token: a.tokenFor(qa.Email),
			key: newRequestID(), claim: liveToken, body: map[string]any{"from": sInQA, "to": sApproved, "head_sha": c.head}})
		wantHTTP(t, st, 200, b)
		v, _ := b["verdict"].(map[string]any)
		if b["state"] != c.want || v == nil || v["cleared"] != c.cleared {
			t.Fatalf("answer %v", b)
		}
	}
}

// Every failure escalates; none approves (Anchor, "Fail closed, by test").
func TestRiskFailsClosed(t *testing.T) {
	h := newHistory(t)
	good := h.head(t, gitfixture.Text("pkg/util.go", "package pkg\n\nvar z = 3\n"))
	empty := h.head(t)
	notUTF8 := h.head(t, gitfixture.Text("pkg/\xff.go", "package pkg\n"))
	many := h.base
	var files []gitfixture.File
	for i := range 40 {
		files = append(files, gitfixture.Text(fmt.Sprintf("pkg/generated/%02d_%s.go", i, strings.Repeat("x", 30)), "package generated\n"))
	}
	many = h.head(t, files...)
	other := runner(callbackapi.RoleQA, "other")

	cases := []struct {
		name         string
		engine       func(t *testing.T) *callbackapi.Engine
		project      string
		caller       callbackapi.Caller
		base, head   string
		wantInReason string
	}{
		{"no policy for the project", func(t *testing.T) *callbackapi.Engine { return riskEngine(t, h.repos) }, "other", other, h.base, good, "policy"},
		{"missing repository", func(t *testing.T) *callbackapi.Engine { return riskEngine(t, t.TempDir()) }, "", qa, h.base, good, "repository"},
		{"unknown sha", func(t *testing.T) *callbackapi.Engine { return riskEngine(t, h.repos) }, "", qa, h.base, strings.Repeat("ab", 20), "commit"},
		{"head not descending from base", func(t *testing.T) *callbackapi.Engine { return riskEngine(t, h.repos) }, "", qa, good, h.base, "descend"},
		{"no base_sha", func(t *testing.T) *callbackapi.Engine { return riskEngine(t, h.repos) }, "", qa, "", good, "base"},
		{"output over the cap", func(t *testing.T) *callbackapi.Engine {
			return callbackapi.NewEngine(riskevaltest.EvaluatorWithGit(t, h.repos, riskevaluator.NewGit(10*time.Second, 300),
				riskevaltest.Policy(t, "foreman", earlyPolicy)), nil)
		}, "", qa, h.base, many, "cap"},
		{"no changed paths", func(t *testing.T) *callbackapi.Engine { return riskEngine(t, h.repos) }, "", qa, h.base, empty, "empty_diff"},
		{"a path that is not UTF-8", func(t *testing.T) *callbackapi.Engine { return riskEngine(t, h.repos) }, "", qa, h.base, notUTF8, "unreadable_path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := fresh(t)
			if c.project != "" {
				addProject(t, conn, c.project)
			}
			id := seed(t, conn, fixture{project: c.project, state: sInQA, attempts: 1, baseSHA: c.base, headSHA: c.head})
			res, err := do(t, c.engine(t), conn, approveAs(id, c.caller, c.head))
			if err != nil {
				t.Fatalf("a failure became an error, not an escalation: %v", err)
			}
			if res.State != sEscalated || state(t, conn, id) != sEscalated || res.Actor != callbackapi.RoleRiskEvaluator {
				t.Fatalf("result %+v", res)
			}
			v := verdictOf(t, conn, id)
			if v.Cleared {
				t.Fatalf("a cleared verdict on failure: %+v", v)
			}
			if k := cols(t, conn, id); !strings.Contains(k.EscalationReason.String+" "+strings.Join(v.MatchedRules, " "), c.wantInReason) {
				t.Fatalf("reason %q, rules %v: want %q in them", k.EscalationReason.String, v.MatchedRules, c.wantInReason)
			}
		})
	}
}

// QA naming another commit than the one submitted escalates, clears head_sha, and leaves only a
// new attempt, failure or abandonment (D10, D14).
func TestQAShaMismatch(t *testing.T) {
	h := newHistory(t)
	head := h.head(t, gitfixture.Text("pkg/util.go", "package pkg\n\nvar w = 4\n"))
	tested := strings.Repeat("cd", 20)
	conn := fresh(t)
	e := riskEngine(t, h.repos)
	id := seed(t, conn, fixture{state: sInQA, attempts: 1, baseSHA: h.base, headSHA: head})
	res := mustDo(t, e, conn, approveAs(id, qa, tested))
	if res.State != sEscalated || res.Actor != callbackapi.RoleRiskEvaluator || res.Verdict == nil ||
		!slices.Equal(res.Verdict.MatchedRules, []string{callbackapi.RuleQAShaMismatch}) {
		t.Fatalf("result %+v", res)
	}
	v := verdictOf(t, conn, id)
	if v.HeadSHA != head || v.TestedSHA != tested || !strings.Contains(v.Reason, head) || !strings.Contains(v.Reason, tested) {
		t.Fatalf("verdict %+v: want both shas named", v)
	}
	if headOf(t, conn, id).Valid {
		t.Fatal("head_sha survived a QA mismatch")
	}
	// Decided on the escalation as it happened here: an approval has no commit to land (409), a
	// return to ready is applied.
	at := escalatedAtOf(t, conn, id)
	approve := request(id, sEscalated, sApproved, humanCaller, chHTTP)
	approve.EscalatedAt = &at
	_, err := do(t, e, conn, approve)
	wantStatus(t, err, 409)
	ready := request(id, sEscalated, sReady, humanCaller, chHTTP)
	ready.EscalatedAt = &at
	mustDo(t, e, conn, ready)
}

// head_sha: required on submission and approval, refused elsewhere, stored, cleared on every move
// to ready, kept through merging and merged. A person's approval and a dev runner's escalation take
// one too (transitions_binding_test.go, P06 T4).
func TestHeadShaLifecycle(t *testing.T) {
	e := newEngine(nil)
	t.Run("required and well-formed on submission", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
		for _, bad := range []string{"", "abc123", strings.ToUpper(strings.Repeat("ab", 20)), strings.Repeat("a", 64)} {
			r := request(id, sInProgress, sAwaiting, dev, chHTTP)
			r.HeadSHA = bad
			_, err := do(t, e, conn, r)
			wantStatus(t, err, 400)
		}
		r := request(id, sInProgress, sAwaiting, dev, chHTTP)
		r.HeadSHA = strings.Repeat("ef", 20)
		mustDo(t, e, conn, r)
		if h := headOf(t, conn, id); h.String != r.HeadSHA {
			t.Fatalf("head_sha %v, want %s", h, r.HeadSHA)
		}
	})
	t.Run("required on approval", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sInQA, attempts: 1})
		r := request(id, sInQA, sApproved, qa, chHTTP)
		r.HeadSHA = ""
		_, err := do(t, e, conn, r)
		wantStatus(t, err, 400)
	})
	t.Run("refused on any other transition", func(t *testing.T) {
		conn := fresh(t)
		for _, c := range []struct {
			from, to callbackapi.State
			caller   callbackapi.Caller
			ch       callbackapi.Channel
		}{{sInProgress, sReady, dev, chHTTP}, {sInQA, sReady, qa, chHTTP}, {sAwaiting, sInQA, dispatcherCaller, chCore}, {sEscalated, sReady, humanCaller, chHTTP}} {
			id := seed(t, conn, fixture{state: c.from, attempts: 1})
			r := request(id, c.from, c.to, c.caller, c.ch)
			r.HeadSHA = fixtureSHA
			_, err := do(t, e, conn, r)
			wantStatus(t, err, 400)
		}
	})
	t.Run("cleared on every move to ready", func(t *testing.T) {
		conn := fresh(t)
		for _, c := range []struct {
			from   callbackapi.State
			caller callbackapi.Caller
		}{{sInQA, qa}, {sMerging, integrator}, {sEscalated, humanCaller}} {
			id := seed(t, conn, fixture{state: c.from, attempts: 1})
			mustDo(t, e, conn, request(id, c.from, sReady, c.caller, chHTTP))
			if headOf(t, conn, id).Valid {
				t.Errorf("%s -> ready kept head_sha", c.from)
			}
		}
	})
	t.Run("kept through merging and merged", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sApproved, attempts: 1})
		claim := mustDo(t, e, conn, request(id, sApproved, sMerging, dispatcherCaller, chCore))
		merge := request(id, sMerging, sMerged, integrator, chHTTP)
		merge.ClaimToken = claim.ClaimToken
		mustDo(t, e, conn, merge)
		if h := headOf(t, conn, id); h.String != fixtureSHA {
			t.Fatalf("head_sha %v after merging", h)
		}
	})
	t.Run("a replay with another head_sha is a conflict", func(t *testing.T) {
		conn := fresh(t)
		id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
		r := request(id, sInProgress, sAwaiting, dev, chHTTP)
		mustDo(t, e, conn, r)
		r.HeadSHA = strings.Repeat("0f", 20)
		_, err := do(t, e, conn, r)
		wantStatus(t, err, 409)
	})
}

// A human's escalated -> approved needs a submitted commit (D14).
func TestEscalatedToApprovedNeedsACommit(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sEscalated, attempts: 1, noHead: true})
	before := snapshot(t, conn, id)
	_, err := do(t, newEngine(nil), conn, request(id, sEscalated, sApproved, humanCaller, chHTTP))
	wantStatus(t, err, 409)
	assertUnchanged(t, conn, id, before, 0, 0)
}

// A database write cannot turn off the meta protections or choose another policy (D5, D6).
func TestTheDatabaseCannotWeakenTheGate(t *testing.T) {
	h := newHistory(t)
	head := h.head(t, gitfixture.Text("cmd/foreman/main.go", "package main\n"))
	conn := fresh(t)
	if _, err := conn.Exec(`UPDATE projects SET is_meta = false, risk_policy_path = 'x' WHERE id = 'foreman'`); err != nil {
		t.Fatal(err)
	}
	id := seed(t, conn, fixture{state: sInQA, attempts: 1, baseSHA: h.base, headSHA: head})
	e := callbackapi.NewEngine(riskevaluator.NewEvaluator(riskevaluator.EmbeddedPolicies(),
		riskevaluator.NewGit(riskevaluator.DefaultGitTimeout, riskevaluator.DefaultGitMaxOutput), h.repos), nil)
	mustDo(t, e, conn, approveAs(id, qa, head))
	v := verdictOf(t, conn, id)
	if !slices.Contains(v.MatchedRules, "protected_paths") || !strings.Contains(v.Reasons["protected_paths"], "cmd/foreman/main.go") {
		t.Fatalf("with is_meta false, cmd/foreman/main.go was not protected: %+v", v)
	}
	raw, err := os.ReadFile("../risk_evaluator/policies/foreman.yml")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if v.Policy == nil || v.Policy.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("the verdict's policy %+v is not the embedded foreman.yml", v.Policy)
	}
}

// Without FOREMAN_REPOS_DIR the evaluator escalates every approval, naming the setting.
func TestFromEnvWithoutReposDirEscalates(t *testing.T) {
	t.Setenv("FOREMAN_REPOS_DIR", "")
	e := callbackapi.NewEngine(riskevaluator.FromEnv(slog.New(slog.NewTextHandler(io.Discard, nil))), nil)
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInQA, attempts: 1, baseSHA: fixtureSHA})
	res := mustDo(t, e, conn, approveAs(id, qa, fixtureSHA))
	if res.State != sEscalated || !strings.Contains(cols(t, conn, id).EscalationReason.String, "FOREMAN_REPOS_DIR") {
		t.Fatalf("result %+v, reason %q", res, cols(t, conn, id).EscalationReason.String)
	}
}

// A replay returns the recorded answer, verdict included.
func TestRiskReplayReturnsTheVerdict(t *testing.T) {
	h := newHistory(t)
	head := h.head(t, gitfixture.Text("auth/login.py", "x\n"))
	conn := fresh(t)
	e := riskEngine(t, h.repos)
	id := seed(t, conn, fixture{state: sInQA, attempts: 1, baseSHA: h.base, headSHA: head})
	r := approveAs(id, qa, head)
	first := mustDo(t, e, conn, r)
	again := mustDo(t, e, conn, r)
	if !again.Replayed || again.Verdict == nil || !slices.Equal(again.Verdict.MatchedRules, first.Verdict.MatchedRules) ||
		!again.Verdict.EvaluatedAt.Equal(first.Verdict.EvaluatedAt) {
		t.Fatalf("first %+v, replay %+v", first.Verdict, again.Verdict)
	}
	if n := eventCount(t, conn, id); n != 1 {
		t.Fatalf("%d events after a replay", n)
	}
}

// End to end: a branch built on a later main that puts back a protected file escalates, though
// the net diff does not show the file (Anchor, "Rules"; D12).
func TestRiskCatchesARevertOfMain(t *testing.T) {
	repos := t.TempDir()
	r := gitfixture.New(t, filepath.Join(repos, "foreman.git"))
	base := r.Commit(nil, "base", gitfixture.Text("auth/login.py", "v1\n"), gitfixture.Text("README", "r1\n"))
	fix := r.Commit([]string{base}, "a protected fix lands on main", gitfixture.Text("auth/login.py", "v2\n"), gitfixture.Text("README", "r1\n"))
	head := r.Commit([]string{fix}, "the branch puts v1 back", gitfixture.Text("auth/login.py", "v1\n"), gitfixture.Text("README", "r2\n"))
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInQA, attempts: 1, baseSHA: base, headSHA: head})
	res := mustDo(t, riskEngine(t, repos), conn, approveAs(id, qa, head))
	v := verdictOf(t, conn, id)
	if res.State != sEscalated || !slices.Contains(v.MatchedRules, "protected_paths") || !strings.Contains(v.Reasons["protected_paths"], "auth/login.py") {
		t.Fatalf("result %+v, verdict %+v", res, v)
	}
}

// No endpoint accepts a diff: a transition body naming one is refused, like any unknown field.
func TestNoEndpointAcceptsADiff(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sInQA, attempts: 1})
	for _, field := range []string{"diff", "changes", "changed_paths"} {
		st, b := a.do(call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/transitions", id), token: a.tokenFor(qa.Email),
			key: newRequestID(), claim: liveToken,
			body: map[string]any{"from": sInQA, "to": sApproved, "head_sha": fixtureSHA, field: "README | 1 +"}})
		wantHTTP(t, st, 400, b)
	}
	if state(t, a.conn, id) != sInQA {
		t.Fatal("the ticket moved")
	}
}
