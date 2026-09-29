package callbackapi

import (
	"context"
	"fmt"
	"time"
)

// RuleQAShaMismatch is the verdict's rule id when QA names another commit than the one the dev
// runner submitted (P03 D10). The risk evaluator reserves it: no policy may use it.
const RuleQAShaMismatch = "qa_sha_mismatch"

// Subject is what the engine tells the risk evaluator about a ticket being approved. IsMeta is
// `projects.is_meta` as the database has it: the evaluator adds its own compiled-in meta projects,
// so a database write can add the protections but never remove them (P03 D6).
type Subject struct {
	TicketID int64
	Project  string
	IsMeta   bool
	BaseSHA  string // empty when the ticket has none
	HeadSHA  string // the submitted commit, which QA named when approving
}

// PolicyRef identifies the policy a verdict was reached under: its project and its file's SHA-256.
type PolicyRef struct {
	Project string `json:"project"`
	SHA256  string `json:"sha256"`
}

// Verdict is the risk evaluator's answer for one `in_qa -> approved` attempt. The engine stamps
// the time and the shas; it is stored in `tickets.risk_verdict`, carried in the event's payload
// and returned in the answer (docs/risk-policy.md, "Verdict shape").
type Verdict struct {
	Cleared      bool              `json:"cleared"`
	MatchedRules []string          `json:"matched_rules"`
	Reasons      map[string]string `json:"reasons,omitempty"`
	Reason       string            `json:"reason,omitempty"`
	EvaluatedAt  time.Time         `json:"evaluated_at"`
	BaseSHA      string            `json:"base_sha,omitempty"`
	HeadSHA      string            `json:"head_sha,omitempty"`
	TestedSHA    string            `json:"tested_sha,omitempty"`
	Policy       *PolicyRef        `json:"policy,omitempty"`
}

// Evaluator decides whether an approval may stand (docs/architecture.md, "Risk evaluator"). The
// engine calls it synchronously on every `in_qa -> approved` whose tested commit is the submitted
// one; anything but a clear verdict with no matched rule, including an error or a panic, escalates.
type Evaluator interface {
	Evaluate(ctx context.Context, s Subject) (Verdict, error)
}

// FailClosed clears nothing, so every approval escalates. It is the engine's default when no
// evaluator is given (P02 D3).
type FailClosed struct{}

// Evaluate never clears.
func (FailClosed) Evaluate(context.Context, Subject) (Verdict, error) {
	return Verdict{
		MatchedRules: []string{},
		Reason:       "no risk evaluator is installed: every approval escalates, fail closed",
	}, nil
}

// evaluate calls the evaluator and turns every failure into an uncleared verdict: fail closed.
func (e *Engine) evaluate(ctx context.Context, s Subject) (v Verdict) {
	defer func() {
		if r := recover(); r != nil {
			v = Verdict{MatchedRules: []string{}, Reason: fmt.Sprintf("risk evaluator panicked: %v", r)}
		}
	}()
	v, err := e.evaluator.Evaluate(ctx, s)
	if err != nil {
		return Verdict{MatchedRules: []string{}, Reason: "risk evaluator failed: " + err.Error()}
	}
	if v.MatchedRules == nil {
		v.MatchedRules = []string{}
	}
	if v.Cleared && len(v.MatchedRules) > 0 {
		// A cleared verdict that matched a rule contradicts itself; any single rule escalates.
		v.Cleared = false
		v.Reason = "risk evaluator cleared the ticket but matched rules: treated as not cleared"
	}
	if !v.Cleared && v.Reason == "" {
		v.Reason = fmt.Sprintf("risk evaluator matched %v", v.MatchedRules)
	}
	return v
}

// qaMismatch is the verdict when QA names another commit than the submitted one: the evaluator is
// not asked, since what QA tested is not what would be evaluated or merged.
func qaMismatch(submitted, tested string) Verdict {
	if submitted == "" {
		submitted = "none"
	}
	reason := fmt.Sprintf("QA tested %s, but the submitted commit is %s", tested, submitted)
	return Verdict{MatchedRules: []string{RuleQAShaMismatch}, Reasons: map[string]string{RuleQAShaMismatch: reason}, Reason: reason}
}
