package riskevaluator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// Evaluator is the production risk evaluator the callback API calls on `in_qa -> approved`
// (P03 Approach 6): the git adapter lists the changes between the ticket's base and submitted
// commits, and the pure function applies the project's policy. Every failure is an error, which
// the engine turns into an escalation naming it.
type Evaluator struct {
	policies *PolicySet
	git      *Git
	reposDir string
	setupErr error // what FromEnv found wrong: every evaluation escalates naming it
}

// NewEvaluator builds an evaluator from policies, git and the directory of bare repositories.
func NewEvaluator(policies *PolicySet, git *Git, reposDir string) *Evaluator {
	return &Evaluator{policies: policies, git: git, reposDir: reposDir}
}

// PolicySetOf holds already-loaded policies, one per project.
func PolicySetOf(policies ...*Policy) *PolicySet {
	s := &PolicySet{byProject: map[string]policyResult{}}
	for _, p := range policies {
		s.byProject[p.Project()] = policyResult{policy: p}
	}
	return s
}

// Evaluate returns the verdict for one approval, or why there is none.
func (e *Evaluator) Evaluate(ctx context.Context, s callbackapi.Subject) (callbackapi.Verdict, error) {
	if e.setupErr != nil {
		return callbackapi.Verdict{}, e.setupErr
	}
	policy, err := e.policies.For(s.Project)
	if err != nil {
		return callbackapi.Verdict{}, err
	}
	if s.BaseSHA == "" {
		return callbackapi.Verdict{}, errors.New("the ticket has no base_sha to diff from")
	}
	if s.HeadSHA == "" {
		return callbackapi.Verdict{}, errors.New("the ticket has no submitted head_sha")
	}
	changes, err := e.git.Changes(ctx, e.reposDir, s.Project, s.BaseSHA, s.HeadSHA)
	if err != nil {
		return callbackapi.Verdict{}, err
	}
	res := Evaluate(changes, Subject{Project: s.Project, Meta: s.IsMeta || isMetaProject(s.Project)}, policy)
	v := callbackapi.Verdict{
		Cleared: res.Cleared, MatchedRules: res.MatchedRules, Reasons: res.Reasons,
		Policy: &callbackapi.PolicyRef{Project: policy.Project(), SHA256: policy.SHA256()},
	}
	if !v.Cleared {
		v.Reason = fmt.Sprintf("risk policy matched %s", strings.Join(res.MatchedRules, ", "))
	}
	return v, nil
}
