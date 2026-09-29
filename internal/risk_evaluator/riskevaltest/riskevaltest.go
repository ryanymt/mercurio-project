// Package riskevaltest builds risk policies for tests, including policies without the late rules,
// which the production loader refuses. Only tests import it; the loader it calls refuses to run
// outside go test, and a test checks the command never links this package (P03 D13).
package riskevaltest

import (
	"testing"

	riskevaluator "github.com/ryanymt/mercurio-project/internal/risk_evaluator"
)

// Policy loads a test policy for project from doc, failing the test if it does not load.
func Policy(t testing.TB, project, doc string) *riskevaluator.Policy {
	t.Helper()
	p, err := riskevaluator.LoadTestPolicy(project, []byte(doc))
	if err != nil {
		t.Fatalf("test policy for %s: %v", project, err)
	}
	return p
}

// Evaluator is a production evaluator over the given policies and the bare repositories under
// repos, with git's default bounds.
func Evaluator(t testing.TB, repos string, policies ...*riskevaluator.Policy) *riskevaluator.Evaluator {
	t.Helper()
	return EvaluatorWithGit(t, repos, riskevaluator.NewGit(riskevaluator.DefaultGitTimeout, riskevaluator.DefaultGitMaxOutput), policies...)
}

// EvaluatorWithGit is Evaluator with a given git, for other bounds.
func EvaluatorWithGit(t testing.TB, repos string, git *riskevaluator.Git, policies ...*riskevaluator.Policy) *riskevaluator.Evaluator {
	t.Helper()
	if err := git.Err(); err != nil {
		t.Fatal(err)
	}
	return riskevaluator.NewEvaluator(riskevaluator.PolicySetOf(policies...), git, repos)
}

// GitAllowingFile is the production git runner, with default bounds, that also reads remotes over
// the file protocol: the tests' remotes are local paths.
func GitAllowingFile(t testing.TB) *riskevaluator.Git {
	t.Helper()
	g, err := riskevaluator.NewGit(riskevaluator.DefaultGitTimeout, riskevaluator.DefaultGitMaxOutput).AllowProtocolsForTests("file")
	if err != nil {
		t.Fatal(err)
	}
	return g
}
