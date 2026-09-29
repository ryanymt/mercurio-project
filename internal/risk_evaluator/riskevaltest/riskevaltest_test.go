package riskevaltest_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/riskevaltest"
)

func TestPolicyOmitsLateRules(t *testing.T) {
	p := riskevaltest.Policy(t, "foreman", "version: 1\nfail_closed: true\nrules:\n  - id: protected_paths\n    reason: r\n    match:\n      any_path: [\"auth/**\"]\n")
	if p.Project() != "foreman" || len(p.RuleIDs()) != 1 {
		t.Fatalf("policy %s %v", p.Project(), p.RuleIDs())
	}
}

// GitAllowingFile reads a local remote, as the dispatcher's tests need.
func TestGitAllowingFileReadsALocalRemote(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "remote.git")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "--bare", dir)
	sha := git("-C", dir, "commit-tree", "-m", "one", "4b825dc642cb6eb9a060e54bf8d69288fbee4904")
	git("-C", dir, "update-ref", "refs/heads/main", sha)
	got, err := riskevaltest.GitAllowingFile(t).LsRemote(context.Background(), dir, "main")
	if err != nil || got != sha {
		t.Fatalf("LsRemote = %q, %v; want %s", got, err, sha)
	}
}
