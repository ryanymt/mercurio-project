package riskevaluator

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/gitfixture"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The engine names a QA mismatch with the id the evaluator reserves (policies may not use it).
func TestQAShaMismatchIDMatchesTheEngine(t *testing.T) {
	if callbackapi.RuleQAShaMismatch != idQAShaMismatch {
		t.Fatalf("engine %q, evaluator %q", callbackapi.RuleQAShaMismatch, idQAShaMismatch)
	}
}

// Every in-module package the command links is protected for foreman, so no linked code can
// route around the gate without escalating; the test-only packages are not linked (D13; red team
// round 2, R1).
func TestEveryLinkedPackageIsProtected(t *testing.T) {
	const module = "github.com/ryanymt/mercurio-project"
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if .Module}}{{if .Module.Main}}{{.ImportPath}}{{end}}{{end}}",
		module+"/cmd/foreman").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	policy, err := EmbeddedPolicies().For("foreman")
	if err != nil {
		t.Fatal(err)
	}
	var pkgs []string
	for _, line := range strings.Fields(string(out)) {
		pkgs = append(pkgs, strings.TrimPrefix(strings.TrimPrefix(line, module), "/"))
	}
	if len(pkgs) < 3 {
		t.Fatalf("go list found only %v", pkgs)
	}
	for _, dir := range pkgs {
		if strings.Contains(dir, "riskevaltest") || strings.Contains(dir, "gitfixture") {
			t.Errorf("the command links the test-only package %s", dir)
		}
		file := dir + "/any_file.go"
		res := Evaluate(Changes{Net: []Change{{Path: file, Status: 'M', OldMode: "100644", NewMode: "100644", Added: 1}}},
			Subject{Project: "foreman", Meta: true}, policy)
		if !strings.Contains(strings.Join(res.MatchedRules, " "), "protected_paths") {
			t.Errorf("the command links %s, and a change to %s is not protected", dir, file)
		}
	}
}

// FromEnv never fails: whatever is wrong is kept, and every evaluation escalates naming it.
func TestFromEnvSettings(t *testing.T) {
	subject := callbackapi.Subject{TicketID: 1, Project: "foreman", BaseSHA: strings.Repeat("a", 40), HeadSHA: strings.Repeat("b", 40)}
	for name, c := range map[string]struct {
		repos, timeout, max, want string
	}{
		"repos dir unset":    {"", "", "", "FOREMAN_REPOS_DIR"},
		"repos dir relative": {"relative/repos", "", "", "FOREMAN_REPOS_DIR"},
		"timeout unreadable": {"/nonexistent", "forever", "", "FOREMAN_GIT_TIMEOUT"},
		"timeout negative":   {"/nonexistent", "-1s", "", "FOREMAN_GIT_TIMEOUT"},
		"max unreadable":     {"/nonexistent", "", "lots", "FOREMAN_GIT_MAX_OUTPUT"},
		"max zero":           {"/nonexistent", "", "0", "FOREMAN_GIT_MAX_OUTPUT"},
		"all set":            {"/nonexistent", "5s", "1048576", "repository"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("FOREMAN_REPOS_DIR", c.repos)
			t.Setenv("FOREMAN_GIT_TIMEOUT", c.timeout)
			t.Setenv("FOREMAN_GIT_MAX_OUTPUT", c.max)
			_, err := FromEnv(quietLog()).Evaluate(context.Background(), subject)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to name %s", err, c.want)
			}
		})
	}
}

// A policy file that is present but refused makes every evaluation for its project fail, naming
// why; the engine escalates on the failure (Anchor, "Policy").
func TestARefusedPolicyFileFailsEveryEvaluation(t *testing.T) {
	set := loadSet(fstest.MapFS{"policies/foreman.yml": {Data: []byte("version: 1\nfail_closed: on\nrules: []\n")}})
	e := NewEvaluator(set, NewGit(DefaultGitTimeout, DefaultGitMaxOutput), t.TempDir())
	_, err := e.Evaluate(context.Background(), callbackapi.Subject{TicketID: 1, Project: "foreman",
		BaseSHA: strings.Repeat("a", 40), HeadSHA: strings.Repeat("b", 40)})
	if err == nil || !strings.Contains(err.Error(), "fail_closed") {
		t.Fatalf("err = %v, want the refusal named", err)
	}
}

// A git that times out makes the evaluation fail, within the deadline (Anchor, "Fail closed").
func TestAGitTimeoutFailsTheEvaluation(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	stub := filepath.Join(t.TempDir(), "git")
	script := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = version ] && { echo 'git version 2.43.0'; exit 0; }; done\nsleep 30\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadTestPolicy("foreman", []byte("version: 1\nfail_closed: true\nrules:\n  - id: protected_paths\n    reason: r\n    match:\n      any_path: [\"auth/**\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEvaluator(PolicySetOf(policy), newGitAt(stub, 500*time.Millisecond, 1<<20), repos)
	start := time.Now()
	_, err = e.Evaluate(context.Background(), callbackapi.Subject{TicketID: 1, Project: "foreman", BaseSHA: base, HeadSHA: base})
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("err = %v, want a deadline", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond+gitWaitDelay+time.Second {
		t.Fatalf("took %s", took)
	}
}
