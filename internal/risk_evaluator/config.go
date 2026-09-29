package riskevaluator

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// FromEnv builds the production evaluator: the command calls this and nothing else to get one
// (P03 D13). It reads FOREMAN_REPOS_DIR (required, absolute), FOREMAN_GIT_TIMEOUT (a duration,
// default 10s) and FOREMAN_GIT_MAX_OUTPUT (bytes, default 10 MB), loads the embedded policies and
// checks git. It never fails: whatever is wrong is kept, so every evaluation escalates naming it,
// and one log line says what the evaluator runs with.
func FromEnv(log *slog.Logger) *Evaluator {
	var problems []error
	timeout := DefaultGitTimeout
	if v := os.Getenv("FOREMAN_GIT_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			problems = append(problems, fmt.Errorf("FOREMAN_GIT_TIMEOUT=%q is not a positive duration", v))
		} else {
			timeout = d
		}
	}
	maxOut := int64(DefaultGitMaxOutput)
	if v := os.Getenv("FOREMAN_GIT_MAX_OUTPUT"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			problems = append(problems, fmt.Errorf("FOREMAN_GIT_MAX_OUTPUT=%q is not a positive number of bytes", v))
		} else {
			maxOut = n
		}
	}
	repos := os.Getenv("FOREMAN_REPOS_DIR")
	switch {
	case repos == "":
		problems = append(problems, errors.New("FOREMAN_REPOS_DIR is not set: no repository to diff"))
	case !filepath.IsAbs(repos):
		problems = append(problems, fmt.Errorf("FOREMAN_REPOS_DIR=%q is not an absolute path", repos))
	}

	e := NewEvaluator(EmbeddedPolicies(), NewGit(timeout, maxOut), repos)
	e.setupErr = errors.Join(problems...)

	policies := map[string]string{}
	for _, p := range e.policies.Projects() {
		if pol, err := e.policies.For(p); err != nil {
			policies[p] = "refused: " + err.Error()
		} else {
			policies[p] = pol.SHA256()
		}
	}
	attrs := []any{"repos_dir", repos, "git", e.git.Path(), "git_version", e.git.Version(),
		"timeout", timeout.String(), "max_output", maxOut, "policies", policies}
	if err := errors.Join(e.setupErr, e.git.Err()); err != nil {
		log.Warn("risk evaluator: every approval will escalate", append(attrs, "error", err.Error())...)
	} else {
		log.Info("risk evaluator ready", attrs...)
	}
	return e
}
