package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// noHome is a home directory that does not exist: git and libcurl read no configuration or
	// .netrc from the image's home (as the dispatcher's git, P05 Approach 3).
	noHome     = "/nonexistent/foreman-git-home"
	gitTimeout = 2 * time.Minute
	maxGitOut  = 2 << 10
)

// gitRunner runs git with an environment built from nothing, so no GIT_TRACE* variable, no
// credential helper and no configuration of the image's reaches it. The token travels as GitHub's
// Authorization header through GIT_CONFIG_*, never in an argument, and the account is the author
// and committer of every commit.
type gitRunner struct {
	path string
	env  []string
}

func newGit(protocols, token, account string) (*gitRunner, error) {
	p, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("git: %w", err)
	}
	name := account[:strings.IndexByte(account, '@')]
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return &gitRunner{path: p, env: []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + noHome,
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"GIT_ALLOW_PROTOCOL=" + protocols,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic " + basic,
		"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + account,
		"GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + account,
	}}, nil
}

// run runs git in dir and returns its trimmed standard output. A failure names the command and
// the start of git's own error output.
func (g *gitRunner) run(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, g.path, args...)
	cmd.Dir, cmd.Env = dir, g.env
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		msg := errOut.String()
		if len(msg) > maxGitOut {
			msg = msg[:maxGitOut]
		}
		return "", fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(msg))
	}
	return strings.TrimSpace(out.String()), nil
}
