package riskevaluator

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The remote read (P04 D4, D12): the head of a project's default branch, read from its repo_url
// with `git ls-remote`, for the dispatcher's new-work claim to record as base_sha. It runs through
// the same hardened runner as the diff (reduced environment, no outside configuration, process
// group, deadline, output cap), with only https allowed, no credential helper, no askpass and no
// terminal prompt. What the remote says is trusted only as far as its one exact line.

// noHome is git's HOME for remote reads: a directory that does not exist. With HOME unset,
// libcurl falls back to the passwd entry's home and reads a .netrc there (P05 consult 1).
const noHome = "/nonexistent/foreman-git-home"

// LsRemoteWithToken is LsRemote with a GitHub App installation token (P05 D3): git gets it through
// its environment (GIT_CONFIG_COUNT), as the Authorization header GitHub documents for App tokens,
// never in its arguments.
func (g *Git) LsRemoteWithToken(ctx context.Context, url, branch, token string) (string, error) {
	if token == "" {
		return "", errors.New("no token to read the remote with")
	}
	return g.lsRemote(ctx, url, branch, token)
}

// LsRemote returns the commit the remote's branch refs/heads/<branch> points at. It fails, and
// the dispatcher claims no new work, on anything else: an unusable git, a branch that is not a
// valid name, a URL that is not a remote, a protocol other than https, no line for exactly that
// ref or more than one, a malformed sha, a timeout or too much output.
func (g *Git) LsRemote(ctx context.Context, url, branch string) (string, error) {
	return g.lsRemote(ctx, url, branch, "")
}

func (g *Git) lsRemote(ctx context.Context, url, branch, token string) (string, error) {
	if g.err != nil {
		return "", g.err
	}
	if !validBranch(branch) {
		return "", fmt.Errorf("%q is not a branch name git can read safely", branch)
	}
	if url == "" || strings.HasPrefix(url, "-") {
		return "", fmt.Errorf("%q is not a repository URL", url)
	}
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	budget := g.maxOut
	ref := "refs/heads/" + branch
	env := []string{"GIT_ALLOW_PROTOCOL=" + g.protocols, "GIT_ASKPASS=", "HOME=" + noHome}
	if token != "" {
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+basic)
	}
	out, code, err := g.runEnv(ctx, &budget, "", env,
		"-c", "credential.helper=", "-c", "core.askPass=", "ls-remote", "--exit-code", "--", url, ref)
	if err != nil {
		return "", err
	}
	// ls-remote matches patterns against the tail of each ref, so a branch named
	// a/refs/heads/main is listed too, and first; only the exact ref counts, whatever the exit
	// status says (2 is no match; 0 may be a lookalike's).
	var shas []string
	for _, line := range strings.Split(string(out), "\n") {
		sha, name, ok := strings.Cut(line, "\t")
		if ok && name == ref {
			shas = append(shas, sha)
		}
	}
	switch {
	case len(shas) == 0 && (code == 0 || code == 2):
		return "", fmt.Errorf("the remote has no branch %s", branch)
	case code != 0 && code != 2:
		return "", fmt.Errorf("git ls-remote failed (exit %d)", code)
	case len(shas) > 1:
		return "", fmt.Errorf("the remote lists %s %d times", ref, len(shas))
	case !shaPattern.MatchString(shas[0]):
		return "", fmt.Errorf("the remote's %s is not a full SHA-1: %q", ref, shas[0])
	}
	return shas[0], nil
}

// validBranch holds a branch name to git's rules for a ref (git check-ref-format), and refuses
// glob characters, which ls-remote would read as a pattern.
func validBranch(b string) bool {
	if b == "" || b == "@" || strings.HasPrefix(b, "-") || strings.HasPrefix(b, "/") ||
		strings.HasSuffix(b, "/") || strings.HasSuffix(b, ".") || strings.Contains(b, "..") ||
		strings.Contains(b, "@{") || strings.Contains(b, "//") {
		return false
	}
	for _, r := range b {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" ~^:?*[\\", r) {
			return false
		}
	}
	for _, part := range strings.Split(b, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

// AllowProtocolsForTests returns a copy of g that also allows the named protocol to remotes: file
// (the tests' remotes are local paths) or ext (a control that shows an ext:: remote is live). It
// refuses to run outside `go test`, so production reads remotes over https only. Tests reach it
// through package riskevaltest.
func (g *Git) AllowProtocolsForTests(protocol string) (*Git, error) {
	if !testing.Testing() {
		return nil, errors.New("another protocol than https is refused outside go test")
	}
	if protocol != "file" && protocol != "ext" {
		return nil, fmt.Errorf("the test option allows file or ext, not %q", protocol)
	}
	c := *g
	c.protocols = "https:" + protocol
	return &c, nil
}
