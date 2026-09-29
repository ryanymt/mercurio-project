package riskevaluator

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/gitfixture"
)

// LsRemote reads the head of a project's default branch from its remote, for the dispatcher's
// new-work claim (P04 D4, D12). The tests' remotes are local paths, which only the test option
// allows.

func remoteGit(t *testing.T) *Git {
	t.Helper()
	g, err := adapter(t).AllowProtocolsForTests("file")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// rawGit runs the real git outside the adapter, with no system or global configuration, for the
// controls.
func rawGit(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C"}
	out, err := cmd.Output()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	}
	t.Fatalf("git %v: %v", args, err)
	return "", -1
}

func TestLsRemoteReadsTheBranchHead(t *testing.T) {
	r, _ := newRepo(t)
	head := r.Commit(nil, "one", gitfixture.Text("README", "1\n"))
	r.Git("update-ref", "refs/heads/main", head)
	r.Git("update-ref", "refs/heads/release/1.2", r.Commit(nil, "two", gitfixture.Text("README", "2\n")))
	got, err := remoteGit(t).LsRemote(context.Background(), r.Dir, "main")
	if err != nil || got != head {
		t.Fatalf("LsRemote = %q, %v; want %s", got, err, head)
	}
}

// ls-remote matches ref names by their tail, so a pushed branch named like the default branch's
// full ref is listed first (red team 1, R2). LsRemote takes only the exact ref's line. The control
// shows git really lists the lookalike first, so a parser taking the first line would be caught.
func TestLsRemoteTakesOnlyTheExactRef(t *testing.T) {
	r, _ := newRepo(t)
	main := r.Commit(nil, "main", gitfixture.Text("README", "1\n"))
	lookalike := r.Commit(nil, "lookalike", gitfixture.Text("README", "2\n"))
	r.Git("update-ref", "refs/heads/main", main)
	r.Git("update-ref", "refs/heads/a/refs/heads/main", lookalike)
	r.Git("update-ref", "refs/heads/foreman/1/1/refs/heads/main", lookalike)

	raw, _ := rawGit(t, "ls-remote", "--exit-code", "--", r.Dir, "refs/heads/main")
	if f := strings.Fields(raw); len(f) < 2 || f[0] != lookalike || f[1] == "refs/heads/main" {
		t.Fatalf("control: git did not list the lookalike first:\n%s", raw)
	}
	got, err := remoteGit(t).LsRemote(context.Background(), r.Dir, "main")
	if err != nil || got != main {
		t.Fatalf("LsRemote = %q, %v; want main's %s, not the lookalike's %s", got, err, main, lookalike)
	}
}

// With the branch gone and only a lookalike left, git still exits 0 (the control); LsRemote fails
// whatever the exit status. A branch that is simply absent fails too.
func TestLsRemoteFailsWithoutTheExactRef(t *testing.T) {
	r, _ := newRepo(t)
	lookalike := r.Commit(nil, "lookalike", gitfixture.Text("README", "2\n"))
	r.Git("update-ref", "refs/heads/a/refs/heads/main", lookalike)

	if _, code := rawGit(t, "ls-remote", "--exit-code", "--", r.Dir, "refs/heads/main"); code != 0 {
		t.Fatalf("control: git exited %d with only a lookalike, want 0", code)
	}
	if got, err := remoteGit(t).LsRemote(context.Background(), r.Dir, "main"); err == nil {
		t.Fatalf("LsRemote = %q with only a lookalike of main, want an error", got)
	}
	if got, err := remoteGit(t).LsRemote(context.Background(), r.Dir, "develop"); err == nil {
		t.Fatalf("LsRemote = %q for an absent branch, want an error", got)
	}
}

// stubGit writes a git that answers `version`, records every other call's arguments and
// environment in dir, and then runs body.
func stubGit(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "git")
	script := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = version ] && { echo 'git version 2.43.0'; exit 0; }; done\n" +
		"printf '%s\\n' \"$@\" > " + filepath.Join(dir, "args") + "\nenv > " + filepath.Join(dir, "env") + "\n" + body + "\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

const stubSHA = "0123456789abcdef0123456789abcdef01234567"

// A default branch that is not a valid branch name, or holds a glob character, is refused before
// git runs. The control shows the stub records a call when the name is good.
func TestLsRemoteRefusesABranchThatIsNotARefName(t *testing.T) {
	dir := t.TempDir()
	g := newGitAt(stubGit(t, dir, "printf '%s\\trefs/heads/%s\\n' "+stubSHA+" main"), 5*time.Second, 1<<20)
	if err := g.Err(); err != nil {
		t.Fatal(err)
	}
	const url = "https://example.invalid/repo.git"
	for _, b := range []string{
		"", "ma*in", "ma?n", "[m]ain", `ma\in`, "-main", "a..b", "ma in", "ma\tin", "ma\x7fin", "a~1", "a^1",
		"a:b", "main.lock", "a/b.lock/c", "/main", "main/", "a//b", "a/.b", ".main", "main.", "a@{1}", "@",
	} {
		if _, err := g.LsRemote(context.Background(), url, b); err == nil {
			t.Errorf("branch %q accepted", b)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "args")); err == nil {
		t.Fatal("git ran for a branch name that must be refused before it")
	}
	for _, b := range []string{"main", "release/1.2", "feature/a-b_c"} {
		if _, err := g.LsRemote(context.Background(), url, b); err != nil && b == "main" {
			t.Fatalf("control: branch %q refused: %v", b, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "args")); err != nil {
			t.Fatalf("control: git never ran for the valid branch %q", b)
		}
	}
}

// Only https: a local path, a file:// URL and ext:: are refused by the production runner. The
// controls show the same remotes are live: the test option reads the local one, and allowing ext
// runs the command.
func TestLsRemoteAllowsOnlyHTTPS(t *testing.T) {
	ctx := context.Background()
	r, _ := newRepo(t)
	head := r.Commit(nil, "one", gitfixture.Text("README", "1\n"))
	r.Git("update-ref", "refs/heads/main", head)

	for _, url := range []string{r.Dir, "file://" + r.Dir} {
		if got, err := adapter(t).LsRemote(ctx, url, "main"); err == nil {
			t.Fatalf("LsRemote(%s) = %q, want the local remote refused", url, got)
		}
		if got, err := remoteGit(t).LsRemote(ctx, url, "main"); err != nil || got != head {
			t.Fatalf("control: with file allowed, LsRemote(%s) = %q, %v", url, got, err)
		}
	}

	marker := filepath.Join(t.TempDir(), "ran")
	ext := "ext::sh -c touch% " + marker
	if _, err := adapter(t).LsRemote(ctx, ext, "main"); err == nil {
		t.Fatal("an ext:: remote was accepted")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("an ext:: remote ran its command")
	}
	extGit, err := adapter(t).AllowProtocolsForTests("ext")
	if err != nil {
		t.Fatal(err)
	}
	extGit.LsRemote(ctx, ext, "main")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("control: with ext allowed, the ext:: remote did not run its command")
	}
}

// A repo_url that git would read as an option is refused, and its command never runs. The control
// shows git runs it when the URL is not preceded by `--`.
func TestLsRemoteRefusesAURLThatIsAnOption(t *testing.T) {
	r, _ := newRepo(t)
	r.Git("update-ref", "refs/heads/main", r.Commit(nil, "one", gitfixture.Text("README", "1\n")))
	marker := filepath.Join(t.TempDir(), "ran")
	url := "--upload-pack=touch " + marker

	if _, err := remoteGit(t).LsRemote(context.Background(), url, "main"); err == nil {
		t.Fatal("a URL starting with - was accepted")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the option in the URL ran its command")
	}
	rawGit(t, "ls-remote", url, r.Dir)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("control: without --, git did not run the command the option names")
	}
}

// git runs with no credential helper, no askpass and no terminal prompt, only https allowed, and
// `--` before the URL.
func TestLsRemoteRunsWithNoCredentialsOrPrompts(t *testing.T) {
	dir := t.TempDir()
	g := newGitAt(stubGit(t, dir, "printf '%s\\trefs/heads/main\\n' "+stubSHA), 5*time.Second, 1<<20)
	const url = "https://example.invalid/repo.git"
	got, err := g.LsRemote(context.Background(), url, "main")
	if err != nil || got != stubSHA {
		t.Fatalf("LsRemote = %q, %v", got, err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	lines := map[string]bool{}
	for _, l := range strings.Split(string(env), "\n") {
		lines[l] = true
		for _, banned := range []string{"SSH_ASKPASS=", "GIT_ASKPASS=/"} {
			if strings.HasPrefix(l, banned) {
				t.Errorf("git ran with %s", l)
			}
		}
	}
	// HOME points nowhere: unset, libcurl would read a .netrc in the passwd entry's home (P05
	// consult 1).
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "GIT_ALLOW_PROTOCOL=https", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + noHome} {
		if !lines[want] {
			t.Errorf("git ran without %s:\n%s", want, env)
		}
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	a := strings.Join(strings.Split(strings.TrimSpace(string(args)), "\n"), " ")
	for _, want := range []string{"-c credential.helper= ", "-c core.askPass= ", "ls-remote --exit-code -- " + url + " refs/heads/main"} {
		if !strings.Contains(a+" ", want) {
			t.Errorf("git's arguments %q lack %q", a, want)
		}
	}
	if !strings.HasSuffix(a, "ls-remote --exit-code -- "+url+" refs/heads/main") {
		t.Errorf("git's arguments %q do not end with the ls-remote call", a)
	}
}

// Bounded in time and output.
func TestLsRemoteIsBounded(t *testing.T) {
	const url = "https://example.invalid/repo.git"
	slow := newGitAt(stubGit(t, t.TempDir(), "sleep 30"), 500*time.Millisecond, 1<<20)
	start := time.Now()
	if _, err := slow.LsRemote(context.Background(), url, "main"); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("err = %v, want a deadline", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond+gitWaitDelay+time.Second {
		t.Fatalf("took %s", took)
	}
	chatty := newGitAt(stubGit(t, t.TempDir(), "head -c 2000000 /dev/zero | tr '\\0' a"), 5*time.Second, 1<<20)
	if _, err := chatty.LsRemote(context.Background(), url, "main"); err == nil {
		t.Fatal("output beyond the cap was accepted")
	}
}

// Outside `go test` the protocol option refuses to run: a real binary built from testdata/protomain
// asks for it and must be refused, so production reads remotes over https only.
func TestTestProtocolsRefusedOutsideTests(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("this test builds a binary and needs the go command:", err)
	}
	bin := filepath.Join(t.TempDir(), "protomain")
	if out, err := exec.Command(gobin, "build", "-o", bin, "./testdata/protomain").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(string(out), "refused") {
		t.Fatalf("the file protocol was allowed outside a test binary: err=%v output=%s", err, out)
	}
}

// Only the protocols the option exists for may be added.
func TestTestProtocolsAreFileOrExt(t *testing.T) {
	for _, p := range []string{"", "https", "ssh", "git", "http", "file:ssh", "FILE"} {
		if _, err := adapter(t).AllowProtocolsForTests(p); err == nil {
			t.Errorf("the protocol option accepted %q", p)
		}
	}
}

// The URL check runs before git: `--` would also stop git reading the URL as an option, but a
// URL that is an option never reaches git at all.
func TestLsRemoteRefusesAnOptionURLBeforeGitRuns(t *testing.T) {
	dir := t.TempDir()
	g := newGitAt(stubGit(t, dir, "printf '%s\\trefs/heads/main\\n' "+stubSHA), 5*time.Second, 1<<20)
	for _, url := range []string{"--upload-pack=touch /tmp/x", "-u", ""} {
		if _, err := g.LsRemote(context.Background(), url, "main"); err == nil {
			t.Errorf("URL %q accepted", url)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "args")); err == nil {
		t.Fatal("git ran for a URL that must be refused before it")
	}
}

// A remote that lists the exact ref more than once is not trusted, even if one of its lines is
// right.
func TestLsRemoteRefusesTheRefListedTwice(t *testing.T) {
	g := newGitAt(stubGit(t, t.TempDir(),
		"printf '%s\\trefs/heads/main\\n%s\\trefs/heads/main\\n' "+stubSHA+" 1111111111111111111111111111111111111111"),
		5*time.Second, 1<<20)
	if got, err := g.LsRemote(context.Background(), "https://example.invalid/repo.git", "main"); err == nil {
		t.Fatalf("LsRemote = %q from a remote listing main twice", got)
	}
}

// With a token, git gets it through its environment as an Authorization header (GitHub's form for
// an App token), never in its arguments (P05 T2).
func TestLsRemoteWithTokenPutsItInGitsEnvironment(t *testing.T) {
	dir := t.TempDir()
	g := newGitAt(stubGit(t, dir, "printf '%s\\trefs/heads/main\\n' "+stubSHA), 5*time.Second, 1<<20)
	const token = "ghs_testtoken0123456789"
	got, err := g.LsRemoteWithToken(context.Background(), "https://example.invalid/repo.git", "main", token)
	if err != nil || got != stubSHA {
		t.Fatalf("LsRemoteWithToken = %q, %v", got, err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	for _, want := range []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=" + header, "HOME=" + noHome} {
		if !strings.Contains(string(env), want+"\n") {
			t.Errorf("git's environment lacks %q", want)
		}
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	for _, secret := range []string{token, base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))} {
		if strings.Contains(string(args), secret) {
			t.Fatalf("the token reached git's arguments: %s", args)
		}
	}
	if _, err := os.Stat(noHome); err == nil {
		t.Fatalf("%s exists; HOME must point nowhere", noHome)
	}
}

// The armed control for HOME: git over http reads $HOME/.netrc, so which HOME git gets decides
// whether a planted .netrc is used. Here git itself, with HOME at a directory holding one, sends
// its credentials; the runner gives git a HOME that does not exist.
func TestHomeDecidesWhichNetrcGitReads(t *testing.T) {
	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			sent = a
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	home := t.TempDir()
	host := strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")[0]
	if err := os.WriteFile(filepath.Join(home, ".netrc"), []byte(fmt.Sprintf("machine %s login netrcuser password netrcpass\n", host)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "ls-remote", "--", srv.URL+"/repo.git")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"}
	cmd.Run()
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("netrcuser:netrcpass")); sent != want {
		t.Fatalf("control: git with HOME at a .netrc sent %q, want the .netrc's credentials", sent)
	}
}
