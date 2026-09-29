package riskevaluator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The git adapter (docs/risk-policy.md, "Where the diff comes from"; P03 Approach 5, D9). It lists
// the changes between two commits in a bare repository the server keeps, with the repository's
// power over git removed: whoever pushes the branch writes its contents, so nothing in them may
// change what git does or reports. It returns an error, never a partial result.

const (
	// DefaultGitTimeout bounds one whole Changes call.
	DefaultGitTimeout = 10 * time.Second
	// DefaultGitMaxOutput bounds the standard output of one whole Changes call, in bytes.
	DefaultGitMaxOutput = 10 << 20

	emptyTree    = "4b825dc642cb6eb9a060e54bf8d69288fbee4904" // attributes are read from nowhere
	gitWaitDelay = 2 * time.Second                            // after a kill, how long Wait waits for pipes
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Git runs git for the adapter. It is built once, at startup: the binary is resolved to an
// absolute path and its version checked there, and an unusable git is kept as its error, so every
// evaluation escalates naming it.
type Git struct {
	path, version string
	pathEnv       string // PATH as it was at startup
	timeout       time.Duration
	maxOut        int64
	uid           int    // the owner every repository must have: the server's user
	protocols     string // GIT_ALLOW_PROTOCOL for remotes (gitremote.go): https, and more only in tests
	err           error
}

// NewGit resolves git on PATH and checks it.
func NewGit(timeout time.Duration, maxOutput int64) *Git {
	p, err := exec.LookPath("git")
	if err == nil {
		p, err = filepath.Abs(p)
	}
	if err != nil {
		return &Git{timeout: timeout, maxOut: maxOutput, uid: os.Getuid(), err: fmt.Errorf("git is not available: %w", err)}
	}
	return newGitAt(p, timeout, maxOutput)
}

func newGitAt(path string, timeout time.Duration, maxOutput int64) *Git {
	g := &Git{path: path, pathEnv: os.Getenv("PATH"), timeout: timeout, maxOut: maxOutput, uid: os.Getuid(), protocols: "https"}
	if timeout <= 0 || maxOutput <= 0 {
		g.err = errors.New("the git timeout and output cap must be positive")
		return g
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	budget := int64(4096)
	out, code, err := g.run(ctx, &budget, "", "version")
	if err != nil || code != 0 {
		g.err = fmt.Errorf("git version failed (exit %d): %v", code, err)
		return g
	}
	g.version = strings.TrimPrefix(strings.TrimSpace(string(out)), "git version ")
	if !versionAtLeast(g.version, 2, 41, 0) {
		g.err = fmt.Errorf("git %q is older than 2.41.0, the first with --attr-source", g.version)
	}
	return g
}

// Path is the absolute path of the git binary in use.
func (g *Git) Path() string { return g.path }

// Version is git's version as it reports it.
func (g *Git) Version() string { return g.version }

// Err is why git cannot be used, or nil.
func (g *Git) Err() error { return g.err }

// Changes lists the net diff from base to head and every path changed by any commit in the range,
// in the bare repository `<reposDir>/<project>.git`.
func (g *Git) Changes(ctx context.Context, reposDir, project, base, head string) (Changes, error) {
	if g.err != nil {
		return Changes{}, g.err
	}
	switch {
	case !validProjectID(project):
		return Changes{}, fmt.Errorf("%q is not a project id", project)
	case !filepath.IsAbs(reposDir):
		return Changes{}, fmt.Errorf("the repositories directory %q is not absolute", reposDir)
	case !shaPattern.MatchString(base) || !shaPattern.MatchString(head):
		return Changes{}, errors.New("base and head must be full SHA-1s in lowercase hex")
	}
	repo := filepath.Join(reposDir, project+".git")
	if err := g.checkOwner(repo); err != nil {
		return Changes{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	budget := g.maxOut
	git := func(args ...string) (string, int, error) {
		out, code, err := g.run(ctx, &budget, repo, args...)
		return string(out), code, err
	}

	// The repository contract: bare, a full clone, not a partial one.
	if out, code, err := git("rev-parse", "--is-bare-repository", "--is-shallow-repository"); err != nil || code != 0 || out != "true\nfalse\n" {
		return Changes{}, fmt.Errorf("%s must be a bare repository and a full clone (%q, exit %d, %v)", repo, out, code, err)
	}
	if _, code, err := git("config", "--get", "extensions.partialclone"); err != nil || code != 1 {
		return Changes{}, fmt.Errorf("%s is a partial clone, or its config cannot be read (exit %d, %v)", repo, code, err)
	}

	// Both commits, commit to commit: never HEAD or any other symbolic ref.
	for _, sha := range []string{base, head} {
		if out, code, err := git("cat-file", "-t", sha); err != nil || code != 0 || out != "commit\n" {
			return Changes{}, fmt.Errorf("%s is not a commit in %s (%q, exit %d, %v)", sha, repo, strings.TrimSpace(out), code, err)
		}
	}
	switch _, code, err := git("merge-base", "--is-ancestor", base, head); {
	case err != nil:
		return Changes{}, err
	case code == 1:
		return Changes{}, fmt.Errorf("head %s does not descend from base %s", head, base)
	case code != 0:
		return Changes{}, fmt.Errorf("merge-base --is-ancestor exited %d", code)
	}

	out, code, err := git("diff-tree", "-r", "-z", "--no-commit-id", "--no-renames", "--no-ext-diff", "--no-textconv",
		"--no-abbrev", "--ignore-submodules=none", "--no-relative", "--diff-algorithm=myers", "--raw", "--numstat", base, head)
	if err != nil || code != 0 {
		return Changes{}, fmt.Errorf("diff-tree failed (exit %d): %v", code, err)
	}
	net, err := parseNet(out)
	if err != nil {
		return Changes{}, err
	}

	// git log is porcelain and reads the repository's config: every behaviour it could take from
	// there is set here (red team round 2, R2).
	out, code, err = git("log", "--diff-merges=separate", "--ignore-submodules=none", "--no-abbrev", "--no-show-signature",
		"--no-color", "--no-relative", "-r", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", "--raw", "--format=",
		base+".."+head, "--")
	if err != nil || code != 0 {
		return Changes{}, fmt.Errorf("log failed (exit %d): %v", code, err)
	}
	paths, err := parseRange(out)
	if err != nil {
		return Changes{}, err
	}
	return Changes{Net: net, Range: paths}, nil
}

// checkOwner requires the repository to be a real directory owned by the server's user:
// safe.directory does nothing under --git-dir, so the check is ours.
func (g *Git) checkOwner(repo string) error {
	fi, err := os.Lstat(repo)
	if err != nil {
		return fmt.Errorf("repository %s: %w", repo, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("repository %s is not a directory", repo)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != g.uid {
		return fmt.Errorf("repository %s has another owner than the server's user", repo)
	}
	return nil
}

// run runs one git command against repo (none for `git version`) on the calling goroutine.
// Standard error goes to /dev/null, so exec starts no copying goroutine of ours; standard output
// is read here, up to the budget left, under the context's deadline; the command runs in its own
// process group, which is killed as a whole on timeout, overflow or cancellation.
func (g *Git) run(ctx context.Context, budget *int64, repo string, args ...string) ([]byte, int, error) {
	return g.runEnv(ctx, budget, repo, nil, args...)
}

// runEnv is run with further environment variables added to the reduced environment (the remote
// read's protocol and credential settings).
func (g *Git) runEnv(ctx context.Context, budget *int64, repo string, env []string, args ...string) ([]byte, int, error) {
	var full []string
	if repo != "" {
		full = append(full, "--git-dir="+repo, "--no-pager", "--no-replace-objects", "--attr-source="+emptyTree,
			"-c", "core.attributesFile=/dev/null", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
			"-c", "core.bigFileThreshold=512m", "-c", "diff.orderFile=/dev/null")
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, g.path, full...)
	cmd.Env = []string{
		"PATH=" + g.pathEnv, "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_GRAFT_FILE=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1",
		"GIT_OPTIONAL_LOCKS=0",
	}
	cmd.Env = append(cmd.Env, env...)
	cmd.Dir = "/"
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return nil, -1, err
	}
	defer devnull.Close()
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = gitWaitDelay
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, -1, err
	}
	if err := cmd.Start(); err != nil {
		return nil, -1, fmt.Errorf("git %s: %w", args[0], err)
	}
	out, rerr := readCapped(ctx, pipe, budget)
	if rerr != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
		return nil, -1, fmt.Errorf("git %s: %w", args[0], rerr)
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, -1, fmt.Errorf("git %s: %w", args[0], ctx.Err())
	}
	var exit *exec.ExitError
	switch {
	case werr == nil:
		return out, 0, nil
	case errors.As(werr, &exit):
		return out, exit.ExitCode(), nil
	default:
		return nil, -1, fmt.Errorf("git %s: %w", args[0], werr)
	}
}

var errOutputCap = errors.New("output over the cap")

// readCapped reads a pipe to its end, refusing more than the budget and stopping at the deadline.
func readCapped(ctx context.Context, pipe io.Reader, budget *int64) ([]byte, error) {
	f, ok := pipe.(*os.File)
	if !ok {
		return nil, errors.New("standard output is not a pipe")
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := f.SetReadDeadline(dl); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		n, err := f.Read(chunk)
		if n > 0 {
			if int64(buf.Len()+n) > *budget {
				return nil, errOutputCap
			}
			buf.Write(chunk[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		if err != nil {
			return nil, err
		}
	}
	*budget -= int64(buf.Len())
	return buf.Bytes(), nil
}

var (
	modePattern     = regexp.MustCompile(`^[0-7]{6}$`)
	numstatNumber   = regexp.MustCompile(`^[0-9]+$`)
	allowedStatuses = "ADMT" // with rename detection off, nothing else can appear
)

// rawRecord parses one raw header, ":oldmode newmode oldsha newsha status". Anything else, a
// combined-diff header or a status with a score included, is an error.
func rawRecord(tok string) (Change, error) {
	f := strings.Split(strings.TrimPrefix(tok, ":"), " ")
	if strings.HasPrefix(tok, "::") || len(f) != 5 || !modePattern.MatchString(f[0]) || !modePattern.MatchString(f[1]) ||
		!shaPattern.MatchString(f[2]) || !shaPattern.MatchString(f[3]) || len(f[4]) != 1 || !strings.Contains(allowedStatuses, f[4]) {
		return Change{}, fmt.Errorf("unexpected raw record %q", tok)
	}
	return Change{Status: f[4][0], OldMode: f[0], NewMode: f[1]}, nil
}

// parseNet reads diff-tree's NUL-delimited output: every raw record (a header, then its one path),
// then every numstat record ("added TAB removed TAB path"), joined by path. Every raw record must
// have exactly one numstat record.
func parseNet(out string) ([]Change, error) {
	toks := strings.Split(out, "\x00")
	var net []Change
	counts := map[string][2]int64{}
	binary := map[string]bool{}
	seen := map[string]bool{}
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		switch {
		case tok == "":
		case strings.HasPrefix(tok, ":"):
			c, err := rawRecord(tok)
			if err != nil {
				return nil, err
			}
			if i+1 >= len(toks) {
				return nil, errors.New("a raw record without its path")
			}
			i++
			c.Path = toks[i]
			if seen[c.Path] {
				return nil, fmt.Errorf("path %q listed twice", c.Path)
			}
			seen[c.Path] = true
			net = append(net, c)
		default:
			parts := strings.SplitN(tok, "\t", 3)
			if len(parts) != 3 {
				return nil, fmt.Errorf("unexpected numstat record %q", tok)
			}
			path := parts[2]
			if _, dup := counts[path]; dup {
				return nil, fmt.Errorf("numstat lists %q twice", path)
			}
			switch {
			case parts[0] == "-" && parts[1] == "-":
				binary[path] = true
				counts[path] = [2]int64{}
			case numstatNumber.MatchString(parts[0]) && numstatNumber.MatchString(parts[1]):
				a, errA := strconv.ParseInt(parts[0], 10, 64)
				r, errR := strconv.ParseInt(parts[1], 10, 64)
				if errA != nil || errR != nil {
					return nil, fmt.Errorf("unreadable line counts in %q", tok)
				}
				counts[path] = [2]int64{a, r}
			default:
				return nil, fmt.Errorf("unexpected numstat record %q", tok)
			}
		}
	}
	if len(counts) != len(net) {
		return nil, fmt.Errorf("%d raw records but %d numstat records", len(net), len(counts))
	}
	for i := range net {
		n, ok := counts[net[i].Path]
		if !ok {
			return nil, fmt.Errorf("no numstat record for %q", net[i].Path)
		}
		net[i].Added, net[i].Removed, net[i].Binary = n[0], n[1], binary[net[i].Path]
	}
	return net, nil
}

// parseRange reads log's NUL-delimited raw records and returns their paths, in order.
func parseRange(out string) ([]string, error) {
	toks := strings.Split(out, "\x00")
	var paths []string
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		if tok == "" {
			continue
		}
		if _, err := rawRecord(tok); err != nil {
			return nil, err
		}
		if i+1 >= len(toks) {
			return nil, errors.New("a raw record without its path")
		}
		i++
		paths = append(paths, toks[i])
	}
	return paths, nil
}

// versionAtLeast compares the leading major.minor.patch of a git version string.
func versionAtLeast(v string, major, minor, patch int) bool {
	var got [3]int
	fields := strings.SplitN(v, ".", 4)
	if len(fields) < 3 {
		return false
	}
	for i := range 3 {
		digits := fields[i]
		if i == 2 {
			end := 0
			for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
				end++
			}
			digits = digits[:end]
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return false
		}
		got[i] = n
	}
	want := [3]int{major, minor, patch}
	for i := range 3 {
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return true
}
