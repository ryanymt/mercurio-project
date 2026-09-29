package riskevaluator

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ryanymt/mercurio-project/internal/risk_evaluator/gitfixture"
)

// The git adapter (P03 Approach 5). Every hostile case first shows the attack working with plain
// git (the armed control), then shows the adapter defeating it: a test that would pass with the
// defence removed proves nothing (red team round 1, R3).

func newRepo(t *testing.T) (*gitfixture.Repo, string) {
	t.Helper()
	repos := t.TempDir()
	return gitfixture.New(t, filepath.Join(repos, "foreman.git")), repos
}

func adapter(t *testing.T) *Git {
	t.Helper()
	g := NewGit(10*time.Second, 10<<20)
	if err := g.Err(); err != nil {
		t.Fatal(err)
	}
	return g
}

func mustChanges(t *testing.T, g *Git, repos, base, head string) Changes {
	t.Helper()
	c, err := g.Changes(context.Background(), repos, "foreman", base, head)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func byPath(cs []Change) map[string]Change {
	m := map[string]Change{}
	for _, c := range cs {
		m[c.Path] = c
	}
	return m
}

func binaryData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	b[1] = 0 // a NUL makes git call it binary
	return b
}

func TestGitIsResolvedAndRecentEnough(t *testing.T) {
	g := adapter(t)
	if !filepath.IsAbs(g.Path()) || !strings.HasPrefix(g.Version(), "2.") {
		t.Fatalf("git %q version %q", g.Path(), g.Version())
	}
}

// Every kind of change comes back as it is, path bytes included.
func TestChangesComeBackExactly(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base",
		gitfixture.Text("README", "one\n"), gitfixture.Text("infra/main.tf", "a\nb\nc\n"),
		gitfixture.Text("run.sh", "echo\n"), gitfixture.File{Path: "img.bin", Data: binaryData(64)})
	head := r.Commit([]string{base}, "head",
		gitfixture.Text("README", "one\ntwo\n"),                                 // modified, one line added
		gitfixture.Text("moved.tf", "a\nb\nc\n"),                                // infra/main.tf renamed
		gitfixture.File{Path: "run.sh", Mode: "100755", Data: []byte("echo\n")}, // mode only
		gitfixture.File{Path: "img.bin", Data: binaryData(80)},                  // binary changed
		gitfixture.File{Path: "link", Mode: "120000", Data: []byte("infra/x")},
		gitfixture.File{Path: "vendor/sub", Mode: "160000", Commit: base},
		gitfixture.Text("a\nb", "newline in the name\n"),
		gitfixture.Text("\xff\xfe.txt", "not UTF-8\n"),
	)
	c := mustChanges(t, adapter(t), repos, base, head)
	got := byPath(c.Net)
	want := map[string]Change{
		"README":        {Path: "README", Status: 'M', OldMode: "100644", NewMode: "100644", Added: 1},
		"infra/main.tf": {Path: "infra/main.tf", Status: 'D', OldMode: "100644", NewMode: "000000", Removed: 3},
		"moved.tf":      {Path: "moved.tf", Status: 'A', OldMode: "000000", NewMode: "100644", Added: 3},
		"run.sh":        {Path: "run.sh", Status: 'M', OldMode: "100644", NewMode: "100755"},
		"img.bin":       {Path: "img.bin", Status: 'M', OldMode: "100644", NewMode: "100644", Binary: true},
		"link":          {Path: "link", Status: 'A', OldMode: "000000", NewMode: "120000", Added: 1},
		"vendor/sub":    {Path: "vendor/sub", Status: 'A', OldMode: "000000", NewMode: "160000", Added: 1},
		"a\nb":          {Path: "a\nb", Status: 'A', OldMode: "000000", NewMode: "100644", Added: 1},
		"\xff\xfe.txt":  {Path: "\xff\xfe.txt", Status: 'A', OldMode: "000000", NewMode: "100644", Added: 1},
	}
	if len(got) != len(want) || len(c.Net) != len(want) {
		t.Fatalf("net diff %d records %v, want %d", len(c.Net), c.Net, len(want))
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%q: got %+v, want %+v", p, got[p], w)
		}
	}
	for p := range want {
		if !slices.Contains(c.Range, p) {
			t.Errorf("range lacks %q: %q", p, c.Range)
		}
	}
}

func TestAnEmptyCommitChangesNothing(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("a", "1\n"))
	head := r.Commit([]string{base}, "empty", gitfixture.Text("a", "1\n"))
	c := mustChanges(t, adapter(t), repos, base, head)
	if len(c.Net) != 0 || len(c.Range) != 0 {
		t.Fatalf("an empty commit: %+v", c)
	}
	if c := mustChanges(t, adapter(t), repos, base, base); len(c.Net) != 0 || len(c.Range) != 0 {
		t.Fatalf("base equal to head: %+v", c)
	}
}

// A file changed and then restored is absent from the net diff and present in the range (D12).
func TestTheRangeShowsARestoredFile(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("auth/login.py", "v1\n"), gitfixture.Text("README", "r1\n"))
	c1 := r.Commit([]string{base}, "fix", gitfixture.Text("auth/login.py", "v2\n"), gitfixture.Text("README", "r1\n"))
	c2 := r.Commit([]string{c1}, "revert", gitfixture.Text("auth/login.py", "v1\n"), gitfixture.Text("README", "r2\n"))
	c := mustChanges(t, adapter(t), repos, base, c2)
	if _, ok := byPath(c.Net)["auth/login.py"]; ok || len(c.Net) != 1 {
		t.Fatalf("net diff %v", c.Net)
	}
	if n := countOf(c.Range, "auth/login.py"); n != 2 {
		t.Fatalf("range %q: auth/login.py %d times, want 2", c.Range, n)
	}
}

func countOf(xs []string, x string) int {
	n := 0
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}

// Hostile: attributes on the mirror's HEAD cannot turn a binary into text.
func TestAttributesCannotHideABinary(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.File{Path: "blob.bin", Data: binaryData(4000)})
	head := r.Commit([]string{base}, "head", gitfixture.File{Path: "blob.bin", Data: binaryData(5000)},
		gitfixture.Text(".gitattributes", "*.bin diff\n"))
	r.Git("update-ref", "refs/heads/main", head)
	r.SetConfig("attr.tree", "HEAD")
	// Armed control: plain git, reading attributes from HEAD, counts the binary as text.
	if out := r.Git("diff-tree", "-r", "--numstat", base, head); strings.Contains(out, "-\t-\tblob.bin") {
		t.Fatalf("control: the attributes did not take effect, so this test would prove nothing:\n%s", out)
	}
	c := mustChanges(t, adapter(t), repos, base, head)
	if got := byPath(c.Net)["blob.bin"]; !got.Binary {
		t.Fatalf("the adapter counted the binary as text: %+v", got)
	}
}

// Hostile: a replacement ref cannot make the adapter diff another commit.
func TestReplaceRefsAreNotHonoured(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	head := r.Commit([]string{base}, "real", gitfixture.Text("README", "1\n"), gitfixture.Text("auth/login.py", "x\n"))
	fake := r.Commit([]string{base}, "fake", gitfixture.Text("README", "2\n"))
	r.Git("replace", head, fake)
	if out := r.Git("diff-tree", "-r", "--name-only", base, head); !strings.Contains(out, "README") || strings.Contains(out, "auth") {
		t.Fatalf("control: the replace ref did not take effect:\n%s", out)
	}
	got := byPath(mustChanges(t, adapter(t), repos, base, head).Net)
	if _, ok := got["auth/login.py"]; !ok || len(got) != 1 {
		t.Fatalf("the adapter diffed the replacement: %v", got)
	}
}

// Hostile: grafts cannot hide a restored protected file from the range.
func TestGraftsAreNotHonoured(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("auth/login.py", "v1\n"), gitfixture.Text("README", "r1\n"))
	m1 := r.Commit([]string{base}, "fix on main", gitfixture.Text("auth/login.py", "v2\n"), gitfixture.Text("README", "r1\n"))
	head := r.Commit([]string{m1}, "revert", gitfixture.Text("auth/login.py", "v1\n"), gitfixture.Text("README", "r2\n"))
	r.WriteFile("info/grafts", []byte(head+" "+base+"\n"))
	if out := r.Git("log", "-r", "--raw", "--format=", "--no-renames", base+".."+head); strings.Contains(out, "auth/login.py") {
		t.Fatalf("control: the graft did not hide the file:\n%s", out)
	}
	if n := countOf(mustChanges(t, adapter(t), repos, base, head).Range, "auth/login.py"); n != 2 {
		t.Fatalf("the adapter honoured the graft: auth/login.py %d times in the range", n)
	}
}

// Hostile: a signature program named in the repository's config never runs.
func TestSignatureProgramsNeverRun(t *testing.T) {
	r, repos := newRepo(t)
	marker := filepath.Join(t.TempDir(), "ran")
	prog := filepath.Join(t.TempDir(), "gpg")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\ntouch "+marker+"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	tree := r.Tree(gitfixture.Text("README", "2\n"))
	signed := strings.TrimSpace(r.GitIn([]byte("tree "+tree+"\nparent "+base+
		"\nauthor f <f@x> 1767225600 +0000\ncommitter f <f@x> 1767225600 +0000\n"+
		"gpgsig -----BEGIN PGP SIGNATURE-----\n junk\n -----END PGP SIGNATURE-----\n\nsigned\n"),
		"hash-object", "-t", "commit", "-w", "--stdin"))
	r.SetConfig("log.showSignature", "true")
	r.SetConfig("gpg.program", prog)
	r.Git("log", "-r", "-z", "--raw", "--format=", base+".."+signed)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("control: git log did not run the signature program, so this test would prove nothing")
	}
	os.Remove(marker)
	mustChanges(t, adapter(t), repos, base, signed)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the adapter ran a program named in the repository's config")
	}
}

// Hostile: log.diffMerges in the repository's config cannot drop a merge's own changes.
func TestMergesAreListedWhateverTheConfig(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	side := r.Commit([]string{base}, "side", gitfixture.Text("README", "1\n"), gitfixture.Text("s.txt", "s\n"))
	main := r.Commit([]string{base}, "main", gitfixture.Text("README", "1\n"), gitfixture.Text("m.txt", "m\n"))
	merge := r.Commit([]string{main, side}, "evil merge", gitfixture.Text("README", "1\n"),
		gitfixture.Text("s.txt", "s\n"), gitfixture.Text("m.txt", "m\n"), gitfixture.Text("auth/x.py", "only in the merge\n"))
	r.SetConfig("log.diffMerges", "off")
	if out := r.Git("log", "-r", "--raw", "--format=", "--no-renames", "-m", base+".."+merge); strings.Contains(out, "auth/x.py") {
		t.Fatalf("control: log.diffMerges=off did not drop the merge's changes:\n%s", out)
	}
	if n := countOf(mustChanges(t, adapter(t), repos, base, merge).Range, "auth/x.py"); n != 2 {
		t.Fatalf("the range lists auth/x.py %d times, want 2 (the merge against each parent)", n)
	}
}

// Hostile: diff.ignoreSubmodules in the repository's config cannot hide a submodule change.
func TestSubmodulesAreListedWhateverTheConfig(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	head := r.Commit([]string{base}, "sub", gitfixture.Text("README", "1\n"), gitfixture.File{Path: "infra/mod", Mode: "160000", Commit: base})
	r.SetConfig("diff.ignoreSubmodules", "all")
	if out := r.Git("log", "-r", "--raw", "--format=", base+".."+head); strings.Contains(out, "infra/mod") {
		t.Fatalf("control: diff.ignoreSubmodules=all did not hide the submodule:\n%s", out)
	}
	if !slices.Contains(mustChanges(t, adapter(t), repos, base, head).Range, "infra/mod") {
		t.Fatal("the range misses the submodule")
	}
}

// Defence in depth (plumbing never runs these anyway): an external diff, a text conversion or a
// hook named in the repository's config runs nothing.
func TestConfiguredProgramsNeverRun(t *testing.T) {
	r, repos := newRepo(t)
	marker := filepath.Join(t.TempDir(), "ran")
	prog := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\ntouch "+marker+"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := t.TempDir()
	for _, h := range []string{"post-checkout", "post-commit", "reference-transaction", "pre-auto-gc"} {
		os.WriteFile(filepath.Join(hooks, h), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)
	}
	base := r.Commit(nil, "base", gitfixture.Text("x.txt", "1\n"))
	head := r.Commit([]string{base}, "head", gitfixture.Text("x.txt", "2\n"), gitfixture.Text(".gitattributes", "*.txt diff=conv\n"))
	r.Git("update-ref", "refs/heads/main", head)
	r.SetConfig("attr.tree", "HEAD")
	r.SetConfig("diff.external", prog)
	r.SetConfig("diff.conv.textconv", prog)
	r.SetConfig("core.hooksPath", hooks)
	r.SetConfig("core.fsmonitor", prog)
	mustChanges(t, adapter(t), repos, base, head)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the adapter ran a program named in the repository's config")
	}
}

// Refusals: each is an error, never a partial result.
func TestRefusals(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	head := r.Commit([]string{base}, "head", gitfixture.Text("README", "2\n"))
	other := r.Commit(nil, "unrelated", gitfixture.Text("other", "1\n"))
	r.Git("tag", "-a", "-m", "annotated", "v1", head)
	tag := strings.TrimSpace(r.Git("rev-parse", "v1"))
	if strings.TrimSpace(r.Git("cat-file", "-t", tag)) != "tag" {
		t.Fatal("control: v1 is not an annotated tag")
	}
	r.Git("cat-file", "-e", tag+"^{commit}") // control: the lenient check would accept it
	g := adapter(t)
	cases := []struct {
		name, repos, project, base, head string
	}{
		{"missing repository", repos, "nope", base, head},
		{"project id with a slash", repos, "../foreman", base, head},
		{"relative repositories directory", "relative/dir", "foreman", base, head},
		{"unknown sha", repos, "foreman", base, strings.Repeat("ab", 20)},
		{"upper-case sha", repos, "foreman", base, strings.ToUpper(head)},
		{"abbreviated sha", repos, "foreman", base, head[:12]},
		{"empty base", repos, "foreman", "", head},
		{"head does not descend from base", repos, "foreman", head, base},
		{"unrelated head", repos, "foreman", base, other},
		{"annotated tag as head", repos, "foreman", base, tag},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := g.Changes(context.Background(), c.repos, c.project, c.base, c.head); err == nil {
				t.Fatalf("no error; changes %+v", got)
			}
		})
	}
}

// The repository contract, checked: owner, bare, not shallow, not a partial clone.
func TestRepositoryContract(t *testing.T) {
	setup := func(t *testing.T) (*gitfixture.Repo, string, string, string) {
		r, repos := newRepo(t)
		base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
		head := r.Commit([]string{base}, "head", gitfixture.Text("README", "2\n"))
		return r, repos, base, head
	}
	t.Run("owned by another user", func(t *testing.T) {
		_, repos, base, head := setup(t)
		g := adapter(t)
		g.uid = os.Getuid() + 1
		if _, err := g.Changes(context.Background(), repos, "foreman", base, head); err == nil || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("err = %v", err)
		}
	})
	for name, arrange := range map[string]func(r *gitfixture.Repo, base string){
		"shallow":  func(r *gitfixture.Repo, base string) { r.WriteFile("shallow", []byte(base+"\n")) },
		"not bare": func(r *gitfixture.Repo, _ string) { r.SetConfig("core.bare", "false") },
		"a partial clone": func(r *gitfixture.Repo, _ string) {
			r.SetConfig("core.repositoryformatversion", "1")
			r.SetConfig("extensions.partialclone", "origin")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, repos, base, head := setup(t)
			arrange(r, base)
			if _, err := adapter(t).Changes(context.Background(), repos, "foreman", base, head); err == nil {
				t.Fatal("no error")
			}
		})
	}
	t.Run("an empty foreman.git inside another repository", func(t *testing.T) {
		// The enclosing repository is bare and holds the very commits asked for, so only the way git
		// is pointed at the repository stands between the adapter and a diff of the wrong one.
		outer := filepath.Join(t.TempDir(), "mirror.git")
		enclosing := gitfixture.New(t, outer)
		base := enclosing.Commit(nil, "base", gitfixture.Text("README", "1\n"))
		head := enclosing.Commit([]string{base}, "head", gitfixture.Text("README", "2\n"))
		dir := filepath.Join(outer, "repos", "foreman.git")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		ctl := exec.Command("git", "-C", dir, "rev-parse", "--absolute-git-dir")
		ctl.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + t.TempDir()}
		if out, err := ctl.Output(); err != nil || strings.TrimSpace(string(out)) != outer {
			t.Fatalf("control: -C did not fall through to the enclosing repository: %q %v", out, err)
		}
		if c, err := adapter(t).Changes(context.Background(), filepath.Join(outer, "repos"), "foreman", base, head); err == nil {
			t.Fatalf("the adapter diffed the enclosing repository: %+v", c)
		}
	})
}

// A stub git that sleeps, with a child holding stdout open: the call ends within the deadline plus
// WaitDelay, because the whole process group is killed.
func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	_, repos := newRepo(t)
	stub := filepath.Join(t.TempDir(), "git")
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = version ] && { echo 'git version 2.43.0'; exit 0; }; done\n" +
		"sleep 30 &\necho $! > " + pidFile + "\nsleep 30\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	g := newGitAt(stub, time.Second, 10<<20)
	if err := g.Err(); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("ab", 20)
	start := time.Now()
	_, err := g.Changes(context.Background(), repos, "foreman", sha, sha)
	if err == nil {
		t.Fatal("a git that never answers produced changes")
	}
	if took := time.Since(start); took > time.Second+gitWaitDelay+time.Second {
		t.Fatalf("the call took %s", took)
	}
	// The background child, which held stdout, died with the group: killing only the stub would
	// leave it running, and the time bound alone cannot tell (WaitDelay rescues that case too).
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the child %d holding stdout outlived the call: the process group was not killed", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestOutputOverTheCapIsAnError(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	var files []gitfixture.File
	for i := range 50 {
		files = append(files, gitfixture.Text(strings.Repeat("d", 40)+"/"+string(rune('a'+i%26))+strings.Repeat("x", i), "x\n"))
	}
	head := r.Commit([]string{base}, "many", files...)
	g := newGitAt(adapter(t).Path(), 10*time.Second, 2000)
	if _, err := g.Changes(context.Background(), repos, "foreman", base, head); err == nil {
		t.Fatal("output over the cap was accepted")
	}
	if _, err := newGitAt(adapter(t).Path(), 10*time.Second, 1<<20).Changes(context.Background(), repos, "foreman", base, head); err != nil {
		t.Fatalf("control: with room enough the same call works: %v", err)
	}
}

func TestOldGitIsRefused(t *testing.T) {
	stub := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'git version 2.40.1'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	g := newGitAt(stub, time.Second, 1<<20)
	if g.Err() == nil {
		t.Fatal("git 2.40.1 was accepted; --attr-source needs 2.41.0")
	}
	_, repos := newRepo(t)
	sha := strings.Repeat("ab", 20)
	if _, err := g.Changes(context.Background(), repos, "foreman", sha, sha); err == nil {
		t.Fatal("an old git produced changes")
	}
}

// Configuration from outside the call is never read: the server's own global and system config,
// config passed in the environment, and git variables the server happens to have set (Anchor,
// "Where the diff comes from"). The probe is a setting the adapter pins no flag for and reads
// itself: extensions.partialclone, which makes it refuse the repository if it comes from anywhere.
func TestOutsideConfigurationIsNotRead(t *testing.T) {
	r, repos := newRepo(t)
	base := r.Commit(nil, "base", gitfixture.Text("README", "1\n"))
	head := r.Commit([]string{base}, "head", gitfixture.Text("README", "2\n"))
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(cfg, []byte("[extensions]\n\tpartialclone = origin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[extensions]\n\tpartialclone = origin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := gitfixture.New(t, filepath.Join(t.TempDir(), "other.git"))
	other.Commit(nil, "unrelated", gitfixture.Text("x", "1\n"))
	for name, c := range map[string]struct {
		env     []string
		control []string // the git command that shows the variable taking effect
	}{
		"global config":     {[]string{"HOME=" + home}, []string{"config", "--get", "extensions.partialclone"}},
		"GIT_CONFIG_GLOBAL": {[]string{"GIT_CONFIG_GLOBAL=" + cfg}, []string{"config", "--get", "extensions.partialclone"}},
		"GIT_CONFIG_SYSTEM": {[]string{"GIT_CONFIG_SYSTEM=" + cfg}, []string{"config", "--get", "extensions.partialclone"}},
		"config in the env": {[]string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=extensions.partialclone", "GIT_CONFIG_VALUE_0=origin"},
			[]string{"config", "--get", "extensions.partialclone"}},
		"another object store": {[]string{"GIT_OBJECT_DIRECTORY=" + filepath.Join(other.Dir, "objects")}, []string{"cat-file", "-t", head}},
	} {
		t.Run(name, func(t *testing.T) {
			// Armed control: plain git given this environment is affected.
			ctl := exec.Command("git", append([]string{"--git-dir=" + r.Dir}, c.control...)...)
			ctl.Env = append([]string{"PATH=" + os.Getenv("PATH")}, c.env...)
			out, err := ctl.Output()
			affected := (c.control[0] == "config" && err == nil && strings.TrimSpace(string(out)) == "origin") ||
				(c.control[0] == "cat-file" && err != nil)
			if !affected {
				t.Fatalf("control: the environment did not take effect: %q %v", out, err)
			}
			for _, kv := range c.env {
				k, v, _ := strings.Cut(kv, "=")
				t.Setenv(k, v)
			}
			if got := mustChanges(t, adapter(t), repos, base, head); len(got.Net) != 1 {
				t.Fatalf("with %v in the environment: %+v", c.env, got)
			}
		})
	}
}
