// Package gitfixture builds git repositories for the risk evaluator's tests. Trees are written with
// git plumbing from an index fed NUL-delimited on stdin, so any path works, newlines and bytes that
// are not UTF-8 included, on any filesystem, and so do symlinks and submodules. Only tests import
// it; a test checks the command never links it (P03 D13).
package gitfixture

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Repo is a bare repository under a test's temporary directory.
type Repo struct {
	t   testing.TB
	Dir string // the bare repository's absolute path
	git string
	env []string
}

// New creates an empty bare repository at dir, which must not exist yet.
func New(t testing.TB, dir string) *Repo {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal("the fixture needs git:", err)
	}
	home := t.TempDir()
	r := &Repo{t: t, Dir: dir, git: git, env: []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	}}
	r.run(nil, "", "init", "-q", "--bare", "-b", "main", dir)
	return r
}

// File is one entry of a tree. Mode defaults to 100644. For a symlink (120000) Data is the target;
// for a submodule (160000) Commit is the commit it points at and Data is ignored.
type File struct {
	Path   string
	Mode   string
	Data   []byte
	Commit string
}

// Text is a regular file with the given content.
func Text(path, content string) File { return File{Path: path, Data: []byte(content)} }

// Tree writes a tree holding exactly these files and returns its id.
func (r *Repo) Tree(files ...File) string {
	r.t.Helper()
	index := filepath.Join(r.t.TempDir(), "index")
	var in bytes.Buffer
	for _, f := range files {
		mode := f.Mode
		if mode == "" {
			mode = "100644"
		}
		id := f.Commit
		if mode != "160000" {
			id = strings.TrimSpace(r.run(f.Data, "", "hash-object", "-w", "--stdin"))
		}
		fmt.Fprintf(&in, "%s %s\t%s\x00", mode, id, f.Path)
	}
	r.run(in.Bytes(), index, "update-index", "-z", "--index-info")
	return strings.TrimSpace(r.run(nil, index, "write-tree"))
}

// Commit writes a commit of exactly these files on the given parents and returns its id.
func (r *Repo) Commit(parents []string, message string, files ...File) string {
	r.t.Helper()
	args := []string{"commit-tree", r.Tree(files...), "-m", message}
	for _, p := range parents {
		args = append(args, "-p", p)
	}
	return strings.TrimSpace(r.run(nil, "", args...))
}

// Git runs a git command in the repository and returns its standard output.
func (r *Repo) Git(args ...string) string {
	r.t.Helper()
	return r.run(nil, "", args...)
}

// GitIn runs a git command with the given standard input.
func (r *Repo) GitIn(stdin []byte, args ...string) string {
	r.t.Helper()
	return r.run(stdin, "", args...)
}

// SetConfig writes a setting into the repository's own config.
func (r *Repo) SetConfig(key, value string) {
	r.t.Helper()
	r.run(nil, "", "config", key, value)
}

// WriteFile writes a file inside the repository directory (info/grafts, shallow and the like).
func (r *Repo) WriteFile(rel string, data []byte) {
	r.t.Helper()
	p := filepath.Join(r.Dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *Repo) run(stdin []byte, index string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command(r.git, append([]string{"--git-dir=" + r.Dir}, args...)...)
	cmd.Env = r.env
	if index != "" {
		cmd.Env = append(append([]string{}, r.env...), "GIT_INDEX_FILE="+index)
	}
	if args[0] == "init" {
		cmd.Args = append([]string{r.git}, args...)
	}
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		r.t.Fatalf("fixture: git %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return out.String()
}
