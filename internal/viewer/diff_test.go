package viewer_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun/cloudruntest"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
	"github.com/ryanymt/mercurio-project/internal/viewer"
)

// --- the diff page --------------------------------------------------------------------------------

// The diff page: no compare without a head; a diff shown escaped; too large with the range, the
// files and a link; a commit GitHub does not know; GitHub not answering (critique G3, consult 1, red
// team R3#2).
func TestTheDiffPage(t *testing.T) {
	r := newRig(t)
	r.start()
	noHead := r.seed("sandbox", "no head", "ready", map[string]any{"base_sha": sha1})
	st, page := r.get(fmt.Sprintf("/tickets/%d/diff", noHead))
	if st != http.StatusOK || !strings.Contains(page, "no commit submitted yet") || r.diffs.calls != 0 {
		t.Fatalf("no head: status %d, %d compares: %s", st, r.diffs.calls, page)
	}

	ok := r.seed("sandbox", "a diff", "awaiting_review", map[string]any{"base_sha": sha1, "head_sha": sha2})
	r.diffs.diffs[sha1+"..."+sha2] = viewer.Diff{Status: viewer.DiffOK, Base: sha1, Head: sha2,
		CompareURL: "https://github.com/your-org/sandbox-repo/compare/" + sha1 + "..." + sha2,
		Text:       "diff --git a/x.html b/x.html\n--- a/x.html\n+++ b/x.html\n@@ -1 +1 @@\n-<p>old</p>\n+<script>alert(1)</script>\n"}
	st, page = r.get(fmt.Sprintf("/tickets/%d/diff", ok))
	if st != http.StatusOK || strings.Contains(page, "<script>alert") || !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("a diff: status %d: %s", st, page)
	}
	for _, want := range []string{`class="add"`, `class="del"`, `class="hunk"`, `class="file"`, sha1, sha2} {
		if !strings.Contains(page, want) {
			t.Errorf("a diff's page lacks %s", want)
		}
	}

	large := r.seed("sandbox", "too large", "escalated", map[string]any{"base_sha": sha1, "head_sha": sha3,
		"escalated_at": time.Now()})
	r.diffs.diffs[sha1+"..."+sha3] = viewer.Diff{Status: viewer.DiffTooLarge, Base: sha1, Head: sha3,
		Files: []string{"a/one.go", "b/<two>.go"}, CompareURL: "https://github.com/your-org/sandbox-repo/compare/" + sha1 + "..." + sha3}
	st, page = r.get(fmt.Sprintf("/tickets/%d/diff", large))
	for _, want := range []string{"too large", sha1 + "..." + sha3, "a/one.go", "b/&lt;two&gt;.go",
		`href="https://github.com/your-org/sandbox-repo/compare/` + sha1 + "..." + sha3 + `"`} {
		if !strings.Contains(page, want) {
			t.Errorf("too large: the page lacks %s", want)
		}
	}
	if st != http.StatusOK {
		t.Fatalf("too large: status %d", st)
	}
	// A diff too large to show is still of a commit GitHub knows: it can be approved.
	if _, tp := r.get(fmt.Sprintf("/tickets/%d", large)); decision(forms(tp), "approved") == nil {
		t.Error("too large: no approval offered")
	}

	unknown := r.seed("sandbox", "unknown", "awaiting_review", map[string]any{"base_sha": sha2, "head_sha": sha3})
	st, page = r.get(fmt.Sprintf("/tickets/%d/diff", unknown))
	if st != http.StatusOK || !strings.Contains(page, "commit not found") {
		t.Fatalf("unknown: status %d: %s", st, page)
	}

	r.diffs.err = errors.New("GitHub is down")
	st, page = r.get(fmt.Sprintf("/tickets/%d/diff", ok))
	if st != http.StatusBadGateway || strings.Contains(page, "GitHub is down") {
		t.Fatalf("GitHub down: status %d: %s", st, page)
	}
}

// When GitHub cannot be asked, the ticket page says so and offers no commit-bound action.
func TestNoCommitBoundActionWhenGitHubCannotBeAsked(t *testing.T) {
	r := newRig(t)
	r.start()
	r.diffs.err = errors.New("GitHub is down")
	id := r.seed("sandbox", "down", "escalated", map[string]any{"base_sha": sha1, "head_sha": sha2, "escalated_at": time.Now()})
	_, page := r.get(fmt.Sprintf("/tickets/%d", id))
	fs := forms(page)
	if decision(fs, "approved") != nil || decision(fs, "awaiting_review") != nil || decision(fs, "done") == nil ||
		!strings.Contains(page, "GitHub could not be asked") {
		t.Fatalf("forms %+v: %s", fs, page)
	}
}

// --- GitHub's compare, through the read-only App ----------------------------------------------------

const sandboxRepo = "https://github.com/your-org/sandbox-repo"

// fakeGitHub mints installation tokens for the sandbox, as cloudruntest's does, and answers its
// compares: the diff form with diffStatus (after delay), the JSON form with n files.
type fakeGitHub struct {
	*httptest.Server
	mu         sync.Mutex
	mints      []string // the contents permission asked, per mint
	compares   []http.Header
	queries    []string
	diffStatus int
	diff       string
	delay      time.Duration
	files      int
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{diffStatus: http.StatusOK}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		const repo = "/repos/" + cloudruntest.Repo
		switch {
		case r.Method == "GET" && r.URL.Path == repo+"/installation":
			f.mu.Unlock()
			fmt.Fprint(w, `{"id": 7}`)
		case r.Method == "POST" && r.URL.Path == "/app/installations/7/access_tokens":
			var body struct {
				Permissions map[string]string `json:"permissions"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			f.mints = append(f.mints, body.Permissions["contents"])
			n := len(f.mints)
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token": "ghs_fakeViewerToken%d", "expires_at": %q, "permissions": {"contents": %q, "metadata": "read"},
				"repositories": [{"full_name": %q}]}`, n, time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				body.Permissions["contents"], cloudruntest.Repo)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, repo+"/compare/"):
			f.compares = append(f.compares, r.Header.Clone())
			f.queries = append(f.queries, r.URL.Path+"?"+r.URL.RawQuery)
			status, diff, delay, files := f.diffStatus, f.diff, f.delay, f.files
			f.mu.Unlock()
			if r.Header.Get("Accept") == "application/vnd.github.diff" {
				time.Sleep(delay)
				w.WriteHeader(status)
				if status == http.StatusOK {
					fmt.Fprint(w, diff)
				}
				return
			}
			var out struct {
				Files []map[string]string `json:"files"`
			}
			for i := 0; i < files; i++ {
				out.Files = append(out.Files, map[string]string{"filename": fmt.Sprintf("dir/file%03d.go", i), "patch": "@@ -1 +1 @@"})
			}
			json.NewEncoder(w).Encode(out)
		default:
			f.mu.Unlock()
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeGitHub) set(status int, diff string, delay time.Duration, files int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.diffStatus, f.diff, f.delay, f.files = status, diff, delay, files
}

func newDiffs(t *testing.T, f *fakeGitHub, client *http.Client) *viewer.GitHubDiffs {
	t.Helper()
	g, err := viewer.NewGitHubDiffs(github.Static("123", cloudruntest.AppKey(t)), f.URL, client)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// A compare asks with a contents-read token minted for the ticket's repository, in the diff form,
// and the token is kept for the next one.
func TestGitHubDiffsAsksWithAReadToken(t *testing.T) {
	f := newFakeGitHub(t)
	g := newDiffs(t, f, nil)
	f.set(http.StatusOK, "diff --git a/x b/x\n", 0, 0)
	for i := 0; i < 2; i++ {
		d, err := g.Compare(context.Background(), sandboxRepo, sha1, sha2)
		if err != nil || d.Status != viewer.DiffOK || d.Text != "diff --git a/x b/x\n" || d.Base != sha1 || d.Head != sha2 ||
			d.CompareURL != "https://github.com/your-org/sandbox-repo/compare/"+sha1+"..."+sha2 {
			t.Fatalf("compare %d: %+v, %v", i+1, d, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mints) != 1 || f.mints[0] != "read" {
		t.Fatalf("tokens minted %v, want one for contents read", f.mints)
	}
	for _, h := range f.compares {
		if h.Get("Authorization") != "Bearer ghs_fakeViewerToken1" || h.Get("Accept") != "application/vnd.github.diff" {
			t.Fatalf("a compare asked with %v", h)
		}
	}
	if f.queries[0] != "/repos/your-org/sandbox-repo/compare/"+sha1+"..."+sha2+"?" {
		t.Fatalf("asked for %s", f.queries[0])
	}
}

// What GitHub answers decides the status: a 404 or 422 is a commit it does not know; a 406, a 5xx,
// a timeout or a diff past the bound is too large, with the first 300 files from the JSON form; any
// other status is an error.
func TestGitHubDiffsStatuses(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		delay  time.Duration
		diff   string
		want   viewer.DiffStatus
		err    bool
	}{
		"404":        {status: 404, want: viewer.DiffNotFound},
		"422":        {status: 422, want: viewer.DiffNotFound},
		"406":        {status: 406, want: viewer.DiffTooLarge},
		"500":        {status: 500, want: viewer.DiffTooLarge},
		"502":        {status: 502, want: viewer.DiffTooLarge},
		"a timeout":  {status: 200, delay: 700 * time.Millisecond, want: viewer.DiffTooLarge},
		"past bound": {status: 200, diff: strings.Repeat("+x\n", 100), want: viewer.DiffTooLarge},
		"at bound":   {status: 200, diff: strings.Repeat("+", 64), want: viewer.DiffOK},
		"401":        {status: 401, err: true},
		"403":        {status: 403, err: true},
		"301":        {status: 301, err: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGitHub(t)
			g := newDiffs(t, f, &http.Client{Timeout: 250 * time.Millisecond})
			g.MaxBytes = 64
			f.set(c.status, c.diff, c.delay, 350)
			d, err := g.Compare(context.Background(), sandboxRepo, sha1, sha2)
			if c.err {
				if err == nil {
					t.Fatalf("no error: %+v", d)
				}
				return
			}
			if err != nil || d.Status != c.want {
				t.Fatalf("got %+v, %v; want %s", d, err, c.want)
			}
			if c.want == viewer.DiffTooLarge {
				if len(d.Files) != 300 || d.Files[0] != "dir/file000.go" || d.Text != "" ||
					!strings.HasSuffix(d.CompareURL, sha1+"..."+sha2) {
					t.Fatalf("too large: %d files, text %q, link %q", len(d.Files), d.Text, d.CompareURL)
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if q := f.queries[len(f.queries)-1]; !strings.Contains(q, "per_page=1") {
					t.Fatalf("the files asked for with %s", q)
				}
			}
		})
	}
}

// Only a github.com repository and two full SHAs are compared; anything else asks nothing.
func TestGitHubDiffsRefusesWhatItCannotName(t *testing.T) {
	f := newFakeGitHub(t)
	g := newDiffs(t, f, nil)
	for name, c := range map[string][3]string{
		"another host":   {"https://gitlab.com/your-org/sandbox-repo", sha1, sha2},
		"a short base":   {sandboxRepo, "1111", sha2},
		"a path in head": {sandboxRepo, sha1, "../../x"},
		"no base":        {sandboxRepo, "", sha2},
	} {
		if _, err := g.Compare(context.Background(), c[0], c[1], c[2]); err == nil {
			t.Errorf("%s: compared", name)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mints)+len(f.compares) != 0 {
		t.Fatalf("GitHub was asked: %d mints, %d compares", len(f.mints), len(f.compares))
	}
}

// A refused token (401) is dropped, so the next compare mints a fresh one.
func TestGitHubDiffsDropsARefusedToken(t *testing.T) {
	f := newFakeGitHub(t)
	g := newDiffs(t, f, nil)
	f.set(http.StatusUnauthorized, "", 0, 0)
	if _, err := g.Compare(context.Background(), sandboxRepo, sha1, sha2); err == nil {
		t.Fatal("a 401 compared")
	}
	f.set(http.StatusOK, "diff\n", 0, 0)
	if d, err := g.Compare(context.Background(), sandboxRepo, sha1, sha2); err != nil || d.Status != viewer.DiffOK {
		t.Fatalf("after a 401: %+v, %v", d, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mints) != 2 {
		t.Fatalf("%d tokens minted, want 2", len(f.mints))
	}
}

// The App's endpoint is https, or a loopback address in tests.
func TestGitHubDiffsEndpoint(t *testing.T) {
	if _, err := viewer.NewGitHubDiffs(github.Static("1", nil), "http://api.github.com", nil); err == nil {
		t.Fatal("plain http accepted")
	}
	if _, err := viewer.NewGitHubDiffs(nil, "", nil); err == nil {
		t.Fatal("no credentials accepted")
	}
}
