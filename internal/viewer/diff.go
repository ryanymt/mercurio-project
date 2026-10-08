package viewer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
)

// DefaultMaxDiffBytes bounds a diff read from GitHub; a longer one is shown as too large.
const DefaultMaxDiffBytes = 2 << 20

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// GitHubDiffs reads base...head through GitHub's compare API, with a contents-read token from the
// read-only App (D6), minted for the ticket's repository and kept until five minutes before it
// expires. The diff form has no pagination: a range GitHub cannot render in time answers a 5xx or
// times out (consult 1), and a 406 is how GitHub says a diff is too large, so each of those is
// "too large", with the first 300 changed files from the JSON form.
type GitHubDiffs struct {
	MaxBytes int64 // DefaultMaxDiffBytes when 0

	tokens *github.Client
	api    string
	client *http.Client
	mu     sync.Mutex
	cache  map[string]github.Token // by owner/name
}

// NewGitHubDiffs asks the API at api (github.DefaultAPI when empty; https, or plain http to a
// loopback address in tests) as the App creds names. With no client, a request times out after 20
// seconds, and a compare that does is too large.
func NewGitHubDiffs(creds github.Credentials, api string, client *http.Client) (*GitHubDiffs, error) {
	if creds == nil {
		return nil, errors.New("viewer: the read-only App's credentials are required")
	}
	if api == "" {
		api = github.DefaultAPI
	}
	if err := checkEndpoint(api); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &GitHubDiffs{tokens: github.New(creds, api, client), api: strings.TrimSuffix(api, "/"), client: client,
		cache: map[string]github.Token{}}, nil
}

func (g *GitHubDiffs) token(ctx context.Context, repo string) (github.Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t, ok := g.cache[repo]; ok && time.Until(t.ExpiresAt()) > 5*time.Minute {
		return t, nil
	}
	t, err := g.tokens.Token(ctx, repo, github.ContentsRead)
	if err != nil {
		return github.Token{}, fmt.Errorf("viewer: a read token for %s: %w", repo, err)
	}
	g.cache[repo] = t
	return t, nil
}

func (g *GitHubDiffs) drop(repo string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.cache, repo)
}

func (g *GitHubDiffs) get(ctx context.Context, path string, token github.Token, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.api+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.Value())
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return g.client.Do(req)
}

// timedOut says whether err is a request that ran out of time.
func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (g *GitHubDiffs) Compare(ctx context.Context, repoURL, base, head string) (Diff, error) {
	repo, err := github.RepoFromURL(repoURL)
	if err != nil {
		return Diff{}, fmt.Errorf("viewer: %w", err)
	}
	if !commitPattern.MatchString(base) || !commitPattern.MatchString(head) {
		return Diff{}, fmt.Errorf("viewer: %q...%q is not a range of two commits", base, head)
	}
	rng := base + "..." + head
	d := Diff{Base: base, Head: head, CompareURL: "https://github.com/" + repo + "/compare/" + rng}
	token, err := g.token(ctx, repo)
	if err != nil {
		return Diff{}, err
	}
	path := "/repos/" + repo + "/compare/" + rng
	tooLarge := func() (Diff, error) {
		d.Status, d.Files = DiffTooLarge, g.files(ctx, path, token)
		return d, nil
	}
	resp, err := g.get(ctx, path, token, "application/vnd.github.diff")
	if err != nil {
		if timedOut(err) {
			return tooLarge()
		}
		return Diff{}, fmt.Errorf("viewer: GitHub's compare: %w", err)
	}
	defer resp.Body.Close()
	switch s := resp.StatusCode; {
	case s == http.StatusOK:
		max := g.MaxBytes
		if max <= 0 {
			max = DefaultMaxDiffBytes
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err != nil {
			if timedOut(err) {
				return tooLarge()
			}
			return Diff{}, fmt.Errorf("viewer: GitHub's compare: %w", err)
		}
		if int64(len(b)) > max {
			return tooLarge()
		}
		d.Status, d.Text = DiffOK, string(b)
		return d, nil
	case s == http.StatusNotFound || s == http.StatusUnprocessableEntity:
		d.Status = DiffNotFound
		return d, nil
	case s == http.StatusNotAcceptable || s >= 500:
		return tooLarge()
	case s == http.StatusUnauthorized:
		g.drop(repo)
	}
	return Diff{}, fmt.Errorf("viewer: GitHub's compare: status %d", resp.StatusCode)
}

// files is the first 300 changed files from the compare's JSON form, which lists files on its first
// page only; nil when GitHub cannot give even that.
func (g *GitHubDiffs) files(ctx context.Context, path string, token github.Token) []string {
	resp, err := g.get(ctx, path+"?per_page=1", token, "application/vnd.github+json")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var got struct {
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&got) != nil {
		return nil
	}
	var out []string
	for _, f := range got.Files {
		if len(out) == 300 {
			break
		}
		out = append(out, f.Filename)
	}
	return out
}

// diffLine is one line of a unified diff, classed for the page.
type diffLine struct {
	Class, Text string
}

func diffLines(text string) []diffLine {
	var out []diffLine
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		c := "ctx"
		switch {
		case strings.HasPrefix(l, "diff --git "), strings.HasPrefix(l, "+++ "), strings.HasPrefix(l, "--- "),
			strings.HasPrefix(l, "index "), strings.HasPrefix(l, "new file"), strings.HasPrefix(l, "deleted file"):
			c = "file"
		case strings.HasPrefix(l, "@@"):
			c = "hunk"
		case strings.HasPrefix(l, "+"):
			c = "add"
		case strings.HasPrefix(l, "-"):
			c = "del"
		}
		out = append(out, diffLine{c, l})
	}
	return out
}

// diffPage shows base...head from GitHub, never the runner's own diff (D6). With no head there is
// nothing to compare, and GitHub is not asked (critique G3).
func (s *Server) diffPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, http.StatusNotFound, "no such ticket")
		return
	}
	t, err := s.ticket(r.Context(), id)
	if errors.Is(err, errNotFound) {
		s.fail(w, http.StatusNotFound, "no such ticket")
		return
	}
	if err != nil {
		s.log.Error("viewer: read a ticket", "ticket", id, "error", err)
		s.fail(w, http.StatusInternalServerError, "the ticket could not be read")
		return
	}
	data := map[string]any{"T": t, "Person": visitorOf(r).caller.Email}
	switch {
	case t.HeadSHA == "":
		data["Note"] = "no commit submitted yet"
	case t.BaseSHA == "":
		data["Note"] = "no base commit is recorded, so there is nothing to compare the head with"
	default:
		d, err := s.cfg.Diffs.Compare(r.Context(), t.RepoURL, t.BaseSHA, t.HeadSHA)
		if err != nil {
			s.log.Error("viewer: compare", "ticket", id, "error", err)
			s.fail(w, http.StatusBadGateway, "GitHub could not be asked for the diff")
			return
		}
		data["D"] = d
		if d.Status == DiffOK {
			data["Lines"] = diffLines(d.Text)
		}
	}
	s.render(w, http.StatusOK, "diff.html", data)
}
