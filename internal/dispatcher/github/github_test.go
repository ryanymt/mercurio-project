package github_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
)

// GitHub App installation tokens (P05 D3; plan T2): one repository, one permission, an hour at most,
// minted with the App's JWT; anything broader is refused, never used.

const appID = "123456"

func newKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// fakeGitHub checks the App's JWT on every call and records what the token was asked for.
type fakeGitHub struct {
	t   *testing.T
	pub *rsa.PublicKey

	mu        sync.Mutex
	repos     []string
	perms     map[string]string
	claims    jwt.Claims
	tokenBody string // replaces the default answer when set
	status    int    // the token call's status, default 201
	noInstall bool
}

func (f *fakeGitHub) checkJWT(r *http.Request) bool {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return false
	}
	var c jwt.Claims
	if err := tok.Claims(f.pub, &c); err != nil {
		return false
	}
	f.mu.Lock()
	f.claims = c
	f.mu.Unlock()
	return true
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !f.checkJWT(r) {
		http.Error(w, `{"message":"bad jwt"}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/repos/your-org/sandbox-repo/installation" && !f.noInstall:
		fmt.Fprint(w, `{"id": 42}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/42/access_tokens":
		var body struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.repos, f.perms = body.Repositories, body.Permissions
		answer, status := f.tokenBody, f.status
		f.mu.Unlock()
		if status == 0 {
			status = http.StatusCreated
		}
		if answer == "" {
			answer = fmt.Sprintf(`{"token": "ghs_faketoken0123456789", "expires_at": %q,
				"permissions": {"contents": %q, "metadata": "read"},
				"repositories": [{"name": "sandbox-repo", "full_name": "your-org/sandbox-repo"}]}`,
				time.Now().Add(time.Hour).UTC().Format(time.RFC3339), body.Permissions["contents"])
		}
		w.WriteHeader(status)
		fmt.Fprint(w, answer)
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T) (*fakeGitHub, *github.Client) {
	t.Helper()
	key, keyPEM := newKey(t)
	f := &fakeGitHub{t: t, pub: &key.PublicKey}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, github.New(github.Static(appID, keyPEM), srv.URL, srv.Client())
}

func TestATokenForOneRepositoryAndOnePermission(t *testing.T) {
	for _, perm := range []github.Permission{github.ContentsRead, github.ContentsWrite} {
		f, c := setup(t)
		tok, err := c.Token(context.Background(), "your-org/sandbox-repo", perm)
		if err != nil {
			t.Fatalf("%s: %v", perm, err)
		}
		if tok.Value() != "ghs_faketoken0123456789" || time.Until(tok.ExpiresAt()) > time.Hour {
			t.Fatalf("%s: token %q expiring %s", perm, tok.Value(), tok.ExpiresAt())
		}
		if len(f.repos) != 1 || f.repos[0] != "sandbox-repo" || len(f.perms) != 1 || f.perms["contents"] != string(perm) {
			t.Fatalf("%s: asked for repositories %v, permissions %v", perm, f.repos, f.perms)
		}
	}
}

// The App's JWT: signed RS256 with its key (the fake verifies it), issued by the App, backdated a
// minute for clock drift, and valid for at most ten minutes.
func TestTheAppsJWT(t *testing.T) {
	f, c := setup(t)
	if _, err := c.Token(context.Background(), "your-org/sandbox-repo", github.ContentsRead); err != nil {
		t.Fatal(err)
	}
	cl := f.claims
	if cl.Issuer != appID || cl.IssuedAt == nil || cl.Expiry == nil {
		t.Fatalf("claims %+v", cl)
	}
	iat, exp := cl.IssuedAt.Time(), cl.Expiry.Time()
	if time.Since(iat) < 30*time.Second || time.Since(iat) > 2*time.Minute || exp.Sub(iat) > 10*time.Minute || !exp.After(time.Now()) {
		t.Fatalf("iat %s, exp %s: want iat backdated about a minute and exp at most ten minutes after it", iat, exp)
	}
}

// Anything broader than asked is refused, never used: another permission, a higher one, another
// repository, a longer life.
func TestABroaderTokenIsRefused(t *testing.T) {
	later := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }
	one := `[{"name": "sandbox-repo", "full_name": "your-org/sandbox-repo"}]`
	cases := map[string]string{
		"another permission":  fmt.Sprintf(`{"token": "ghs_x", "expires_at": %q, "permissions": {"contents": "read", "issues": "write"}, "repositories": %s}`, later(time.Hour), one),
		"a higher permission": fmt.Sprintf(`{"token": "ghs_x", "expires_at": %q, "permissions": {"contents": "write"}, "repositories": %s}`, later(time.Hour), one),
		"another repository": fmt.Sprintf(`{"token": "ghs_x", "expires_at": %q, "permissions": {"contents": "read"},
			"repositories": [{"name": "sandbox-repo", "full_name": "your-org/sandbox-repo"}, {"name": "other", "full_name": "ryanymt/other"}]}`, later(time.Hour)),
		"no repository list":           fmt.Sprintf(`{"token": "ghs_x", "expires_at": %q, "permissions": {"contents": "read"}}`, later(time.Hour)),
		"a longer life":                fmt.Sprintf(`{"token": "ghs_x", "expires_at": %q, "permissions": {"contents": "read"}, "repositories": %s}`, later(2*time.Hour), one),
		"no expiry":                    fmt.Sprintf(`{"token": "ghs_x", "permissions": {"contents": "read"}, "repositories": %s}`, one),
		"no token":                     fmt.Sprintf(`{"expires_at": %q, "permissions": {"contents": "read"}, "repositories": %s}`, later(time.Hour), one),
		"without the asked permission": fmt.Sprintf(`{"token": "ghs_x", "expires_at": %q, "permissions": {"metadata": "read"}, "repositories": %s}`, later(time.Hour), one),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := setup(t)
			f.tokenBody = body
			if tok, err := c.Token(context.Background(), "your-org/sandbox-repo", github.ContentsRead); err == nil {
				t.Fatalf("a token %q was accepted", tok.Value())
			}
		})
	}
}

func TestFailuresAreErrors(t *testing.T) {
	f, c := setup(t)
	f.noInstall = true
	if _, err := c.Token(context.Background(), "your-org/sandbox-repo", github.ContentsRead); err == nil {
		t.Fatal("no installation, yet a token")
	}
	f, c = setup(t)
	f.status, f.tokenBody = http.StatusUnprocessableEntity, `{"message": "no"}`
	if _, err := c.Token(context.Background(), "your-org/sandbox-repo", github.ContentsRead); err == nil {
		t.Fatal("a refused token request, yet a token")
	}
	if _, err := c.Token(context.Background(), "your-org/sandbox-repo", "admin"); err == nil {
		t.Fatal("a permission other than contents read or write was asked for")
	}
	if _, err := c.Token(context.Background(), "not-a-repo", github.ContentsRead); err == nil {
		t.Fatal("a repository that is not owner/name was accepted")
	}
}

// The App's key in either PEM form; anything else refused.
func TestCredentials(t *testing.T) {
	key, pkcs1 := newKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	f := &fakeGitHub{t: t, pub: &key.PublicKey}
	srv := httptest.NewServer(f)
	defer srv.Close()
	for name, keyPEM := range map[string][]byte{"PKCS#1": pkcs1, "PKCS#8": pkcs8} {
		c := github.New(github.Static(appID, keyPEM), srv.URL, srv.Client())
		if _, err := c.Token(context.Background(), "your-org/sandbox-repo", github.ContentsRead); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	for name, cr := range map[string]github.Credentials{
		"not PEM":     github.Static(appID, []byte("not a key")),
		"no app id":   github.Static("", pkcs1),
		"a bad block": github.Static(appID, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("junk")})),
	} {
		c := github.New(cr, srv.URL, srv.Client())
		if _, err := c.Token(context.Background(), "your-org/sandbox-repo", github.ContentsRead); err == nil {
			t.Errorf("%s: a token was minted", name)
		}
	}
}

// A token never prints its value, whatever the format verb.
func TestATokenNeverPrintsItsValue(t *testing.T) {
	_, c := setup(t)
	tok, err := c.Token(context.Background(), "your-org/sandbox-repo", github.ContentsRead)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s", tok, tok, tok, tok)} {
		if strings.Contains(s, tok.Value()) {
			t.Fatalf("the token printed its value: %s", s)
		}
	}
}

func TestRepoFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/your-org/sandbox-repo":     "your-org/sandbox-repo",
		"https://github.com/your-org/sandbox-repo.git": "your-org/sandbox-repo",
		"https://github.com/your-org/sandbox-repo/":    "your-org/sandbox-repo",
	} {
		if got, err := github.RepoFromURL(in); err != nil || got != want {
			t.Errorf("RepoFromURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"http://github.com/your-org/sandbox-repo", "https://gitlab.com/your-org/sandbox-repo",
		"https://github.com/ryanymt", "https://github.com/your-org/sandbox-repo/tree/main",
		"https://user@github.com/your-org/sandbox-repo", "", "github.com/your-org/sandbox-repo",
	} {
		if got, err := github.RepoFromURL(in); err == nil {
			t.Errorf("RepoFromURL(%q) = %q, want an error", in, got)
		}
	}
}

// recordingGit stands in for the hardened git runner: it records what it was asked.
type recordingGit struct{ url, branch, token string }

func (r *recordingGit) LsRemoteWithToken(ctx context.Context, url, branch, token string) (string, error) {
	r.url, r.branch, r.token = url, branch, token
	return "3333333333333333333333333333333333333333", nil
}

// The dispatcher's Remote mints a read token for the project's repository and reads the head with
// it (red team 1, R4).
func TestTheRemoteReadsWithAReadToken(t *testing.T) {
	f, c := setup(t)
	g := &recordingGit{}
	head, err := github.Remote{Tokens: c, Git: g}.LsRemote(context.Background(), "https://github.com/your-org/sandbox-repo", "main")
	if err != nil || head != "3333333333333333333333333333333333333333" {
		t.Fatalf("LsRemote = %q, %v", head, err)
	}
	if g.token != "ghs_faketoken0123456789" || g.branch != "main" || f.perms["contents"] != "read" {
		t.Fatalf("git asked with token %q, branch %q; the token's permissions %v", g.token, g.branch, f.perms)
	}
}
