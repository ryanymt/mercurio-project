// Package github mints GitHub App installation tokens for the dispatcher (P05 D3): one repository,
// one permission (contents read or write), an hour at most, and nothing broader, ever. The App's
// key is read only here, by the dispatcher; a runner receives a token, never the key. It is a
// package of its own so the tick's package imports nothing that talks to the network.
package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// DefaultAPI is GitHub's REST API.
const DefaultAPI = "https://api.github.com"

// Permission is the level of the one permission a token carries: contents.
type Permission string

const (
	ContentsRead  Permission = "read"  // the dispatcher's ls-remote
	ContentsWrite Permission = "write" // a runner's push
)

// Credentials returns the App's id and private key (PEM, PKCS#1 or PKCS#8). The deployed dispatcher
// reads them from Secret Manager when it mints (P05 Approach 2), so they are never in its
// environment.
type Credentials func(ctx context.Context) (appID string, keyPEM []byte, err error)

// Static returns fixed credentials.
func Static(appID string, keyPEM []byte) Credentials {
	return func(context.Context) (string, []byte, error) { return appID, keyPEM, nil }
}

// Client mints installation tokens.
type Client struct {
	creds Credentials
	api   string
	http  *http.Client
}

// New returns a client for the API at api (DefaultAPI when empty); a nil httpClient gets one with
// a 30-second timeout, well inside the ten minutes a claim gives its runner's first call.
func New(creds Credentials, api string, httpClient *http.Client) *Client {
	if api == "" {
		api = DefaultAPI
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{creds: creds, api: strings.TrimSuffix(api, "/"), http: httpClient}
}

// Token is an installation token. Its value never prints: String and GoString redact it.
type Token struct {
	value   string
	expires time.Time
}

func (t Token) Value() string        { return t.value }
func (t Token) ExpiresAt() time.Time { return t.expires }
func (t Token) String() string       { return "github.Token[redacted]" }
func (t Token) GoString() string     { return "github.Token[redacted]" }

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)

// Token mints a token for the repository owner/name with contents at perm, and refuses one GitHub
// grants more broadly than asked: another permission (metadata read, which every token carries,
// aside), a higher level, another repository, or a life beyond an hour.
func (c *Client) Token(ctx context.Context, repo string, perm Permission) (Token, error) {
	if perm != ContentsRead && perm != ContentsWrite {
		return Token{}, fmt.Errorf("permission %q: only contents read or write", perm)
	}
	if !repoPattern.MatchString(repo) {
		return Token{}, fmt.Errorf("%q is not owner/name", repo)
	}
	appJWT, err := c.appJWT(ctx)
	if err != nil {
		return Token{}, err
	}
	var inst struct {
		ID int64 `json:"id"`
	}
	if err := c.call(ctx, "GET", "/repos/"+repo+"/installation", appJWT, nil, http.StatusOK, &inst); err != nil {
		return Token{}, fmt.Errorf("the App's installation on %s: %w", repo, err)
	}
	if inst.ID == 0 {
		return Token{}, fmt.Errorf("the App has no installation on %s", repo)
	}
	name := repo[strings.Index(repo, "/")+1:]
	req := map[string]any{"repositories": []string{name}, "permissions": map[string]string{"contents": string(perm)}}
	var got struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if err := c.call(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", inst.ID), appJWT, req,
		http.StatusCreated, &got); err != nil {
		return Token{}, fmt.Errorf("a token for %s: %w", repo, err)
	}
	switch {
	case got.Token == "":
		return Token{}, errors.New("GitHub answered with no token")
	case got.ExpiresAt.IsZero() || time.Until(got.ExpiresAt) > time.Hour+time.Minute:
		return Token{}, fmt.Errorf("the token expires at %v, beyond an hour: refused", got.ExpiresAt)
	case len(got.Repositories) != 1 || !strings.EqualFold(got.Repositories[0].FullName, repo):
		return Token{}, fmt.Errorf("the token covers %d repositories, not just %s: refused", len(got.Repositories), repo)
	}
	for p, level := range got.Permissions {
		switch {
		case p == "contents" && level == string(perm):
		case p == "metadata" && level == "read":
		default:
			return Token{}, fmt.Errorf("the token carries %s: %s, beyond contents: %s: refused", p, level, perm)
		}
	}
	if got.Permissions["contents"] != string(perm) {
		return Token{}, fmt.Errorf("the token lacks contents: %s: refused", perm)
	}
	return Token{value: got.Token, expires: got.ExpiresAt}, nil
}

// appJWT signs the App's JWT: RS256, issued by the App, backdated a minute for clock drift, and
// valid nine minutes after that (GitHub allows ten).
func (c *Client) appJWT(ctx context.Context) (string, error) {
	appID, keyPEM, err := c.creds(ctx)
	if err != nil {
		return "", fmt.Errorf("the App's credentials: %w", err)
	}
	if appID == "" {
		return "", errors.New("the App's id is empty")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   appID,
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}).Serialize()
}

func parseKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("the App's key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the App's key is neither a PKCS#1 nor a PKCS#8 RSA key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the App's key is not an RSA key")
	}
	return rk, nil
}

// call makes one API call with the App's JWT and decodes a successful answer into out. An error
// names the status, never the request's contents.
func (c *Client) call(ctx context.Context, method, path, appJWT string, body any, want int, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// RepoFromURL returns owner/name for an https://github.com/owner/name URL (a trailing .git or
// slash allowed), and refuses anything else.
func RepoFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q is not an https://github.com repository URL", raw)
	}
	repo := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), "/"), ".git")
	if !repoPattern.MatchString(repo) {
		return "", fmt.Errorf("%q is not an https://github.com/owner/name URL", raw)
	}
	return repo, nil
}

// Remote is the dispatcher's Remote (red team 1, R4): it reads a branch's head from a private
// repository with a contents-read token minted for that repository.
type Remote struct {
	Tokens *Client
	Git    interface {
		LsRemoteWithToken(ctx context.Context, url, branch, token string) (string, error)
	}
}

// LsRemote mints a read token for the repository at url and reads branch's head with it.
func (r Remote) LsRemote(ctx context.Context, url, branch string) (string, error) {
	repo, err := RepoFromURL(url)
	if err != nil {
		return "", err
	}
	tok, err := r.Tokens.Token(ctx, repo, ContentsRead)
	if err != nil {
		return "", err
	}
	return r.Git.LsRemoteWithToken(ctx, url, branch, tok.Value())
}
