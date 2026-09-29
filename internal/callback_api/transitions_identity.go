package callbackapi

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// Identity is verified here, not upstream (docs/architecture.md): every caller presents a
// Google-signed ID token, and the verified email alone decides who it is. Nothing in a request
// body can name a role or a project.

const (
	// GoogleJWKSURL is where Google publishes the keys that sign its ID tokens.
	GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	googleIssuer  = "https://accounts.google.com" // go-oidc also accepts accounts.google.com
)

//go:embed transitions_identity_map.json
var embeddedIdentityMap []byte

// IdentityMap maps a verified email to a role and, for runners, a project. The production map is
// embedded in the binary: changing who is what is a reviewed change to a protected file (D12).
type IdentityMap struct {
	byEmail map[string]Caller
}

type identityEntry struct {
	Email   string `json:"email"`
	Role    Role   `json:"role"`
	Project string `json:"project,omitempty"`
}

// isServiceAccount decides an identity's kind from its email, never from its token's audience:
// any gserviceaccount.com domain (iam., developer., appspot., cloudbuild., …) is a service account.
func isServiceAccount(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	return domain == "gserviceaccount.com" || strings.HasSuffix(domain, ".gserviceaccount.com")
}

var mappableRoles = []Role{RoleHuman, RoleDispatcher, RoleSpec, RoleArchitect, RoleDev, RoleQA, RoleIntegrator}

// LoadIdentityMap parses and checks a map. It refuses a service account mapped to human, a
// person mapped to an agent role, a runner without a project, a project on anything else,
// internal or unknown roles, and duplicates (emails compare lower-cased).
func LoadIdentityMap(data []byte) (*IdentityMap, error) {
	var entries []identityEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("identity map: %w", err)
	}
	m := &IdentityMap{byEmail: map[string]Caller{}}
	for _, e := range entries {
		email := strings.ToLower(strings.TrimSpace(e.Email))
		switch {
		case email == "" || !strings.Contains(email, "@"):
			return nil, fmt.Errorf("identity map: bad email %q", e.Email)
		case !slices.Contains(mappableRoles, e.Role):
			return nil, fmt.Errorf("identity map: %s has role %q, which no caller may hold", email, e.Role)
		case e.Role == RoleHuman && isServiceAccount(email):
			return nil, fmt.Errorf("identity map: service account %s mapped to human", email)
		case e.Role != RoleHuman && !isServiceAccount(email):
			return nil, fmt.Errorf("identity map: %s is not a service account but has role %s", email, e.Role)
		case e.Role.IsRunner() && e.Project == "":
			return nil, fmt.Errorf("identity map: runner %s has no project", email)
		case !e.Role.IsRunner() && e.Project != "":
			return nil, fmt.Errorf("identity map: %s (%s) cannot be scoped to a project", email, e.Role)
		}
		if _, dup := m.byEmail[email]; dup {
			return nil, fmt.Errorf("identity map: %s appears twice", email)
		}
		m.byEmail[email] = Caller{Email: email, Role: e.Role, Project: e.Project}
	}
	return m, nil
}

// EmbeddedIdentityMap is the production map, compiled into the binary.
func EmbeddedIdentityMap() (*IdentityMap, error) { return LoadIdentityMap(embeddedIdentityMap) }

// Lookup returns the caller for an email, compared lower-cased.
func (m *IdentityMap) Lookup(email string) (Caller, bool) {
	c, ok := m.byEmail[strings.ToLower(email)]
	return c, ok
}

// Len is the number of mapped identities.
func (m *IdentityMap) Len() int { return len(m.byEmail) }

// VerifierConfig configures token verification.
type VerifierConfig struct {
	JWKSURL         string           // default GoogleJWKSURL
	ServiceAudience string           // required: the audience service accounts mint tokens for
	HumanAudiences  []string         // no default: with none, no human can authenticate
	Now             func() time.Time // tests only
}

// Verifier turns a bearer token into a Caller.
type Verifier struct {
	oidc    *oidc.IDTokenVerifier
	service string
	humans  []string
	ids     *IdentityMap
}

// NewVerifier builds a verifier over the given identity map.
func NewVerifier(ctx context.Context, cfg VerifierConfig, ids *IdentityMap) (*Verifier, error) {
	if cfg.ServiceAudience == "" {
		return nil, fmt.Errorf("verifier: a service audience is required")
	}
	if ids == nil {
		return nil, fmt.Errorf("verifier: an identity map is required")
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = GoogleJWKSURL
	}
	if err := checkJWKSURL(cfg.JWKSURL); err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	keys := &keySet{url: cfg.JWKSURL, client: &http.Client{Timeout: keyFetchTimeout}, now: now}
	v := oidc.NewVerifier(googleIssuer, keys, &oidc.Config{
		SkipClientIDCheck: true, // the audience is checked below, per kind of identity
		Now:               cfg.Now,
	})
	return &Verifier{oidc: v, service: cfg.ServiceAudience, humans: cfg.HumanAudiences, ids: ids}, nil
}

type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
}

// Verify checks, in order: signature, expiry and issuer; a verified email; an audience in the
// service audience or the human audiences (all 401); the kind from the email and that kind's own
// audience (401); then the identity map (403 when unmapped).
func (v *Verifier) Verify(ctx context.Context, raw string) (Caller, error) {
	if raw == "" {
		return Caller{}, refuse(401, "a bearer token is required")
	}
	tok, err := v.oidc.Verify(ctx, raw)
	if err != nil {
		return Caller{}, refuse(401, "invalid token: %v", err)
	}
	var cl googleClaims
	if err := tok.Claims(&cl); err != nil {
		return Caller{}, refuse(401, "unreadable token claims")
	}
	if cl.Email == "" || cl.EmailVerified == nil || !*cl.EmailVerified {
		return Caller{}, refuse(401, "the token carries no verified email")
	}
	email := strings.ToLower(cl.Email)

	if !slices.Contains(tok.Audience, v.service) && !slices.ContainsFunc(tok.Audience, v.isHumanAudience) {
		return Caller{}, refuse(401, "the token is not for this service")
	}
	if isServiceAccount(email) {
		if !slices.Contains(tok.Audience, v.service) {
			return Caller{}, refuse(401, "a service account's token must carry the service audience")
		}
	} else if !slices.ContainsFunc(tok.Audience, v.isHumanAudience) {
		return Caller{}, refuse(401, "a person's token must carry a human audience")
	}

	c, ok := v.ids.Lookup(email)
	if !ok {
		return Caller{}, refuse(403, "%s is not a known identity", email)
	}
	return c, nil
}

func (v *Verifier) isHumanAudience(aud string) bool { return slices.Contains(v.humans, aud) }

// checkJWKSURL accepts only an https key URL, so the keys that decide every identity cannot be
// swapped on the way ([P02/review]); plain http is allowed to a loopback address, the tests' key
// servers.
func checkJWKSURL(raw string) error {
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" && u.User == nil {
		if u.Scheme == "https" {
			return nil
		}
		if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("verifier: the JWKS URL %q is not an https URL", raw)
}

const (
	// minKeyRefetch is the least time between two fetches of the signing keys ([P02/review]):
	// go-oidc's RemoteKeySet fetches again for every token whose key id it has not seen, so a
	// stream of forged tokens would be a stream of fetches. Google publishes a key well before
	// signing with it, so a new key waits at most this long.
	minKeyRefetch   = time.Minute
	keyFetchTimeout = 10 * time.Second
)

// keySet verifies a token's signature with Google's published keys, fetching them when a token's
// key is not among those held, at most once every minKeyRefetch.
type keySet struct {
	url    string
	client *http.Client
	now    func() time.Time

	fetch sync.Mutex // held through a fetch: concurrent callers wait for its result

	mu      sync.RWMutex
	keys    []jose.JSONWebKey
	fetched time.Time // the last fetch, successful or not; zero before the first
}

// VerifySignature implements oidc.KeySet. The verifier has already checked the algorithm.
func (k *keySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("a token carries exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID
	if payload, ok := k.verify(jws, kid); ok {
		return payload, nil
	}
	k.fetch.Lock()
	defer k.fetch.Unlock()
	if payload, ok := k.verify(jws, kid); ok { // fetched while this caller waited
		return payload, nil
	}
	k.mu.RLock()
	last := k.fetched
	k.mu.RUnlock()
	if !last.IsZero() && k.now().Sub(last) < minKeyRefetch {
		return nil, fmt.Errorf("no key %q among those fetched %v ago; the next fetch is allowed after %v",
			kid, k.now().Sub(last).Round(time.Second), minKeyRefetch)
	}
	keys, err := k.get(ctx)
	k.mu.Lock()
	k.fetched = k.now()
	if err == nil {
		k.keys = keys
	}
	k.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if payload, ok := k.verify(jws, kid); ok {
		return payload, nil
	}
	return nil, fmt.Errorf("no published key %q verifies the token", kid)
}

// verify tries the held keys with the token's key id (every key when it names none).
func (k *keySet) verify(jws *jose.JSONWebSignature, kid string) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for i := range k.keys {
		if kid == "" || k.keys[i].KeyID == kid {
			if payload, err := jws.Verify(&k.keys[i]); err == nil {
				return payload, true
			}
		}
	}
	return nil, false
}

// get fetches the published keys. It is not cut short when the request that asked for it ends,
// since the fetch it spends is the minute's.
func (k *keySet) get(ctx context.Context) ([]jose.JSONWebKey, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", k.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch the signing keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch the signing keys: status %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("fetch the signing keys: %w", err)
	}
	return set.Keys, nil
}

// ClockSkewLimit is how far the host's clock may be from the database's before CheckClock logs an
// error: token expiry is judged by the host's clock ([P02/review2]), the rest by the database's.
const ClockSkewLimit = 5 * time.Second

// CheckClock compares the host's clock (now) with the database's, allowing for the query's round
// trip, logs the skew (as an error beyond ClockSkewLimit) and returns it: positive when the
// database is ahead. A database clock it cannot read is logged as a warning, and the skew is 0.
func CheckClock(ctx context.Context, conn *sql.DB, now func() time.Time, log *slog.Logger) time.Duration {
	before := now()
	var db time.Time
	if err := conn.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&db); err != nil {
		log.Warn("the host clock was not checked: the database's clock could not be read", "error", err)
		return 0
	}
	after := now()
	skew := db.Sub(before.Add(after.Sub(before) / 2))
	attrs := []any{"skew_seconds", skew.Seconds(), "limit_seconds", ClockSkewLimit.Seconds(),
		"round_trip_seconds", after.Sub(before).Seconds()}
	if skew > ClockSkewLimit || skew < -ClockSkewLimit {
		log.Error("the host clock is off the database's: token expiry is judged by the host's", attrs...)
	} else {
		log.Info("the host clock checked against the database's", attrs...)
	}
	return skew
}
