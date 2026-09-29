package callbackapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

const (
	serviceAudience = "https://callback-api.example.test"
	humanAudience   = "foreman-cli.apps.googleusercontent.com"
	devEmail        = "dev-foreman@your-project-id.iam.gserviceaccount.com"
	humanEmail      = "operator@example.com"
	defaultCompute  = "123456789012-compute@developer.gserviceaccount.com"
)

// A local signer and an in-process key server stand in for Google.
type signer struct {
	key *rsa.PrivateKey
	kid string
}

func newSigner(t *testing.T, kid string) signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signer{k, kid}
}

func (s signer) public() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"}
}

func (s signer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := sig.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type keyServer struct {
	*httptest.Server
	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetches int
	down    bool // answer 503
}

func newKeyServer(t *testing.T, keys ...signer) *keyServer {
	ks := &keyServer{}
	for _, k := range keys {
		ks.keys = append(ks.keys, k.public())
	}
	ks.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks.mu.Lock()
		defer ks.mu.Unlock()
		ks.fetches++
		if ks.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: ks.keys})
	}))
	t.Cleanup(ks.Close)
	return ks
}

func (ks *keyServer) add(s signer) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys = append(ks.keys, s.public())
}

func claimsFor(email string, aud any) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": "https://accounts.google.com", "aud": aud, "sub": "1234567890", "email": email,
		"email_verified": true, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
}

const testMap = `[
  {"email": "dispatcher@your-project-id.iam.gserviceaccount.com", "role": "dispatcher"},
  {"email": "dev-foreman@your-project-id.iam.gserviceaccount.com", "role": "dev", "project": "foreman"},
  {"email": "operator@example.com", "role": "human"}
]`

func verifier(t *testing.T, ks *keyServer, humanAudiences ...string) *callbackapi.Verifier {
	t.Helper()
	ids, err := callbackapi.LoadIdentityMap([]byte(testMap))
	if err != nil {
		t.Fatal(err)
	}
	v, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		JWKSURL: ks.URL, ServiceAudience: serviceAudience, HumanAudiences: humanAudiences,
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifiesServiceAccountsAndHumans(t *testing.T) {
	k := newSigner(t, "k1")
	v := verifier(t, newKeyServer(t, k), humanAudience)

	c, err := v.Verify(context.Background(), k.sign(t, claimsFor(devEmail, serviceAudience)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != devEmail || c.Role != callbackapi.RoleDev || c.Project != "foreman" {
		t.Fatalf("service account = %+v", c)
	}
	h, err := v.Verify(context.Background(), k.sign(t, claimsFor(humanEmail, []string{humanAudience, "another"})))
	if err != nil {
		t.Fatal(err)
	}
	if h.Role != callbackapi.RoleHuman || h.Project != "" {
		t.Fatalf("human = %+v", h)
	}
}

func TestBothGoogleIssuerFormsAndNoOther(t *testing.T) {
	k := newSigner(t, "k1")
	v := verifier(t, newKeyServer(t, k), humanAudience)
	for iss, ok := range map[string]bool{
		"https://accounts.google.com": true, "accounts.google.com": true, "https://evil.example": false,
	} {
		c := claimsFor(devEmail, serviceAudience)
		c["iss"] = iss
		_, err := v.Verify(context.Background(), k.sign(t, c))
		if ok && err != nil {
			t.Errorf("issuer %s refused: %v", iss, err)
		}
		if !ok {
			wantStatus(t, err, 401)
		}
	}
}

// Every refusal in the pipeline's order: 401 until the identity is established, 403 when it is
// established but not mapped.
func TestVerificationRefusals(t *testing.T) {
	k := newSigner(t, "k1")
	stranger := newSigner(t, "k-unknown")
	forger := newSigner(t, "k1") // another RSA key under the published key's id
	alter := func(token string, claims map[string]any) string {
		parts := strings.Split(token, ".")
		body, _ := json.Marshal(claims)
		parts[1] = base64.RawURLEncoding.EncodeToString(body)
		return strings.Join(parts, ".")
	}
	ks := newKeyServer(t, k)
	v := verifier(t, ks, humanAudience)
	noHumans := verifier(t, ks)
	with := func(email string, aud any, mod func(map[string]any)) map[string]any {
		c := claimsFor(email, aud)
		if mod != nil {
			mod(c)
		}
		return c
	}
	cases := []struct {
		name   string
		v      *callbackapi.Verifier
		token  string
		status int
	}{
		{"empty", v, "", 401},
		{"not a JWT", v, "not.a.token", 401},
		{"signed by an unknown key", v, stranger.sign(t, claimsFor(devEmail, serviceAudience)), 401},
		{"forged under a published key id", v, forger.sign(t, claimsFor(devEmail, serviceAudience)), 401},
		{"payload altered after signing", v, alter(k.sign(t, claimsFor(devEmail, serviceAudience)), claimsFor(humanEmail, humanAudience)), 401},
		{"expired", v, k.sign(t, with(devEmail, serviceAudience, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })), 401},
		{"email not verified", v, k.sign(t, with(devEmail, serviceAudience, func(c map[string]any) { c["email_verified"] = false })), 401},
		{"email_verified missing", v, k.sign(t, with(devEmail, serviceAudience, func(c map[string]any) { delete(c, "email_verified") })), 401},
		{"no email", v, k.sign(t, with(devEmail, serviceAudience, func(c map[string]any) { delete(c, "email") })), 401},
		{"audience in neither list", v, k.sign(t, claimsFor(devEmail, "https://someone-else.example")), 401},
		{"service account with a human audience", v, k.sign(t, claimsFor(devEmail, humanAudience)), 401},
		{"human with the service audience", v, k.sign(t, claimsFor(humanEmail, serviceAudience)), 401},
		{"human, no human audience configured", noHumans, k.sign(t, claimsFor(humanEmail, humanAudience)), 401},
		{"unmapped service account", v, k.sign(t, claimsFor("viewer@your-project-id.iam.gserviceaccount.com", serviceAudience)), 403},
		{"unmapped human", v, k.sign(t, claimsFor("someone@example.com", humanAudience)), 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.v.Verify(context.Background(), c.token)
			wantStatus(t, err, c.status)
		})
	}
}

// Any *.gserviceaccount.com domain is a service account, including the default compute account
// (which holds Editor): never classed as a human, whatever audience it carries.
func TestAnyGServiceAccountDomainIsAServiceAccount(t *testing.T) {
	k := newSigner(t, "k1")
	v := verifier(t, newKeyServer(t, k), humanAudience)
	_, err := v.Verify(context.Background(), k.sign(t, claimsFor(defaultCompute, humanAudience)))
	wantStatus(t, err, 401) // a service account must carry the service audience
	_, err = v.Verify(context.Background(), k.sign(t, claimsFor(defaultCompute, serviceAudience)))
	wantStatus(t, err, 403) // and it is not mapped
}

func TestEmailsCompareLowerCased(t *testing.T) {
	k := newSigner(t, "k1")
	v := verifier(t, newKeyServer(t, k), humanAudience)
	c, err := v.Verify(context.Background(), k.sign(t, claimsFor(strings.ToUpper(devEmail), serviceAudience)))
	if err != nil || c.Role != callbackapi.RoleDev || c.Email != devEmail {
		t.Fatalf("upper-case email: %+v, %v", c, err)
	}
}

// testClock is a clock the test moves, safe to read from any goroutine.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: time.Now()} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (ks *keyServer) fetchCount() int {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.fetches
}

// verifierAt is verifier with the test's clock, for token expiry and key refetches alike.
func verifierAt(t *testing.T, ks *keyServer, now func() time.Time) *callbackapi.Verifier {
	t.Helper()
	ids, err := callbackapi.LoadIdentityMap([]byte(testMap))
	if err != nil {
		t.Fatal(err)
	}
	v, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		JWKSURL: ks.URL, ServiceAudience: serviceAudience, HumanAudiences: []string{humanAudience}, Now: now,
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A key the verifier has not seen is fetched again from the key server (Google rotates keys), once
// a minute has passed since the last fetch (P05 Approach 6; [P02/review]). The minute was a P05
// change: until then every unknown key id fetched at once.
func TestUnknownKeyIDRefreshes(t *testing.T) {
	k1, k2 := newSigner(t, "k1"), newSigner(t, "k2")
	ks := newKeyServer(t, k1)
	clock := newTestClock()
	v := verifierAt(t, ks, clock.now)
	if _, err := v.Verify(context.Background(), k1.sign(t, claimsFor(devEmail, serviceAudience))); err != nil {
		t.Fatal(err)
	}
	ks.add(k2)
	clock.advance(time.Minute + time.Second)
	if _, err := v.Verify(context.Background(), k2.sign(t, claimsFor(devEmail, serviceAudience))); err != nil {
		t.Fatalf("a rotated-in key was not fetched: %v", err)
	}
	if n := ks.fetchCount(); n != 2 {
		t.Fatalf("key server fetched %d times, want 2", n)
	}
}

// A burst of tokens whose key ids are unknown, forged or not, makes at most one fetch a minute,
// however many arrive and however concurrently; tokens signed with a known key never wait for one
// (P05 Approach 6; [P02/review]).
func TestUnknownKeyIDsRefetchAtMostOnceAMinute(t *testing.T) {
	k1, k2 := newSigner(t, "k1"), newSigner(t, "k2")
	ks := newKeyServer(t, k1)
	clock := newTestClock()
	v := verifierAt(t, ks, clock.now)
	ctx := context.Background()
	good := k1.sign(t, claimsFor(devEmail, serviceAudience))
	if _, err := v.Verify(ctx, good); err != nil {
		t.Fatal(err)
	}
	forged := make([]string, 20)
	for i := range forged {
		forged[i] = newSigner(t, fmt.Sprintf("forged-%d", i)).sign(t, claimsFor(devEmail, serviceAudience))
	}
	burst := func() {
		var wg sync.WaitGroup
		for _, raw := range forged {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := v.Verify(ctx, raw); err == nil {
					t.Error("a token signed with an unpublished key was accepted")
				}
			}()
		}
		wg.Wait()
	}

	clock.advance(30 * time.Second)
	burst()
	if n := ks.fetchCount(); n != 1 {
		t.Fatalf("within the first fetch's minute: %d fetches, want 1", n)
	}
	if _, err := v.Verify(ctx, good); err != nil {
		t.Fatalf("a known key refused during the burst: %v", err)
	}

	clock.advance(31 * time.Second) // a minute and a second since the first fetch
	burst()
	if n := ks.fetchCount(); n != 2 {
		t.Fatalf("a minute later: %d fetches, want 2", n)
	}

	ks.add(k2) // published just after that fetch
	rotated := k2.sign(t, claimsFor(devEmail, serviceAudience))
	clock.advance(59 * time.Second)
	if _, err := v.Verify(ctx, rotated); err == nil {
		t.Fatal("a key published after the last fetch was fetched within the minute")
	}
	if n := ks.fetchCount(); n != 2 {
		t.Fatalf("%d fetches, want still 2", n)
	}
	// A minute on, callers arriving together with the new key all verify: those that waited for
	// the fetch use its result.
	clock.advance(2 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(ctx, k2.sign(t, claimsFor(devEmail, serviceAudience))); err != nil {
				t.Errorf("the rotated-in key, a minute on: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := ks.fetchCount(); n != 3 {
		t.Fatalf("%d fetches, want 3", n)
	}
}

// A failed fetch counts as a fetch, so a key server that is down does not turn a burst into a
// burst of fetches; and it keeps the keys already held.
func TestAFailedFetchCountsAgainstTheMinute(t *testing.T) {
	k1 := newSigner(t, "k1")
	ks := newKeyServer(t, k1)
	clock := newTestClock()
	v := verifierAt(t, ks, clock.now)
	ctx := context.Background()
	if _, err := v.Verify(ctx, k1.sign(t, claimsFor(devEmail, serviceAudience))); err != nil {
		t.Fatal(err)
	}
	ks.mu.Lock()
	ks.down = true
	ks.mu.Unlock()
	clock.advance(time.Minute + time.Second)
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(ctx, newSigner(t, fmt.Sprintf("x%d", i)).sign(t, claimsFor(devEmail, serviceAudience))); err == nil {
			t.Fatal("a token signed with an unpublished key was accepted")
		}
	}
	if n := ks.fetchCount(); n != 2 {
		t.Fatalf("%d fetches, want 2: the first, then one failed", n)
	}
	if _, err := v.Verify(ctx, k1.sign(t, claimsFor(devEmail, serviceAudience))); err != nil {
		t.Fatalf("the held key was lost with the failed fetch: %v", err)
	}
	clock.advance(time.Minute + time.Second)
	v.Verify(ctx, newSigner(t, "y").sign(t, claimsFor(devEmail, serviceAudience)))
	if n := ks.fetchCount(); n != 3 {
		t.Fatalf("%d fetches, want 3: a minute after the failed one", n)
	}
}

// The key URL is https: plain http is refused, except to a loopback address (the tests' key
// servers) (P05 Approach 6; [P02/review]).
func TestTheJWKSURLMustBeHTTPS(t *testing.T) {
	ids, err := callbackapi.LoadIdentityMap([]byte(testMap))
	if err != nil {
		t.Fatal(err)
	}
	for u, ok := range map[string]bool{
		"":                            true, // Google's, over https
		callbackapi.GoogleJWKSURL:     true,
		"https://keys.example/certs":  true,
		"http://127.0.0.1:8080/certs": true,
		"http://[::1]:8080/certs":     true,
		"http://www.googleapis.com/oauth2/v3/certs": false,
		"http://localhost:8080/certs":               false,
		"http://10.0.0.1/certs":                     false,
		"file:///etc/keys.json":                     false,
		"ftp://keys.example/certs":                  false,
		"https:///certs":                            false,
		"https://user:secret@keys.example/certs":    false,
		"//keys.example/certs":                      false,
		"HTTP://www.googleapis.com/oauth2/v3/certs": false,
	} {
		_, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{JWKSURL: u, ServiceAudience: serviceAudience}, ids)
		if (err == nil) != ok {
			t.Errorf("JWKS URL %q: %v, want accepted %v", u, err, ok)
		}
	}
}

// Token expiry is judged by the host's clock, so the API compares it with the database's at
// startup and logs a skew beyond the limit as an error (P05 Approach 6; [P02/review2]).
func TestCheckClock(t *testing.T) {
	conn := fresh(t)
	for name, c := range map[string]struct {
		offset time.Duration
		level  string
	}{
		"in step":         {0, "INFO"},
		"behind a little": {-callbackapi.ClockSkewLimit / 2, "INFO"},
		"ahead":           {callbackapi.ClockSkewLimit + 5*time.Second, "ERROR"},
		"behind":          {-callbackapi.ClockSkewLimit - 5*time.Second, "ERROR"},
		"a minute ahead":  {time.Minute, "ERROR"},
		"an hour behind":  {-time.Hour, "ERROR"},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			skew := callbackapi.CheckClock(context.Background(), conn, func() time.Time { return time.Now().Add(c.offset) }, log)
			if d := skew + c.offset; d < -time.Second || d > time.Second {
				t.Errorf("skew %v with the host %v off, want about %v", skew, c.offset, -c.offset)
			}
			var line struct {
				Level string  `json:"level"`
				Msg   string  `json:"msg"`
				Skew  float64 `json:"skew_seconds"`
			}
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("not one JSON line: %q", buf.String())
			}
			if line.Level != c.level || !strings.Contains(line.Msg, "clock") {
				t.Fatalf("logged %s %q, want %s about the clock", line.Level, line.Msg, c.level)
			}
		})
	}
	var buf bytes.Buffer
	closed := fresh(t)
	closed.Close()
	callbackapi.CheckClock(context.Background(), closed, time.Now, slog.New(slog.NewJSONHandler(&buf, nil)))
	if !strings.Contains(buf.String(), `"level":"WARN"`) || !strings.Contains(buf.String(), "clock") {
		t.Fatalf("an unreadable database clock: %s", buf.String())
	}
}

func TestIdentityMapRefusals(t *testing.T) {
	for name, m := range map[string]string{
		"a service account mapped to human": `[{"email": "dev-foreman@x.iam.gserviceaccount.com", "role": "human"}]`,
		"default compute mapped to human":   `[{"email": "1-compute@developer.gserviceaccount.com", "role": "human"}]`,
		"a person mapped to an agent role":  `[{"email": "someone@example.com", "role": "dev", "project": "foreman"}]`,
		"a runner without a project":        `[{"email": "dev-foreman@x.iam.gserviceaccount.com", "role": "dev"}]`,
		"a project on a non-runner":         `[{"email": "dispatcher@x.iam.gserviceaccount.com", "role": "dispatcher", "project": "foreman"}]`,
		"an internal role":                  `[{"email": "cb@x.iam.gserviceaccount.com", "role": "callback_api"}]`,
		"an unknown role":                   `[{"email": "x@x.iam.gserviceaccount.com", "role": "root"}]`,
		"a duplicate, differently cased":    `[{"email": "a@example.com", "role": "human"}, {"email": "A@example.com", "role": "human"}]`,
		"not JSON":                          `{`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := callbackapi.LoadIdentityMap([]byte(m)); err == nil {
				t.Fatal("the map loaded")
			}
		})
	}
}

// The production map: the role-bearing service accounts of foreman and the sandbox (P05) and the
// organisation account;
// viewer, callback-api and the default compute account deliberately absent (P02 Approach 4).
func TestEmbeddedIdentityMap(t *testing.T) {
	m, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	const sa = "@your-project-id.iam.gserviceaccount.com"
	want := map[string]callbackapi.Caller{
		"dispatcher" + sa:         {Role: callbackapi.RoleDispatcher},
		"dev-foreman" + sa:        {Role: callbackapi.RoleDev, Project: "foreman"},
		"qa-foreman" + sa:         {Role: callbackapi.RoleQA, Project: "foreman"},
		"spec-foreman" + sa:       {Role: callbackapi.RoleSpec, Project: "foreman"},
		"architect-foreman" + sa:  {Role: callbackapi.RoleArchitect, Project: "foreman"},
		"integrator-foreman" + sa: {Role: callbackapi.RoleIntegrator, Project: "foreman"},
		"dev-sandbox" + sa:        {Role: callbackapi.RoleDev, Project: "sandbox"},
		"qa-sandbox" + sa:         {Role: callbackapi.RoleQA, Project: "sandbox"},
		"spec-sandbox" + sa:       {Role: callbackapi.RoleSpec, Project: "sandbox"},
		"architect-sandbox" + sa:  {Role: callbackapi.RoleArchitect, Project: "sandbox"},
		"integrator-sandbox" + sa: {Role: callbackapi.RoleIntegrator, Project: "sandbox"},
		humanEmail:                {Role: callbackapi.RoleHuman},
	}
	for email, w := range want {
		c, ok := m.Lookup(email)
		if !ok || c.Role != w.Role || c.Project != w.Project {
			t.Errorf("%s = %+v (found %v), want %+v", email, c, ok, w)
		}
	}
	for _, email := range []string{"viewer" + sa, "callback-api" + sa, "assistant-vm" + sa, defaultCompute} {
		if _, ok := m.Lookup(email); ok {
			t.Errorf("%s must not be mapped", email)
		}
	}
	if n := m.Len(); n != len(want) {
		t.Errorf("the map has %d entries, want %d", n, len(want))
	}
}
