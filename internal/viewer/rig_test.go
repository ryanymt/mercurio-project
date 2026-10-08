package viewer_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/testdb"
	"github.com/ryanymt/mercurio-project/internal/viewer"
)

const (
	operator    = "operator@example.com" // the identity map's human
	iapAudience = "/projects/123456789012/locations/us-central1/services/viewer"
	origin      = "https://viewer-123456789012.us-central1.run.app"
)

// iapKey signs IAP-shaped assertions; the key server publishes it.
type iapKey struct {
	key *ecdsa.PrivateKey
	url string
}

func newIAPKey(t *testing.T) *iapKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "iap", Algorithm: "ES256", Use: "sig"}}})
	}))
	t.Cleanup(srv.Close)
	return &iapKey{key: k, url: srv.URL}
}

// assertion is an IAP assertion for email, with the claims IAP sends (P06 T2).
func (k *iapKey) assertion(t *testing.T, email string) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": "https://cloud.google.com/iap", "aud": iapAudience, "azp": iapAudience,
		"sub": "accounts.google.com:1", "email": email, "identity_source": "GOOGLE", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k.key, KeyID: "iap"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := jws.CompactSerialize()
	return raw
}

// memChunks is the artifacts bucket, in memory.
type memChunks struct {
	mu      sync.Mutex
	objects map[string][]byte
	reads   int
}

func (m *memChunks) put(name, data string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objects == nil {
		m.objects = map[string][]byte{}
	}
	m.objects[name] = []byte(data)
}

func (m *memChunks) List(_ context.Context, prefix string, max int) ([]viewer.Object, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for n := range m.objects {
		if strings.HasPrefix(n, prefix+"/") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	more := len(names) > max
	if more {
		names = names[:max]
	}
	var out []viewer.Object
	for _, n := range names {
		out = append(out, viewer.Object{Name: n, Size: int64(len(m.objects[n]))})
	}
	return out, more, nil
}

func (m *memChunks) Read(_ context.Context, name string, max int64) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	b, ok := m.objects[name]
	if !ok {
		return nil, false, fmt.Errorf("no object %s", name)
	}
	if int64(len(b)) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}

// fakeDiffs answers compares from a table; a missing entry is a commit GitHub does not know.
type fakeDiffs struct {
	mu    sync.Mutex
	diffs map[string]viewer.Diff // base...head
	calls int
	err   error // when set, every compare fails
}

func (f *fakeDiffs) Compare(_ context.Context, repoURL, base, head string) (viewer.Diff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return viewer.Diff{}, f.err
	}
	if d, ok := f.diffs[base+"..."+head]; ok {
		return d, nil
	}
	return viewer.Diff{Status: viewer.DiffNotFound, Base: base, Head: head}, nil
}

// rig is the viewer over a test database read as `viewer`, IAP's assertions verified with the real
// Verifier against a fake key server, an in-memory bucket and a table of diffs. Steps 4 and 5 add
// the relay to the real callback API.
type rig struct {
	t      *testing.T
	owner  *sql.DB // the test server's own user, to seed rows
	conn   *sql.DB // as viewer
	iap    *iapKey
	chunks *memChunks
	diffs  *fakeDiffs
	cfg    viewer.Config
	srv    *httptest.Server
	logs   *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	owner, conn := testdb.NewAsViewer(t)
	r := &rig{t: t, owner: owner, conn: conn, iap: newIAPKey(t), chunks: &memChunks{}, diffs: &fakeDiffs{diffs: map[string]viewer.Diff{}},
		logs: &bytes.Buffer{}}
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		ServiceAudience: "https://callback-api.example.test", IAPAudience: iapAudience, IAPJWKSURL: r.iap.url,
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	r.cfg = viewer.Config{DB: conn, Identify: verifier.VerifyRelayed, Chunks: r.chunks, Diffs: r.diffs,
		Relay: refusingRelay{}, CSRFKey: []byte("a csrf key of thirty-two bytes!!"), Origins: []string{origin},
		Log: slog.New(slog.NewJSONHandler(r.logs, nil))}
	return r
}

// refusingRelay stands in until a test wires the real callback API.
type refusingRelay struct{}

func (refusingRelay) Send(context.Context, string, string, string, string, any) (int, string, map[string]any, error) {
	return 0, "", nil, fmt.Errorf("no callback API in this test")
}

// start serves the viewer with the rig's configuration as it stands.
func (r *rig) start() {
	r.t.Helper()
	s, err := viewer.New(r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	r.srv = httptest.NewServer(s.Handler())
	r.t.Cleanup(r.srv.Close)
}

// get fetches path as the operator, through IAP.
func (r *rig) get(path string) (int, string) {
	r.t.Helper()
	return r.request(http.MethodGet, path, nil, r.iap.assertion(r.t, operator), nil)
}

func (r *rig) request(method, path string, form url.Values, assertion string, header map[string]string) (int, string) {
	r.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, r.srv.URL+path, body)
	if err != nil {
		r.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if assertion != "" {
		req.Header.Set("X-Goog-Iap-Jwt-Assertion", assertion)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// seed inserts a ticket as the server's own user and returns its id.
func (r *rig) seed(project, title, state string, set map[string]any) int64 {
	r.t.Helper()
	var id int64
	if err := r.owner.QueryRow(`INSERT INTO tickets (project_id, title, state, acceptance_criteria) VALUES ($1, $2, $3,
		'[{"id":"AC1","text":"it works"}]') RETURNING id`, project, title, state).Scan(&id); err != nil {
		r.t.Fatal(err)
	}
	for col, v := range set {
		if _, err := r.owner.Exec(`UPDATE tickets SET `+col+` = $2 WHERE id = $1`, id, v); err != nil {
			r.t.Fatalf("set %s: %v", col, err)
		}
	}
	return id
}

func (r *rig) event(ticket int64, from, to, actor, actorID, payload string) {
	r.t.Helper()
	var f any
	if from != "" {
		f = from
	}
	if _, err := r.owner.Exec(`INSERT INTO ticket_events (ticket_id, from_state, to_state, actor, actor_id, payload)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)`, ticket, f, to, actor, actorID, payload); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) artifact(ticket int64, attempt int, kind, path string) int64 {
	r.t.Helper()
	var id int64
	if err := r.owner.QueryRow(`INSERT INTO artifacts (ticket_id, attempt, kind, gcs_path) VALUES ($1, $2, $3, $4) RETURNING id`,
		ticket, attempt, kind, path).Scan(&id); err != nil {
		r.t.Fatal(err)
	}
	return id
}
