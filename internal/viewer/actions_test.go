package viewer_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/viewer"
)

const viewerAccount = "viewer@your-project-id.iam.gserviceaccount.com"

// metadata is the viewer's metadata server: ID tokens signed with a local key, the email only with
// format=full, as Google's metadata server does (P05 R3).
type metadata struct {
	*httptest.Server
	key     *rsa.PrivateKey
	mu      sync.Mutex
	queries []string
}

func newMetadata(t *testing.T) *metadata {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &metadata{key: k}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const base = "/computeMetadata/v1/instance/service-accounts/default/"
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "no Metadata-Flavor", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case base + "token":
			fmt.Fprint(w, `{"access_token": "fake-viewer-access", "expires_in": 3599, "token_type": "Bearer"}`)
		case base + "identity":
			m.mu.Lock()
			m.queries = append(m.queries, r.URL.RawQuery)
			m.mu.Unlock()
			now := time.Now()
			claims := map[string]any{"iss": "https://accounts.google.com", "aud": r.URL.Query().Get("audience"),
				"sub": "viewer-sub", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
			if r.URL.Query().Get("format") == "full" {
				claims["email"], claims["email_verified"] = viewerAccount, true
			}
			s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k, KeyID: "meta"}},
				(&jose.SignerOptions{}).WithType("JWT"))
			payload, _ := json.Marshal(claims)
			jws, _ := s.Sign(payload)
			raw, _ := jws.CompactSerialize()
			io.WriteString(w, raw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *metadata) jwks() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &m.key.PublicKey, KeyID: "meta", Algorithm: "RS256", Use: "sig"}}})
	}))
}

// seen is one request the callback API received from the viewer.
type seen struct {
	Method, Path string
	Header       http.Header
	Body         map[string]any
}

// withAPI wires the real callback API in process, behind a recorder, and the viewer's real relay to
// it, with its ID token from the fake metadata server.
func (r *rig) withAPI() (*metadata, func() []seen) {
	r.t.Helper()
	meta := newMetadata(r.t)
	keys := meta.jwks()
	r.t.Cleanup(keys.Close)
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		r.t.Fatal(err)
	}
	// The API's URL is its audience, known from the listener before the server starts.
	api := httptest.NewUnstartedServer(nil)
	apiURL := "http://" + api.Listener.Addr().String()
	verifier, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		JWKSURL: keys.URL, ServiceAudience: apiURL, IAPJWKSURL: r.iap.url, IAPAudience: iapAudience,
	}, ids)
	if err != nil {
		r.t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := callbackapi.NewServer(r.owner, callbackapi.NewEngine(nil, quiet), verifier, quiet).Handler()
	var mu sync.Mutex
	var got []seen
	api.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		b, _ := io.ReadAll(q.Body)
		s := seen{Method: q.Method, Path: q.URL.Path, Header: q.Header.Clone()}
		json.Unmarshal(b, &s.Body)
		mu.Lock()
		got = append(got, s)
		mu.Unlock()
		q.Body = io.NopCloser(strings.NewReader(string(b)))
		handler.ServeHTTP(w, q)
	})
	api.Start()
	r.t.Cleanup(api.Close)
	md := viewer.NewMetadata(strings.TrimPrefix(meta.URL, "http://"), nil)
	relay, err := viewer.NewHTTPRelay(apiURL, md.IDToken, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	r.cfg.Relay = relay
	return meta, func() []seen { mu.Lock(); defer mu.Unlock(); return append([]seen(nil), got...) }
}

// form is one rendered form: where it posts, its fields, and its button's label.
type form struct {
	action string
	fields url.Values
	label  string
}

var (
	formPattern   = regexp.MustCompile(`(?s)<form[^>]*method="post"[^>]*action="([^"]+)"[^>]*>(.*?)</form>`)
	inputPattern  = regexp.MustCompile(`<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"`)
	buttonPattern = regexp.MustCompile(`(?s)<button[^>]*>(.*?)</button>`)
)

func forms(page string) []form {
	var out []form
	for _, m := range formPattern.FindAllStringSubmatch(page, -1) {
		f := form{action: html.UnescapeString(m[1]), fields: url.Values{}}
		for _, in := range inputPattern.FindAllStringSubmatch(m[2], -1) {
			f.fields.Set(in[1], html.UnescapeString(in[2]))
		}
		if b := buttonPattern.FindStringSubmatch(m[2]); b != nil {
			f.label = strings.TrimSpace(html.UnescapeString(b[1]))
		}
		out = append(out, f)
	}
	return out
}

// decision is the rendered form moving the ticket to `to` (parking: to "parked" or "unparked").
func decision(fs []form, to string) *form {
	for i, f := range fs {
		if f.fields.Get("to") == to || (to == "parked" && f.fields.Get("parked") == "true") ||
			(to == "unparked" && f.fields.Get("parked") == "false") {
			return &fs[i]
		}
	}
	return nil
}

// post sends a form as the operator, from the viewer's own page.
func (r *rig) post(f *form, extra map[string]string) (int, string, http.Header) {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+f.action, strings.NewReader(f.fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Goog-Iap-Jwt-Assertion", r.iap.assertion(r.t, operator))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range extra {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// escalated seeds an escalated ticket whose head GitHub knows, and returns it and its page's forms.
func (r *rig) escalated(title string, set map[string]any) (int64, []form) {
	r.t.Helper()
	fields := map[string]any{"escalated_at": time.Date(2026, 10, 6, 10, 0, 0, 654321000, time.UTC), "head_sha": sha2,
		"base_sha": sha1, "attempt_count": 1, "escalation_reason": "needs a person"}
	for k, v := range set {
		fields[k] = v
	}
	id := r.seed("sandbox", title, "escalated", fields)
	r.diffs.mu.Lock()
	r.diffs.diffs[sha1+"..."+sha2] = viewer.Diff{Status: viewer.DiffOK, Base: sha1, Head: sha2, Text: "diff --git a/x b/x\n"}
	r.diffs.mu.Unlock()
	_, page := r.get(fmt.Sprintf("/tickets/%d", id))
	return id, forms(page)
}

func (r *rig) stateOf(id int64) (state string, head string) {
	r.t.Helper()
	var h *string
	r.owner.QueryRow(`SELECT state, head_sha FROM tickets WHERE id = $1`, id).Scan(&state, &h)
	if h != nil {
		head = *h
	}
	return state, head
}

func (r *rig) lastEvent(id int64) (actorID string, payload map[string]any) {
	r.t.Helper()
	var b []byte
	r.owner.QueryRow(`SELECT coalesce(actor_id, ''), coalesce(payload, '{}'::jsonb) FROM ticket_events WHERE ticket_id = $1
		ORDER BY id DESC LIMIT 1`, id).Scan(&actorID, &b)
	json.Unmarshal(b, &payload)
	return actorID, payload
}

// --- creating a ticket -----------------------------------------------------------------------------

// From the viewer you create a ticket, a draft or ready with criteria, relayed and landing as you.
func TestCreateATicketFromTheViewer(t *testing.T) {
	r := newRig(t)
	r.withAPI()
	r.start()
	for name, c := range map[string]struct {
		criteria string
		state    string
	}{"a draft": {"", "draft"}, "ready with criteria": {"it echoes\nit is pushed", "ready"}} {
		t.Run(name, func(t *testing.T) {
			_, page := r.get("/new")
			fs := forms(page)
			if len(fs) != 1 || fs[0].action != "/create" {
				t.Fatalf("the new-ticket page's forms %+v", fs)
			}
			f := fs[0]
			f.fields.Set("project", "sandbox")
			f.fields.Set("title", "from the viewer: "+name)
			f.fields.Set("body", "made by a person")
			f.fields.Set("criteria", c.criteria)
			st, body, h := r.post(&f, nil)
			if st != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/tickets/") {
				t.Fatalf("status %d, location %q: %s", st, h.Get("Location"), body)
			}
			var id int64
			fmt.Sscanf(strings.TrimPrefix(h.Get("Location"), "/tickets/"), "%d", &id)
			var state, title string
			var criteria []byte
			r.owner.QueryRow(`SELECT state, title, coalesce(acceptance_criteria, 'null') FROM tickets WHERE id = $1`, id).Scan(&state, &title, &criteria)
			if state != c.state || title != "from the viewer: "+name {
				t.Fatalf("ticket %d is %s %q, want %s", id, state, title, c.state)
			}
			if c.criteria != "" && !strings.Contains(string(criteria), `"it is pushed"`) {
				t.Fatalf("criteria %s", criteria)
			}
			if actor, _ := r.lastEvent(id); actor != operator {
				t.Fatalf("created by %q, want %s", actor, operator)
			}
		})
	}
}

// --- decisions -----------------------------------------------------------------------------------

// Every decision on an escalated ticket, parking included, is relayed with your assertion and lands
// as you, bound to the escalation the page showed, at its full precision, and an approval to its head
// (D19, D5).
func TestEveryDecisionRelaysAsThePerson(t *testing.T) {
	r := newRig(t)
	_, requests := r.withAPI()
	r.start()
	for _, to := range []string{"ready", "approved", "awaiting_review", "done", "failed", "abandoned", "parked"} {
		t.Run(to, func(t *testing.T) {
			id, fs := r.escalated("decide "+to, nil)
			f := decision(fs, to)
			if f == nil {
				t.Fatalf("no form for %s among %+v", to, fs)
			}
			if f.fields.Get("escalated_at") != "2026-10-06T10:00:00.654321Z" {
				t.Fatalf("the form carries escalated_at %q, want it at full precision", f.fields.Get("escalated_at"))
			}
			if to == "parked" {
				f.fields.Set("reason", "waiting on a vendor")
			}
			st, body, h := r.post(f, nil)
			if st != http.StatusSeeOther || h.Get("Location") != fmt.Sprintf("/tickets/%d", id) {
				t.Fatalf("status %d: %s", st, body)
			}
			state, _ := r.stateOf(id)
			want := to
			if to == "parked" {
				want = "escalated"
			}
			if state != want {
				t.Fatalf("state %s, want %s", state, want)
			}
			actor, payload := r.lastEvent(id)
			bound, _ := payload["bound_to"].(map[string]any)
			if actor != operator || bound["escalated_at"] != "2026-10-06T10:00:00.654321Z" {
				t.Fatalf("event by %q bound to %v", actor, bound)
			}
			if (to == "approved" || to == "awaiting_review") && bound["head_sha"] != sha2 {
				t.Fatalf("an approval bound to head %v, want %s", bound["head_sha"], sha2)
			}
		})
	}
	if len(requests()) == 0 {
		t.Fatal("nothing reached the callback API")
	}
}

// With no verdict for the head, the approval says it skips QA and the risk evaluator, and "send to
// QA" stands beside it; with one, it is a plain approval (D21; red team R3#2).
func TestTheApprovalSaysWhatItSkips(t *testing.T) {
	r := newRig(t)
	r.start()
	_, fs := r.escalated("no verdict", nil)
	approve, toQA := decision(fs, "approved"), decision(fs, "awaiting_review")
	if approve == nil || !strings.Contains(approve.label, "approve without QA or risk evaluation") || toQA == nil ||
		!strings.Contains(toQA.label, "send to QA") {
		t.Fatalf("approve %+v, send to QA %+v", approve, toQA)
	}
	_, fs = r.escalated("a verdict", map[string]any{"risk_verdict": fmt.Sprintf(`{"cleared": false, "matched_rules": ["r1"],
		"evaluated_at": "2026-10-06T09:00:00Z", "base_sha": %q, "head_sha": %q, "tested_sha": %q}`, sha1, sha2, sha2)})
	if a := decision(fs, "approved"); a == nil || strings.Contains(a.label, "without QA") {
		t.Fatalf("with a verdict for the head, the approval reads %+v", a)
	}
	_, fs = r.escalated("a stale verdict", map[string]any{"risk_verdict": fmt.Sprintf(`{"cleared": true, "matched_rules": [],
		"evaluated_at": "2026-10-06T09:00:00Z", "base_sha": %q, "head_sha": %q, "tested_sha": %q}`, sha1, sha3, sha3)})
	if a := decision(fs, "approved"); a == nil || !strings.Contains(a.label, "approve without QA or risk evaluation") {
		t.Fatalf("with a verdict for another head, the approval reads %+v", a)
	}
}

// A commit-bound action is offered only for a head GitHub knows: none with no head, none for a head
// GitHub does not know; the other decisions stay (critique G3; red team R3#2).
func TestCommitBoundActionsNeedAKnownCommit(t *testing.T) {
	r := newRig(t)
	r.start()
	for name, set := range map[string]map[string]any{
		"no head":      {"head_sha": nil},
		"unknown head": {"head_sha": sha3},
	} {
		t.Run(name, func(t *testing.T) {
			_, fs := r.escalated(name, set)
			if decision(fs, "approved") != nil || decision(fs, "awaiting_review") != nil {
				t.Fatalf("a commit-bound action offered: %+v", fs)
			}
			for _, to := range []string{"ready", "done", "failed", "abandoned"} {
				if decision(fs, to) == nil {
					t.Fatalf("no %s form", to)
				}
			}
		})
	}
}

// A ticket with children leaves escalated only to end: done, failed or abandoned, as the engine
// allows (P04).
func TestAParentLeavesEscalatedOnlyToEnd(t *testing.T) {
	r := newRig(t)
	r.start()
	parent := r.seed("sandbox", "parent", "decomposed", nil)
	r.diffs.diffs[sha1+"..."+sha2] = viewer.Diff{Status: viewer.DiffOK, Base: sha1, Head: sha2}
	if _, err := r.owner.Exec(`INSERT INTO tickets (project_id, title, state, parent_ticket_id, depth)
		VALUES ('sandbox', 'child', 'ready', $1, 1)`, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := r.owner.Exec(`UPDATE tickets SET state = 'escalated', escalated_at = now(), base_sha = $2, head_sha = $3
		WHERE id = $1`, parent, sha1, sha2); err != nil {
		t.Fatal(err)
	}
	_, page := r.get(fmt.Sprintf("/tickets/%d", parent))
	fs := forms(page)
	for _, to := range []string{"ready", "approved", "awaiting_review"} {
		if decision(fs, to) != nil {
			t.Errorf("a parent offered %s", to)
		}
	}
	for _, to := range []string{"done", "failed", "abandoned", "parked"} {
		if decision(fs, to) == nil {
			t.Errorf("a parent not offered %s", to)
		}
	}
}

// What was shown is what is sent (red team R5#2): a page loaded before the ticket was escalated
// again, or before its head moved, decides nothing. The API refuses it (409), nothing changes, and
// the page says the ticket changed since it was loaded.
func TestWhatWasShownIsWhatIsSent(t *testing.T) {
	r := newRig(t)
	r.withAPI()
	r.start()
	for name, change := range map[string]string{
		"escalated again": `UPDATE tickets SET escalated_at = escalated_at + interval '1 minute' WHERE id = $1`,
		"head moved":      `UPDATE tickets SET head_sha = '` + sha3 + `' WHERE id = $1`,
	} {
		for _, to := range []string{"approved", "done"} {
			t.Run(name+"/"+to, func(t *testing.T) {
				id, fs := r.escalated(name+" "+to, nil)
				f := decision(fs, to)
				if _, err := r.owner.Exec(change, id); err != nil {
					t.Fatal(err)
				}
				st, body, _ := r.post(f, nil)
				state, _ := r.stateOf(id)
				if to == "done" && name == "head moved" {
					// A decision not about a commit is bound to the escalation only.
					if st != http.StatusSeeOther || state != "done" {
						t.Fatalf("status %d, state %s: %s", st, state, body)
					}
					return
				}
				if st != http.StatusConflict || state != "escalated" || !strings.Contains(body, "changed since this page was loaded") ||
					!strings.Contains(body, "nothing was done") {
					t.Fatalf("status %d, state %s: %s", st, state, body)
				}
			})
		}
	}
}

// A double tap sends the same idempotency key, so the API replays: one decision, one event.
func TestADoubleTapReplays(t *testing.T) {
	r := newRig(t)
	r.withAPI()
	r.start()
	id, fs := r.escalated("double tap", nil)
	f := decision(fs, "done")
	for i := 0; i < 2; i++ {
		if st, body, _ := r.post(f, nil); st != http.StatusSeeOther {
			t.Fatalf("tap %d: status %d: %s", i+1, st, body)
		}
	}
	var n int
	r.owner.QueryRow(`SELECT count(*) FROM ticket_events WHERE ticket_id = $1 AND to_state = 'done'`, id).Scan(&n)
	if n != 1 {
		t.Fatalf("%d decisions recorded, want 1", n)
	}
}

// Parking and unparking from the viewer.
func TestParkAndUnpark(t *testing.T) {
	r := newRig(t)
	r.withAPI()
	r.start()
	id, fs := r.escalated("park me", nil)
	if decision(fs, "unparked") != nil {
		t.Fatal("an unpark form on an unparked ticket")
	}
	park := decision(fs, "parked")
	park.fields.Set("reason", "after the release")
	if st, body, _ := r.post(park, nil); st != http.StatusSeeOther {
		t.Fatalf("park: %d %s", st, body)
	}
	_, page := r.get(fmt.Sprintf("/tickets/%d", id))
	unpark := decision(forms(page), "unparked")
	if unpark == nil {
		t.Fatal("no unpark form on a parked ticket")
	}
	if st, body, _ := r.post(unpark, nil); st != http.StatusSeeOther {
		t.Fatalf("unpark: %d %s", st, body)
	}
	var parked bool
	r.owner.QueryRow(`SELECT parked FROM tickets WHERE id = $1`, id).Scan(&parked)
	if parked {
		t.Fatal("still parked")
	}
}

// --- what an action must carry ------------------------------------------------------------------

// A POST needs the CSRF token the page gave: for this person, this kind of act and this ticket,
// within the hour. A token from one viewer instance verifies in a fresh one: the key is shared, not
// made at startup (critique G2; red team R6).
func TestCSRF(t *testing.T) {
	r := newRig(t)
	r.withAPI()
	r.start()
	id, fs := r.escalated("csrf", nil)
	other, _ := r.escalated("another", nil)
	f := decision(fs, "done")
	for name, mutate := range map[string]func(*form){
		"no token":          func(f *form) { f.fields.Del("csrf") },
		"a tampered token":  func(f *form) { f.fields.Set("csrf", f.fields.Get("csrf")+"x") },
		"another ticket's":  func(f *form) { f.action = fmt.Sprintf("/tickets/%d/decide", other) },
		"another act's":     func(f *form) { f.action = fmt.Sprintf("/tickets/%d/park", id) },
		"a token from 1970": func(f *form) { f.fields.Set("csrf", "0."+strings.SplitN(f.fields.Get("csrf"), ".", 2)[1]) },
	} {
		t.Run(name, func(t *testing.T) {
			g := form{action: f.action, fields: url.Values{}}
			for k, v := range f.fields {
				g.fields[k] = append([]string(nil), v...)
			}
			mutate(&g)
			if st, body, _ := r.post(&g, nil); st != http.StatusForbidden {
				t.Fatalf("status %d: %s", st, body)
			}
		})
	}
	if state, _ := r.stateOf(id); state != "escalated" {
		t.Fatalf("state %s after refused posts", state)
	}

	// The same key in a fresh instance accepts the token; an hour on, it does not.
	fresh, err := viewer.New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	later := r.cfg
	later.Now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	stale, err := viewer.New(later)
	if err != nil {
		t.Fatal(err)
	}
	staleSrv := httptest.NewServer(stale.Handler())
	defer staleSrv.Close()
	saved := r.srv
	r.srv = staleSrv
	if st, _, _ := r.post(f, nil); st != http.StatusForbidden {
		t.Fatalf("a token an hour old: status %d", st)
	}
	freshSrv := httptest.NewServer(fresh.Handler())
	defer freshSrv.Close()
	r.srv = freshSrv
	if st, body, _ := r.post(f, nil); st != http.StatusSeeOther {
		t.Fatalf("a token from another instance: status %d: %s", st, body)
	}
	r.srv = saved
}

// A POST is the viewer's own: Sec-Fetch-Site same-origin, or, from a browser that sends none, the
// viewer's own Origin; anything else is refused (D17).
func TestPostsFromElsewhereAreRefused(t *testing.T) {
	r := newRig(t)
	r.withAPI()
	r.start()
	for name, c := range map[string]struct {
		header map[string]string
		want   int
	}{
		"cross-site":                     {map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		"same-site":                      {map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		"no Sec-Fetch-Site, no Origin":   {map[string]string{"Sec-Fetch-Site": ""}, http.StatusForbidden},
		"no Sec-Fetch-Site, evil Origin": {map[string]string{"Sec-Fetch-Site": "", "Origin": "https://evil.example"}, http.StatusForbidden},
		"no Sec-Fetch-Site, own Origin":  {map[string]string{"Sec-Fetch-Site": "", "Origin": origin}, http.StatusSeeOther},
	} {
		t.Run(name, func(t *testing.T) {
			_, fs := r.escalated(name, nil)
			if st, body, _ := r.post(decision(fs, "done"), c.header); st != c.want {
				t.Fatalf("status %d, want %d: %s", st, c.want, body)
			}
		})
	}
}

// The relay builds each request to the callback API from nothing: the viewer's own ID token (asked
// for with format=full, for the API's audience), the person's assertion, the form's idempotency key
// and the body. Nothing of the person's request reaches the API: not IAP's cookie, its
// X-Serverless-Authorization, or anything else (review of T1 to T3).
func TestTheRelaySendsOnlyItsOwn(t *testing.T) {
	r := newRig(t)
	meta, requests := r.withAPI()
	r.start()
	_, fs := r.escalated("relay", nil)
	f := decision(fs, "done")
	assertion := r.iap.assertion(t, operator)
	st, body, _ := r.post(f, map[string]string{
		"X-Goog-Iap-Jwt-Assertion":   assertion,
		"Cookie":                     "GCP_IAP_UID=iap-session-cookie",
		"X-Serverless-Authorization": "Bearer iap-to-cloud-run",
		"Authorization":              "Bearer the-persons-own",
		"X-Forwarded-For":            "203.0.113.7",
		"X-Custom":                   "anything",
	})
	if st != http.StatusSeeOther {
		t.Fatalf("status %d: %s", st, body)
	}
	got := requests()
	last := got[len(got)-1]
	h := last.Header
	if h.Get("X-Foreman-Iap-Assertion") != assertion || h.Get("Idempotency-Key") != f.fields.Get("key") ||
		!strings.HasPrefix(h.Get("Authorization"), "Bearer ey") || h.Get("Authorization") == "Bearer the-persons-own" {
		t.Fatalf("the relayed request's headers %v", h)
	}
	for name := range h {
		switch http.CanonicalHeaderKey(name) {
		case "Authorization", "X-Foreman-Iap-Assertion", "Idempotency-Key", "Content-Type", "Content-Length",
			"User-Agent", "Accept-Encoding":
		default:
			t.Errorf("the relayed request carries %s: %v", name, h.Values(name))
		}
	}
	meta.mu.Lock()
	defer meta.mu.Unlock()
	if len(meta.queries) == 0 || !strings.Contains(meta.queries[0], "format=full") {
		t.Fatalf("the viewer's ID token asked for with %v", meta.queries)
	}
}

// An expired IAP session's redirect turns a form's POST into a GET of its URL: the page says the
// session expired and nothing was done (consult 1).
func TestAnExpiredSessionsGETDoesNothing(t *testing.T) {
	r := newRig(t)
	r.start()
	id, _ := r.escalated("expired", nil)
	for _, path := range []string{fmt.Sprintf("/tickets/%d/decide", id), fmt.Sprintf("/tickets/%d/park", id), "/create"} {
		st, body := r.get(path)
		if st != http.StatusOK || !strings.Contains(body, "session expired") || !strings.Contains(body, "nothing was done") {
			t.Fatalf("GET %s: status %d: %s", path, st, body)
		}
	}
	if state, _ := r.stateOf(id); state != "escalated" {
		t.Fatalf("state %s", state)
	}
}

// Decisions are offered by state: an escalated ticket gets every decision and parking; another
// unfinished ticket, abandoning; a finished one, nothing.
func TestTheActionsFollowTheState(t *testing.T) {
	r := newRig(t)
	r.start()
	ready := r.seed("sandbox", "ready one", "ready", nil)
	_, page := r.get(fmt.Sprintf("/tickets/%d", ready))
	fs := forms(page)
	if len(fs) != 1 || fs[0].fields.Get("to") != "abandoned" || fs[0].fields.Get("escalated_at") != "" {
		t.Fatalf("a ready ticket's forms %+v", fs)
	}
	done := r.seed("sandbox", "done one", "done", nil)
	if _, page := r.get(fmt.Sprintf("/tickets/%d", done)); len(forms(page)) != 0 {
		t.Fatalf("a done ticket offers %+v", forms(page))
	}
}

// A token is the person's own: another person posting it is refused (D17). The rig's identity map
// gains a second person for this.
func TestATokenIsItsPersonsAlone(t *testing.T) {
	r := newRig(t)
	const other = "someone-else@example.com"
	ids, err := callbackapi.LoadIdentityMap([]byte(`[{"email": "` + operator + `", "role": "human"},
		{"email": "` + other + `", "role": "human"}]`))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		ServiceAudience: "https://callback-api.example.test", IAPAudience: iapAudience, IAPJWKSURL: r.iap.url,
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.Identify = verifier.VerifyRelayed
	r.start()
	id, fs := r.escalated("whose token", nil)
	f := decision(fs, "done")
	if st, body, _ := r.post(f, map[string]string{"X-Goog-Iap-Jwt-Assertion": r.iap.assertion(t, other)}); st != http.StatusForbidden {
		t.Fatalf("another person's post: status %d: %s", st, body)
	}
	// The person it was made for gets past the token, to the relay (which this rig does not have).
	if st, body, _ := r.post(f, nil); st == http.StatusForbidden {
		t.Fatalf("its own person's post: status %d: %s", st, body)
	}
	if state, _ := r.stateOf(id); state != "escalated" {
		t.Fatalf("state %s", state)
	}
}

// statusRelay answers every act with one status and reason, as a callback API would.
type statusRelay struct {
	status int
	reason string
}

func (s statusRelay) Send(context.Context, string, string, string, string, any) (int, string, map[string]any, error) {
	return s.status, s.reason, nil, nil
}

// When the callback API cannot be reached, or fails (5xx), the person is told it is not known
// whether anything was done, and that sending again is safe; a refusal (4xx) says nothing was done.
func TestWhenTheAPIDoesNotAnswerClearly(t *testing.T) {
	for name, c := range map[string]struct {
		relay  viewer.Relay
		status int
		says   string
	}{
		"unreachable": {refusingRelay{}, http.StatusBadGateway, "not known whether this was done"},
		"a 500":       {statusRelay{500, "internal error"}, http.StatusBadGateway, "not known whether this was done"},
		"a 503":       {statusRelay{503, ""}, http.StatusBadGateway, "not known whether this was done"},
		"a 400":       {statusRelay{400, "bad request body"}, http.StatusBadRequest, "nothing was done"},
		"a 403":       {statusRelay{403, "not a person"}, http.StatusForbidden, "nothing was done"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.cfg.Relay = c.relay
			r.start()
			_, fs := r.escalated(name, nil)
			st, body, _ := r.post(decision(fs, "done"), nil)
			if st != c.status || !strings.Contains(body, c.says) {
				t.Fatalf("status %d, want %d saying %q: %s", st, c.status, c.says, body)
			}
			if c.status == http.StatusBadGateway && !strings.Contains(body, "same idempotency key") {
				t.Fatalf("the page does not say sending again is safe: %s", body)
			}
		})
	}
}

// An escalated ticket with no escalation time, which the engine never writes, offers no decision,
// since none could name the escalation, and says so.
func TestAnEscalationWithNoTimeOffersNothing(t *testing.T) {
	r := newRig(t)
	r.start()
	id := r.seed("sandbox", "no time", "escalated", map[string]any{"base_sha": sha1, "head_sha": sha2})
	st, page := r.get(fmt.Sprintf("/tickets/%d", id))
	if st != http.StatusOK || len(forms(page)) != 0 || !strings.Contains(page, "no time recorded") {
		t.Fatalf("status %d, forms %+v: %s", st, forms(page), page)
	}
}

// At the attempt cap the engine turns a return to ready into failed, which is terminal, so the
// button says so and is styled as risky; below the cap it is a plain return (the validation round).
func TestSendingBackToReadyAtTheCapSaysItFails(t *testing.T) {
	r := newRig(t)
	r.withAPI()
	r.start()
	if _, fs := r.escalated("one attempt used", map[string]any{"attempt_count": 1}); decision(fs, "ready") == nil ||
		decision(fs, "ready").label != "send back to ready" {
		t.Fatalf("below the cap: %+v", decision(fs, "ready"))
	}
	id, fs := r.escalated("every attempt used", map[string]any{"attempt_count": callbackapi.AttemptCap})
	f := decision(fs, "ready")
	if f == nil || !strings.Contains(f.label, "attempts are used, so this fails the ticket") {
		t.Fatalf("at the cap: %+v", f)
	}
	_, page := r.get(fmt.Sprintf("/tickets/%d", id))
	if !regexp.MustCompile(`<button[^>]*class="risky"[^>]*>send back to ready: `).MatchString(page) {
		t.Fatalf("at the cap the button is not styled as risky: %s", page)
	}
	// What it says is what happens.
	if st, body, _ := r.post(f, nil); st != http.StatusSeeOther {
		t.Fatalf("status %d: %s", st, body)
	}
	if state, _ := r.stateOf(id); state != "failed" {
		t.Fatalf("state %s, want failed", state)
	}
}
