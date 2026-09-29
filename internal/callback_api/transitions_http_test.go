package callbackapi_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// The HTTP tests run the real handler, the real verifier and the real engine, with tokens signed
// by a local key that an in-process key server publishes.

const httpMap = `[
  {"email": "dispatcher@your-project-id.iam.gserviceaccount.com", "role": "dispatcher"},
  {"email": "dev-foreman@your-project-id.iam.gserviceaccount.com", "role": "dev", "project": "foreman"},
  {"email": "qa-foreman@your-project-id.iam.gserviceaccount.com", "role": "qa", "project": "foreman"},
  {"email": "spec-foreman@your-project-id.iam.gserviceaccount.com", "role": "spec", "project": "foreman"},
  {"email": "architect-foreman@your-project-id.iam.gserviceaccount.com", "role": "architect", "project": "foreman"},
  {"email": "integrator-foreman@your-project-id.iam.gserviceaccount.com", "role": "integrator", "project": "foreman"},
  {"email": "operator@example.com", "role": "human"}
]`

type api struct {
	t    *testing.T
	conn *sql.DB
	srv  *httptest.Server
	key  signer
	eng  *callbackapi.Engine
}

func newAPI(t *testing.T) *api {
	t.Helper()
	return newAPIWith(t, newEngine(nil))
}

// newAPIWith serves the API over a given engine: the real risk evaluator's tests use it.
func newAPIWith(t *testing.T, e *callbackapi.Engine) *api {
	t.Helper()
	conn := fresh(t)
	k := newSigner(t, "k1")
	ks := newKeyServer(t, k)
	ids, err := callbackapi.LoadIdentityMap([]byte(httpMap))
	if err != nil {
		t.Fatal(err)
	}
	v, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		JWKSURL: ks.URL, ServiceAudience: serviceAudience, HumanAudiences: []string{humanAudience},
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(callbackapi.NewServer(conn, e, v, nil).Handler())
	t.Cleanup(srv.Close)
	return &api{t: t, conn: conn, srv: srv, key: k, eng: e}
}

// tokenFor signs a token for an email with the audience its kind must carry.
func (a *api) tokenFor(email string) string {
	aud := humanAudience
	if strings.HasSuffix(email, "gserviceaccount.com") {
		aud = serviceAudience
	}
	return a.key.sign(a.t, claimsFor(email, aud))
}

type call struct {
	method, path, token, key, claim string
	body                            any
}

func (a *api) do(c call) (int, map[string]any) {
	a.t.Helper()
	var r io.Reader
	if c.body != nil {
		b, _ := json.Marshal(c.body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(c.method, a.srv.URL+c.path, r)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.key != "" {
		req.Header.Set("Idempotency-Key", c.key)
	}
	if c.claim != "" {
		req.Header.Set("X-Foreman-Claim-Token", c.claim)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// transition posts {from, to} for id as email, with a fresh key and the fixture's claim token.
func (a *api) transition(email string, id int64, from, to callbackapi.State) (int, map[string]any) {
	a.t.Helper()
	body := map[string]any{"from": from, "to": to}
	if from == sDraft && to == sReady {
		body["acceptance_criteria"] = oneAC
	}
	if carriesCommit(from, to) {
		body["head_sha"] = fixtureSHA
	}
	return a.do(call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/transitions", id),
		token: a.tokenFor(email), key: newRequestID(), claim: liveToken, body: body})
}

func wantHTTP(t *testing.T, got, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("status %d, want %d (%v)", got, want, body)
	}
}

// --- authentication ------------------------------------------------------------------------------

func TestHTTPRequiresAValidToken(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	path := fmt.Sprintf("/v1/tickets/%d/transitions", id)
	body := map[string]any{"from": sInProgress, "to": sAwaiting}
	st, b := a.do(call{method: "POST", path: path, key: newRequestID(), claim: liveToken, body: body})
	wantHTTP(t, st, 401, b)
	st, b = a.do(call{method: "POST", path: path, token: "not-a-token", key: newRequestID(), claim: liveToken, body: body})
	wantHTTP(t, st, 401, b)
}

// viewer, callback-api, the default compute account and an unknown person hold valid tokens but
// no mapping: refused on every caller-driven row, and nothing changes.
// Valid tokens for identities the map does not name.
var unmapped = []string{
	"viewer@your-project-id.iam.gserviceaccount.com",
	"callback-api@your-project-id.iam.gserviceaccount.com",
	defaultCompute,
	"someone@example.com",
}

func TestHTTPUnmappedIdentitiesAreRefusedEverywhere(t *testing.T) {
	a := newAPI(t)
	for _, r := range callbackapi.Table() {
		if r.Channel != callbackapi.ChannelHTTP {
			continue
		}
		id := seed(t, a.conn, fixture{state: r.From, attempts: 1})
		before := snapshot(t, a.conn, id)
		for _, email := range unmapped {
			st, b := a.transition(email, id, r.From, r.To)
			if st != 403 {
				t.Errorf("%s on %s -> %s: status %d, want 403 (%v)", email, r.From, r.To, st, b)
			}
		}
		assertUnchanged(t, a.conn, id, before, 0, 0)
	}
}

// --- the Anchor's named cases, over HTTP ----------------------------------------------------------

func TestHTTPChunkTwoNamedCases(t *testing.T) {
	a := newAPI(t)

	id := seed(t, a.conn, fixture{state: sInQA, attempts: 1})
	before := snapshot(t, a.conn, id)
	st, b := a.transition(dev.Email, id, sInQA, sApproved)
	wantHTTP(t, st, 403, b)
	assertUnchanged(t, a.conn, id, before, 0, 0)

	esc := seed(t, a.conn, fixture{state: sEscalated, attempts: 1})
	before = snapshot(t, a.conn, esc)
	st, b = a.transition(qa.Email, esc, sEscalated, sReady)
	wantHTTP(t, st, 403, b)

	st, b = a.do(call{method: "PUT", path: fmt.Sprintf("/v1/tickets/%d/parking", esc),
		token: a.tokenFor(dispatcherCaller.Email), key: newRequestID(),
		body: map[string]any{"parked": true, "reason": "the dispatcher tries"}})
	wantHTTP(t, st, 403, b)
	assertUnchanged(t, a.conn, esc, before, 0, 0)

	// A request that fails validation writes no event and no ticket update.
	bad := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	before = snapshot(t, a.conn, bad)
	st, b = a.transition(dev.Email, bad, sInProgress, "blocked")
	wantHTTP(t, st, 400, b)
	assertUnchanged(t, a.conn, bad, before, 0, 0)

	// The same request id replayed: one event, the same answer.
	work := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	c := call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/transitions", work), token: a.tokenFor(dev.Email),
		key: newRequestID(), claim: liveToken, body: map[string]any{"from": sInProgress, "to": sAwaiting, "head_sha": fixtureSHA}}
	st1, b1 := a.do(c)
	st2, b2 := a.do(c)
	wantHTTP(t, st1, 200, b1)
	wantHTTP(t, st2, 200, b2)
	if b1["event_id"] != b2["event_id"] || eventCount(t, a.conn, work) != 1 {
		t.Fatalf("replay: %v then %v, %d events", b1, b2, eventCount(t, a.conn, work))
	}
}

func TestHTTPFailureAfterUpdateRollsBack(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	if _, err := a.conn.Exec(`
		CREATE FUNCTION refuse_event() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'event insert refused by test'; END $$;
		CREATE TRIGGER refuse_event BEFORE INSERT ON ticket_events FOR EACH ROW EXECUTE FUNCTION refuse_event();`); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, a.conn, id)
	st, b := a.transition(dev.Email, id, sInProgress, sAwaiting)
	wantHTTP(t, st, 500, b)
	if strings.Contains(fmt.Sprint(b), "refused by test") {
		t.Fatalf("an internal error leaked its detail: %v", b)
	}
	assertUnchanged(t, a.conn, id, before, 0, 0)
}

// Rows that are not on the http channel are refused on /transitions for every caller: the
// dispatcher's claims and reaps, `ready -> decomposed`, and the internal rows.
// The dispatcher's rows, the internal rows and `ready -> decomposed` are refused on /transitions
// for every caller: each of the seven roles and every unmapped identity. Where an HTTP row shares
// the pair (`in_progress -> ready` is the dispatcher's reap and the dev runner giving up), that
// row's own actor is skipped: the matrix tests it.
func TestHTTPOnlyHTTPRows(t *testing.T) {
	a := newAPI(t)
	var everyone []string
	for _, role := range callerRoles {
		c, _ := callerFor(role)
		everyone = append(everyone, c.Email)
	}
	everyone = append(everyone, unmapped...)
	for p, rows := range pairs() {
		viaHTTP, offHTTP := map[string]bool{}, false
		for _, r := range rows {
			if r.Channel == callbackapi.ChannelHTTP {
				c, _ := callerFor(r.Actor)
				viaHTTP[c.Email] = true
			} else {
				offHTTP = true
			}
		}
		if !offHTTP {
			continue
		}
		id := seed(t, a.conn, fixture{state: p.from, attempts: 1})
		before := snapshot(t, a.conn, id)
		for _, email := range everyone {
			if viaHTTP[email] {
				continue
			}
			st, b := a.transition(email, id, p.from, p.to)
			if st != 403 {
				t.Errorf("%s -> %s by %s over HTTP: %d, want 403 (%v)", p.from, p.to, email, st, b)
			}
		}
		assertUnchanged(t, a.conn, id, before, 0, 0)
	}
}

func TestHTTPProjectScope(t *testing.T) {
	a := newAPI(t)
	addProject(t, a.conn, "other")
	id := seed(t, a.conn, fixture{project: "other", state: sInProgress, attempts: 1})
	st, b := a.transition(dev.Email, id, sInProgress, sAwaiting)
	wantHTTP(t, st, 403, b)
	esc := seed(t, a.conn, fixture{project: "other", state: sEscalated, attempts: 1})
	st, b = a.transition(humanCaller.Email, esc, sEscalated, sReady)
	wantHTTP(t, st, 200, b)
}

func TestHTTPIdempotencyKeyRequired(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	for name, key := range map[string]string{"missing": "", "not a uuid": "retry-1"} {
		t.Run(name, func(t *testing.T) {
			st, b := a.do(call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/transitions", id),
				token: a.tokenFor(dev.Email), key: key, claim: liveToken,
				body: map[string]any{"from": sInProgress, "to": sAwaiting, "head_sha": fixtureSHA}})
			wantHTTP(t, st, 400, b)
		})
	}
}

// The request body is an allowlist: an unknown field is refused, so creation cannot name a
// state, a parent or a depth.
func TestHTTPUnknownFieldsRefused(t *testing.T) {
	a := newAPI(t)
	for _, field := range []string{"state", "parent_ticket_id", "depth", "attempt_count", "parked"} {
		st, b := a.do(call{method: "POST", path: "/v1/tickets", token: a.tokenFor(humanCaller.Email), key: newRequestID(),
			body: map[string]any{"project": "foreman", "title": "sneaky", field: 1}})
		if st != 400 {
			t.Errorf("creation with %q: %d, want 400 (%v)", field, st, b)
		}
	}
	if n := count(t, a.conn, `SELECT count(*) FROM tickets`); n != 0 {
		t.Fatalf("%d tickets created", n)
	}
}

// --- fencing, heartbeats, artifacts ------------------------------------------------------------------

// A reaped runner's token is refused once the ticket has been claimed again.
func TestHTTPReapedRunnerIsFencedOut(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sReady})
	claim1 := mustDo(t, a.eng, a.conn, request(id, sReady, sClaimed, dispatcherCaller, chCore))
	expire(t, a.conn, id)
	mustDo(t, a.eng, a.conn, request(id, sClaimed, sReady, dispatcherCaller, chCore)) // reaped
	claim2 := mustDo(t, a.eng, a.conn, request(id, sReady, sClaimed, dispatcherCaller, chCore))

	path := fmt.Sprintf("/v1/tickets/%d/transitions", id)
	body := map[string]any{"from": sClaimed, "to": sInProgress}
	st, b := a.do(call{method: "POST", path: path, token: a.tokenFor(dev.Email), key: newRequestID(), claim: claim1.ClaimToken, body: body})
	wantHTTP(t, st, 409, b)
	st, b = a.do(call{method: "POST", path: path, token: a.tokenFor(dev.Email), key: newRequestID(), claim: claim2.ClaimToken, body: body})
	wantHTTP(t, st, 200, b)
}

func TestHTTPHeartbeat(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	path := fmt.Sprintf("/v1/tickets/%d/heartbeat", id)
	st, b := a.do(call{method: "POST", path: path, token: a.tokenFor(dev.Email), key: newRequestID(), claim: liveToken})
	wantHTTP(t, st, 200, b)
	if b["lease_expires_at"] == nil || eventCount(t, a.conn, id) != 1 {
		t.Fatalf("heartbeat response %v, %d events", b, eventCount(t, a.conn, id))
	}
	st, b = a.do(call{method: "POST", path: path, token: a.tokenFor(qa.Email), key: newRequestID(), claim: liveToken})
	wantHTTP(t, st, 409, b) // QA does not own in_progress's lease
	st, b = a.do(call{method: "POST", path: path, token: a.tokenFor(humanCaller.Email), key: newRequestID()})
	wantHTTP(t, st, 403, b)
}

func TestHTTPArtifacts(t *testing.T) {
	a := newAPI(t)
	id := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	path := fmt.Sprintf("/v1/tickets/%d/artifacts", id)
	good := fmt.Sprintf("foreman/%d/1/transcript.jsonl", id)
	register := func(email, claim, kind, gcs string) (int, map[string]any) {
		return a.do(call{method: "POST", path: path, token: a.tokenFor(email), key: newRequestID(), claim: claim,
			body: map[string]any{"kind": kind, "gcs_path": gcs}})
	}
	st, b := register(dev.Email, liveToken, "transcript", good)
	wantHTTP(t, st, 201, b)
	var n int
	a.conn.QueryRow(`SELECT count(*) FROM artifacts WHERE ticket_id = $1 AND attempt = 1 AND gcs_path = $2`, id, good).Scan(&n)
	if n != 1 {
		t.Fatal("the artifact was not recorded for attempt 1")
	}
	for name, c := range map[string]struct {
		email, claim, kind, gcs string
		status                  int
	}{
		"another attempt":    {dev.Email, liveToken, "transcript", fmt.Sprintf("foreman/%d/2/t.jsonl", id), 400},
		"another project":    {dev.Email, liveToken, "transcript", fmt.Sprintf("other/%d/1/t.jsonl", id), 400},
		"another ticket":     {dev.Email, liveToken, "transcript", fmt.Sprintf("foreman/%d/1/t.jsonl", id+1), 400},
		"traversal":          {dev.Email, liveToken, "log", fmt.Sprintf("foreman/%d/1/../2/x", id), 400},
		"leading slash":      {dev.Email, liveToken, "log", fmt.Sprintf("/foreman/%d/1/x", id), 400},
		"empty segment":      {dev.Email, liveToken, "log", fmt.Sprintf("foreman/%d/1//x", id), 400},
		"no file":            {dev.Email, liveToken, "log", fmt.Sprintf("foreman/%d/1/", id), 400},
		"unknown kind":       {dev.Email, liveToken, "secrets", good, 400},
		"no token":           {dev.Email, "", "log", good, 409},
		"stale token":        {dev.Email, "claim-token-of-a-reaped-run", "log", good, 409},
		"not the lease role": {qa.Email, liveToken, "log", good, 409},
		"a human":            {humanCaller.Email, "", "log", good, 403},
	} {
		t.Run(name, func(t *testing.T) {
			st, b := register(c.email, c.claim, c.kind, c.gcs)
			wantHTTP(t, st, c.status, b)
		})
	}
	t.Run("another project's runner", func(t *testing.T) {
		addProject(t, a.conn, "other")
		other := seed(t, a.conn, fixture{project: "other", state: sInProgress, attempts: 1})
		st, b := a.do(call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/artifacts", other),
			token: a.tokenFor(dev.Email), key: newRequestID(), claim: liveToken,
			body: map[string]any{"kind": "log", "gcs_path": fmt.Sprintf("other/%d/1/x", other)}})
		wantHTTP(t, st, 403, b)
	})
	if n := count(t, a.conn, `SELECT count(*) FROM artifacts`); n != 1 {
		t.Fatalf("%d artifacts, want only the one registered by the lease holder", n)
	}
}

// --- the other routes -----------------------------------------------------------------------------

func TestHTTPCreateDecomposeParkPromote(t *testing.T) {
	a := newAPI(t)
	st, b := a.do(call{method: "POST", path: "/v1/tickets", token: a.tokenFor(humanCaller.Email), key: newRequestID(),
		body: map[string]any{"project": "foreman", "title": "a parent", "acceptance_criteria": oneAC}})
	wantHTTP(t, st, 201, b)
	parent := int64(b["ticket_id"].(float64))

	kids := []map[string]any{}
	for i := 0; i < 6; i++ {
		kids = append(kids, map[string]any{"title": fmt.Sprint("child ", i), "acceptance_criteria": oneAC})
	}
	st, b = a.do(call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/decompose", parent), token: a.tokenFor(spec.Email),
		key: newRequestID(), body: map[string]any{"children": kids}})
	wantHTTP(t, st, 200, b)
	if b["state"] != string(sEscalated) {
		t.Fatalf("six children: %v, want the escalated parent", b)
	}

	st, b = a.do(call{method: "PUT", path: fmt.Sprintf("/v1/tickets/%d/parking", parent), token: a.tokenFor(humanCaller.Email),
		key: newRequestID(), body: map[string]any{"parked": true, "reason": "discussing the split"}})
	wantHTTP(t, st, 200, b)

	for _, role := range agentRoles {
		c, _ := callerFor(role)
		st, b = a.do(call{method: "POST", path: "/v1/promotions", token: a.tokenFor(c.Email), key: newRequestID(),
			body: map[string]any{"component": "dispatcher", "image_digest": digest('a'), "git_sha": gitSHA('1')}})
		if st != 403 {
			t.Errorf("%s promoting: %d, want 403", role, st)
		}
	}
	st, b = a.do(call{method: "POST", path: "/v1/promotions", token: a.tokenFor(humanCaller.Email), key: newRequestID(),
		body: map[string]any{"component": "dispatcher", "image_digest": digest('a'), "git_sha": gitSHA('1')}})
	wantHTTP(t, st, 201, b)
	if b["promoted_by"] != humanCaller.Email {
		t.Fatalf("promoted_by %v, want the verified email", b["promoted_by"])
	}
}

func TestHTTPHealthPingsTheDatabase(t *testing.T) {
	a := newAPI(t)
	st, b := a.do(call{method: "GET", path: "/healthz"})
	wantHTTP(t, st, 200, b)

	closed := fresh(t)
	closed.Close()
	down := httptest.NewServer(callbackapi.NewServer(closed, a.eng, nil, nil).Handler())
	defer down.Close()
	resp, err := http.Get(down.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("health with the database closed: %d, want 503", resp.StatusCode)
	}
}

func TestHTTPUnknownRoutesAndMethods(t *testing.T) {
	a := newAPI(t)
	st, _ := a.do(call{method: "GET", path: "/v1/tickets/1/transitions", token: a.tokenFor(dev.Email)})
	if st != 405 && st != 404 {
		t.Fatalf("GET on a POST route: %d", st)
	}
	st, _ = a.do(call{method: "POST", path: "/v1/nothing", token: a.tokenFor(dev.Email), key: newRequestID()})
	if st != 404 {
		t.Fatalf("unknown route: %d", st)
	}
}
