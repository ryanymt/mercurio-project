package callbackapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// A person acts only through the viewer (P06 D3, D4, D20): the viewer calls the API with its own
// service account's token and relays the person's IAP assertion, which the API verifies itself.

const (
	iapAudience = "/projects/123456789012/locations/us-central1/services/viewer"
	viewerEmail = "viewer@your-project-id.iam.gserviceaccount.com"
)

// realIAPClaims are the claims of a real IAP assertion, recorded in P06's spike (T2).
//
//go:embed testdata/iap_claims.json
var realIAPClaims []byte

// iapClaimsFor is the spike's claim set for email, issued now and expiring in ten minutes, as IAP's
// do. It carries no email_verified: IAP sends none.
func iapClaimsFor(t *testing.T, email string) map[string]any {
	t.Helper()
	var doc struct {
		Claims map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(realIAPClaims, &doc); err != nil {
		t.Fatal(err)
	}
	c := doc.Claims
	if _, ok := c["email_verified"]; ok {
		t.Fatal("the recorded claims carry email_verified, which IAP does not send")
	}
	if c["aud"] != iapAudience || c["iss"] != "https://cloud.google.com/iap" {
		t.Fatalf("the recorded claims are not the viewer's: %v", c)
	}
	now := time.Now()
	c["email"], c["iat"], c["exp"] = email, now.Unix(), now.Add(10*time.Minute).Unix()
	return c
}

// iapSigner signs assertions as IAP does: ES256 on P-256.
type iapSigner struct {
	key *ecdsa.PrivateKey
	kid string
}

func newIAPSigner(t *testing.T, kid string) iapSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return iapSigner{k, kid}
}

func (s iapSigner) public() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "ES256", Use: "sig"}
}

func (s iapSigner) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}},
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

// relayVerifier verifies Google tokens with ks's keys and IAP assertions with iapKS's, for the
// viewer's audience, on the given clock.
func relayVerifier(t *testing.T, ks, iapKS *keyServer, now func() time.Time) *callbackapi.Verifier {
	t.Helper()
	ids, err := callbackapi.LoadIdentityMap([]byte(httpMap))
	if err != nil {
		t.Fatal(err)
	}
	v, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		JWKSURL: ks.URL, ServiceAudience: serviceAudience, IAPJWKSURL: iapKS.URL, IAPAudience: iapAudience, Now: now,
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// --- the assertion ------------------------------------------------------------------------------

// A real IAP claim set, signed by a published IAP key, names the person: a human from the map.
func TestARelayedAssertionNamesThePerson(t *testing.T) {
	iap := newIAPSigner(t, "1F5uEQ")
	v := relayVerifier(t, newKeyServer(t), newKeyServerOf(t, iap.public()), nil)
	c, err := v.VerifyRelayed(context.Background(), iap.sign(t, iapClaimsFor(t, humanEmail)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != humanEmail || c.Role != callbackapi.RoleHuman || c.Project != "" {
		t.Fatalf("relayed caller %+v", c)
	}
	upper, err := v.VerifyRelayed(context.Background(), iap.sign(t, iapClaimsFor(t, strings.ToUpper(humanEmail))))
	if err != nil || upper.Email != humanEmail {
		t.Fatalf("an upper-case email: %+v, %v", upper, err)
	}
}

// Every way an assertion can be wrong is a 401; a valid one naming an email the map does not know
// is a 403. Times have 30 seconds of leeway, and no more.
func TestRelayedAssertionRefusals(t *testing.T) {
	iap := newIAPSigner(t, "iap-1")
	stranger := newIAPSigner(t, "iap-unknown")
	forger := newIAPSigner(t, "iap-1") // another key under the published key's id
	rsaKey := newSigner(t, "rsa-in-iap-set")
	google := newSigner(t, "google-1")
	v := relayVerifier(t, newKeyServer(t, google), newKeyServerOf(t, iap.public(), rsaKey.public()), nil)
	with := func(email string, mod func(map[string]any)) map[string]any {
		c := iapClaimsFor(t, email)
		if mod != nil {
			mod(c)
		}
		return c
	}
	at := func(d time.Duration) int64 { return time.Now().Add(d).Unix() }
	alter := func(raw string, claims map[string]any) string {
		parts := strings.Split(raw, ".")
		b, _ := json.Marshal(claims)
		parts[1] = base64.RawURLEncoding.EncodeToString(b)
		return strings.Join(parts, ".")
	}
	ok := 0
	cases := []struct {
		name      string
		assertion string
		status    int // 0: accepted
	}{
		{"empty", "", 401},
		{"not a JWT", "not.an.assertion", 401},
		{"expired 40 s ago", iap.sign(t, with(humanEmail, func(c map[string]any) { c["exp"] = at(-40 * time.Second) })), 401},
		{"expired 20 s ago, within the leeway", iap.sign(t, with(humanEmail, func(c map[string]any) { c["exp"] = at(-20 * time.Second) })), ok},
		{"issued 40 s in the future", iap.sign(t, with(humanEmail, func(c map[string]any) { c["iat"] = at(40 * time.Second) })), 401},
		{"issued 20 s in the future, within the leeway", iap.sign(t, with(humanEmail, func(c map[string]any) { c["iat"] = at(20 * time.Second) })), ok},
		{"no expiry", iap.sign(t, with(humanEmail, func(c map[string]any) { delete(c, "exp") })), 401},
		{"no issue time", iap.sign(t, with(humanEmail, func(c map[string]any) { delete(c, "iat") })), 401},
		{"another service's audience", iap.sign(t, with(humanEmail, func(c map[string]any) {
			c["aud"] = "/projects/123456789012/locations/us-central1/services/callback-api"
		})), 401},
		{"the API's own audience", iap.sign(t, with(humanEmail, func(c map[string]any) { c["aud"] = serviceAudience })), 401},
		{"no audience", iap.sign(t, with(humanEmail, func(c map[string]any) { delete(c, "aud") })), 401},
		{"Google's issuer", iap.sign(t, with(humanEmail, func(c map[string]any) { c["iss"] = "https://accounts.google.com" })), 401},
		{"no issuer", iap.sign(t, with(humanEmail, func(c map[string]any) { delete(c, "iss") })), 401},
		{"RS256, under a key IAP's set publishes", rsaKey.sign(t, iapClaimsFor(t, humanEmail)), 401},
		{"signed by a key only Google publishes", google.sign(t, iapClaimsFor(t, humanEmail)), 401},
		{"signed by an unpublished key", stranger.sign(t, iapClaimsFor(t, humanEmail)), 401},
		{"forged under a published key id", forger.sign(t, iapClaimsFor(t, humanEmail)), 401},
		{"payload altered after signing", alter(iap.sign(t, iapClaimsFor(t, "someone@example.com")), iapClaimsFor(t, humanEmail)), 401},
		{"no email", iap.sign(t, with(humanEmail, func(c map[string]any) { delete(c, "email") })), 401},
		{"a mapped service account", iap.sign(t, iapClaimsFor(t, devEmail)), 401},
		{"the viewer's own account", iap.sign(t, iapClaimsFor(t, viewerEmail)), 401},
		{"an unmapped service account", iap.sign(t, iapClaimsFor(t, defaultCompute)), 401},
		{"a person the map does not know", iap.sign(t, iapClaimsFor(t, "someone@example.com")), 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := v.VerifyRelayed(context.Background(), c.assertion)
			if c.status == ok {
				if err != nil || got.Email != humanEmail {
					t.Fatalf("refused: %+v, %v", got, err)
				}
				return
			}
			wantStatus(t, err, c.status)
		})
	}
}

// An assertion's times are judged by the verifier's clock (Now in its configuration, the host's in
// production), as a Google token's are: with that clock eleven minutes ahead, an assertion issued
// now has expired, and one issued eleven minutes from now is current.
func TestAssertionTimesAreJudgedByTheVerifiersClock(t *testing.T) {
	iap := newIAPSigner(t, "iap-1")
	ahead := func() time.Time { return time.Now().Add(11 * time.Minute) }
	v := relayVerifier(t, newKeyServer(t), newKeyServerOf(t, iap.public()), ahead)
	_, err := v.VerifyRelayed(context.Background(), iap.sign(t, iapClaimsFor(t, humanEmail)))
	wantStatus(t, err, 401)
	later := iapClaimsFor(t, humanEmail)
	later["iat"], later["exp"] = ahead().Unix(), ahead().Add(10*time.Minute).Unix()
	if c, err := v.VerifyRelayed(context.Background(), iap.sign(t, later)); err != nil || c.Email != humanEmail {
		t.Fatalf("an assertion current by the verifier's clock: %+v, %v", c, err)
	}
}

// Without the viewer's audience configured, no relayed person is accepted: the check fails closed
// rather than skipping the audience (red team R10#2).
func TestNoIAPAudienceAcceptsNoRelay(t *testing.T) {
	iap := newIAPSigner(t, "iap-1")
	iapKS := newKeyServerOf(t, iap.public())
	ids, err := callbackapi.LoadIdentityMap([]byte(httpMap))
	if err != nil {
		t.Fatal(err)
	}
	v, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
		JWKSURL: newKeyServer(t).URL, ServiceAudience: serviceAudience, IAPJWKSURL: iapKS.URL,
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, aud := range []any{iapAudience, "", nil} {
		c := iapClaimsFor(t, humanEmail)
		if aud == nil {
			delete(c, "aud")
		} else {
			c["aud"] = aud
		}
		_, err := v.VerifyRelayed(context.Background(), iap.sign(t, c))
		wantStatus(t, err, 401)
	}
	if n := iapKS.fetchCount(); n != 0 {
		t.Fatalf("IAP's keys were fetched %d times with no audience configured", n)
	}
}

// IAP's keys are fetched from IAP's own key URL, kept apart from Google's, and refetched at most
// once a minute however many unknown key ids arrive.
func TestIAPKeysRefetchAtMostOnceAMinute(t *testing.T) {
	k1, k2 := newIAPSigner(t, "iap-1"), newIAPSigner(t, "iap-2")
	ks, iapKS := newKeyServer(t, newSigner(t, "g1")), newKeyServerOf(t, k1.public())
	clock := newTestClock()
	v := relayVerifier(t, ks, iapKS, clock.now)
	ctx := context.Background()
	if _, err := v.VerifyRelayed(ctx, k1.sign(t, iapClaimsFor(t, humanEmail))); err != nil {
		t.Fatal(err)
	}
	forged := make([]string, 20)
	for i := range forged {
		forged[i] = newIAPSigner(t, fmt.Sprintf("forged-%d", i)).sign(t, iapClaimsFor(t, humanEmail))
	}
	burst := func() {
		var wg sync.WaitGroup
		for _, raw := range forged {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := v.VerifyRelayed(ctx, raw); err == nil {
					t.Error("an assertion signed with an unpublished key was accepted")
				}
			}()
		}
		wg.Wait()
	}
	clock.advance(30 * time.Second)
	burst()
	if n := iapKS.fetchCount(); n != 1 {
		t.Fatalf("within the first fetch's minute: %d fetches, want 1", n)
	}
	iapKS.addKey(k2.public())
	clock.advance(31 * time.Second)
	if _, err := v.VerifyRelayed(ctx, k2.sign(t, iapClaimsFor(t, humanEmail))); err != nil {
		t.Fatalf("a rotated-in IAP key, a minute on: %v", err)
	}
	if n := iapKS.fetchCount(); n != 2 {
		t.Fatalf("a minute later: %d fetches, want 2", n)
	}
	if n := ks.fetchCount(); n != 0 {
		t.Fatalf("Google's key server was asked %d times for IAP's keys", n)
	}
}

// IAP's key URL is https, as Google's is.
func TestTheIAPKeyURLMustBeHTTPS(t *testing.T) {
	ids, err := callbackapi.LoadIdentityMap([]byte(httpMap))
	if err != nil {
		t.Fatal(err)
	}
	for u, ok := range map[string]bool{
		"":                                  true, // IAP's, over https
		callbackapi.IAPJWKSURL:              true,
		"http://127.0.0.1:8080/iap":         true,
		"http://www.gstatic.com/iap/verify": false,
		"https://user:pw@keys.example/iap":  false,
	} {
		_, err := callbackapi.NewVerifier(context.Background(), callbackapi.VerifierConfig{
			ServiceAudience: serviceAudience, IAPAudience: iapAudience, IAPJWKSURL: u,
		}, ids)
		if (err == nil) != ok {
			t.Errorf("IAP key URL %q: %v, want accepted %v", u, err, ok)
		}
	}
	if callbackapi.IAPJWKSURL != "https://www.gstatic.com/iap/verify/public_key-jwk" {
		t.Fatalf("IAP's key URL is %s", callbackapi.IAPJWKSURL)
	}
}

// A person's own Google ID token is refused for every audience: a person acts only through the
// viewer (red team R3; D20).
func TestAPersonsOwnTokenIsRefusedForAnyAudience(t *testing.T) {
	k := newSigner(t, "k1")
	v := relayVerifier(t, newKeyServer(t, k), newKeyServerOf(t), nil)
	for _, aud := range []any{serviceAudience, humanAudience, "32555940559.apps.googleusercontent.com", iapAudience,
		[]string{serviceAudience, humanAudience}} {
		_, err := v.Verify(context.Background(), k.sign(t, claimsFor(humanEmail, aud)))
		wantStatus(t, err, 401)
	}
}

// --- the relay over HTTP --------------------------------------------------------------------------

// The viewer relaying a person creates a ticket, makes a transition and parks, each as that person:
// the event's actor is the human and its actor id the person's email.
func TestHTTPRelayActsAsThePerson(t *testing.T) {
	a := newAPI(t)
	st, b := a.do(call{method: "POST", path: "/v1/tickets", as: humanEmail, key: newRequestID(),
		body: map[string]any{"project": "foreman", "title": "from the viewer", "acceptance_criteria": oneAC}})
	wantHTTP(t, st, 201, b)
	created := int64(b["ticket_id"].(float64))
	if b["state"] != string(sReady) {
		t.Fatalf("created %v, want ready (criteria given)", b)
	}

	esc := seed(t, a.conn, fixture{state: sEscalated, attempts: 1})
	st, b = a.do(call{method: "PUT", path: fmt.Sprintf("/v1/tickets/%d/parking", esc), as: humanEmail,
		key: newRequestID(), body: map[string]any{"parked": true, "reason": "deciding later", "escalated_at": fixtureEscalatedAt}})
	wantHTTP(t, st, 200, b)
	parked := lastEvent(t, a.conn, esc)

	st, b = a.transition(humanEmail, esc, sEscalated, sReady)
	wantHTTP(t, st, 200, b)
	moved := lastEvent(t, a.conn, esc)

	var createdBy event
	if err := a.conn.QueryRow(`SELECT actor, actor_id FROM ticket_events WHERE ticket_id = $1`, created).
		Scan(&createdBy.Actor, &createdBy.ActorID); err != nil {
		t.Fatal(err)
	}
	for name, ev := range map[string]event{"create": createdBy, "park": parked, "transition": moved} {
		if ev.Actor != string(callbackapi.RoleHuman) || ev.ActorID != humanEmail {
			t.Errorf("%s recorded actor %s %s, want human %s", name, ev.Actor, ev.ActorID, humanEmail)
		}
	}
	if n := count(t, a.conn, `SELECT count(*) FROM api_requests WHERE caller = $1`, viewerEmail); n != 0 {
		t.Fatalf("%d requests recorded as the viewer's own", n)
	}
}

// What the relay refuses, with nothing changed.
func TestHTTPRelayRefusals(t *testing.T) {
	a := newAPI(t)
	esc := seed(t, a.conn, fixture{state: sEscalated, attempts: 1})
	work := seed(t, a.conn, fixture{state: sInProgress, attempts: 1})
	ready := seed(t, a.conn, fixture{state: sReady})
	before, workBefore := snapshot(t, a.conn, esc), snapshot(t, a.conn, work)
	viewerToken, assertion := a.tokenFor(viewerEmail), a.assertionFor(humanEmail)
	escBody := map[string]any{"from": sEscalated, "to": sReady}
	escPath := fmt.Sprintf("/v1/tickets/%d/transitions", esc)

	// A refusal for the route says so: the relay's mark refuses before the engine's own rules,
	// which would refuse a person heartbeating or decomposing too.
	const routeRefusal = "relays a person only"
	cases := []struct {
		name  string
		c     call
		want  int
		cause string // a fragment of the error, where the status alone does not say who refused
	}{
		// The viewer alone is nobody.
		{"the viewer without an assertion, creating", call{method: "POST", path: "/v1/tickets", token: viewerToken,
			body: map[string]any{"project": "foreman", "title": "x"}}, 401, "exactly one IAP assertion"},
		{"the viewer without an assertion, deciding", call{method: "POST", path: escPath, token: viewerToken, body: escBody}, 401,
			"exactly one IAP assertion"},
		{"the viewer without an assertion, parking", call{method: "PUT", path: fmt.Sprintf("/v1/tickets/%d/parking", esc),
			token: viewerToken, body: map[string]any{"parked": true, "reason": "r"}}, 401, "exactly one IAP assertion"},
		{"the viewer with an invalid assertion", call{method: "POST", path: escPath, token: viewerToken,
			assertion: "not.an.assertion", body: escBody}, 401, "invalid IAP assertion"},
		{"the viewer with two assertions", call{method: "POST", path: escPath, token: viewerToken, assertion: assertion,
			extraAssertion: assertion, body: escBody}, 401, "exactly one IAP assertion"},
		// A relayed person reaches only the three routes.
		{"relayed, promoting", call{method: "POST", path: "/v1/promotions", token: viewerToken, assertion: assertion,
			body: map[string]any{"component": "dispatcher", "image_digest": digest('a'), "git_sha": gitSHA('1')}}, 403, routeRefusal},
		{"relayed, heartbeating", call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/heartbeat", work),
			token: viewerToken, assertion: assertion, claim: liveToken}, 403, routeRefusal},
		{"relayed, registering an artifact", call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/artifacts", work),
			token: viewerToken, assertion: assertion, claim: liveToken,
			body: map[string]any{"kind": "log", "gcs_path": fmt.Sprintf("foreman/%d/1/x", work)}}, 403, routeRefusal},
		{"relayed, decomposing", call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/decompose", ready),
			token: viewerToken, assertion: assertion,
			body: map[string]any{"children": []map[string]any{{"title": "c", "acceptance_criteria": oneAC}}}}, 403, routeRefusal},
		{"relayed, reporting a rate limit", call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/rate-limit", work),
			token: viewerToken, assertion: assertion, claim: liveToken,
			body: map[string]any{"reset_at": time.Now().Add(time.Hour)}}, 403, routeRefusal},
		// Nobody else may relay.
		{"a dev runner sending an assertion", call{method: "POST", path: escPath, token: a.tokenFor(devEmail),
			assertion: assertion, body: escBody}, 403, "only the viewer relays"},
		{"the dispatcher sending an assertion", call{method: "POST", path: "/v1/tickets", token: a.tokenFor(dispatcherCaller.Email),
			assertion: assertion, body: map[string]any{"project": "foreman", "title": "x"}}, 403, "only the viewer relays"},
		{"a runner sending an empty assertion header", call{method: "POST", path: fmt.Sprintf("/v1/tickets/%d/heartbeat", work),
			token: a.tokenFor(devEmail), assertion: "", emptyAssertion: true, claim: liveToken}, 403, "only the viewer relays"},
		// A person's own token, with no viewer.
		{"a person's own token", call{method: "POST", path: "/v1/tickets",
			token: a.key.sign(t, claimsFor(humanEmail, serviceAudience)), body: map[string]any{"project": "foreman", "title": "x"}},
			401, "own token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.c.key = newRequestID()
			st, b := a.do(c.c)
			wantHTTP(t, st, c.want, b)
			if !strings.Contains(fmt.Sprint(b["error"]), c.cause) {
				t.Fatalf("refused for %q, want a refusal naming %q", b["error"], c.cause)
			}
		})
	}
	assertUnchanged(t, a.conn, esc, before, 0, 0)
	if after := snapshot(t, a.conn, work); fmt.Sprint(after) != fmt.Sprint(workBefore) {
		t.Fatalf("the in-progress ticket changed: %v", after)
	}
	if n := count(t, a.conn, `SELECT count(*) FROM tickets`); n != 3 {
		t.Fatalf("%d tickets, want the three seeded", n)
	}
}

// The engine refuses the viewer as a caller at every entry point, so a viewer caller that slipped
// past the HTTP layer could do nothing as itself (red team R4).
func TestEngineRefusesTheViewerAsACaller(t *testing.T) {
	conn := fresh(t)
	e := newEngine(nil)
	ctx := context.Background()
	viewer := callbackapi.Caller{Email: viewerEmail, Role: callbackapi.RoleViewer}
	esc := seed(t, conn, fixture{state: sEscalated, attempts: 1})
	work := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	ready := seed(t, conn, fixture{state: sReady})
	path := func(id int64, op string) string { return fmt.Sprintf("/v1/tickets/%d/%s", id, op) }
	for name, call := range map[string]func(tx *sql.Tx) error{
		"transition": func(tx *sql.Tx) error {
			_, err := e.Transition(ctx, tx, request(esc, sEscalated, sReady, viewer, chHTTP))
			return err
		},
		"create": func(tx *sql.Tx) error {
			_, err := e.Create(ctx, tx, callbackapi.CreateRequest{Caller: viewer, Project: "foreman", Title: "x",
				RequestID: newRequestID(), Method: "POST", Path: "/v1/tickets"})
			return err
		},
		"park": func(tx *sql.Tx) error {
			_, err := e.Park(ctx, tx, callbackapi.ParkingRequest{TicketID: esc, Caller: viewer, Parked: true, Reason: "r",
				RequestID: newRequestID(), Method: "PUT", Path: path(esc, "parking")})
			return err
		},
		"heartbeat": func(tx *sql.Tx) error {
			_, err := e.Heartbeat(ctx, tx, callbackapi.HeartbeatRequest{TicketID: work, Caller: viewer, ClaimToken: liveToken,
				RequestID: newRequestID(), Method: "POST", Path: path(work, "heartbeat")})
			return err
		},
		"artifact": func(tx *sql.Tx) error {
			_, err := e.RegisterArtifact(ctx, tx, callbackapi.ArtifactRequest{TicketID: work, Caller: viewer, Kind: "log",
				GCSPath: fmt.Sprintf("foreman/%d/1/x", work), ClaimToken: liveToken, RequestID: newRequestID(),
				Method: "POST", Path: path(work, "artifacts")})
			return err
		},
		"decompose": func(tx *sql.Tx) error {
			_, err := e.Decompose(ctx, tx, callbackapi.DecomposeRequest{TicketID: ready, Caller: viewer,
				Children:  []callbackapi.ChildSpec{{Title: "c", AcceptanceCriteria: oneAC}},
				RequestID: newRequestID(), Method: "POST", Path: path(ready, "decompose")})
			return err
		},
		"promote": func(tx *sql.Tx) error {
			_, err := e.Promote(ctx, tx, callbackapi.PromotionRequest{Caller: viewer, Component: "dispatcher",
				ImageDigest: digest('a'), GitSHA: gitSHA('1'), RequestID: newRequestID(), Method: "POST", Path: "/v1/promotions"})
			return err
		},
		"rate limit": func(tx *sql.Tx) error {
			_, err := e.RateLimit(ctx, tx, callbackapi.RateLimitRequest{TicketID: work, Caller: viewer, ClaimToken: liveToken,
				ResetAt: time.Now().Add(time.Hour), RequestID: newRequestID(), Method: "POST", Path: path(work, "rate-limit")})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := callbackapi.BeginTx(ctx, conn)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = call(tx)
			wantStatus(t, err, 403)
			// The refusal is the engine's rule for the viewer, not a row's: the rows would refuse it too.
			if !strings.Contains(err.Error(), "viewer acts only") {
				t.Fatalf("refused for %v, want the viewer's own refusal", err)
			}
		})
	}
	if n := count(t, conn, `SELECT count(*) FROM ticket_events`); n != 0 {
		t.Fatalf("%d events written for the viewer", n)
	}
}
