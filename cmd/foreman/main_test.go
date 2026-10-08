package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun/cloudruntest"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// `foreman dispatch` makes one tick against DATABASE_URL, with the recording launcher writing each
// launch request as a JSON line to standard output (P04 T6). QA work needs no ls-remote, so the
// test reaches no network.
func TestDispatchRunsOneTick(t *testing.T) {
	url := testdb.Empty(t)
	t.Setenv("DATABASE_URL", url)
	ctx := context.Background()
	var out, errs bytes.Buffer
	if code := run(ctx, []string{"migrate", "up"}, &out, &errs); code != 0 {
		t.Fatalf("migrate up: exit %d\n%s", code, errs.String())
	}
	conn, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var id int64
	if err := conn.QueryRow(`
		INSERT INTO tickets (project_id, title, state, attempt_count, acceptance_criteria, head_sha)
		VALUES ('foreman', 'reviewed', 'awaiting_review', 1, '[{"id":"AC1","text":"it works"}]',
		  '4444444444444444444444444444444444444444') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errs.Reset()
	if code := run(ctx, []string{"dispatch"}, &out, &errs); code != 0 {
		t.Fatalf("dispatch: exit %d\n%s", code, errs.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var req dispatcher.LaunchRequest
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &req) != nil {
		t.Fatalf("standard output %q, want one launch request", out.String())
	}
	if req.TicketID != id || req.Role != "qa" || req.Model != "claude-opus-5-5" || req.ClaimToken == "" {
		t.Fatalf("launch request %+v", req)
	}
	if !strings.Contains(errs.String(), "dispatch tick") {
		t.Fatalf("the tick logged nothing: %s", errs.String())
	}
	var state string
	var launchID sql.NullString
	if err := conn.QueryRow(`SELECT t.state, a.launch_id FROM tickets t JOIN attempts a ON a.ticket_id = t.id WHERE t.id = $1`, id).
		Scan(&state, &launchID); err != nil {
		t.Fatal(err)
	}
	if state != "in_qa" || launchID.String != "recorded-1" {
		t.Fatalf("ticket %s, launch id %v", state, launchID)
	}
}

const (
	sandboxJob  = "projects/your-project-id/locations/us-central1/jobs/echo-runner-sandbox"
	callbackURL = "https://callback-api-123456789012.us-central1.run.app"
	stubSHA     = "0123456789abcdef0123456789abcdef01234567"
)

// cloudRunEnv points `foreman dispatch` at fakes of GitHub and Google's APIs through its
// environment, as the deployed job is configured (P05 T3), with the App's id and key in the fake
// Secret Manager.
func cloudRunEnv(t *testing.T) (*cloudruntest.GCP, *cloudruntest.GitHub) {
	t.Helper()
	gcp := cloudruntest.NewGCP(t)
	gh := cloudruntest.NewGitHub(t)
	gcp.SetSecret("github-app-id", []byte("12345"))
	gcp.SetSecret("github-app-key", cloudruntest.AppKey(t))
	for k, v := range map[string]string{
		"FOREMAN_LAUNCHER": "cloudrun",
		"FOREMAN_RUNNER_JOBS": `[{"role": "dev", "project": "sandbox", "job": "` + sandboxJob + `",
			"account": "dev-sandbox@your-project-id.iam.gserviceaccount.com",
			"token_secret": "projects/your-project-id/secrets/github-token-dev-sandbox"}]`,
		"FOREMAN_CALLBACK_URL":          callbackURL,
		"FOREMAN_CALLBACK_AUDIENCE":     callbackURL,
		"FOREMAN_GITHUB_APP_ID_SECRET":  "projects/your-project-id/secrets/github-app-id/versions/latest",
		"FOREMAN_GITHUB_APP_KEY_SECRET": "projects/your-project-id/secrets/github-app-key/versions/latest",
		"GCE_METADATA_HOST":             gcp.MetadataHost(),
		"FOREMAN_SECRETMANAGER_API":     gcp.URL(),
		"FOREMAN_RUN_API":               gcp.URL(),
		"FOREMAN_GITHUB_API":            gh.URL(),
	} {
		t.Setenv(k, v)
	}
	return gcp, gh
}

// stubGitOnPath puts first on PATH a git that answers `version`, records the arguments and
// environment of every other call in dir, and lists stubSHA as refs/heads/main.
func stubGitOnPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = version ] && { echo 'git version 2.47.3'; exit 0; }; done\n" +
		"printf '%s\\n' \"$@\" > " + filepath.Join(dir, "args") + "\nenv > " + filepath.Join(dir, "env") + "\n" +
		"printf '%s\\trefs/heads/main\\n' " + stubSHA + "\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// Under FOREMAN_LAUNCHER=cloudrun, `foreman dispatch` reads the sandbox's head through the github
// Remote, with a read token minted from the App's credentials in Secret Manager, and launches the
// claim as an execution of the sandbox's job, its write token handed over as version 1 (P05 T3).
func TestDispatchUnderCloudRun(t *testing.T) {
	_, conn := migrated(t)
	ctx := context.Background()
	var out, errs bytes.Buffer
	if code := run(ctx, []string{"project", "activate", "sandbox"}, &out, &errs); code != 0 {
		t.Fatalf("activate sandbox: exit %d\n%s", code, errs.String())
	}
	var id int64
	if err := conn.QueryRow(`INSERT INTO tickets (project_id, title, state, acceptance_criteria)
		VALUES ('sandbox', 'echo', 'ready', '[{"id":"AC1","text":"it echoes"}]') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	gcp, gh := cloudRunEnv(t)
	dir := stubGitOnPath(t)

	out.Reset()
	errs.Reset()
	if code := run(ctx, []string{"dispatch"}, &out, &errs); code != 0 {
		t.Fatalf("dispatch: exit %d\n%s", code, errs.String())
	}
	args, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatalf("git was never asked for the head: %v\n%s", err, errs.String())
	}
	if !strings.Contains(string(args), "https://github.com/your-org/sandbox-repo\nrefs/heads/main") {
		t.Fatalf("git's arguments:\n%s", args)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + cloudruntest.TokenFor(1)))
	if !strings.Contains(string(env), "GIT_CONFIG_VALUE_0=Authorization: Basic "+basic+"\n") {
		t.Fatalf("git did not get the read token in its environment:\n%s", env)
	}
	if got := gh.Asked(); len(got) != 2 || got[0] != "read" || got[1] != "write" {
		t.Fatalf("tokens minted with contents %v, want read (the head) then write (the runner)", got)
	}
	runs := gcp.Runs()
	if len(runs) != 1 || runs[0].Job != sandboxJob || runs[0].Env["FOREMAN_TOKEN_VERSION"] != "1" {
		t.Fatalf("runs %+v", runs)
	}
	if data, _, _ := gcp.Version("github-token-dev-sandbox", 1); string(data) != cloudruntest.TokenFor(2) {
		t.Fatalf("version 1 holds %q, want the write token", data)
	}
	var state, base string
	var launchID sql.NullString
	if err := conn.QueryRow(`SELECT t.state, t.base_sha, a.launch_id FROM tickets t JOIN attempts a ON a.ticket_id = t.id WHERE t.id = $1`, id).
		Scan(&state, &base, &launchID); err != nil {
		t.Fatal(err)
	}
	if state != "claimed" || base != stubSHA || launchID.String != sandboxJob+"/executions/ex-1" {
		t.Fatalf("ticket %s at %s, launch id %v", state, base, launchID)
	}
	if out.Len() != 0 {
		t.Fatalf("the recording launcher wrote: %s", out.String())
	}
	for n := 1; n <= 2; n++ {
		if leaks := cloudruntest.Leaks(errs.String(), cloudruntest.TokenFor(n)); len(leaks) > 0 {
			t.Fatalf("the logs hold token %d: %v", n, leaks)
		}
	}
}

// A launcher that is misconfigured, or unknown, stops the command before any tick.
func TestDispatchRefusesABadLauncher(t *testing.T) {
	_, conn := migrated(t)
	ctx := context.Background()
	if _, err := conn.Exec(`INSERT INTO tickets (project_id, title, state, acceptance_criteria, head_sha, attempt_count)
		VALUES ('foreman', 'reviewed', 'awaiting_review', '[{"id":"AC1","text":"it works"}]', '4444444444444444444444444444444444444444', 1)`); err != nil {
		t.Fatal(err)
	}
	cloudRunEnv(t)
	for name, env := range map[string][2]string{
		"no jobs":          {"FOREMAN_RUNNER_JOBS", ""},
		"an http endpoint": {"FOREMAN_RUN_API", "http://run.googleapis.com"},
		"an unknown kind":  {"FOREMAN_LAUNCHER", "kubernetes"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			var out, errs bytes.Buffer
			if code := run(ctx, []string{"dispatch"}, &out, &errs); code != 2 {
				t.Fatalf("exit %d, want 2\n%s", code, errs.String())
			}
		})
	}
	var n int
	if err := conn.QueryRow(`SELECT count(*) FROM attempts`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d attempts (%v): a tick ran", n, err)
	}
}

// The command links none of the tests' fakes.
func TestTheCommandLinksNoFake(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if .Module}}{{if .Module.Main}}{{.ImportPath}}{{end}}{{end}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	pkgs := strings.Fields(string(out))
	if len(pkgs) < 3 {
		t.Fatalf("go list found only %v", pkgs)
	}
	for _, p := range pkgs {
		base := p[strings.LastIndex(p, "/")+1:]
		if strings.HasSuffix(base, "test") || base == "testdb" || base == "gitfixture" {
			t.Errorf("the command links %s", p)
		}
	}
	if !slices.Contains(pkgs, "github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun") {
		t.Errorf("the command does not link the Cloud Run launcher: %v", pkgs)
	}
}

// lockedBuffer is a log sink the test reads while the command writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// callbackAPIEnv is the callback API's least configuration, on a free local port.
func callbackAPIEnv(t *testing.T) {
	t.Helper()
	migrated(t)
	t.Setenv("FOREMAN_SERVICE_AUDIENCE", callbackURL)
	t.Setenv("FOREMAN_ADDR", "127.0.0.1:0")
}

// `foreman callback-api` refuses a key URL that is not https, before it listens (P05 T4;
// [P02/review]).
func TestCallbackAPIRefusesAnHTTPKeyURL(t *testing.T) {
	callbackAPIEnv(t)
	t.Setenv("FOREMAN_JWKS_URL", "http://www.googleapis.com/oauth2/v3/certs")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out, errs bytes.Buffer
	if code := run(ctx, []string{"callback-api"}, &out, &errs); code != 2 {
		t.Fatalf("exit %d, want 2\n%s", code, errs.String())
	}
	if strings.Contains(errs.String(), "listening") || !strings.Contains(errs.String(), "https") {
		t.Fatalf("the refusal:\n%s", errs.String())
	}
}

// `foreman callback-api` refuses an IAP key URL that is not https, before it listens (P06 T3).
func TestCallbackAPIRefusesAnHTTPIAPKeyURL(t *testing.T) {
	callbackAPIEnv(t)
	t.Setenv("FOREMAN_IAP_AUDIENCE", "/projects/123456789012/locations/us-central1/services/viewer")
	t.Setenv("FOREMAN_IAP_JWKS_URL", "http://www.gstatic.com/iap/verify/public_key-jwk")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out, errs bytes.Buffer
	if code := run(ctx, []string{"callback-api"}, &out, &errs); code != 2 {
		t.Fatalf("exit %d, want 2\n%s", code, errs.String())
	}
	if strings.Contains(errs.String(), "listening") || !strings.Contains(errs.String(), "https") {
		t.Fatalf("the refusal:\n%s", errs.String())
	}
}

// `foreman callback-api` logs the viewer's IAP audience it accepts relayed people for; without
// FOREMAN_IAP_AUDIENCE it still serves the runners, and warns that no person can act (P06 T3).
func TestCallbackAPILogsWhoMayRelay(t *testing.T) {
	for name, aud := range map[string]string{
		"configured": "/projects/123456789012/locations/us-central1/services/viewer",
		"unset":      "",
	} {
		t.Run(name, func(t *testing.T) {
			callbackAPIEnv(t)
			t.Setenv("FOREMAN_IAP_AUDIENCE", aud)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			errs := &lockedBuffer{}
			done := make(chan int, 1)
			go func() {
				var out bytes.Buffer
				done <- run(ctx, []string{"callback-api"}, &out, errs)
			}()
			for deadline := time.Now().Add(10 * time.Second); !strings.Contains(errs.String(), "callback api listening"); {
				if time.Now().After(deadline) {
					t.Fatalf("the API never listened:\n%s", errs.String())
				}
				time.Sleep(20 * time.Millisecond)
			}
			cancel()
			if code := <-done; code != 0 {
				t.Fatalf("exit %d\n%s", code, errs.String())
			}
			var listening struct {
				IAPAudience *string `json:"iap_audience"`
			}
			warned := false
			for _, l := range strings.Split(strings.TrimSpace(errs.String()), "\n") {
				var line struct{ Level, Msg string }
				json.Unmarshal([]byte(l), &line)
				if line.Msg == "callback api listening" {
					json.Unmarshal([]byte(l), &listening)
				}
				if line.Level == "WARN" && strings.Contains(line.Msg, "FOREMAN_IAP_AUDIENCE") {
					warned = true
				}
			}
			if listening.IAPAudience == nil || *listening.IAPAudience != aud {
				t.Fatalf("the listening line's iap_audience, want %q:\n%s", aud, errs.String())
			}
			if warned != (aud == "") {
				t.Fatalf("warned %v with the audience %q:\n%s", warned, aud, errs.String())
			}
			if strings.Contains(errs.String(), "human_audiences") {
				t.Fatalf("a human audience is still reported:\n%s", errs.String())
			}
		})
	}
}

// keyServer publishes keys as Google's and IAP's key URLs do, on loopback.
func keyServer(t *testing.T, keys ...jose.JSONWebKey) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// signJWT signs claims with key under kid.
func signJWT(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// `foreman callback-api`, as deployed, takes a person relayed by the viewer: the viewer's own
// Google token, and the person's IAP assertion for FOREMAN_IAP_AUDIENCE, verified with
// FOREMAN_IAP_JWKS_URL's keys. The ticket is created as the person (P06 T3).
func TestCallbackAPIAcceptsARelayedPerson(t *testing.T) {
	_, conn := migrated(t)
	google, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iap, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const iapAudience = "/projects/123456789012/locations/us-central1/services/viewer"
	t.Setenv("FOREMAN_SERVICE_AUDIENCE", callbackURL)
	t.Setenv("FOREMAN_JWKS_URL", keyServer(t, jose.JSONWebKey{Key: &google.PublicKey, KeyID: "g", Algorithm: "RS256", Use: "sig"}))
	t.Setenv("FOREMAN_IAP_JWKS_URL", keyServer(t, jose.JSONWebKey{Key: &iap.PublicKey, KeyID: "i", Algorithm: "ES256", Use: "sig"}))
	t.Setenv("FOREMAN_IAP_AUDIENCE", iapAudience)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	t.Setenv("FOREMAN_ADDR", addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		var out bytes.Buffer
		done <- run(ctx, []string{"callback-api"}, &out, errs)
	}()
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(errs.String(), "callback api listening"); {
		if time.Now().After(deadline) {
			t.Fatalf("the API never listened:\n%s", errs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	now := time.Now()
	viewerToken := signJWT(t, jose.RS256, google, "g", map[string]any{
		"iss": "https://accounts.google.com", "aud": callbackURL, "sub": "1",
		"email": "viewer@your-project-id.iam.gserviceaccount.com", "email_verified": true,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	assertion := signJWT(t, jose.ES256, iap, "i", map[string]any{
		"iss": "https://cloud.google.com/iap", "aud": iapAudience, "azp": iapAudience, "sub": "accounts.google.com:1",
		"email": operator, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	req, err := http.NewRequest("POST", "http://"+addr+"/v1/tickets",
		strings.NewReader(`{"project": "foreman", "title": "relayed from the viewer"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	req.Header.Set("X-Foreman-IAP-Assertion", assertion)
	req.Header.Set("Idempotency-Key", newRequestID())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s\n%s", resp.StatusCode, body, errs.String())
	}
	var actor string
	if err := conn.QueryRow(`SELECT actor_id FROM ticket_events ORDER BY id DESC LIMIT 1`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != operator {
		t.Fatalf("the ticket was created by %q, want the relayed person %s", actor, operator)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d\n%s", code, errs.String())
	}
}

// At startup `foreman callback-api` compares the host's clock with the database's and logs the
// skew, before it listens (P05 T4; [P02/review2]).
func TestCallbackAPIChecksTheClockAtStartup(t *testing.T) {
	callbackAPIEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		var out bytes.Buffer
		done <- run(ctx, []string{"callback-api"}, &out, errs)
	}()
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(errs.String(), "callback api listening"); {
		if time.Now().After(deadline) {
			t.Fatalf("the API never listened:\n%s", errs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d\n%s", code, errs.String())
	}
	clock, listening := -1, -1
	for i, l := range strings.Split(strings.TrimSpace(errs.String()), "\n") {
		var line struct {
			Level string   `json:"level"`
			Msg   string   `json:"msg"`
			Skew  *float64 `json:"skew_seconds"`
		}
		if json.Unmarshal([]byte(l), &line) != nil {
			continue
		}
		switch {
		case strings.Contains(line.Msg, "clock") && line.Skew != nil && line.Level == "INFO":
			clock = i
		case line.Msg == "callback api listening":
			listening = i
		}
	}
	if clock < 0 || clock > listening {
		t.Fatalf("no clock check logged before listening:\n%s", errs.String())
	}
}

const operator = "operator@example.com" // the identity map's human

// `foreman ticket create` is gone: a person creates tickets from the viewer, as themselves (P06 T8).
func TestTicketCreateIsRetired(t *testing.T) {
	var out, errs bytes.Buffer
	code := run(context.Background(), []string{"ticket", "create", "--as", operator, "--project", "sandbox", "--title", "t"}, &out, &errs)
	if code != 2 || strings.Contains(errs.String(), "ticket create") {
		t.Fatalf("exit %d, want 2 and a usage that does not name it:\n%s", code, errs.String())
	}
}

// newRequestID is a random (version 4) UUID, the form the API takes as an idempotency key.
func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func TestDispatchNeedsADatabase(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"dispatch"}, &out, &errs); code != 2 {
		t.Fatalf("exit %d without DATABASE_URL, want 2", code)
	}
	if code := run(context.Background(), []string{"dispatch", "now"}, &out, &errs); code != 2 {
		t.Fatalf("exit %d with an extra argument, want 2", code)
	}
}

func TestUsageNamesDispatch(t *testing.T) {
	var out, errs bytes.Buffer
	run(context.Background(), nil, &out, &errs)
	for _, c := range []string{"dispatch", "viewer"} {
		if !strings.Contains(errs.String(), c) {
			t.Fatalf("usage does not name %s:\n%s", c, errs.String())
		}
	}
	if strings.Contains(errs.String(), "ticket") {
		t.Fatalf("usage names the retired ticket create:\n%s", errs.String())
	}
}

// migrated returns the URL of a fresh, migrated database, and a connection to it.
func migrated(t *testing.T) (string, *sql.DB) {
	t.Helper()
	url := testdb.Empty(t)
	t.Setenv("DATABASE_URL", url)
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"migrate", "up"}, &out, &errs); code != 0 {
		t.Fatalf("migrate up: exit %d\n%s", code, errs.String())
	}
	conn, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return url, conn
}

// `foreman project activate <id>` makes that project the only active one (P05 D18).
func TestProjectActivate(t *testing.T) {
	_, conn := migrated(t)
	ctx := context.Background()
	var out, errs bytes.Buffer
	if code := run(ctx, []string{"project", "activate", "sandbox"}, &out, &errs); code != 0 {
		t.Fatalf("activate sandbox: exit %d\n%s", code, errs.String())
	}
	var active string
	if err := conn.QueryRow(`SELECT string_agg(id, ',') FROM projects WHERE is_active`).Scan(&active); err != nil || active != "sandbox" {
		t.Fatalf("active projects %q (%v), want sandbox", active, err)
	}
	if !strings.Contains(errs.String(), "sandbox") {
		t.Fatalf("the activation was not logged: %s", errs.String())
	}
	if code := run(ctx, []string{"project", "activate", "nowhere"}, &out, &errs); code != 1 {
		t.Fatalf("activate an unknown project: exit %d, want 1", code)
	}
	for _, args := range [][]string{{"project", "activate"}, {"project", "activate", "a", "b"}, {"project"}} {
		if code := run(ctx, args, &out, &errs); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
}

// `foreman db rights` prints what the connected user can do, as one JSON object, and changes
// nothing.
func TestDBRights(t *testing.T) {
	migrated(t)
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"db", "rights"}, &out, &errs); code != 0 {
		t.Fatalf("db rights: exit %d\n%s", code, errs.String())
	}
	var r map[string]any
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("output %q is not one JSON object: %v", out.String(), err)
	}
	for _, k := range []string{"user", "cloudsqlsuperuser", "createrole", "createdb", "create_table_refused"} {
		if _, ok := r[k]; !ok {
			t.Errorf("the report lacks %q: %s", k, out.String())
		}
	}
}

const (
	viewerOrigin      = "https://viewer-123456789012.us-central1.run.app"
	viewerIAPAudience = "/projects/123456789012/locations/us-central1/services/viewer"
)

// viewerSecret names a secret's latest version in the fake Secret Manager.
func viewerSecret(short string) string {
	return "projects/" + cloudruntest.ProjectNumber + "/secrets/" + short + "/versions/latest"
}

// viewerEnv configures `foreman viewer` as it is deployed: its own database user, the metadata
// server and Secret Manager (the CSRF key and the read-only App's id and key), IAP's keys and
// audience, the callback API, its own origins and the bucket. It returns the database's owner, to
// seed, the fake GCP, and IAP's key, to sign assertions.
func viewerEnv(t *testing.T) (*sql.DB, *cloudruntest.GCP, *ecdsa.PrivateKey) {
	t.Helper()
	owner, url := testdb.NewViewerURL(t)
	gcp := cloudruntest.NewGCP(t)
	gcp.SetSecret("viewer-csrf-key", []byte("a csrf key of thirty-two bytes!!"))
	gcp.SetSecret("viewer-github-app-id", []byte("67890"))
	gcp.SetSecret("viewer-github-app-key", cloudruntest.AppKey(t))
	iap, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"DATABASE_URL":                  url,
		"FOREMAN_ADDR":                  "127.0.0.1:0",
		"FOREMAN_IAP_AUDIENCE":          viewerIAPAudience,
		"FOREMAN_IAP_JWKS_URL":          keyServer(t, jose.JSONWebKey{Key: &iap.PublicKey, KeyID: "i", Algorithm: "ES256", Use: "sig"}),
		"FOREMAN_CALLBACK_URL":          callbackURL,
		"FOREMAN_ORIGINS":               viewerOrigin + ",https://viewer-abcdefghij-uc.a.run.app",
		"FOREMAN_ARTIFACTS_BUCKET":      "your-project-id-artifacts",
		"FOREMAN_CSRF_KEY_SECRET":       viewerSecret("viewer-csrf-key"),
		"FOREMAN_GITHUB_APP_ID_SECRET":  viewerSecret("viewer-github-app-id"),
		"FOREMAN_GITHUB_APP_KEY_SECRET": viewerSecret("viewer-github-app-key"),
		"GCE_METADATA_HOST":             gcp.MetadataHost(),
		"FOREMAN_SECRETMANAGER_API":     gcp.URL(),
	} {
		t.Setenv(k, v)
	}
	return owner, gcp, iap
}

// `foreman viewer`, as deployed: it checks its database user's rights and logs them before it
// listens (P06 D7), and serves the pages to a person IAP vouches for, and nothing to anyone else.
func TestViewerServes(t *testing.T) {
	owner, _, iap := viewerEnv(t)
	if _, err := owner.Exec(`INSERT INTO tickets (project_id, title, state) VALUES ('sandbox', 'seen through the viewer', 'draft')`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		var out bytes.Buffer
		done <- run(ctx, []string{"viewer"}, &out, errs)
	}()
	var addr string
	rights, listening := -1, -1
	for deadline := time.Now().Add(10 * time.Second); addr == ""; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the viewer never listened:\n%s", errs.String())
		}
		for i, l := range strings.Split(errs.String(), "\n") {
			var line struct {
				Msg, Addr, User string
				Reads, Writes   []string
			}
			if json.Unmarshal([]byte(l), &line) != nil {
				continue
			}
			switch line.Msg {
			case "viewer database rights":
				if line.User == "viewer" && len(line.Reads) == 5 && len(line.Writes) == 0 {
					rights = i
				}
			case "viewer listening":
				addr, listening = line.Addr, i
			}
		}
	}
	if rights < 0 || rights > listening {
		t.Fatalf("no rights check logged before listening:\n%s", errs.String())
	}
	now := time.Now()
	assertion := signJWT(t, jose.ES256, iap, "i", map[string]any{
		"iss": "https://cloud.google.com/iap", "aud": viewerIAPAudience, "azp": viewerIAPAudience, "sub": "accounts.google.com:1",
		"email": operator, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	get := func(path, assertion string) (int, string) {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if assertion != "" {
			req.Header.Set("X-Goog-Iap-Jwt-Assertion", assertion)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if st, body := get("/", assertion); st != http.StatusOK || !strings.Contains(body, "seen through the viewer") {
		t.Fatalf("the list: status %d:\n%s", st, body)
	}
	if st, body := get("/new", assertion); st != http.StatusOK || !strings.Contains(body, `name="csrf"`) {
		t.Fatalf("the new-ticket form: status %d:\n%s", st, body)
	}
	if st, _ := get("/", ""); st != http.StatusUnauthorized {
		t.Fatalf("without an assertion: status %d", st)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d\n%s", code, errs.String())
	}
}

// `foreman viewer` refuses to start, naming why, when its configuration is missing or wrong, or
// when its database user could write (P06 D7).
func TestViewerRefusesToStart(t *testing.T) {
	ownerURL, _ := migrated(t)
	_, gcp, _ := viewerEnv(t)
	gcp.SetSecret("short", []byte("too short"))
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no database":             {map[string]string{"DATABASE_URL": ""}, "DATABASE_URL"},
		"no IAP audience":         {map[string]string{"FOREMAN_IAP_AUDIENCE": ""}, "FOREMAN_IAP_AUDIENCE"},
		"no callback API":         {map[string]string{"FOREMAN_CALLBACK_URL": ""}, "FOREMAN_CALLBACK_URL"},
		"an http callback API":    {map[string]string{"FOREMAN_CALLBACK_URL": "http://callback.example"}, "not an https URL"},
		"no origins":              {map[string]string{"FOREMAN_ORIGINS": ""}, "FOREMAN_ORIGINS"},
		"an http origin":          {map[string]string{"FOREMAN_ORIGINS": viewerOrigin + ",http://viewer.example"}, "FOREMAN_ORIGINS"},
		"an origin with a path":   {map[string]string{"FOREMAN_ORIGINS": viewerOrigin + "/"}, "FOREMAN_ORIGINS"},
		"no bucket":               {map[string]string{"FOREMAN_ARTIFACTS_BUCKET": ""}, "FOREMAN_ARTIFACTS_BUCKET"},
		"not a secret version":    {map[string]string{"FOREMAN_CSRF_KEY_SECRET": "viewer-csrf-key"}, "FOREMAN_CSRF_KEY_SECRET"},
		"no App key":              {map[string]string{"FOREMAN_GITHUB_APP_KEY_SECRET": ""}, "FOREMAN_GITHUB_APP_KEY_SECRET"},
		"a short CSRF key":        {map[string]string{"FOREMAN_CSRF_KEY_SECRET": viewerSecret("short")}, "CSRF key"},
		"an unreadable CSRF key":  {map[string]string{"FOREMAN_CSRF_KEY_SECRET": viewerSecret("absent")}, "CSRF key"},
		"a user that can write":   {map[string]string{"DATABASE_URL": ownerURL}, "can write"},
		"a metadata host w/ path": {map[string]string{"GCE_METADATA_HOST": "metadata.example/x"}, "metadata"},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var out bytes.Buffer
			errs := &lockedBuffer{}
			if code := run(ctx, []string{"viewer"}, &out, errs); code != 2 || !strings.Contains(errs.String(), c.want) ||
				strings.Contains(errs.String(), "viewer listening") {
				t.Fatalf("exit %d, want 2 naming %s:\n%s", code, c.want, errs.String())
			}
		})
	}
}
