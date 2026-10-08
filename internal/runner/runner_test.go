package runner_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/capture/capturetest"
	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun/cloudruntest"
	"github.com/ryanymt/mercurio-project/internal/runner"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

const (
	account      = "dev-sandbox@your-project-id.iam.gserviceaccount.com"
	tokenSecret  = "projects/your-project-id/secrets/github-token-dev-sandbox"
	tokenVersion = 3
	ghToken      = "ghs_echoRunnerTestToken0123456789abcdefXYZ"
	accessToken  = "ya29.echo-runner-access-token"
	noHome       = "/nonexistent/foreman-git-home"
	bucket       = "your-project-id-artifacts"
)

var realGit = func() string {
	p, err := exec.LookPath("git")
	if err != nil {
		panic(err)
	}
	return p
}()

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// syncBuffer is an output sink safe to read while the runner writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// gitIn runs the real git (never the recording wrapper) in dir, with its own identity and no
// trace variables, and returns its trimmed output.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(realGit, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.com",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.com"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit adds a file in the work clone, commits it and pushes HEAD to ref, returning the commit.
func commit(t *testing.T, work, file, content, ref string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(work, file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, work, "add", file)
	gitIn(t, work, "commit", "--quiet", "-m", "fixture: "+file)
	gitIn(t, work, "push", "--quiet", "--force", "origin", "HEAD:"+ref)
	return gitIn(t, work, "rev-parse", "HEAD")
}

type fixedRemote string

func (r fixedRemote) LsRemote(ctx context.Context, url, branch string) (string, error) {
	return string(r), nil
}

// apiCall is one request the runner made to the callback API.
type apiCall struct {
	Path, Claim, Key, Auth string
	Body                   map[string]any
}

func (c apiCall) kind() string {
	switch {
	case strings.HasSuffix(c.Path, "/heartbeat"):
		return "heartbeat"
	case strings.HasSuffix(c.Path, "/artifacts"):
		return fmt.Sprintf("artifacts %v", c.Body["kind"])
	}
	return fmt.Sprintf("%v->%v", c.Body["from"], c.Body["to"])
}

// idServer is the metadata server and Secret Manager in one: an access token, ID tokens signed
// with a local key (the email only with format=full, as Google's metadata server does), and
// version tokenVersion of the token secret, and no other version.
type idServer struct {
	*httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	accessed []string // every Secret Manager path asked for
	idQuery  []string // every identity request's query
}

func newIDServer(t *testing.T) *idServer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &idServer{key: k}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *idServer) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: "meta", Algorithm: "RS256", Use: "sig"}}}
}

func (s *idServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	const meta = "/computeMetadata/v1/instance/service-accounts/default/"
	switch {
	case strings.HasPrefix(r.URL.Path, meta) && r.Header.Get("Metadata-Flavor") != "Google":
		http.Error(w, "no Metadata-Flavor", http.StatusForbidden)
	case r.URL.Path == meta+"token":
		fmt.Fprintf(w, `{"access_token": %q, "expires_in": 3599, "token_type": "Bearer"}`, accessToken)
	case r.URL.Path == meta+"identity":
		s.idQuery = append(s.idQuery, r.URL.RawQuery)
		now := time.Now()
		claims := map[string]any{"iss": "https://accounts.google.com", "aud": r.URL.Query().Get("audience"),
			"sub": "112233", "azp": "112233", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
		if r.URL.Query().Get("format") == "full" {
			claims["email"], claims["email_verified"] = account, true
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: s.key, KeyID: "meta"}},
			(&jose.SignerOptions{}).WithType("JWT"))
		payload, _ := json.Marshal(claims)
		jws, _ := sig.Sign(payload)
		raw, _ := jws.CompactSerialize()
		io.WriteString(w, raw)
	case strings.HasPrefix(r.URL.Path, "/v1/"):
		s.accessed = append(s.accessed, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer "+accessToken ||
			r.URL.Path != fmt.Sprintf("/v1/%s/versions/%d:access", tokenSecret, tokenVersion) {
			http.Error(w, `{"error": {"code": 404, "status": "NOT_FOUND"}}`, http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"name": "%s/versions/%d", "payload": {"data": %q}}`, tokenSecret, tokenVersion,
			base64.StdEncoding.EncodeToString([]byte(ghToken)))
	default:
		http.NotFound(w, r)
	}
}

// rig is a claimed dev ticket in the sandbox, whose repository is a local bare remote; the real
// callback API over a test database, behind a proxy that records every call and can refuse one;
// the metadata server and Secret Manager; Cloud Storage as the dev runner's rights shape it; and a
// git on PATH that records every call's arguments and environment before running the real one.
type rig struct {
	t        *testing.T
	conn     *sql.DB
	bare     string
	work     string
	base     string // main when the ticket was claimed
	ticket   int64
	request  string // the launch request, as the dispatcher wrote it
	ids      *idServer
	api      *httptest.Server
	gcs      *capturetest.GCS // what was created, behind storage
	storage  *httptest.Server
	mu       sync.Mutex
	calls    []apiCall
	order    []string // API calls and storage requests, in the order they arrived
	refuseAt int      // the index of the call to refuse with 409; -1 for none
	gitLog   string
	out      *syncBuffer
}

func (r *rig) note(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, s)
}

func newRig(t *testing.T) *rig { return newRigTitled(t, "echo") }

// newRigTitled is a rig whose ticket has the given title, the echo runner's instruction.
func newRigTitled(t *testing.T, title string) *rig {
	t.Helper()
	r := &rig{t: t, refuseAt: -1, out: &syncBuffer{}}
	ctx := context.Background()

	root := t.TempDir()
	r.bare, r.work = filepath.Join(root, "sandbox.git"), filepath.Join(root, "work")
	gitIn(t, root, "init", "--quiet", "--bare", "--initial-branch=main", r.bare)
	gitIn(t, root, "clone", "--quiet", r.bare, r.work)
	r.base = commit(t, r.work, "README.md", "the sandbox\n", "refs/heads/main")

	r.conn = testdb.New(t)
	if err := db.ActivateProject(ctx, r.conn, "sandbox"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.conn.Exec(`UPDATE projects SET repo_url = $1 WHERE id = 'sandbox'`, r.bare); err != nil {
		t.Fatal(err)
	}
	if err := r.conn.QueryRow(`INSERT INTO tickets (project_id, title, state, acceptance_criteria)
		VALUES ('sandbox', $1, 'ready', '[{"id":"AC1","text":"it echoes"}]') RETURNING id`, title).Scan(&r.ticket); err != nil {
		t.Fatal(err)
	}
	tiers, err := dispatcher.EmbeddedTiers()
	if err != nil {
		t.Fatal(err)
	}
	var launched bytes.Buffer
	out, err := dispatcher.New(r.conn, callbackapi.NewEngine(nil, quiet()), tiers, fixedRemote(r.base),
		dispatcher.NewRecordingLauncher(&launched), quiet()).Tick(ctx)
	if err != nil || out.Claimed != r.ticket {
		t.Fatalf("the tick claimed %d (%v), want %d", out.Claimed, err, r.ticket)
	}
	r.request = strings.TrimSpace(launched.String())

	r.ids = newIDServer(t)
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(r.ids.jwks())
	}))
	t.Cleanup(keys.Close)
	var handler http.Handler
	r.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { handler.ServeHTTP(w, q) }))
	t.Cleanup(r.api.Close)
	idMap, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := callbackapi.NewVerifier(ctx, callbackapi.VerifierConfig{JWKSURL: keys.URL, ServiceAudience: r.api.URL}, idMap)
	if err != nil {
		t.Fatal(err)
	}
	real := callbackapi.NewServer(r.conn, callbackapi.NewEngine(nil, quiet()), verifier, quiet()).Handler()
	handler = http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		body, _ := io.ReadAll(q.Body)
		c := apiCall{Path: q.URL.Path, Claim: q.Header.Get("X-Foreman-Claim-Token"), Key: q.Header.Get("Idempotency-Key"),
			Auth: q.Header.Get("Authorization")}
		json.Unmarshal(body, &c.Body)
		r.mu.Lock()
		r.calls = append(r.calls, c)
		r.order = append(r.order, "api "+c.kind())
		refuse := len(r.calls)-1 == r.refuseAt
		r.mu.Unlock()
		if refuse {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"error": "refused by the test"}`)
			return
		}
		q.Body = io.NopCloser(bytes.NewReader(body))
		real.ServeHTTP(w, q)
	})

	// Cloud Storage as the dev runner's objectCreator right, conditioned on sandbox/, shapes it
	// (P06 Approach 3, IAM): it creates objects under its project's prefix and nowhere else, and
	// reads and lists nothing. capturetest's fake keeps what is created.
	r.gcs = capturetest.NewGCS(t, bucket, accessToken)
	target, err := url.Parse(r.gcs.URL())
	if err != nil {
		t.Fatal(err)
	}
	created := httputil.NewSingleHostReverseProxy(target)
	r.storage = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		name := q.URL.Query().Get("name")
		r.note(fmt.Sprintf("storage %s %s %s", q.Method, q.URL.Path, name))
		if q.Method != http.MethodPost || q.URL.Path != "/upload/storage/v1/b/"+bucket+"/o" || !strings.HasPrefix(name, "sandbox/") {
			http.Error(w, `{"error":{"code":403,"message":"the caller does not have access"}}`, http.StatusForbidden)
			return
		}
		created.ServeHTTP(w, q)
	}))
	t.Cleanup(r.storage.Close)

	wrap := t.TempDir()
	r.gitLog = t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nn=$(date +%%s%%N)-$$\nprintf '%%s\\n' \"$@\" > %s/args.$n\nenv > %s/env.$n\nexec %s \"$@\"\n",
		r.gitLog, r.gitLog, realGit)
	if err := os.WriteFile(filepath.Join(wrap, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrap+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, v := range []string{"GIT_TRACE", "GIT_TRACE_CURL", "GIT_TRACE_PACKET", "GIT_TRACE2_EVENT"} {
		t.Setenv(v, "1") // none may reach git
	}
	return r
}

// env is the job's environment for this rig's launch.
func (r *rig) env(over map[string]string) func(string) string {
	full := map[string]string{
		"FOREMAN_LAUNCH_REQUEST":    r.request,
		"FOREMAN_CALLBACK_URL":      r.api.URL,
		"FOREMAN_CALLBACK_AUDIENCE": r.api.URL,
		"FOREMAN_TOKEN_SECRET":      tokenSecret,
		"FOREMAN_TOKEN_VERSION":     fmt.Sprint(tokenVersion),
		"ECHO_HOLD_SECONDS":         "0",
		"GCE_METADATA_HOST":         strings.TrimPrefix(r.ids.URL, "http://"),
		"FOREMAN_SECRETMANAGER_API": r.ids.URL,
		"FOREMAN_ARTIFACTS_BUCKET":  bucket,
		"FOREMAN_STORAGE_API":       r.storage.URL,
	}
	return func(k string) string {
		if v, ok := over[k]; ok {
			return v
		}
		return full[k]
	}
}

// config is the runner's configuration from the rig's environment, with a local remote allowed,
// a short hold and heartbeats only around it.
func (r *rig) config() runner.Config {
	r.t.Helper()
	cfg, err := runner.FromEnv(r.env(nil))
	if err != nil {
		r.t.Fatal(err)
	}
	cfg.GitProtocols = "file"
	cfg.Hold, cfg.HeartbeatEvery = 50*time.Millisecond, time.Hour
	cfg.Log = slog.New(slog.NewJSONHandler(r.out, nil))
	return cfg
}

func (r *rig) apiCalls() []apiCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]apiCall(nil), r.calls...)
}

func (r *rig) kinds() []string {
	var ks []string
	for _, c := range r.apiCalls() {
		ks = append(ks, c.kind())
	}
	return ks
}

func (r *rig) branch() string { return fmt.Sprintf("foreman/%d/1", r.ticket) }

// remoteBranch is the branch's commit on the remote, or "" when it has none.
func (r *rig) remoteBranch() string {
	r.t.Helper()
	cmd := exec.Command(realGit, "--git-dir="+r.bare, "rev-parse", "--verify", "--quiet", "refs/heads/"+r.branch())
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

func (r *rig) ticketState() (string, string) {
	r.t.Helper()
	var state string
	var head sql.NullString
	if err := r.conn.QueryRow(`SELECT state, head_sha FROM tickets WHERE id = $1`, r.ticket).Scan(&state, &head); err != nil {
		r.t.Fatal(err)
	}
	return state, head.String
}

// gitCalls lists each recorded git call's arguments and environment, in order.
func (r *rig) gitCalls() (args [][]string, envs []map[string]string) {
	r.t.Helper()
	names, _ := filepath.Glob(filepath.Join(r.gitLog, "args.*"))
	sort.Strings(names)
	for _, n := range names {
		a, _ := os.ReadFile(n)
		e, _ := os.ReadFile(strings.Replace(n, "args.", "env.", 1))
		args = append(args, strings.Split(strings.TrimSuffix(string(a), "\n"), "\n"))
		m := map[string]string{}
		for _, l := range strings.Split(string(e), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				m[k] = v
			}
		}
		envs = append(envs, m)
	}
	return args, envs
}

// chunks is every object the runner created, by name.
func (r *rig) chunks() map[string]string {
	out := map[string]string{}
	for _, n := range r.gcs.Names() {
		b, _ := r.gcs.Object(n)
		out[n] = string(b)
	}
	return out
}

// transcript is the runner's stored transcript, its chunks in order.
func (r *rig) transcript() string {
	var names []string
	for n := range r.chunks() {
		if strings.Contains(n, "/transcript/") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		data, _ := r.gcs.Object(n)
		b.Write(data)
	}
	return b.String()
}

// noLeaks checks the token is in no git argument, in nothing the runner wrote or stored, and that
// no trace variable reached git.
func (r *rig) noLeaks(errs ...error) {
	r.t.Helper()
	args, envs := r.gitCalls()
	places := map[string]string{"the runner's output": r.out.String()}
	for name, data := range r.chunks() {
		places["the stored "+name] = data
	}
	for i, a := range args {
		places[fmt.Sprintf("git call %d's arguments", i)] = strings.Join(a, " ")
	}
	for i, err := range errs {
		if err != nil {
			places[fmt.Sprintf("error %d", i)] = err.Error()
		}
	}
	for place, s := range places {
		if l := cloudruntest.Leaks(s, ghToken); len(l) > 0 {
			r.t.Errorf("%s holds the token: %v", place, l)
		}
	}
	for i, e := range envs {
		for k := range e {
			if strings.HasPrefix(k, "GIT_TRACE") {
				r.t.Errorf("git call %d (%v) got %s", i, args[i], k)
			}
		}
	}
}

// The echo runner takes a claimed ticket to review: its token read by number, its session started,
// a heartbeat before and after its hold, a clone at base_sha, one file under echo/ committed with
// an explicit author, its branch force-pushed (new or existing), and the pushed commit submitted.
// Every call goes through the real Verifier, with ID tokens from the metadata server (P05 T5).
func TestTheEchoRunnerTakesAClaimToReview(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "a new branch", true: "an existing branch"}[existing], func(t *testing.T) {
			r := newRig(t)
			newer := commit(t, r.work, "later.md", "main moved on\n", "refs/heads/main") // after the claim
			var stale string
			if existing {
				gitIn(t, r.work, "checkout", "--quiet", "--detach", r.base)
				stale = commit(t, r.work, "stale.md", "an earlier claim of the attempt\n", "refs/heads/"+r.branch())
			}
			if err := runner.Run(context.Background(), r.config()); err != nil {
				t.Fatalf("run: %v\n%s", err, r.out.String())
			}

			if got := r.ids.accessed; len(got) != 1 || got[0] != fmt.Sprintf("/v1/%s/versions/%d:access", tokenSecret, tokenVersion) {
				t.Fatalf("Secret Manager asked for %v, want version %d once", got, tokenVersion)
			}
			for _, q := range r.ids.idQuery {
				if !strings.Contains(q, "format=full") || !strings.Contains(q, "audience=") {
					t.Fatalf("an ID token asked for with %q", q)
				}
			}
			want := []string{"claimed->in_progress", "artifacts transcript", "artifacts test_report", "heartbeat", "heartbeat",
				"in_progress->awaiting_review"}
			if got := r.kinds(); strings.Join(got, " ") != strings.Join(want, " ") {
				t.Fatalf("calls %v, want %v", got, want)
			}
			var req struct {
				ClaimToken string `json:"claim_token"`
			}
			json.Unmarshal([]byte(r.request), &req)
			keys := map[string]bool{}
			for _, c := range r.apiCalls() {
				if c.Claim != req.ClaimToken || c.Key == "" || keys[c.Key] || !strings.HasPrefix(c.Auth, "Bearer ") {
					t.Fatalf("call %+v: want the claim token, a fresh idempotency key and a bearer token", c)
				}
				keys[c.Key] = true
			}

			head := r.remoteBranch()
			if head == "" || head == stale {
				t.Fatalf("the branch is at %q (stale %q): not pushed", head, stale)
			}
			if parent := gitIn(t, r.bare, "rev-parse", head+"^"); parent != r.base || parent == newer {
				t.Fatalf("the commit's parent is %s, want base_sha %s", parent, r.base)
			}
			file := fmt.Sprintf("echo/%d.txt", r.ticket)
			if files := gitIn(t, r.bare, "diff-tree", "--no-commit-id", "--name-only", "-r", head); files != file {
				t.Fatalf("the commit changes %q, want only %s", files, file)
			}
			if who := gitIn(t, r.bare, "log", "-1", "--format=%an <%ae> %cn <%ce>", head); who != "dev-sandbox <"+account+"> dev-sandbox <"+account+">" {
				t.Fatalf("author and committer %q", who)
			}
			if state, sha := r.ticketState(); state != "awaiting_review" || sha != head {
				t.Fatalf("ticket %s with head %s, want awaiting_review with %s", state, sha, head)
			}
			if last := r.apiCalls()[5]; last.Body["head_sha"] != head {
				t.Fatalf("submitted %v, want the pushed %s", last.Body["head_sha"], head)
			}

			args, envs := r.gitCalls()
			header := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+ghToken))
			var remoteCalls int
			for i, a := range args {
				if envs[i]["HOME"] != noHome {
					t.Errorf("git %v ran with HOME=%q", a, envs[i]["HOME"])
				}
				if a[0] == "clone" || a[0] == "push" || (len(a) > 2 && (a[2] == "clone" || a[2] == "push")) {
					remoteCalls++
					if envs[i]["GIT_CONFIG_KEY_0"] != "http.extraHeader" || envs[i]["GIT_CONFIG_VALUE_0"] != header {
						t.Errorf("git %v did not get the token as GitHub's header", a)
					}
				}
			}
			if remoteCalls != 2 {
				t.Errorf("%d clones and pushes among %v", remoteCalls, args)
			}
			r.noLeaks()
		})
	}
}

// A refused call ends the run at once, with an error and nothing more sent: no further call, and
// no push before the refusal was one.
func TestARefusalEndsTheRunAtOnce(t *testing.T) {
	for _, c := range []struct {
		name   string
		at     int
		pushed bool
	}{
		{"the start", 0, false},
		{"the transcript's registration", 1, false},
		{"the test report's registration", 2, false},
		{"the heartbeat before the hold", 3, false},
		{"the heartbeat after the hold", 4, false},
		{"the submission", 5, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.refuseAt = c.at
			err := runner.Run(context.Background(), r.config())
			if err == nil || !strings.Contains(err.Error(), "409") {
				t.Fatalf("run: %v, want the refusal's 409", err)
			}
			if n := len(r.apiCalls()); n != c.at+1 {
				t.Fatalf("%d calls (%v), want none after the refused one", n, r.kinds())
			}
			if pushed := r.remoteBranch() != ""; pushed != c.pushed {
				t.Fatalf("pushed: %v, want %v", pushed, c.pushed)
			}
			r.noLeaks(err)
		})
	}
}

// During a hold longer than the heartbeat interval the runner heartbeats within it, so its lease
// never goes a minute without one (docs/architecture.md, the runner contract).
func TestTheHoldHeartbeatsEveryInterval(t *testing.T) {
	r := newRig(t)
	cfg := r.config()
	cfg.Hold, cfg.HeartbeatEvery = 400*time.Millisecond, 100*time.Millisecond
	if err := runner.Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, k := range r.kinds() {
		if k == "heartbeat" {
			n++
		}
	}
	if n < 4 {
		t.Fatalf("%d heartbeats (%v), want one before, at least two within and one after the hold", n, r.kinds())
	}
}

// The runner reads only its own version of the token, and an ID token without its email is
// refused by the API: nothing starts.
func TestNothingStartsWithoutItsTokenOrItsIdentity(t *testing.T) {
	r := newRig(t)
	cfg, err := runner.FromEnv(r.env(map[string]string{"FOREMAN_TOKEN_VERSION": "2"}))
	if err != nil {
		t.Fatal(err)
	}
	cfg.GitProtocols, cfg.Log = "file", slog.New(slog.NewJSONHandler(r.out, nil))
	if err := runner.Run(context.Background(), cfg); err == nil {
		t.Fatal("ran with a version Secret Manager refused")
	}
	if len(r.apiCalls()) != 0 {
		t.Fatalf("calls %v with no token", r.kinds())
	}
	if state, _ := r.ticketState(); state != "claimed" {
		t.Fatalf("ticket %s", state)
	}
	if names := r.gcs.Names(); len(names) != 0 {
		t.Fatalf("stored %v with no token", names)
	}
}

// The configuration comes from the job's environment; whatever is missing or wrong is named.
func TestFromEnv(t *testing.T) {
	r := newRig(t)
	cfg, err := runner.FromEnv(r.env(map[string]string{"ECHO_HOLD_SECONDS": "90"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hold != 90*time.Second || cfg.HeartbeatEvery > time.Minute || cfg.GitProtocols != "https" ||
		cfg.TokenVersion != tokenVersion || cfg.Request.TicketID != r.ticket || cfg.Request.Branch != r.branch() {
		t.Fatalf("configuration %+v", cfg)
	}
	var other map[string]any
	json.Unmarshal([]byte(r.request), &other)
	with := func(k string, v any) string {
		m := map[string]any{}
		for a, b := range other {
			m[a] = b
		}
		m[k] = v
		b, _ := json.Marshal(m)
		return string(b)
	}
	for name, c := range map[string]struct {
		over map[string]string
		want string
	}{
		"no launch request":      {map[string]string{"FOREMAN_LAUNCH_REQUEST": ""}, "FOREMAN_LAUNCH_REQUEST"},
		"a request not JSON":     {map[string]string{"FOREMAN_LAUNCH_REQUEST": "ticket 7"}, "FOREMAN_LAUNCH_REQUEST"},
		"another role":           {map[string]string{"FOREMAN_LAUNCH_REQUEST": with("role", "qa")}, "role"},
		"another branch":         {map[string]string{"FOREMAN_LAUNCH_REQUEST": with("branch", "main")}, "branch"},
		"a short base":           {map[string]string{"FOREMAN_LAUNCH_REQUEST": with("base_sha", "abc")}, "base_sha"},
		"no claim token":         {map[string]string{"FOREMAN_LAUNCH_REQUEST": with("claim_token", "")}, "claim_token"},
		"no callback URL":        {map[string]string{"FOREMAN_CALLBACK_URL": ""}, "FOREMAN_CALLBACK_URL"},
		"an http callback":       {map[string]string{"FOREMAN_CALLBACK_URL": "http://callback.example"}, "FOREMAN_CALLBACK_URL"},
		"no audience":            {map[string]string{"FOREMAN_CALLBACK_AUDIENCE": ""}, "FOREMAN_CALLBACK_AUDIENCE"},
		"no secret":              {map[string]string{"FOREMAN_TOKEN_SECRET": ""}, "FOREMAN_TOKEN_SECRET"},
		"a secret's version":     {map[string]string{"FOREMAN_TOKEN_SECRET": tokenSecret + "/versions/3"}, "FOREMAN_TOKEN_SECRET"},
		"version latest":         {map[string]string{"FOREMAN_TOKEN_VERSION": "latest"}, "FOREMAN_TOKEN_VERSION"},
		"version zero":           {map[string]string{"FOREMAN_TOKEN_VERSION": "0"}, "FOREMAN_TOKEN_VERSION"},
		"a hold not a number":    {map[string]string{"ECHO_HOLD_SECONDS": "long"}, "ECHO_HOLD_SECONDS"},
		"a negative hold":        {map[string]string{"ECHO_HOLD_SECONDS": "-1"}, "ECHO_HOLD_SECONDS"},
		"an http Secret Manager": {map[string]string{"FOREMAN_SECRETMANAGER_API": "http://secretmanager.example"}, "FOREMAN_SECRETMANAGER_API"},
		"a metadata URL":         {map[string]string{"GCE_METADATA_HOST": "http://metadata.google.internal"}, "GCE_METADATA_HOST"},
		"no bucket":              {map[string]string{"FOREMAN_ARTIFACTS_BUCKET": ""}, "FOREMAN_ARTIFACTS_BUCKET"},
		"a bucket not a name":    {map[string]string{"FOREMAN_ARTIFACTS_BUCKET": "gs://x/y"}, "FOREMAN_ARTIFACTS_BUCKET"},
		"an http storage API":    {map[string]string{"FOREMAN_STORAGE_API": "http://storage.example"}, "FOREMAN_STORAGE_API"},
	} {
		if _, err := runner.FromEnv(r.env(c.over)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %s", name, err, c.want)
		}
	}
}

// The runner reads the dispatcher's launch request: every field it uses has the same name and
// value (the runner's binary does not link the dispatcher, so the two types are kept in step here).
func TestTheRequestIsTheDispatchers(t *testing.T) {
	sent := dispatcher.LaunchRequest{TicketID: 7, Project: "sandbox", RepoURL: "https://github.com/your-org/sandbox-repo",
		Role: callbackapi.RoleDev, ServiceAccount: account, Branch: "foreman/7/2", BaseSHA: strings.Repeat("a", 40),
		ClaimToken: "claim", Attempt: 2, Provider: "anthropic", Model: "claude-sonnet-5", Tier: "dev-sonnet", Credential: "claude-oauth-token",
		Title: "[echo:escalate] a title"}
	raw, _ := json.Marshal(sent)
	got, err := runner.ParseRequest(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := runner.Request{TicketID: 7, Project: "sandbox", RepoURL: sent.RepoURL, Role: "dev", ServiceAccount: account,
		Branch: "foreman/7/2", BaseSHA: sent.BaseSHA, ClaimToken: "claim", Attempt: 2, Title: "[echo:escalate] a title"}
	if got != want {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
}

// transcriptLines is the stored transcript's lines, decoded.
func (r *rig) transcriptLines() []map[string]any {
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(r.transcript()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			lines = append(lines, m)
		}
	}
	return lines
}

// steps is the transcript's steps, in order.
func (r *rig) steps() []string {
	var s []string
	for _, l := range r.transcriptLines() {
		if v, ok := l["step"].(string); ok {
			s = append(s, v)
		}
	}
	return s
}

var runPrefix = regexp.MustCompile(`^sandbox/(\d+)/1/dev-([0-9a-f]{32})/(transcript|test_report)$`)

// The runner registers its two prefixes right after its start and before anything else, then
// stores its transcript, every step of the run, and its test report, the echo file checked, under
// them (P06 T6, Approach 3).
func TestTheEchoRunnerCapturesWhatItDid(t *testing.T) {
	r := newRig(t)
	if err := runner.Run(context.Background(), r.config()); err != nil {
		t.Fatalf("run: %v\n%s", err, r.out.String())
	}
	calls := r.apiCalls()
	if len(calls) < 3 || calls[1].kind() != "artifacts transcript" || calls[2].kind() != "artifacts test_report" {
		t.Fatalf("calls %v: want both registrations right after the start", r.kinds())
	}
	var run string
	prefixes := map[string]bool{}
	for _, c := range calls[1:3] {
		path, _ := c.Body["gcs_path"].(string)
		m := runPrefix.FindStringSubmatch(path)
		if m == nil || m[1] != fmt.Sprint(r.ticket) || (run != "" && m[2] != run) || c.Claim == "" {
			t.Fatalf("registered %q", path)
		}
		run = m[2]
		prefixes[path] = true
	}
	var registered int
	r.conn.QueryRow(`SELECT count(*) FROM artifacts WHERE ticket_id = $1 AND attempt = 1`, r.ticket).Scan(&registered)
	if registered != 2 {
		t.Fatalf("%d artifacts registered, want 2", registered)
	}
	for name := range r.chunks() {
		if !prefixes[name[:strings.LastIndex(name, "/")]] || !strings.HasSuffix(name, ".jsonl") {
			t.Fatalf("stored %s, outside the registered prefixes %v", name, prefixes)
		}
	}
	want := []string{"started", "probe", "probe", "probe", "probe", "canary", "cloned", "committed", "pushed", "submitted"}
	if got := r.steps(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("transcript steps %v, want %v", got, want)
	}
	head := r.remoteBranch()
	for _, l := range r.transcriptLines() {
		if (l["step"] == "pushed" || l["step"] == "submitted") && l["head_sha"] != head {
			t.Fatalf("transcript line %v, want head_sha %s", l, head)
		}
	}
	var names []string
	for name := range r.chunks() {
		if strings.Contains(name, "/test_report/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var whole strings.Builder // the report's chunks, in order
	for _, n := range names {
		data, _ := r.gcs.Object(n)
		whole.Write(data)
	}
	report := []string{whole.String()}
	file := fmt.Sprintf("echo/%d.txt", r.ticket)
	header := `{"format":"` + runner.TranscriptFormat + `","harness":"` + runner.Harness + `","version":"1"}` + "\n"
	if len(report) != 1 || report[0] != header+fmt.Sprintf(`{"file":%q,"ok":true,"test":"echo file"}`+"\n", file) {
		t.Fatalf("test report %q", report)
	}
	// Each stream begins with the header naming its harness and format, which the viewer reads it by
	// (P06 D22).
	if first := strings.SplitN(r.transcript(), "\n", 2)[0] + "\n"; first != header {
		t.Fatalf("the transcript begins %q, want the header %q", first, header)
	}
	if runner.Harness != "echo-runner" || runner.TranscriptFormat != "echo-steps" {
		t.Fatalf("the echo runner names itself %s/%s", runner.Harness, runner.TranscriptFormat)
	}
	r.flushedBeforeTheEnd("in_progress->awaiting_review")
	r.noLeaks()
}

// flushedBeforeTheEnd checks a transcript chunk holding the push was stored before the call that
// ended the lease.
func (r *rig) flushedBeforeTheEnd(final string) {
	r.t.Helper()
	r.mu.Lock()
	order := append([]string(nil), r.order...)
	r.mu.Unlock()
	pushedAt, endAt := -1, -1
	for i, o := range order {
		if strings.HasPrefix(o, "storage POST") && strings.Contains(o, "/transcript/") && pushedAt < 0 {
			name := o[strings.LastIndex(o, " ")+1:]
			if data, _ := r.gcs.Object(name); strings.Contains(string(data), `"step":"pushed"`) {
				pushedAt = i
			}
		}
		if o == "api "+final {
			endAt = i
		}
	}
	if pushedAt < 0 || endAt < 0 || pushedAt > endAt {
		r.t.Fatalf("the push was stored at %d and %s called at %d, want the flush first:\n%s", pushedAt, final, endAt,
			strings.Join(order, "\n"))
	}
}

// Its transcript records its bucket rights as GCP enforces them: creating under its own prefix
// allowed; creating under another project's, reading an object and listing denied (red team R7).
func TestTheProbeRecordsTheBucketRights(t *testing.T) {
	r := newRig(t)
	if err := runner.Run(context.Background(), r.config()); err != nil {
		t.Fatalf("run: %v\n%s", err, r.out.String())
	}
	got := map[string]string{}
	for _, l := range r.transcriptLines() {
		if l["step"] == "probe" {
			got[fmt.Sprint(l["check"])] = fmt.Sprint(l["result"])
		}
	}
	want := map[string]string{
		"create under its own prefix":           "allowed",
		"create under another project's prefix": "denied",
		"get an object":                         "denied",
		"list objects":                          "denied",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("probe results %v, want %v", got, want)
	}
	r.mu.Lock()
	order := strings.Join(r.order, "\n")
	r.mu.Unlock()
	for _, asked := range []string{"storage POST /upload/storage/v1/b/" + bucket + "/o foreman/", "storage GET /storage/v1/b/" + bucket + "/o"} {
		if !strings.Contains(order, asked) {
			t.Fatalf("storage never asked %q:\n%s", asked, order)
		}
	}
	for _, name := range r.gcs.Names() {
		if !strings.HasPrefix(name, "sandbox/") {
			t.Fatalf("an object outside sandbox/: %s", name)
		}
	}
}

var appTokenShape = regexp.MustCompile(`ghs_[0-9A-Za-z]{36}`)

// A canary, a token-shaped string the runner makes at run time, is stored only as redacted: in GCP
// it proves the scrubber runs where the transcript is written (red team R7). Neither it nor the
// runner's own token appears in what it stored or logged.
func TestTheCanaryIsStoredOnlyRedacted(t *testing.T) {
	r := newRig(t)
	if err := runner.Run(context.Background(), r.config()); err != nil {
		t.Fatalf("run: %v\n%s", err, r.out.String())
	}
	var canary map[string]any
	for _, l := range r.transcriptLines() {
		if l["step"] == "canary" {
			canary = l
		}
	}
	if canary == nil || canary["value"] != "[redacted:github-app-token]" {
		t.Fatalf("the canary's line %v, want its value redacted", canary)
	}
	for where, s := range map[string]string{"the transcript": r.transcript(), "the runner's output": r.out.String()} {
		if m := appTokenShape.FindString(s); m != "" {
			t.Fatalf("%s holds a token-shaped string", where)
		}
	}
	r.noLeaks()
}

// A title holding [echo:escalate] makes the runner stop for a person after pushing: it stores its
// transcript, then escalates naming its commit and a reason, and the ticket waits with that head
// (P06 D14, D21).
func TestTheEchoRunnerEscalatesOnRequest(t *testing.T) {
	r := newRigTitled(t, "[echo:escalate] needs a person")
	if err := runner.Run(context.Background(), r.config()); err != nil {
		t.Fatalf("run: %v\n%s", err, r.out.String())
	}
	want := []string{"claimed->in_progress", "artifacts transcript", "artifacts test_report", "heartbeat", "heartbeat",
		"in_progress->escalated"}
	if got := r.kinds(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("calls %v, want %v", got, want)
	}
	head := r.remoteBranch()
	last := r.apiCalls()[5]
	payload, _ := last.Body["payload"].(map[string]any)
	if head == "" || last.Body["head_sha"] != head || payload == nil || payload["reason"] == "" {
		t.Fatalf("escalated with %v (pushed %q): want the pushed commit and a reason", last.Body, head)
	}
	state, sha := r.ticketState()
	var reason sql.NullString
	r.conn.QueryRow(`SELECT escalation_reason FROM tickets WHERE id = $1`, r.ticket).Scan(&reason)
	if state != "escalated" || sha != head || reason.String != payload["reason"] {
		t.Fatalf("ticket %s with head %s and reason %v, want escalated with %s and %v", state, sha, reason, head, payload["reason"])
	}
	steps := r.steps()
	if steps[len(steps)-1] != "escalated" {
		t.Fatalf("transcript steps %v, want it to end escalated", steps)
	}
	r.flushedBeforeTheEnd("in_progress->escalated")
	r.noLeaks()
}

// A run stopped by a refusal stores what it had done and why it stopped.
func TestAStoppedRunStoresWhyItStopped(t *testing.T) {
	r := newRig(t)
	r.refuseAt = 3 // the heartbeat before the hold
	if err := runner.Run(context.Background(), r.config()); err == nil {
		t.Fatal("ran past a refusal")
	}
	steps := r.steps()
	if len(steps) == 0 || steps[len(steps)-1] != "stopped" || !strings.Contains(r.transcript(), "409") {
		t.Fatalf("transcript steps %v: want it to end stopped, naming the refusal", steps)
	}
	r.noLeaks()
}
