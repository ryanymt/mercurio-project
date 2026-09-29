package cloudrun_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun/cloudruntest"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
)

const (
	job         = "projects/your-project-id/locations/us-central1/jobs/echo-runner-sandbox"
	account     = "dev-sandbox@your-project-id.iam.gserviceaccount.com"
	tokenShort  = "github-token-dev-sandbox"
	tokenSecret = "projects/your-project-id/secrets/" + tokenShort
	callbackURL = "https://callback-api-123456789012.us-central1.run.app"
	repoURL     = "https://github.com/your-org/sandbox-repo"
	echoed      = "refused; the request was" // what the fakes' error answers carry
)

var (
	appKeyOnce sync.Once
	appKey     []byte
)

func key(t *testing.T) []byte {
	appKeyOnce.Do(func() { appKey = cloudruntest.AppKey(t) })
	return appKey
}

// syncBuffer is a log sink safe to read while the launcher writes.
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

type rig struct {
	t    *testing.T
	gcp  *cloudruntest.GCP
	gh   *cloudruntest.GitHub
	logs *syncBuffer
	l    *cloudrun.Launcher
}

type rigOptions struct {
	timeout time.Duration // each call's bound; a second by default
	run     string        // the Cloud Run endpoint; the fake by default
	jobs    []cloudrun.Job
}

func sandboxJob() cloudrun.Job {
	return cloudrun.Job{Role: callbackapi.RoleDev, Project: "sandbox", Job: job, Account: account, TokenSecret: tokenSecret}
}

func newRig(t *testing.T, o rigOptions) *rig {
	t.Helper()
	r := &rig{t: t, gcp: cloudruntest.NewGCP(t), gh: cloudruntest.NewGitHub(t), logs: &syncBuffer{}}
	if o.timeout == 0 {
		o.timeout = time.Second
	}
	if o.run == "" {
		o.run = r.gcp.URL()
	}
	if o.jobs == nil {
		o.jobs = []cloudrun.Job{sandboxJob()}
	}
	g, err := cloudrun.NewGCP(cloudrun.Endpoints{MetadataHost: r.gcp.MetadataHost(), SecretManager: r.gcp.URL(), Run: o.run},
		&http.Client{Timeout: o.timeout})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	tokens := github.New(github.Static("12345", key(t)), r.gh.URL(), nil)
	r.l, err = cloudrun.New(cloudrun.Config{Jobs: o.jobs, CallbackURL: callbackURL, Audience: callbackURL}, g, tokens, ids,
		slog.New(slog.NewJSONHandler(r.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func request(ticket int64) dispatcher.LaunchRequest {
	return dispatcher.LaunchRequest{TicketID: ticket, Project: "sandbox", RepoURL: repoURL, Role: callbackapi.RoleDev,
		ServiceAccount: account, Branch: fmt.Sprintf("foreman/%d/1", ticket), BaseSHA: strings.Repeat("3", 40),
		ClaimToken: fmt.Sprintf("claim-%d", ticket), Attempt: 1, Provider: "zai", Model: "glm-5.3-flash",
		Tier: "dev-glm-flash", Credential: "zai-api-key"}
}

// noLeaks checks that no token minted so far is in any request to Cloud Run, in the logs, or in
// the errors given.
func (r *rig) noLeaks(errs ...error) {
	r.t.Helper()
	var runs strings.Builder
	for _, c := range r.gcp.Runs() {
		fmt.Fprintf(&runs, "%s\n%v\n%s\n", c.Path, c.Header, c.Body)
	}
	places := map[string]string{"a request to Cloud Run": runs.String(), "the logs": r.logs.String()}
	for i, err := range errs {
		if err != nil {
			places[fmt.Sprintf("error %d", i)] = err.Error()
		}
	}
	for n := 1; n <= len(r.gh.Asked()); n++ {
		for place, s := range places {
			if leaks := cloudruntest.Leaks(s, cloudruntest.TokenFor(n)); len(leaks) > 0 {
				r.t.Errorf("%s holds token %d: %v", place, n, leaks)
			}
		}
	}
	for place, s := range places {
		if place != "a request to Cloud Run" && strings.Contains(s, echoed) {
			r.t.Errorf("%s passes on an answer's body: %s", place, s)
		}
	}
}

// One launch: a write token minted, added as version 1 of the role and project's secret, and the
// job run with the request, the callback URL, the audience and the version, as the dispatcher's
// own account (P05 Approach 4, D17).
func TestLaunchHandsTheTokenOverThroughSecretManager(t *testing.T) {
	r := newRig(t, rigOptions{})
	req := request(7)
	id, err := r.l.Launch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if want := job + "/executions/ex-1"; id != want {
		t.Fatalf("launch id %q, want the execution %q", id, want)
	}
	if got := r.gh.Asked(); !slices.Equal(got, []string{"write"}) {
		t.Fatalf("tokens minted with contents %v, want one write token", got)
	}
	data, destroyed, ok := r.gcp.Version(tokenShort, 1)
	if !ok || destroyed || string(data) != cloudruntest.TokenFor(1) {
		t.Fatalf("version 1: %q, destroyed %v, exists %v; want the token", data, destroyed, ok)
	}
	if got := r.gcp.Events(); !slices.Equal(got, []string{"add 1", "run"}) {
		t.Fatalf("calls %v", got)
	}
	runs := r.gcp.Runs()
	if len(runs) != 1 || runs[0].Job != job {
		t.Fatalf("runs %+v, want one of %s", runs, job)
	}
	if auth := runs[0].Header.Get("Authorization"); auth != "Bearer "+cloudruntest.DispatcherToken {
		t.Fatalf("jobs.run authorized by %q, not the dispatcher's access token", auth)
	}
	env := runs[0].Env
	want := map[string]string{
		"FOREMAN_CALLBACK_URL":      callbackURL,
		"FOREMAN_CALLBACK_AUDIENCE": callbackURL,
		"FOREMAN_TOKEN_SECRET":      tokenSecret,
		"FOREMAN_TOKEN_VERSION":     "1",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("override %s = %q, want %q", k, env[k], v)
		}
	}
	var got dispatcher.LaunchRequest
	if err := json.Unmarshal([]byte(env["FOREMAN_LAUNCH_REQUEST"]), &got); err != nil || !reflect.DeepEqual(got, req) {
		t.Errorf("override FOREMAN_LAUNCH_REQUEST = %s (%v), want %+v", env["FOREMAN_LAUNCH_REQUEST"], err, req)
	}
	if len(env) != len(want)+1 {
		t.Errorf("overrides %v: want exactly the launch request and %v", env, want)
	}
	r.noLeaks(err)
}

// Each launch destroys the versions before its own, and only after the run was sent: past version
// 10, no version is destroyed twice, and only the newest is left.
func TestEveryLaunchLeavesOnlyTheNewestVersion(t *testing.T) {
	r := newRig(t, rigOptions{})
	for n := int64(1); n <= 12; n++ {
		before := len(r.gcp.Events())
		if _, err := r.l.Launch(context.Background(), request(n)); err != nil {
			t.Fatalf("launch %d: %v", n, err)
		}
		want := []string{fmt.Sprintf("add %d", n), "run"}
		if n > 1 {
			want = append(want, fmt.Sprintf("destroy %d", n-1))
		}
		if got := r.gcp.Events()[before:]; !slices.Equal(got, want) {
			t.Fatalf("launch %d called %v, want %v", n, got, want)
		}
		if v := r.gcp.Runs()[n-1].Env["FOREMAN_TOKEN_VERSION"]; v != strconv.FormatInt(n, 10) {
			t.Fatalf("launch %d named version %q", n, v)
		}
	}
	if got := r.gcp.Enabled(tokenShort); !slices.Equal(got, []int64{12}) {
		t.Fatalf("enabled versions %v, want only 12", got)
	}
	for n := int64(1); n < 12; n++ {
		if c := r.gcp.Destroys(tokenShort, n); c != 1 {
			t.Errorf("version %d: %d destroy calls, want 1", n, c)
		}
	}
	if re := r.gcp.Redestroyed(); len(re) > 0 {
		t.Errorf("destroyed again: %v", re)
	}
	r.noLeaks()
}

// A destroy that fails is logged and the launch still succeeds; the next launch that can destroy
// clears every older version, however many pages the listing takes, comparing numbers as numbers.
func TestADestroyFailureIsLoggedNotReturned(t *testing.T) {
	r := newRig(t, rigOptions{})
	r.gcp.DestroyStatus = http.StatusInternalServerError
	for n := int64(1); n <= 10; n++ {
		id, err := r.l.Launch(context.Background(), request(n))
		if err != nil || id == "" {
			t.Fatalf("launch %d with destroys failing: %q, %v; want the execution and no error", n, id, err)
		}
	}
	if got := r.gcp.Enabled(tokenShort); len(got) != 10 {
		t.Fatalf("enabled versions %v, want all ten", got)
	}
	logs := r.logs.String()
	if !strings.Contains(logs, "destroy") || !strings.Contains(logs, tokenShort) || !strings.Contains(logs, `"level":"WARN"`) {
		t.Fatalf("the failed destroys were not logged as warnings naming the secret:\n%s", logs)
	}
	r.gcp.DestroyStatus = 0
	if _, err := r.l.Launch(context.Background(), request(11)); err != nil {
		t.Fatal(err)
	}
	if got := r.gcp.Enabled(tokenShort); !slices.Equal(got, []int64{11}) {
		t.Fatalf("enabled versions %v, want only 11 (%d to a page)", got, cloudruntest.PageSize)
	}
	if re := r.gcp.Redestroyed(); len(re) > 0 {
		t.Errorf("destroyed again: %v", re)
	}
	r.noLeaks()
}

func closedURL(t *testing.T) string {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}

// An error means no execution was created: a failure or timeout before jobs.run is sent, or an
// answer refusing it. A timeout after it was sent, or a server error, is uncertain, and returns no
// error so the lease is reaped (P04 D10).
func TestLaunchErrorContract(t *testing.T) {
	for _, c := range []struct {
		name    string
		opts    func(t *testing.T) rigOptions
		setup   func(r *rig)
		wantErr string // a substring of the error; "" for none
		ran     bool   // a jobs.run was received
		id      string // the launch id when there is no error
	}{
		{name: "GitHub mints no token", setup: func(r *rig) { r.gh.SetDown(true) }, wantErr: "503"},
		{name: "Secret Manager refuses the version", setup: func(r *rig) { r.gcp.AddStatus = 500 }, wantErr: "500"},
		{name: "Secret Manager times out", setup: func(r *rig) { r.gcp.AddDelay = time.Second },
			opts: func(*testing.T) rigOptions { return rigOptions{timeout: 200 * time.Millisecond} }, wantErr: "addVersion"},
		{name: "Cloud Run is unreachable", opts: func(t *testing.T) rigOptions { return rigOptions{run: closedURL(t)} }, wantErr: "jobs.run"},
		{name: "jobs.run refused", setup: func(r *rig) { r.gcp.RunStatus = 403 }, wantErr: "403", ran: true},
		{name: "jobs.run rate-limited", setup: func(r *rig) { r.gcp.RunStatus = 429 }, wantErr: "429", ran: true},
		{name: "jobs.run finds no job", setup: func(r *rig) { r.gcp.RunStatus = 404 }, wantErr: "404", ran: true},
		{name: "jobs.run fails on the server", setup: func(r *rig) { r.gcp.RunStatus = 500 }, ran: true},
		{name: "jobs.run unavailable", setup: func(r *rig) { r.gcp.RunStatus = 503 }, ran: true},
		{name: "jobs.run times out after it was sent", setup: func(r *rig) { r.gcp.RunDelay = time.Second },
			opts: func(*testing.T) rigOptions { return rigOptions{timeout: 200 * time.Millisecond} }, ran: true},
		{name: "jobs.run names no execution", setup: func(r *rig) { r.gcp.RunNoMetadata = true }, ran: true,
			id: "projects/your-project-id/locations/us-central1/operations/op-1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := rigOptions{}
			if c.opts != nil {
				o = c.opts(t)
			}
			r := newRig(t, o)
			if c.setup != nil {
				c.setup(r)
			}
			id, err := r.l.Launch(context.Background(), request(1))
			switch {
			case c.wantErr != "" && err == nil:
				t.Fatalf("no error (launch id %q); want one naming %q", id, c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("error %q does not name %q", err, c.wantErr)
			case c.wantErr == "" && err != nil:
				t.Fatalf("error %v, want none: the run may have started", err)
			case c.wantErr == "" && id != c.id:
				t.Fatalf("launch id %q, want %q", id, c.id)
			}
			if ran := len(r.gcp.Runs()) > 0; ran != c.ran {
				t.Fatalf("jobs.run received: %v, want %v", ran, c.ran)
			}
			r.noLeaks(err)
		})
	}
}

// A request that does not match a configured job is refused before any call: no token is minted,
// no version added, nothing run.
func TestARequestNoJobMatchesIsRefusedBeforeAnyCall(t *testing.T) {
	r := newRig(t, rigOptions{})
	for name, mutate := range map[string]func(*dispatcher.LaunchRequest){
		"another account": func(q *dispatcher.LaunchRequest) {
			q.ServiceAccount = "dev-foreman@your-project-id.iam.gserviceaccount.com"
		},
		"a project with no job": func(q *dispatcher.LaunchRequest) {
			q.Project, q.ServiceAccount = "foreman", "dev-foreman@your-project-id.iam.gserviceaccount.com"
		},
		"a role with no job": func(q *dispatcher.LaunchRequest) {
			q.Role, q.ServiceAccount = callbackapi.RoleQA, "qa-sandbox@your-project-id.iam.gserviceaccount.com"
		},
		"a repository not on GitHub": func(q *dispatcher.LaunchRequest) { q.RepoURL = "https://example.com/your-org/sandbox-repo" },
	} {
		req := request(1)
		mutate(&req)
		if id, err := r.l.Launch(context.Background(), req); err == nil {
			t.Errorf("%s: launched %q", name, id)
		}
	}
	if n, m := r.gcp.Requests(), r.gh.Requests(); n != 0 || m != 0 {
		t.Fatalf("%d calls to Google and %d to GitHub, want none", n, m)
	}
}

// The configuration is checked when the launcher is made, so a deployment that could never launch
// fails at once rather than claiming tickets.
func TestNewRefusesABadConfiguration(t *testing.T) {
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	g, err := cloudrun.NewGCP(cloudrun.Endpoints{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens := github.New(github.Static("1", nil), "", nil)
	with := func(f func(*cloudrun.Job)) []cloudrun.Job {
		j := sandboxJob()
		f(&j)
		return []cloudrun.Job{j}
	}
	good := cloudrun.Config{Jobs: []cloudrun.Job{sandboxJob()}, CallbackURL: callbackURL, Audience: callbackURL}
	if _, err := cloudrun.New(good, g, tokens, ids, nil); err != nil {
		t.Fatalf("the good configuration: %v", err)
	}
	// A map that knows a second account as the sandbox's dev runner: the claim's request always
	// carries dev-sandbox's, so a job running as the other could never launch.
	twice, err := callbackapi.LoadIdentityMap([]byte(`[
		{"email": "` + account + `", "role": "dev", "project": "sandbox"},
		{"email": "dev-sandbox-2@your-project-id.iam.gserviceaccount.com", "role": "dev", "project": "sandbox"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cloudrun.New(cloudrun.Config{Jobs: with(func(j *cloudrun.Job) {
		j.Account = "dev-sandbox-2@your-project-id.iam.gserviceaccount.com"
	}), CallbackURL: callbackURL, Audience: callbackURL}, g, tokens, twice, nil); err == nil {
		t.Error("a job running as another account the map knows as the same runner: accepted")
	}
	for name, cfg := range map[string]cloudrun.Config{
		"no jobs":            {CallbackURL: callbackURL, Audience: callbackURL},
		"not a runner role":  {Jobs: with(func(j *cloudrun.Job) { j.Role = callbackapi.RoleDispatcher }), CallbackURL: callbackURL, Audience: callbackURL},
		"a bad project id":   {Jobs: with(func(j *cloudrun.Job) { j.Project = "Sandbox!" }), CallbackURL: callbackURL, Audience: callbackURL},
		"a job name":         {Jobs: with(func(j *cloudrun.Job) { j.Job = "echo-runner-sandbox" }), CallbackURL: callbackURL, Audience: callbackURL},
		"a job with a slash": {Jobs: with(func(j *cloudrun.Job) { j.Job = job + "/executions/x" }), CallbackURL: callbackURL, Audience: callbackURL},
		"a secret name":      {Jobs: with(func(j *cloudrun.Job) { j.TokenSecret = tokenShort }), CallbackURL: callbackURL, Audience: callbackURL},
		"a secret's version": {Jobs: with(func(j *cloudrun.Job) { j.TokenSecret = tokenSecret + "/versions/1" }), CallbackURL: callbackURL, Audience: callbackURL},
		"another account":    {Jobs: with(func(j *cloudrun.Job) { j.Account = "dev-foreman@your-project-id.iam.gserviceaccount.com" }), CallbackURL: callbackURL, Audience: callbackURL},
		"an unmapped project": {Jobs: with(func(j *cloudrun.Job) {
			j.Project, j.Account = "nowhere", "dev-nowhere@your-project-id.iam.gserviceaccount.com"
		}), CallbackURL: callbackURL, Audience: callbackURL},
		"a job twice":      {Jobs: []cloudrun.Job{sandboxJob(), sandboxJob()}, CallbackURL: callbackURL, Audience: callbackURL},
		"an http callback": {Jobs: good.Jobs, CallbackURL: "http://callback.example", Audience: callbackURL},
		"no callback":      {Jobs: good.Jobs, Audience: callbackURL},
		"no audience":      {Jobs: good.Jobs, CallbackURL: callbackURL},
	} {
		if _, err := cloudrun.New(cfg, g, tokens, ids, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Roles names the roles with a job for the project, and nothing for a project with none (D8, D20).
func TestRolesNamesTheProjectsJobs(t *testing.T) {
	qa := cloudrun.Job{Role: callbackapi.RoleQA, Project: "sandbox", Job: "projects/your-project-id/locations/us-central1/jobs/qa-sandbox",
		Account: "qa-sandbox@your-project-id.iam.gserviceaccount.com", TokenSecret: "projects/your-project-id/secrets/github-token-qa-sandbox"}
	r := newRig(t, rigOptions{jobs: []cloudrun.Job{sandboxJob(), qa}})
	if got := r.l.Roles("sandbox"); !slices.Equal(got, []callbackapi.Role{callbackapi.RoleDev, callbackapi.RoleQA}) {
		t.Fatalf("roles for sandbox %v", got)
	}
	if got := r.l.Roles("foreman"); len(got) != 0 {
		t.Fatalf("roles for foreman %v, want none", got)
	}
}

// The App's id and key are read from Secret Manager when a token is minted, as the dispatcher's
// account, and a failure names no secret's contents.
func TestSecretCredentialsReadTheAppFromSecretManager(t *testing.T) {
	gcp := cloudruntest.NewGCP(t)
	gcp.SetSecret("github-app-id", []byte("12345\n"))
	gcp.SetSecret("github-app-key", key(t))
	g, err := cloudrun.NewGCP(cloudrun.Endpoints{MetadataHost: gcp.MetadataHost(), SecretManager: gcp.URL(), Run: gcp.URL()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const base = "projects/your-project-id/secrets/"
	id, pem, err := cloudrun.SecretCredentials(g, base+"github-app-id/versions/latest", base+"github-app-key/versions/1")(context.Background())
	if err != nil || id != "12345" || !bytes.Equal(pem, key(t)) {
		t.Fatalf("credentials %q, %d bytes of key, %v", id, len(pem), err)
	}
	_, _, err = cloudrun.SecretCredentials(g, base+"github-app-id/versions/latest", base+"nothing/versions/latest")(context.Background())
	if err == nil || strings.Contains(err.Error(), echoed) {
		t.Fatalf("a missing key: %v", err)
	}
}

// Every endpoint is https, except plain http to a loopback address (the tests' fakes).
func TestEndpointsAreHTTPSOrLoopback(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://run.googleapis.com":           true,
		"https://api.github.com":               true,
		"http://127.0.0.1:8080":                true,
		"http://[::1]:8080":                    true,
		"http://run.googleapis.com":            false,
		"http://localhost:8080":                false,
		"http://10.0.0.1":                      false,
		"ftp://run.googleapis.com":             false,
		"https://user:pw@run.googleapis.com":   false,
		"https://run.googleapis.com/v2?x=1":    false,
		"":                                     false,
		"run.googleapis.com":                   false,
		"https://":                             false,
		"https://run.googleapis.com/#fragment": false,
	} {
		if err := cloudrun.CheckEndpoint(raw); (err == nil) != ok {
			t.Errorf("%q: %v, want accepted %v", raw, err, ok)
		}
	}
	if _, err := cloudrun.NewGCP(cloudrun.Endpoints{Run: "http://run.googleapis.com"}, nil); err == nil {
		t.Error("NewGCP accepted an http endpoint")
	}
	for _, h := range []string{"metadata.google.internal", "169.254.169.254", "127.0.0.1:8080"} {
		if _, err := cloudrun.NewGCP(cloudrun.Endpoints{MetadataHost: h}, nil); err != nil {
			t.Errorf("metadata host %q: %v", h, err)
		}
	}
	for _, h := range []string{"http://metadata.google.internal", "a/b", "user@host"} {
		if _, err := cloudrun.NewGCP(cloudrun.Endpoints{MetadataHost: h}, nil); err == nil {
			t.Errorf("metadata host %q accepted", h)
		}
	}
}

// The command's configuration comes from its environment; whatever is missing or wrong is named.
func TestFromEnv(t *testing.T) {
	gcp := cloudruntest.NewGCP(t)
	gh := cloudruntest.NewGitHub(t)
	gcp.SetSecret("github-app-id", []byte("12345"))
	gcp.SetSecret("github-app-key", key(t))
	jobs, _ := json.Marshal([]map[string]string{{"role": "dev", "project": "sandbox", "job": job, "account": account, "token_secret": tokenSecret}})
	full := map[string]string{
		"FOREMAN_RUNNER_JOBS":           string(jobs),
		"FOREMAN_CALLBACK_URL":          callbackURL,
		"FOREMAN_CALLBACK_AUDIENCE":     callbackURL,
		"FOREMAN_GITHUB_APP_ID_SECRET":  "projects/your-project-id/secrets/github-app-id/versions/latest",
		"FOREMAN_GITHUB_APP_KEY_SECRET": "projects/your-project-id/secrets/github-app-key/versions/latest",
		"GCE_METADATA_HOST":             gcp.MetadataHost(),
		"FOREMAN_SECRETMANAGER_API":     gcp.URL(),
		"FOREMAN_RUN_API":               gcp.URL(),
		"FOREMAN_GITHUB_API":            gh.URL(),
	}
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	env := func(over map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return full[k]
		}
	}
	l, tokens, err := cloudrun.FromEnv(env(nil), ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Launch(context.Background(), request(1)); err != nil {
		t.Fatalf("a launch configured from the environment: %v", err)
	}
	if _, err := tokens.Token(context.Background(), cloudruntest.Repo, github.ContentsRead); err != nil {
		t.Fatalf("a token from the App's credentials in Secret Manager: %v", err)
	}
	for name, c := range map[string]struct {
		over map[string]string
		want string
	}{
		"no jobs":             {map[string]string{"FOREMAN_RUNNER_JOBS": ""}, "FOREMAN_RUNNER_JOBS"},
		"jobs not JSON":       {map[string]string{"FOREMAN_RUNNER_JOBS": "dev=sandbox"}, "FOREMAN_RUNNER_JOBS"},
		"a job's unknown key": {map[string]string{"FOREMAN_RUNNER_JOBS": `[{"role":"dev","project":"sandbox","job":"` + job + `","account":"` + account + `","token_secret":"` + tokenSecret + `","token":"x"}]`}, "FOREMAN_RUNNER_JOBS"},
		"no callback URL":     {map[string]string{"FOREMAN_CALLBACK_URL": ""}, "FOREMAN_CALLBACK_URL"},
		"no audience":         {map[string]string{"FOREMAN_CALLBACK_AUDIENCE": ""}, "FOREMAN_CALLBACK_AUDIENCE"},
		"no App id":           {map[string]string{"FOREMAN_GITHUB_APP_ID_SECRET": ""}, "FOREMAN_GITHUB_APP_ID_SECRET"},
		"no App key":          {map[string]string{"FOREMAN_GITHUB_APP_KEY_SECRET": ""}, "FOREMAN_GITHUB_APP_KEY_SECRET"},
		"an App key's name":   {map[string]string{"FOREMAN_GITHUB_APP_KEY_SECRET": "github-app-key"}, "FOREMAN_GITHUB_APP_KEY_SECRET"},
		"http Cloud Run":      {map[string]string{"FOREMAN_RUN_API": "http://run.googleapis.com"}, "FOREMAN_RUN_API"},
		"http Secret Manager": {map[string]string{"FOREMAN_SECRETMANAGER_API": "http://secretmanager.googleapis.com"}, "FOREMAN_SECRETMANAGER_API"},
		"http GitHub":         {map[string]string{"FOREMAN_GITHUB_API": "http://api.github.com"}, "FOREMAN_GITHUB_API"},
		"a metadata URL":      {map[string]string{"GCE_METADATA_HOST": "http://metadata.google.internal"}, "GCE_METADATA_HOST"},
	} {
		if _, _, err := cloudrun.FromEnv(env(c.over), ids, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %s", name, err, c.want)
		}
	}
}
