package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// `foreman ticket create` makes a ticket through the core as a person the identity map knows, for
// the operator to run as an execution of the dispatcher job (P05 T8: Cloud Run alters a person's
// gcloud token, so the person's API path waits for P06). Without criteria it is a draft; with
// them, ready. It prints the result as one JSON object.
func TestTicketCreate(t *testing.T) {
	_, conn := migrated(t)
	ctx := context.Background()
	for _, c := range []struct {
		criteria string
		state    string
	}{
		{"", "draft"},
		{`[{"id": "AC1", "text": "it echoes"}]`, "ready"},
	} {
		args := []string{"ticket", "create", "--as", operator, "--project", "sandbox", "--title", "an echo, with commas, and spaces"}
		if c.criteria != "" {
			args = append(args, "--criteria", c.criteria)
		}
		var out, errs bytes.Buffer
		if code := run(ctx, args, &out, &errs); code != 0 {
			t.Fatalf("%v: exit %d\n%s", args, code, errs.String())
		}
		var res struct {
			TicketID int64  `json:"ticket_id"`
			Project  string `json:"project"`
			State    string `json:"state"`
		}
		if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.TicketID == 0 || res.Project != "sandbox" || res.State != c.state {
			t.Fatalf("output %q (%v), want a %s ticket in sandbox", out.String(), err, c.state)
		}
		var title, state, actor, actorID string
		if err := conn.QueryRow(`SELECT t.title, t.state, e.actor, e.actor_id FROM tickets t JOIN ticket_events e ON e.ticket_id = t.id
			WHERE t.id = $1`, res.TicketID).Scan(&title, &state, &actor, &actorID); err != nil {
			t.Fatal(err)
		}
		if title != "an echo, with commas, and spaces" || state != c.state || actor != "human" || actorID != operator {
			t.Fatalf("ticket %q %s, event by %s %s", title, state, actor, actorID)
		}
	}
}

// Whatever is missing or wrong stops the command, and no ticket is made.
func TestTicketCreateRefusals(t *testing.T) {
	_, conn := migrated(t)
	ctx := context.Background()
	base := []string{"ticket", "create", "--as", operator, "--project", "sandbox", "--title", "t"}
	for name, c := range map[string]struct {
		args []string
		code int
	}{
		"no --as":             {[]string{"ticket", "create", "--project", "sandbox", "--title", "t"}, 2},
		"an unknown person":   {[]string{"ticket", "create", "--as", "someone@example.com", "--project", "sandbox", "--title", "t"}, 2},
		"a runner's account":  {[]string{"ticket", "create", "--as", "dev-sandbox@your-project-id.iam.gserviceaccount.com", "--project", "sandbox", "--title", "t"}, 2},
		"no title":            {[]string{"ticket", "create", "--as", operator, "--project", "sandbox"}, 2},
		"no project":          {[]string{"ticket", "create", "--as", operator, "--title", "t"}, 2},
		"criteria not JSON":   {append(append([]string{}, base...), "--criteria", "it echoes"), 2},
		"a criterion's field": {append(append([]string{}, base...), "--criteria", `[{"id": "AC1", "text": "x", "done": true}]`), 2},
		"an unknown flag":     {append(append([]string{}, base...), "--state", "ready"), 2},
		"a stray argument":    {append(append([]string{}, base...), "extra"), 2},
		"an unknown project":  {[]string{"ticket", "create", "--as", operator, "--project", "nowhere", "--title", "t"}, 1},
		"a criterion no text": {append(append([]string{}, base...), "--criteria", `[{"id": "AC1"}]`), 1},
	} {
		var out, errs bytes.Buffer
		if code := run(ctx, c.args, &out, &errs); code != c.code {
			t.Errorf("%s: exit %d, want %d\n%s", name, code, c.code, errs.String())
		}
	}
	var n int
	if err := conn.QueryRow(`SELECT count(*) FROM tickets WHERE project_id = 'sandbox'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d sandbox tickets (%v), want none", n, err)
	}
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
	for _, c := range []string{"dispatch", "ticket create"} {
		if !strings.Contains(errs.String(), c) {
			t.Fatalf("usage does not name %s:\n%s", c, errs.String())
		}
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
