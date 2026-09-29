// Command foreman is the operator CLI for the foreman control plane.
//
//	foreman migrate up       apply every pending migration
//	foreman migrate status   list the migrations and which are applied
//	foreman callback-api     serve the callback API
//	foreman dispatch         make one dispatcher tick and exit
//	foreman project activate <id>   make that project the only active one
//	foreman db rights        report what the database user can do
//	foreman ticket create    make a ticket as a person the identity map knows
//
// The database is the one DATABASE_URL points at, a postgres:// URL. The callback API also reads
// FOREMAN_SERVICE_AUDIENCE (required: the audience service accounts mint their tokens for),
// FOREMAN_HUMAN_AUDIENCES (comma-separated; none by default, so no person can call it),
// FOREMAN_JWKS_URL (default: Google's keys; https only) and FOREMAN_ADDR (default :$PORT, PORT
// default 8080). At startup it compares the host's clock with the database's, and logs a skew
// beyond a few seconds as an error.
// Its risk evaluator reads FOREMAN_REPOS_DIR (the directory of bare repositories, one
// <project>.git each), FOREMAN_GIT_TIMEOUT and FOREMAN_GIT_MAX_OUTPUT (internal/risk_evaluator,
// FromEnv); without FOREMAN_REPOS_DIR it starts, and every approval escalates naming it.
//
// The dispatcher's tick reaps, gates, claims one ticket and launches it (internal/dispatcher); its
// log goes to standard error. With FOREMAN_LAUNCHER unset it launches nothing: each launch request
// is written as one JSON line to standard output, and new work reads the project's default branch
// with git ls-remote over https. With FOREMAN_LAUNCHER=cloudrun (the deployed dispatcher) it
// launches Cloud Run job executions, configured as internal/dispatcher/cloudrun's FromEnv
// describes, and reads heads with a GitHub App read token.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
	riskevaluator "github.com/ryanymt/mercurio-project/internal/risk_evaluator"
)

const usage = `usage: foreman <command> [arguments]

commands:
  migrate up       apply every pending migration to the DATABASE_URL database
  migrate status   list the migrations and which are applied
  callback-api     serve the callback API (see FOREMAN_* in the package documentation)
  dispatch         make one dispatcher tick and exit; launch requests go to standard output,
                   or to Cloud Run with FOREMAN_LAUNCHER=cloudrun
  project activate <id>
                   make that project the only active one
  db rights        report what the DATABASE_URL user can do, as JSON, changing nothing
  ticket create --as <email> --project <id> --title <text> [--body <text>] [--criteria <json>]
                   make a ticket as a person the identity map knows: a draft, or ready with
                   acceptance criteria ([{"id": "AC1", "text": "..."}])
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one command and returns the process exit status: 0 on success, 1 on failure,
// 2 on a usage error.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "callback-api" {
		return serveCallbackAPI(ctx, stderr)
	}
	if len(args) == 1 && args[0] == "dispatch" {
		return dispatch(ctx, stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "ticket" && args[1] == "create" {
		return createTicket(ctx, args[2:], stdout, stderr)
	}
	database := len(args) == 2 && args[0] == "migrate" && (args[1] == "up" || args[1] == "status") ||
		len(args) == 3 && args[0] == "project" && args[1] == "activate" ||
		len(args) == 2 && args[0] == "db" && args[1] == "rights"
	if !database {
		fmt.Fprint(stderr, usage)
		return 2
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		fmt.Fprintln(stderr, "foreman: DATABASE_URL is not set")
		return 2
	}
	conn, err := db.Open(ctx, url)
	if err != nil {
		fmt.Fprintln(stderr, "foreman:", err)
		return 1
	}
	defer conn.Close()

	switch args[0] {
	case "project":
		return activateProject(ctx, conn, args[2], stderr)
	case "db":
		return dbRights(ctx, conn, stdout, stderr)
	}
	if args[1] == "up" {
		res, err := db.Up(ctx, conn)
		for _, r := range res {
			if r.Error == nil {
				fmt.Fprintf(stdout, "applied %s (%s)\n", r.Source.Path, r.Duration.Round(time.Millisecond))
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "foreman:", err)
			return 1
		}
		v, err := db.Version(ctx, conn)
		if err != nil {
			fmt.Fprintln(stderr, "foreman:", err)
			return 1
		}
		fmt.Fprintf(stdout, "database at version %d (%d applied now)\n", v, len(res))
		return 0
	}

	st, err := db.Status(ctx, conn)
	if err != nil {
		fmt.Fprintln(stderr, "foreman:", err)
		return 1
	}
	for _, s := range st {
		when := "pending"
		if !s.AppliedAt.IsZero() {
			when = "applied " + s.AppliedAt.UTC().Format("2006-01-02 15:04:05Z")
		}
		fmt.Fprintf(stdout, "%05d  %-28s  %s\n", s.Source.Version, s.Source.Path, when)
	}
	return 0
}

// serveCallbackAPI runs the callback API until ctx ends (SIGINT or SIGTERM), then shuts down.
func serveCallbackAPI(ctx context.Context, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	fail := func(format string, a ...any) int {
		log.Error(fmt.Sprintf(format, a...))
		return 2
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return fail("DATABASE_URL is not set")
	}
	audience := os.Getenv("FOREMAN_SERVICE_AUDIENCE")
	if audience == "" {
		return fail("FOREMAN_SERVICE_AUDIENCE is not set: the audience service accounts mint their tokens for")
	}
	var humans []string
	for _, a := range strings.Split(os.Getenv("FOREMAN_HUMAN_AUDIENCES"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			humans = append(humans, a)
		}
	}
	addr := os.Getenv("FOREMAN_ADDR")
	if addr == "" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		addr = ":" + port
	}

	conn, err := db.Open(ctx, url)
	if err != nil {
		return fail("%v", err)
	}
	defer conn.Close()
	// Token expiry is judged by this host's clock (P05 Approach 6).
	callbackapi.CheckClock(ctx, conn, time.Now, log)
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		return fail("%v", err)
	}
	verifier, err := callbackapi.NewVerifier(ctx, callbackapi.VerifierConfig{
		JWKSURL: os.Getenv("FOREMAN_JWKS_URL"), ServiceAudience: audience, HumanAudiences: humans,
	}, ids)
	if err != nil {
		return fail("%v", err)
	}
	// The evaluator comes only from FromEnv, a protected function (P03 D13).
	engine := callbackapi.NewEngine(riskevaluator.FromEnv(log), log)
	srv := &http.Server{
		Addr:              addr,
		Handler:           callbackapi.NewServer(conn, engine, verifier, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("callback api listening", "addr", addr, "service_audience", audience,
		"human_audiences", len(humans), "identities", ids.Len())

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return fail("%v", err)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			return fail("shutdown: %v", err)
		}
	}
	log.Info("callback api stopped")
	return 0
}

// dispatch makes one tick against DATABASE_URL and exits: 0 when the tick ran, whatever it claimed;
// 1 when something is wrong that a person must fix; 2 when it cannot start.
func dispatch(ctx context.Context, stdout, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		log.Error("DATABASE_URL is not set")
		return 2
	}
	tiers, err := dispatcher.EmbeddedTiers()
	if err != nil {
		log.Error("the tier table refuses to load, so nothing launches", "error", err)
		return 2
	}
	git := riskevaluator.NewGit(riskevaluator.DefaultGitTimeout, riskevaluator.DefaultGitMaxOutput)
	if err := git.Err(); err != nil {
		log.Warn("git is unusable: no new work can be claimed", "error", err)
	}
	var launcher dispatcher.Launcher = dispatcher.NewRecordingLauncher(stdout)
	var remote dispatcher.Remote = git
	switch kind := os.Getenv("FOREMAN_LAUNCHER"); kind {
	case "":
	case "cloudrun":
		ids, err := callbackapi.EmbeddedIdentityMap()
		if err != nil {
			log.Error("the identity map refuses to load, so nothing launches", "error", err)
			return 2
		}
		l, tokens, err := cloudrun.FromEnv(os.Getenv, ids, log)
		if err != nil {
			log.Error("the Cloud Run launcher is misconfigured, so nothing launches", "error", err)
			return 2
		}
		// Heads are read with a read token for the project's repository (P05 Approach 3).
		launcher, remote = l, github.Remote{Tokens: tokens, Git: git}
	default:
		log.Error("FOREMAN_LAUNCHER names no launcher (cloudrun, or unset to record)", "launcher", kind)
		return 2
	}
	conn, err := db.Open(ctx, url)
	if err != nil {
		log.Error(err.Error())
		return 2
	}
	defer conn.Close()
	// The engine's evaluator comes only from FromEnv (P03 D13). The dispatcher never asks it for a
	// verdict, so its startup warning about the repositories would only be noise here.
	quiet := slog.New(slog.NewJSONHandler(io.Discard, nil))
	engine := callbackapi.NewEngine(riskevaluator.FromEnv(quiet), log)
	d := dispatcher.New(conn, engine, tiers, remote, launcher, log)
	if _, err := d.Tick(ctx); err != nil {
		log.Error("dispatch tick failed", "error", err)
		return 1
	}
	return 0
}

// createTicket makes one ticket through the core as a person the identity map knows (P05 T8). A
// person's gcloud ID token does not reach the deployed API intact (Cloud Run alters it), so until
// P06 the operator runs this as an execution of the dispatcher job, whose database user is `app`.
// Only someone who may run that job with overrides can, so the person named by --as is the
// operator's own word: it is recorded as the event's actor, and Cloud Run's audit log records who
// ran the execution. Its arguments are checked before the database is opened.
func createTicket(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	fs := flag.NewFlagSet("ticket create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	as := fs.String("as", "", "the person creating it: a human in the identity map")
	project := fs.String("project", "", "the project it belongs to")
	title := fs.String("title", "", "its title")
	body := fs.String("body", "", "its body")
	criteria := fs.String("criteria", "", `its acceptance criteria as JSON, [{"id": "AC1", "text": "..."}]; without, a draft`)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case fs.NArg() > 0:
		log.Error("unexpected arguments", "args", fs.Args())
		return 2
	case *as == "" || *project == "" || *title == "":
		log.Error("--as, --project and --title are required")
		return 2
	}
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		log.Error("the identity map refuses to load", "error", err)
		return 2
	}
	caller, ok := ids.Lookup(*as)
	if !ok || caller.Role != callbackapi.RoleHuman {
		log.Error("the identity map knows no person by that email", "as", *as)
		return 2
	}
	var ac []callbackapi.Criterion
	if *criteria != "" {
		dec := json.NewDecoder(strings.NewReader(*criteria))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ac); err != nil {
			log.Error("--criteria is not a JSON list of criteria", "error", err)
			return 2
		}
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		log.Error("DATABASE_URL is not set")
		return 2
	}
	conn, err := db.Open(ctx, url)
	if err != nil {
		log.Error(err.Error())
		return 1
	}
	defer conn.Close()
	// The engine's evaluator comes only from FromEnv (P03 D13); creating a ticket never asks it.
	engine := callbackapi.NewEngine(riskevaluator.FromEnv(slog.New(slog.NewJSONHandler(io.Discard, nil))), log)
	tx, err := callbackapi.BeginTx(ctx, conn)
	if err != nil {
		log.Error(err.Error())
		return 1
	}
	defer tx.Rollback()
	res, err := engine.Create(ctx, tx, callbackapi.CreateRequest{Caller: caller, Project: *project, Title: *title,
		Body: *body, AcceptanceCriteria: ac, RequestID: newRequestID(), Method: "CLI", Path: "foreman ticket create"})
	if err != nil {
		log.Error("ticket not created", "error", err)
		return 1
	}
	if err := tx.Commit(); err != nil {
		log.Error("ticket not created", "error", err)
		return 1
	}
	log.Info("ticket created", "ticket", res.TicketID, "project", res.Project, "state", res.State, "as", caller.Email)
	if err := json.NewEncoder(stdout).Encode(res); err != nil {
		return 1
	}
	return 0
}

// newRequestID is a random (version 4) UUID, the form the core takes as an idempotency key.
func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// activateProject makes one project the only active one (P05 D18), logging what it did.
func activateProject(ctx context.Context, conn *sql.DB, id string, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	if err := db.ActivateProject(ctx, conn, id); err != nil {
		log.Error("project not activated", "project", id, "error", err)
		return 1
	}
	log.Info("project activated", "project", id)
	return 0
}

// dbRights prints what the connected database user can do, as one JSON object (P05 D11).
func dbRights(ctx context.Context, conn *sql.DB, stdout, stderr io.Writer) int {
	r, err := db.ReportRights(ctx, conn)
	if err != nil {
		fmt.Fprintln(stderr, "foreman:", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(r); err != nil {
		fmt.Fprintln(stderr, "foreman:", err)
		return 1
	}
	return 0
}
