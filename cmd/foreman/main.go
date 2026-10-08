// Command foreman is the operator CLI for the foreman control plane.
//
//	foreman migrate up       apply every pending migration
//	foreman migrate status   list the migrations and which are applied
//	foreman callback-api     serve the callback API
//	foreman viewer           serve the viewer, behind IAP
//	foreman dispatch         make one dispatcher tick and exit
//	foreman project activate <id>   make that project the only active one
//	foreman db rights        report what the database user can do
//
// The database is the one DATABASE_URL points at, a postgres:// URL. The callback API also reads
// FOREMAN_SERVICE_AUDIENCE (required: the audience service accounts mint their tokens for),
// FOREMAN_IAP_AUDIENCE (the viewer's IAP audience, /projects/<number>/locations/<region>/services/
// viewer: a person acts only through the viewer, which relays their IAP assertion; unset, no person
// can act, and it says so at startup), FOREMAN_JWKS_URL and FOREMAN_IAP_JWKS_URL (default: Google's
// and IAP's keys; https only) and FOREMAN_ADDR (default :$PORT, PORT default 8080). A person's own
// token is never accepted. At startup it compares the host's clock with the database's, and logs a
// skew beyond a few seconds as an error.
// Its risk evaluator reads FOREMAN_REPOS_DIR (the directory of bare repositories, one
// <project>.git each), FOREMAN_GIT_TIMEOUT and FOREMAN_GIT_MAX_OUTPUT (internal/risk_evaluator,
// FromEnv); without FOREMAN_REPOS_DIR it starts, and every approval escalates naming it.
//
// The viewer (internal/viewer) reads FOREMAN_ADDR as the callback API does, and:
//
//	DATABASE_URL                   its own database user's, which may only read (P06 D7)
//	FOREMAN_IAP_AUDIENCE           its IAP audience; FOREMAN_IAP_JWKS_URL as the callback API's
//	FOREMAN_CALLBACK_URL           the callback API, where a person's acts are relayed; also the
//	                               audience of the viewer's ID token
//	FOREMAN_ORIGINS                its own origins, comma-separated, https
//	FOREMAN_ARTIFACTS_BUCKET       the bucket of transcripts and test output
//	FOREMAN_CSRF_KEY_SECRET        the secret version holding the CSRF key, read at startup
//	FOREMAN_GITHUB_APP_ID_SECRET   the secret versions holding the read-only App's id and key (D6),
//	FOREMAN_GITHUB_APP_KEY_SECRET  read when a token is minted
//
// and, for tests, GCE_METADATA_HOST, FOREMAN_SECRETMANAGER_API, FOREMAN_GITHUB_API and
// FOREMAN_STORAGE_API in place of the real endpoints. Before it listens it checks that its
// database user reads what it shows and can write nothing, logs what it found, and refuses to
// start otherwise.
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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/db"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
	riskevaluator "github.com/ryanymt/mercurio-project/internal/risk_evaluator"
	"github.com/ryanymt/mercurio-project/internal/viewer"
)

const usage = `usage: foreman <command> [arguments]

commands:
  migrate up       apply every pending migration to the DATABASE_URL database
  migrate status   list the migrations and which are applied
  callback-api     serve the callback API (see FOREMAN_* in the package documentation)
  viewer           serve the viewer, reached only through IAP (see FOREMAN_* in the package
                   documentation)
  dispatch         make one dispatcher tick and exit; launch requests go to standard output,
                   or to Cloud Run with FOREMAN_LAUNCHER=cloudrun
  project activate <id>
                   make that project the only active one
  db rights        report what the DATABASE_URL user can do, as JSON, changing nothing
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
	if len(args) == 1 && args[0] == "viewer" {
		return serveViewer(ctx, stderr)
	}
	if len(args) == 1 && args[0] == "dispatch" {
		return dispatch(ctx, stdout, stderr)
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
	iapAudience := os.Getenv("FOREMAN_IAP_AUDIENCE")
	addr := listenAddr()

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
		JWKSURL: os.Getenv("FOREMAN_JWKS_URL"), ServiceAudience: audience,
		IAPJWKSURL: os.Getenv("FOREMAN_IAP_JWKS_URL"), IAPAudience: iapAudience,
	}, ids)
	if err != nil {
		return fail("%v", err)
	}
	if iapAudience == "" {
		log.Warn("FOREMAN_IAP_AUDIENCE is not set: no person can act, since a person acts only through the viewer")
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
		"iap_audience", iapAudience, "identities", ids.Len())

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

// listenAddr is FOREMAN_ADDR, or :$PORT (Cloud Run's), or :8080.
func listenAddr() string {
	if addr := os.Getenv("FOREMAN_ADDR"); addr != "" {
		return addr
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return ":" + port
}

// secretVersion is a Secret Manager version's name.
var secretVersion = regexp.MustCompile(`^projects/[^/]+/secrets/[^/]+/versions/(latest|[1-9][0-9]*)$`)

// viewerOrigins reads FOREMAN_ORIGINS: each an https origin, a scheme and a host and nothing more.
func viewerOrigins(raw string) ([]string, error) {
	var out []string
	for _, o := range strings.Split(raw, ",") {
		u, err := url.Parse(strings.TrimSpace(o))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("FOREMAN_ORIGINS: %q is not an https origin", o)
		}
		out = append(out, u.Scheme+"://"+u.Host)
	}
	return out, nil
}

// serveViewer runs the viewer until ctx ends (SIGINT or SIGTERM), then shuts down. It refuses to
// start (2) when its configuration is missing or wrong, or its database user could write.
func serveViewer(ctx context.Context, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	fail := func(format string, a ...any) int {
		log.Error(fmt.Sprintf(format, a...))
		return 2
	}
	for _, name := range []string{"DATABASE_URL", "FOREMAN_IAP_AUDIENCE", "FOREMAN_CALLBACK_URL", "FOREMAN_ORIGINS",
		"FOREMAN_ARTIFACTS_BUCKET"} {
		if os.Getenv(name) == "" {
			return fail("%s is not set", name)
		}
	}
	for _, name := range []string{"FOREMAN_CSRF_KEY_SECRET", "FOREMAN_GITHUB_APP_ID_SECRET", "FOREMAN_GITHUB_APP_KEY_SECRET"} {
		if v := os.Getenv(name); !secretVersion.MatchString(v) {
			return fail("%s = %q is not a secret version's name (projects/P/secrets/S/versions/N or latest)", name, v)
		}
	}
	origins, err := viewerOrigins(os.Getenv("FOREMAN_ORIGINS"))
	if err != nil {
		return fail("%v", err)
	}
	metadataHost := os.Getenv("GCE_METADATA_HOST")
	gcp, err := cloudrun.NewGCP(cloudrun.Endpoints{MetadataHost: metadataHost, SecretManager: os.Getenv("FOREMAN_SECRETMANAGER_API")}, nil)
	if err != nil {
		return fail("%v", err)
	}
	md := viewer.NewMetadata(metadataHost, nil)
	relay, err := viewer.NewHTTPRelay(os.Getenv("FOREMAN_CALLBACK_URL"), md.IDToken, nil)
	if err != nil {
		return fail("FOREMAN_CALLBACK_URL: %v", err)
	}
	storage := os.Getenv("FOREMAN_STORAGE_API")
	if storage == "" {
		storage = viewer.GCSEndpoint
	}
	chunks, err := viewer.NewGCSChunks(storage, os.Getenv("FOREMAN_ARTIFACTS_BUCKET"), md.AccessToken, nil)
	if err != nil {
		return fail("%v", err)
	}
	diffs, err := viewer.NewGitHubDiffs(cloudrun.SecretCredentials(gcp, os.Getenv("FOREMAN_GITHUB_APP_ID_SECRET"),
		os.Getenv("FOREMAN_GITHUB_APP_KEY_SECRET")), os.Getenv("FOREMAN_GITHUB_API"), nil)
	if err != nil {
		return fail("%v", err)
	}
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		return fail("%v", err)
	}
	// The viewer verifies only IAP's assertions (VerifyRelayed); the service audience the verifier
	// requires is its own origin, and no service token is ever asked of it.
	verifier, err := callbackapi.NewVerifier(ctx, callbackapi.VerifierConfig{ServiceAudience: origins[0],
		IAPJWKSURL: os.Getenv("FOREMAN_IAP_JWKS_URL"), IAPAudience: os.Getenv("FOREMAN_IAP_AUDIENCE")}, ids)
	if err != nil {
		return fail("%v", err)
	}

	conn, err := db.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return fail("%v", err)
	}
	defer conn.Close()
	rights, err := viewer.CheckRights(ctx, conn)
	if err != nil {
		return fail("the viewer refuses to start: %v", err)
	}
	log.Info("viewer database rights", "user", rights.User, "reads", rights.Reads, "writes", rights.Writes)
	key, err := gcp.AccessSecret(ctx, os.Getenv("FOREMAN_CSRF_KEY_SECRET"))
	if err != nil {
		return fail("the CSRF key: %v", err)
	}
	s, err := viewer.New(viewer.Config{DB: conn, Identify: verifier.VerifyRelayed, Chunks: chunks, Diffs: diffs,
		Relay: relay, CSRFKey: key, Origins: origins, Log: log})
	if err != nil {
		return fail("%v", err)
	}

	ln, err := net.Listen("tcp", listenAddr())
	if err != nil {
		return fail("%v", err)
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("viewer listening", "addr", ln.Addr().String(), "iap_audience", os.Getenv("FOREMAN_IAP_AUDIENCE"),
		"origins", origins, "identities", ids.Len())

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
	log.Info("viewer stopped")
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
