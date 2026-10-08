// Package runner is the echo runner (P05 Approach 5): the loop end to end with no model in it. The
// dispatcher's Cloud Run launcher starts it as its ticket's dev runner. It reads its GitHub token
// from Secret Manager by number, takes the ticket from claimed to in_progress, starts capturing
// (internal/capture: both prefixes registered on the ticket at once), heartbeats, probes its bucket
// rights, writes a canary, clones the repository at base_sha, commits one file under echo/, checks
// it, holds, heartbeats again, force-pushes its own branch, stores its transcript, and submits the
// commit for review, or, when its ticket's title holds [echo:escalate], escalates naming the
// commit (P06 D14, D21). Any refused call ends it at once, its transcript saying why. It links no
// control-plane package (D12): its account and its token are all it holds.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ryanymt/mercurio-project/internal/capture"
)

// Request is the part of the dispatcher's launch request the runner uses; its JSON names are the
// dispatcher's (internal/dispatcher.LaunchRequest), and fields it does not use are ignored.
type Request struct {
	TicketID       int64  `json:"ticket_id"`
	Project        string `json:"project"`
	RepoURL        string `json:"repo_url"`
	Role           string `json:"role"`
	ServiceAccount string `json:"service_account"`
	Branch         string `json:"branch"`
	BaseSHA        string `json:"base_sha"`
	ClaimToken     string `json:"claim_token"`
	Attempt        int    `json:"attempt"`
	Title          string `json:"title"` // the ticket's, cut by the dispatcher: the runner's instruction
}

// EscalateMarker in a ticket's title makes the echo runner stop for a person after pushing.
const EscalateMarker = "[echo:escalate]"

// Harness and TranscriptFormat name the echo runner's transcripts: each stream's first line says
// them, and the viewer reads the lines through the adapter they name (P06 D22).
const (
	Harness          = "echo-runner"
	TranscriptFormat = "echo-steps"
	transcriptLayout = "1" // the version of the echo runner's lines
)

var (
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	secretPattern  = regexp.MustCompile(`^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]+$`)
	bucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
	accountPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*@[a-z0-9.-]+$`)
)

// ParseRequest reads a launch request and refuses one the echo runner cannot act on: another
// role, a branch that is not the ticket's own for its attempt, a base that is not a commit.
func ParseRequest(raw string) (Request, error) {
	var r Request
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return Request{}, fmt.Errorf("the launch request is not JSON: %w", err)
	}
	switch {
	case r.Role != "dev":
		return Request{}, fmt.Errorf("the launch request's role is %q: the echo runner plays dev", r.Role)
	case r.TicketID <= 0 || r.Attempt <= 0:
		return Request{}, fmt.Errorf("the launch request names ticket %d, attempt %d", r.TicketID, r.Attempt)
	case r.Branch != fmt.Sprintf("foreman/%d/%d", r.TicketID, r.Attempt):
		return Request{}, fmt.Errorf("the launch request's branch %q is not the ticket's own for its attempt", r.Branch)
	case !shaPattern.MatchString(r.BaseSHA):
		return Request{}, fmt.Errorf("the launch request's base_sha %q is not a commit", r.BaseSHA)
	case r.ClaimToken == "":
		return Request{}, errors.New("the launch request has no claim_token")
	case r.RepoURL == "" || strings.HasPrefix(r.RepoURL, "-"):
		return Request{}, fmt.Errorf("the launch request's repo_url %q is not a repository", r.RepoURL)
	case !accountPattern.MatchString(r.ServiceAccount):
		return Request{}, fmt.Errorf("the launch request's service_account %q is not an account", r.ServiceAccount)
	}
	return r, nil
}

// DefaultHeartbeatEvery keeps a runner's lease well inside the contract's once a minute.
const DefaultHeartbeatEvery = 30 * time.Second

// Config is one run.
type Config struct {
	Request         Request
	CallbackURL     string        // the callback API
	Audience        string        // the audience of the runner's ID tokens (D19)
	TokenSecret     string        // projects/P/secrets/S, holding the GitHub token
	TokenVersion    int64         // the version this launch added (D17)
	Hold            time.Duration // how long to hold between the commit and the push (R14)
	HeartbeatEvery  time.Duration // the most time between two heartbeats while holding
	MetadataHost    string        // host[:port]; the metadata server by default
	SecretManager   string        // Secret Manager's base URL; Google's by default
	GitProtocols    string        // what git may use, as GIT_ALLOW_PROTOCOL: https in the job
	ArtifactsBucket string        // the private bucket the transcript goes to
	StorageAPI      string        // Cloud Storage's base URL; Google's by default
	CaptureInterval time.Duration // the longest a transcript line waits; capture's default when 0
	Log             *slog.Logger
}

// FromEnv reads the job's environment: the overrides the launcher sets (FOREMAN_LAUNCH_REQUEST,
// FOREMAN_CALLBACK_URL, FOREMAN_CALLBACK_AUDIENCE, FOREMAN_TOKEN_SECRET, FOREMAN_TOKEN_VERSION),
// the job's ECHO_HOLD_SECONDS and FOREMAN_ARTIFACTS_BUCKET, and, for tests, GCE_METADATA_HOST,
// FOREMAN_SECRETMANAGER_API and FOREMAN_STORAGE_API. Whatever is missing or wrong is named.
func FromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{GitProtocols: "https", HeartbeatEvery: DefaultHeartbeatEvery}
	raw := getenv("FOREMAN_LAUNCH_REQUEST")
	if raw == "" {
		return Config{}, errors.New("FOREMAN_LAUNCH_REQUEST is not set")
	}
	req, err := ParseRequest(raw)
	if err != nil {
		return Config{}, fmt.Errorf("FOREMAN_LAUNCH_REQUEST: %w", err)
	}
	cfg.Request = req
	if cfg.CallbackURL = getenv("FOREMAN_CALLBACK_URL"); cfg.CallbackURL == "" {
		return Config{}, errors.New("FOREMAN_CALLBACK_URL is not set")
	}
	if err := checkBaseURL(cfg.CallbackURL); err != nil {
		return Config{}, fmt.Errorf("FOREMAN_CALLBACK_URL: %w", err)
	}
	if cfg.Audience = getenv("FOREMAN_CALLBACK_AUDIENCE"); cfg.Audience == "" {
		return Config{}, errors.New("FOREMAN_CALLBACK_AUDIENCE is not set")
	}
	if cfg.TokenSecret = getenv("FOREMAN_TOKEN_SECRET"); !secretPattern.MatchString(cfg.TokenSecret) {
		return Config{}, fmt.Errorf("FOREMAN_TOKEN_SECRET = %q is not a secret's name (projects/P/secrets/S)", cfg.TokenSecret)
	}
	v := getenv("FOREMAN_TOKEN_VERSION")
	if cfg.TokenVersion, err = strconv.ParseInt(v, 10, 64); err != nil || cfg.TokenVersion < 1 {
		return Config{}, fmt.Errorf("FOREMAN_TOKEN_VERSION = %q is not a version number", v)
	}
	if h := getenv("ECHO_HOLD_SECONDS"); h != "" {
		s, err := strconv.Atoi(h)
		if err != nil || s < 0 {
			return Config{}, fmt.Errorf("ECHO_HOLD_SECONDS = %q is not a number of seconds", h)
		}
		cfg.Hold = time.Duration(s) * time.Second
	}
	if cfg.MetadataHost = getenv("GCE_METADATA_HOST"); cfg.MetadataHost != "" && !validHost(cfg.MetadataHost) {
		return Config{}, fmt.Errorf("GCE_METADATA_HOST = %q is not a host[:port]", cfg.MetadataHost)
	}
	if cfg.SecretManager = getenv("FOREMAN_SECRETMANAGER_API"); cfg.SecretManager != "" {
		if err := checkBaseURL(cfg.SecretManager); err != nil {
			return Config{}, fmt.Errorf("FOREMAN_SECRETMANAGER_API: %w", err)
		}
	}
	if cfg.ArtifactsBucket = getenv("FOREMAN_ARTIFACTS_BUCKET"); !bucketPattern.MatchString(cfg.ArtifactsBucket) {
		return Config{}, fmt.Errorf("FOREMAN_ARTIFACTS_BUCKET = %q is not a bucket's name", cfg.ArtifactsBucket)
	}
	if cfg.StorageAPI = getenv("FOREMAN_STORAGE_API"); cfg.StorageAPI != "" {
		if err := checkBaseURL(cfg.StorageAPI); err != nil {
			return Config{}, fmt.Errorf("FOREMAN_STORAGE_API: %w", err)
		}
	}
	return cfg, nil
}

// checkBaseURL accepts an https base URL, or plain http to a loopback address (the tests').
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q is not a base URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%q is not https", raw)
}

func validHost(h string) bool { return h != "" && !strings.ContainsAny(h, "/@?# \t\\") }

// Run takes the ticket from claimed to awaiting_review, or to escalated when its title asks. It
// stops at the first failure, with an error, and sends nothing more: a refused call is never
// retried. Once capturing, it stores its transcript on the way out, whatever stopped it.
func Run(ctx context.Context, cfg Config) (err error) {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = DefaultHeartbeatEvery
	}
	storage := cfg.StorageAPI
	if storage == "" {
		storage = capture.GCSEndpoint
	}
	storage = strings.TrimSuffix(storage, "/")
	req := cfg.Request
	g := newGoogle(cfg.MetadataHost, cfg.SecretManager)
	token, err := g.secret(ctx, fmt.Sprintf("%s/versions/%d", cfg.TokenSecret, cfg.TokenVersion))
	if err != nil {
		return fmt.Errorf("the GitHub token: %w", err)
	}
	a := &api{base: strings.TrimSuffix(cfg.CallbackURL, "/"), audience: cfg.Audience, ids: g, http: g.http,
		ticket: req.TicketID, claim: req.ClaimToken}
	if err := a.transition(ctx, "claimed", "in_progress", "", nil); err != nil {
		return err
	}
	log.Info("started", "ticket", req.TicketID, "attempt", req.Attempt, "branch", req.Branch)

	// Capture starts at once, registering both prefixes before anything else (P06 Approach 3). The
	// runner's own secrets are redacted wherever they would appear.
	store, err := capture.NewGCS(storage, cfg.ArtifactsBucket, capture.TokenFunc(g.accessToken), g.http)
	if err != nil {
		return err
	}
	run := capture.NewRun()
	c, err := capture.Start(ctx, capture.Config{Project: req.Project, Ticket: req.TicketID, Attempt: req.Attempt,
		Role: req.Role, Run: run, Store: store, Registrar: a, Known: []string{string(token), req.ClaimToken},
		Interval: cfg.CaptureInterval, Log: log})
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			c.Event(capture.Transcript, map[string]any{"step": "stopped", "error": err.Error()})
		}
		closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), callTimeout)
		defer cancel()
		if cerr := c.Close(closing); cerr != nil {
			log.Error("the transcript was not all stored", "ticket", req.TicketID, "error", cerr)
		}
	}()
	for _, k := range []capture.Kind{capture.Transcript, capture.TestReport} {
		c.Event(k, map[string]string{"harness": Harness, "version": transcriptLayout, "format": TranscriptFormat})
	}
	step := func(name string, kv ...any) {
		line := map[string]any{"step": name}
		for i := 0; i+1 < len(kv); i += 2 {
			line[fmt.Sprint(kv[i])] = kv[i+1]
		}
		c.Event(capture.Transcript, line)
	}
	step("started", "ticket", req.TicketID, "attempt", req.Attempt, "branch", req.Branch, "run", run)
	if err := a.heartbeat(ctx); err != nil {
		return err
	}
	probe(ctx, c, g, storage, cfg.ArtifactsBucket, req.Project, run)
	step("canary", "value", canary())

	git, err := newGit(cfg.GitProtocols, string(token), req.ServiceAccount)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "echo-runner-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	work := filepath.Join(dir, "repo")
	if _, err := git.run(ctx, dir, "clone", "--quiet", "--no-checkout", "--", req.RepoURL, work); err != nil {
		return err
	}
	if _, err := git.run(ctx, work, "checkout", "--quiet", "-B", req.Branch, req.BaseSHA); err != nil {
		return err
	}
	step("cloned", "base_sha", req.BaseSHA)
	file := filepath.Join("echo", fmt.Sprintf("%d.txt", req.TicketID))
	if err := os.MkdirAll(filepath.Join(work, "echo"), 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("ticket %d, attempt %d, echoed by %s at %s\n", req.TicketID, req.Attempt, req.ServiceAccount,
		time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(work, file), []byte(content), 0o644); err != nil {
		return err
	}
	if _, err := git.run(ctx, work, "add", "--", file); err != nil {
		return err
	}
	msg := fmt.Sprintf("echo: ticket %d, attempt %d", req.TicketID, req.Attempt)
	if _, err := git.run(ctx, work, "commit", "--quiet", "--no-verify", "-m", msg); err != nil {
		return err
	}
	head, err := git.run(ctx, work, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if !shaPattern.MatchString(head) {
		return fmt.Errorf("git named the commit %q", head)
	}
	step("committed", "head_sha", head, "file", file)
	// The echo runner's test: the committed file holds what was written.
	committed, err := git.run(ctx, work, "show", "HEAD:"+filepath.ToSlash(file))
	ok := err == nil && committed == strings.TrimSpace(content)
	c.Event(capture.TestReport, map[string]any{"test": "echo file", "file": filepath.ToSlash(file), "ok": ok})
	if !ok {
		return fmt.Errorf("the committed %s does not hold what was written", file)
	}

	if err := hold(ctx, cfg.Hold, cfg.HeartbeatEvery, a.heartbeat); err != nil {
		return err
	}
	if _, err := git.run(ctx, work, "push", "--quiet", "--force", "origin", "HEAD:refs/heads/"+req.Branch); err != nil {
		return err
	}
	step("pushed", "branch", req.Branch, "head_sha", head)
	log.Info("pushed", "ticket", req.TicketID, "branch", req.Branch, "head_sha", head)
	// The transcript is stored before the call that ends the lease (P06 Approach 3); a failure is
	// logged, and the run goes on: Close tries again.
	if err := c.Flush(ctx); err != nil {
		log.Error("the transcript was not stored before the lease ends", "ticket", req.TicketID, "error", err)
	}
	if strings.Contains(req.Title, EscalateMarker) {
		reason := "the ticket's title asks the echo runner to stop for a person after pushing (" + EscalateMarker + ")"
		if err := a.transition(ctx, "in_progress", "escalated", head, map[string]any{"reason": reason}); err != nil {
			return err
		}
		step("escalated", "head_sha", head, "reason", reason)
		log.Info("escalated for a person", "ticket", req.TicketID, "head_sha", head)
		return nil
	}
	if err := a.transition(ctx, "in_progress", "awaiting_review", head, nil); err != nil {
		return err
	}
	step("submitted", "head_sha", head)
	log.Info("submitted for review", "ticket", req.TicketID, "head_sha", head)
	return nil
}

// hold waits d, heartbeating at least every interval within it and once at its end.
func hold(ctx context.Context, d, every time.Duration, heartbeat func(context.Context) error) error {
	end := time.Now().Add(d)
	for {
		left := time.Until(end)
		if left <= 0 {
			break
		}
		t := time.NewTimer(min(left, every))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if time.Until(end) > 0 {
			if err := heartbeat(ctx); err != nil {
				return err
			}
		}
	}
	return heartbeat(ctx)
}
