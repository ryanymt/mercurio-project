// Package cloudrun is the deployed dispatcher's launcher (P05 Approach 4): a claim becomes one
// execution of its role and project's Cloud Run job, and the runner's GitHub token reaches it
// through Secret Manager, never through Cloud Run (D17). It is a package of its own, protected
// with the dispatcher's, so the tick's package imports nothing that talks to the network (D13).
package cloudrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
)

// Job is the Cloud Run job that runs one role for one project (D20), the account it runs as, and
// the secret its runner's token is handed over in.
type Job struct {
	Role        callbackapi.Role `json:"role"`
	Project     string           `json:"project"`
	Job         string           `json:"job"`          // projects/P/locations/L/jobs/J
	Account     string           `json:"account"`      // the job's service account
	TokenSecret string           `json:"token_secret"` // projects/P/secrets/S
}

// Config is the launcher's configuration.
type Config struct {
	Jobs        []Job
	CallbackURL string // the callback API, as runners call it
	Audience    string // the audience runners ask their ID tokens for (D19)
}

// Launcher launches claims as Cloud Run job executions.
type Launcher struct {
	jobs     []Job
	callback string
	audience string
	gcp      *GCP
	tokens   *github.Client
	ids      *callbackapi.IdentityMap
	log      *slog.Logger
}

// New checks the configuration against the identity map, so a deployment that could never launch
// fails at once rather than claiming tickets.
func New(cfg Config, gcp *GCP, tokens *github.Client, ids *callbackapi.IdentityMap, log *slog.Logger) (*Launcher, error) {
	if gcp == nil || tokens == nil || ids == nil {
		return nil, errors.New("the launcher needs Google's APIs, a token minter and the identity map")
	}
	if len(cfg.Jobs) == 0 {
		return nil, errors.New("no runner jobs: nothing could be launched")
	}
	if u, err := url.Parse(cfg.CallbackURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("the callback URL %q is not an https URL", cfg.CallbackURL)
	}
	if cfg.Audience == "" {
		return nil, errors.New("no audience for the runners' ID tokens")
	}
	seen := map[string]bool{}
	for _, j := range cfg.Jobs {
		want, err := dispatcher.ServiceAccount(j.Role, j.Project)
		if err != nil {
			return nil, fmt.Errorf("job %s: %w", j.Job, err)
		}
		switch {
		case j.Account != want:
			return nil, fmt.Errorf("job %s runs as %s, but a %s runner for %s runs as %s", j.Job, j.Account, j.Role, j.Project, want)
		case !jobPattern.MatchString(j.Job):
			return nil, fmt.Errorf("%q is not a job's name (projects/P/locations/L/jobs/J)", j.Job)
		case !secretPattern.MatchString(j.TokenSecret):
			return nil, fmt.Errorf("job %s: %q is not a secret's name (projects/P/secrets/S)", j.Job, j.TokenSecret)
		case seen[string(j.Role)+"/"+j.Project]:
			return nil, fmt.Errorf("two jobs launch %s for %s", j.Role, j.Project)
		}
		seen[string(j.Role)+"/"+j.Project] = true
		if err := checkIdentity(ids, j); err != nil {
			return nil, err
		}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Launcher{jobs: append([]Job(nil), cfg.Jobs...), callback: cfg.CallbackURL, audience: cfg.Audience,
		gcp: gcp, tokens: tokens, ids: ids, log: log}, nil
}

// checkIdentity refuses a job whose account the callback API would not take as that role for that
// project.
func checkIdentity(ids *callbackapi.IdentityMap, j Job) error {
	c, ok := ids.Lookup(j.Account)
	if !ok || c.Role != j.Role || c.Project != j.Project {
		return fmt.Errorf("the identity map does not know %s as the %s runner for %s: refused", j.Account, j.Role, j.Project)
	}
	return nil
}

// Roles names the roles with a job for the project, in the configuration's order.
func (l *Launcher) Roles(project string) []callbackapi.Role {
	var out []callbackapi.Role
	for _, j := range l.jobs {
		if j.Project == project {
			out = append(out, j.Role)
		}
	}
	return out
}

// Launch mints the runner's write token, adds it as version N of the job's token secret, runs the
// job with the launch request, the callback URL and audience, the secret and N as environment
// overrides, and then destroys the secret's enabled versions older than N (D17). An error means
// no execution was created; an uncertain outcome returns none, and the lease is reaped (P04 D10).
func (l *Launcher) Launch(ctx context.Context, req dispatcher.LaunchRequest) (string, error) {
	job, err := l.jobFor(req)
	if err != nil {
		return "", err
	}
	repo, err := github.RepoFromURL(req.RepoURL)
	if err != nil {
		return "", err
	}
	request, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	tok, err := l.tokens.Token(ctx, repo, github.ContentsWrite)
	if err != nil {
		return "", fmt.Errorf("the runner's token: %w", err)
	}
	n, err := l.gcp.AddSecretVersion(ctx, job.TokenSecret, []byte(tok.Value()))
	if err != nil {
		return "", fmt.Errorf("hand the runner's token over: %w", err)
	}
	execution, err := l.gcp.RunJob(ctx, job.Job, []EnvVar{
		{Name: "FOREMAN_LAUNCH_REQUEST", Value: string(request)},
		{Name: "FOREMAN_CALLBACK_URL", Value: l.callback},
		{Name: "FOREMAN_CALLBACK_AUDIENCE", Value: l.audience},
		{Name: "FOREMAN_TOKEN_SECRET", Value: job.TokenSecret},
		{Name: "FOREMAN_TOKEN_VERSION", Value: strconv.FormatInt(n, 10)},
	})
	var uncertain *UncertainError
	if errors.As(err, &uncertain) {
		l.log.Warn("jobs.run's outcome is unknown; if nothing started, the lease will be reaped",
			"ticket", req.TicketID, "job", job.Job, "error", err)
		err = nil
	}
	l.destroyOlder(ctx, job.TokenSecret, n)
	if err != nil {
		return "", fmt.Errorf("jobs.run %s: %w", job.Job, err)
	}
	if execution == "" && uncertain == nil {
		l.log.Warn("jobs.run named no execution", "ticket", req.TicketID, "job", job.Job)
	}
	return execution, nil
}

// jobFor finds the request's job, refusing it before any call when the account is not the job's
// or the identity map would not take the job's account as that runner.
func (l *Launcher) jobFor(req dispatcher.LaunchRequest) (Job, error) {
	for _, j := range l.jobs {
		if j.Role != req.Role || j.Project != req.Project {
			continue
		}
		if req.ServiceAccount != j.Account {
			return Job{}, fmt.Errorf("the request runs as %s, but the %s job for %s runs as %s: refused",
				req.ServiceAccount, j.Role, j.Project, j.Account)
		}
		if err := checkIdentity(l.ids, j); err != nil {
			return Job{}, err
		}
		return j, nil
	}
	return Job{}, fmt.Errorf("no job launches %s for %s", req.Role, req.Project)
}

// destroyOlder destroys the secret's enabled versions older than n. A failure is logged, never
// returned: the run has been asked for, and the next launch tries again.
func (l *Launcher) destroyOlder(ctx context.Context, secret string, n int64) {
	versions, err := l.gcp.EnabledVersions(ctx, secret)
	if err != nil {
		l.log.Warn("older token versions not listed, so not destroyed; the next launch tries again", "secret", secret, "error", err)
		return
	}
	for _, v := range versions {
		if v >= n {
			continue
		}
		if err := l.gcp.DestroySecretVersion(ctx, secret, v); err != nil {
			l.log.Warn("an older token version was not destroyed; the next launch tries again",
				"secret", secret, "version", v, "error", err)
		}
	}
}

// SecretCredentials reads the App's id and private key from Secret Manager whenever a token is
// minted (P05 Approach 2), so neither is in the dispatcher's environment.
func SecretCredentials(g *GCP, appIDVersion, keyVersion string) github.Credentials {
	return func(ctx context.Context) (string, []byte, error) {
		id, err := g.AccessSecret(ctx, appIDVersion)
		if err != nil {
			return "", nil, fmt.Errorf("the App's id: %w", err)
		}
		key, err := g.AccessSecret(ctx, keyVersion)
		if err != nil {
			return "", nil, fmt.Errorf("the App's key: %w", err)
		}
		return strings.TrimSpace(string(id)), key, nil
	}
}
