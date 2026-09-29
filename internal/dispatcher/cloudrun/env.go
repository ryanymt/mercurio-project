package cloudrun

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
)

// FromEnv configures the launcher, and the token minter the dispatcher's Remote shares with it,
// from the deployed dispatcher's environment:
//
//	FOREMAN_RUNNER_JOBS            a JSON list of jobs: role, project, job, account, token_secret
//	FOREMAN_CALLBACK_URL           the callback API's URL, as runners call it
//	FOREMAN_CALLBACK_AUDIENCE      the audience runners ask their ID tokens for (D19: the same URL)
//	FOREMAN_GITHUB_APP_ID_SECRET   the secret version holding the App's id
//	FOREMAN_GITHUB_APP_KEY_SECRET  the secret version holding the App's private key
//
// and, for tests, GCE_METADATA_HOST, FOREMAN_SECRETMANAGER_API, FOREMAN_RUN_API and
// FOREMAN_GITHUB_API in place of the real endpoints. Whatever is missing or wrong is named.
func FromEnv(getenv func(string) string, ids *callbackapi.IdentityMap, log *slog.Logger) (*Launcher, *github.Client, error) {
	raw := getenv("FOREMAN_RUNNER_JOBS")
	if raw == "" {
		return nil, nil, fmt.Errorf("FOREMAN_RUNNER_JOBS is not set")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var jobs []Job
	if err := dec.Decode(&jobs); err != nil {
		return nil, nil, fmt.Errorf("FOREMAN_RUNNER_JOBS: %w", err)
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("FOREMAN_RUNNER_JOBS: more than one JSON value")
	}
	for _, name := range []string{"FOREMAN_CALLBACK_URL", "FOREMAN_CALLBACK_AUDIENCE"} {
		if getenv(name) == "" {
			return nil, nil, fmt.Errorf("%s is not set", name)
		}
	}
	for _, name := range []string{"FOREMAN_GITHUB_APP_ID_SECRET", "FOREMAN_GITHUB_APP_KEY_SECRET"} {
		if v := getenv(name); !versionPattern.MatchString(v) {
			return nil, nil, fmt.Errorf("%s = %q is not a secret version's name (projects/P/secrets/S/versions/N or latest)", name, v)
		}
	}
	for _, name := range []string{"FOREMAN_SECRETMANAGER_API", "FOREMAN_RUN_API", "FOREMAN_GITHUB_API"} {
		if v := getenv(name); v != "" {
			if err := CheckEndpoint(v); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if v := getenv("GCE_METADATA_HOST"); v != "" {
		if err := checkHost(v); err != nil {
			return nil, nil, fmt.Errorf("GCE_METADATA_HOST: %w", err)
		}
	}
	gcp, err := NewGCP(Endpoints{MetadataHost: getenv("GCE_METADATA_HOST"), SecretManager: getenv("FOREMAN_SECRETMANAGER_API"),
		Run: getenv("FOREMAN_RUN_API")}, nil)
	if err != nil {
		return nil, nil, err
	}
	tokens := github.New(SecretCredentials(gcp, getenv("FOREMAN_GITHUB_APP_ID_SECRET"), getenv("FOREMAN_GITHUB_APP_KEY_SECRET")),
		getenv("FOREMAN_GITHUB_API"), nil)
	l, err := New(Config{Jobs: jobs, CallbackURL: getenv("FOREMAN_CALLBACK_URL"), Audience: getenv("FOREMAN_CALLBACK_AUDIENCE")},
		gcp, tokens, ids, log)
	if err != nil {
		return nil, nil, err
	}
	return l, tokens, nil
}
