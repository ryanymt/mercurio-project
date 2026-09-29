package cloudrun

import (
	"context"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun/cloudruntest"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/github"
)

// New refuses a job whose account the identity map does not know; Launch checks again, against
// the map it holds, before any call (P05 Approach 4). The map is swapped here, past New, to reach
// that second check; the App's key is real, so a launch past it would call GitHub.
func TestLaunchRechecksTheIdentityMap(t *testing.T) {
	const acct = "dev-sandbox@your-project-id.iam.gserviceaccount.com"
	gcp := cloudruntest.NewGCP(t)
	gh := cloudruntest.NewGitHub(t)
	g, err := NewGCP(Endpoints{MetadataHost: gcp.MetadataHost(), SecretManager: gcp.URL(), Run: gcp.URL()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	job := Job{Role: callbackapi.RoleDev, Project: "sandbox", Job: "projects/your-project-id/locations/us-central1/jobs/echo-runner-sandbox",
		Account: acct, TokenSecret: "projects/your-project-id/secrets/github-token-dev-sandbox"}
	cfg := Config{Jobs: []Job{job}, CallbackURL: "https://callback.example", Audience: "https://callback.example"}
	l, err := New(cfg, g, github.New(github.Static("1", cloudruntest.AppKey(t)), gh.URL(), nil), ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := dispatcher.LaunchRequest{TicketID: 1, Project: "sandbox", RepoURL: "https://github.com/your-org/sandbox-repo",
		Role: callbackapi.RoleDev, ServiceAccount: acct, ClaimToken: "claim", Attempt: 1}
	for name, m := range map[string]string{
		"not mapped":                `[{"email": "dev-foreman@your-project-id.iam.gserviceaccount.com", "role": "dev", "project": "foreman"}]`,
		"mapped to another project": `[{"email": "` + acct + `", "role": "dev", "project": "foreman"}]`,
		"mapped to another role":    `[{"email": "` + acct + `", "role": "qa", "project": "sandbox"}]`,
	} {
		other, err := callbackapi.LoadIdentityMap([]byte(m))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		l.ids = other
		if id, err := l.Launch(context.Background(), req); err == nil {
			t.Errorf("%s: launched %q", name, id)
		}
		if _, err := New(cfg, g, l.tokens, other, nil); err == nil {
			t.Errorf("%s: New accepted the job", name)
		}
	}
	if n, m := gcp.Requests(), gh.Requests(); n != 0 || m != 0 {
		t.Fatalf("%d calls to Google and %d to GitHub, want none", n, m)
	}
}
