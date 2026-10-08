package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// A job with no launch request exits 2, naming what is missing.
func TestAMissingConfigurationExits2(t *testing.T) {
	var errs bytes.Buffer
	if code := run(context.Background(), func(string) string { return "" }, &errs); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errs.String(), "FOREMAN_LAUNCH_REQUEST") {
		t.Fatalf("the refusal does not name what is missing:\n%s", errs.String())
	}
}

// A run that fails exits 1 with its error logged as one JSON line; here the metadata server is
// unreachable, so nothing is read and nothing is called.
func TestAFailedRunExits1(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	host := strings.TrimPrefix(closed.URL, "http://")
	req, _ := json.Marshal(map[string]any{"ticket_id": 7, "project": "sandbox", "repo_url": "https://github.com/your-org/sandbox-repo",
		"role": "dev", "service_account": "dev-sandbox@your-project-id.iam.gserviceaccount.com", "branch": "foreman/7/1",
		"base_sha": strings.Repeat("a", 40), "claim_token": "claim", "attempt": 1})
	env := map[string]string{
		"FOREMAN_LAUNCH_REQUEST":    string(req),
		"FOREMAN_CALLBACK_URL":      "https://callback-api-123456789012.us-central1.run.app",
		"FOREMAN_CALLBACK_AUDIENCE": "https://callback-api-123456789012.us-central1.run.app",
		"FOREMAN_TOKEN_SECRET":      "projects/your-project-id/secrets/github-token-dev-sandbox",
		"FOREMAN_TOKEN_VERSION":     "1",
		"GCE_METADATA_HOST":         host,
		"FOREMAN_SECRETMANAGER_API": closed.URL,
		"FOREMAN_ARTIFACTS_BUCKET":  "your-project-id-artifacts",
	}
	var errs bytes.Buffer
	if code := run(context.Background(), func(k string) string { return env[k] }, &errs); code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, errs.String())
	}
	var line struct {
		Level string `json:"level"`
	}
	lines := strings.Split(strings.TrimSpace(errs.String()), "\n")
	if json.Unmarshal([]byte(lines[len(lines)-1]), &line) != nil || line.Level != "ERROR" {
		t.Fatalf("the failure was not logged as an error:\n%s", errs.String())
	}
}

// The runner's binary links no control-plane package: it runs with a runner's account and a
// GitHub token, and needs none of the database, the core or the dispatcher (D12).
func TestTheRunnerLinksNoControlPlane(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 10 {
		t.Fatalf("go list found only %v", deps)
	}
	for _, p := range deps {
		for _, banned := range []string{"/internal/callback_api", "/internal/dispatcher", "/internal/db", "/internal/risk_evaluator",
			"/internal/testdb", "/migrations", "jackc/pgx", "pressly/goose", "database/sql"} {
			if strings.Contains(p, banned) {
				t.Errorf("the echo runner links %s", p)
			}
		}
	}
	if !strings.Contains(string(out), "mercurio-project/internal/runner") {
		t.Errorf("the echo runner does not link internal/runner")
	}
}
