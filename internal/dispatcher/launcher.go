package dispatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// LaunchRequest is everything a runner is started with (P04 Approach 2, step 7). The callback
// endpoint is the launcher's own configuration, not the ticket's.
type LaunchRequest struct {
	TicketID       int64            `json:"ticket_id"`
	Project        string           `json:"project"`
	RepoURL        string           `json:"repo_url"`
	Role           callbackapi.Role `json:"role"`
	ServiceAccount string           `json:"service_account"`
	Branch         string           `json:"branch,omitempty"`
	BaseSHA        string           `json:"base_sha,omitempty"`
	HeadSHA        string           `json:"head_sha,omitempty"` // QA and integration
	ClaimToken     string           `json:"claim_token"`
	Attempt        int              `json:"attempt"`
	Provider       string           `json:"provider,omitempty"` // none for the integrator
	Model          string           `json:"model,omitempty"`
	Tier           string           `json:"tier,omitempty"`
	Credential     string           `json:"credential,omitempty"` // the one secret to inject
}

// Launcher starts a runner. Its contract (P04 D10): an error means the run definitely did not
// start, and the tick returns the ticket at once and refunds its unit. Anything uncertain, such as
// a timeout after the request was sent, must return no error: the lease is then left to be reaped,
// with no refund, since a runner that did start may have spent quota. Roles names the roles it can
// start for a project; the tick claims no other (P05 D8, D20).
type Launcher interface {
	Launch(ctx context.Context, req LaunchRequest) (launchID string, err error)
	Roles(project string) []callbackapi.Role
}

// runnerRoles are every role a runner plays.
var runnerRoles = []callbackapi.Role{callbackapi.RoleIntegrator, callbackapi.RoleQA, callbackapi.RoleDev,
	callbackapi.RoleSpec, callbackapi.RoleArchitect}

// RecordingLauncher starts nothing: it writes each request as one JSON line, for running a tick
// locally (P04 D2). The deployed dispatcher launches through internal/dispatcher/cloudrun.
type RecordingLauncher struct {
	mu sync.Mutex
	w  io.Writer
	n  int
}

// NewRecordingLauncher writes launch requests to w.
func NewRecordingLauncher(w io.Writer) *RecordingLauncher { return &RecordingLauncher{w: w} }

// Roles is every runner role, for any project: recording one costs nothing.
func (r *RecordingLauncher) Roles(project string) []callbackapi.Role {
	return append([]callbackapi.Role(nil), runnerRoles...)
}

// Launch records the request and returns a launch id naming the record.
func (r *RecordingLauncher) Launch(ctx context.Context, req LaunchRequest) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(r.w, "%s\n", line); err != nil {
		return "", err
	}
	r.n++
	return fmt.Sprintf("recorded-%d", r.n), nil
}
