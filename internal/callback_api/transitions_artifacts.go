package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// Artifacts (docs/state-machine.md, "Artifacts and the lease"; P02 D20): only the runner holding
// the lease registers one, with its claim token, for the ticket's current attempt, under
// `{project}/{ticket}/{attempt}/`. Registration adds a row to `artifacts` and does not change the
// ticket, so it writes no ticket event.

var artifactKinds = map[string]bool{"transcript": true, "diff": true, "test_report": true, "qa_report": true, "log": true}

// ArtifactRequest registers one artifact's storage path.
type ArtifactRequest struct {
	TicketID     int64
	Caller       Caller
	Kind         string
	GCSPath      string
	RequestID    string
	ClaimToken   string
	Method, Path string
}

// ArtifactResult is what a registration did; also its recorded response.
type ArtifactResult struct {
	ArtifactID int64  `json:"artifact_id"`
	TicketID   int64  `json:"ticket_id"`
	Attempt    int    `json:"attempt"`
	Kind       string `json:"kind"`
	GCSPath    string `json:"gcs_path"`
	Replayed   bool   `json:"-"`
}

// cleanPath refuses a leading slash, backslashes, and empty, `.` or `..` segments.
func cleanPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// RegisterArtifact records an artifact. Order as elsewhere: validation (400), a lease-holding
// role in its own project (403), the request log, the lock, the lease owner, the fence and the
// lease's expiry (409), then the path's prefix against the ticket's project, id and current
// attempt (400).
func (e *Engine) RegisterArtifact(ctx context.Context, tx *sql.Tx, req ArtifactRequest) (ArtifactResult, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return ArtifactResult{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return ArtifactResult{}, err
	}
	if req.TicketID <= 0 || !validRequestID(req.RequestID) {
		return ArtifactResult{}, refuse(400, "a ticket id and a UUID idempotency key are required")
	}
	if !artifactKinds[req.Kind] {
		return ArtifactResult{}, refuse(400, "unknown artifact kind %q", req.Kind)
	}
	if !cleanPath(req.GCSPath) {
		return ArtifactResult{}, refuse(400, "the path must be relative, with no empty, . or .. segments")
	}
	switch req.Caller.Role {
	case RoleDev, RoleQA, RoleIntegrator:
	default:
		return ArtifactResult{}, refuse(403, "%s never holds a lease, so it registers no artifacts", req.Caller.Role)
	}
	if err := checkProject(ctx, tx, req.TicketID, req.Caller.Project); err != nil {
		return ArtifactResult{}, err
	}

	hash := requestHash(map[string]any{"method": req.Method, "path": req.Path, "ticket": req.TicketID,
		"kind": req.Kind, "gcs_path": req.GCSPath, "claim_token": req.ClaimToken})
	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, hash)
	if err != nil {
		return ArtifactResult{}, err
	}
	if replay != nil {
		var res ArtifactResult
		if err := json.Unmarshal(replay, &res); err != nil {
			return ArtifactResult{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	t, err := lockTicket(ctx, tx, req.TicketID)
	if err != nil {
		return ArtifactResult{}, err
	}
	if !IsLeased(t.State) || leaseOwner(t.State) != req.Caller.Role {
		return ArtifactResult{}, refuse(409, "ticket %d is %s: no lease of a %s runner", t.ID, t.State, req.Caller.Role)
	}
	if err := fence(t, req.Caller, req.ClaimToken); err != nil {
		return ArtifactResult{}, err
	}
	if err := leaseLive(ctx, tx, t, req.Caller); err != nil {
		return ArtifactResult{}, err
	}
	prefix := fmt.Sprintf("%s/%d/%d/", t.Project, t.ID, t.Attempts)
	if !strings.HasPrefix(req.GCSPath, prefix) {
		return ArtifactResult{}, refuse(400, "artifacts of this attempt go under %s", prefix)
	}

	var id int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO artifacts (ticket_id, attempt, kind, gcs_path) VALUES ($1, $2, $3, $4) RETURNING id`,
		t.ID, t.Attempts, req.Kind, req.GCSPath).Scan(&id); err != nil {
		return ArtifactResult{}, internal("register artifact", err)
	}
	e.log.Info("artifact registered", "ticket", t.ID, "project", t.Project, "attempt", t.Attempts,
		"kind", req.Kind, "actor_id", req.Caller.Email)
	res := ArtifactResult{ArtifactID: id, TicketID: t.ID, Attempt: t.Attempts, Kind: req.Kind, GCSPath: req.GCSPath}
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 201, res); err != nil {
		return ArtifactResult{}, err
	}
	return res, nil
}
