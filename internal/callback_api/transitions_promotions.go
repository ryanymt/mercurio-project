package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5/pgconn"
)

// Promotions: the self-deploy tripwire's record (docs/architecture.md, "Self-modification").
// Promotion is always a human act; merge is not deploy. P09 builds the tripwire on this.

var (
	componentPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	gitSHAPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// PromotionRequest records a new current image for a component.
type PromotionRequest struct {
	Caller       Caller
	Component    string
	ImageDigest  string
	GitSHA       string
	RequestID    string
	Method, Path string
}

// PromotionResult is what a promotion did; also its recorded response.
type PromotionResult struct {
	PromotionID int64  `json:"promotion_id"`
	Component   string `json:"component"`
	ImageDigest string `json:"image_digest"`
	GitSHA      string `json:"git_sha"`
	PromotedBy  string `json:"promoted_by"`
	Retired     int64  `json:"retired,omitempty"` // the promotion it replaced, if any
	Replayed    bool   `json:"-"`
}

// Promote retires the component's current promotion and then inserts the new one, in one
// transaction; the partial unique index is checked immediately, so the order matters. A
// concurrent promotion of the same component waits for this one, then conflicts: 409.
// `promoted_by` is the caller's verified email.
func (e *Engine) Promote(ctx context.Context, tx *sql.Tx, req PromotionRequest) (PromotionResult, error) {
	if err := requireReadCommitted(ctx, tx); err != nil {
		return PromotionResult{}, err
	}
	if err := validCaller(req.Caller); err != nil {
		return PromotionResult{}, err
	}
	if !validRequestID(req.RequestID) {
		return PromotionResult{}, refuse(400, "the idempotency key must be a UUID")
	}
	switch {
	case !componentPattern.MatchString(req.Component):
		return PromotionResult{}, refuse(400, "component must be lower-case letters, digits and dashes")
	case !digestPattern.MatchString(req.ImageDigest):
		return PromotionResult{}, refuse(400, "image_digest must be sha256:<64 hex digits>")
	case !gitSHAPattern.MatchString(req.GitSHA):
		return PromotionResult{}, refuse(400, "git_sha must be a full 40-digit commit sha")
	}
	if req.Caller.Role != RoleHuman {
		return PromotionResult{}, refuse(403, "promotion is a human act")
	}

	hash := requestHash(map[string]any{"method": req.Method, "path": req.Path, "component": req.Component,
		"image_digest": req.ImageDigest, "git_sha": req.GitSHA})
	replay, err := claimRequest(ctx, tx, req.Caller.Email, req.RequestID, hash)
	if err != nil {
		return PromotionResult{}, err
	}
	if replay != nil {
		var res PromotionResult
		if err := json.Unmarshal(replay, &res); err != nil {
			return PromotionResult{}, internal("decode recorded response", err)
		}
		res.Replayed = true
		return res, nil
	}

	var retired int64
	err = tx.QueryRowContext(ctx,
		`UPDATE promotions SET is_current = false WHERE component = $1 AND is_current RETURNING id`,
		req.Component).Scan(&retired)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return PromotionResult{}, internal("retire current promotion", err)
	}
	var id int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO promotions (component, image_digest, git_sha, promoted_by) VALUES ($1, $2, $3, $4)
		RETURNING id`, req.Component, req.ImageDigest, req.GitSHA, req.Caller.Email).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "one_current_promotion_per_component" {
		return PromotionResult{}, refuse(409, "%s was promoted concurrently; retry against the new current promotion", req.Component)
	}
	if err != nil {
		return PromotionResult{}, internal("insert promotion", err)
	}
	e.log.Info("promotion", "component", req.Component, "image_digest", req.ImageDigest,
		"git_sha", req.GitSHA, "promoted_by", req.Caller.Email, "retired", retired)
	res := PromotionResult{
		PromotionID: id, Component: req.Component, ImageDigest: req.ImageDigest, GitSHA: req.GitSHA,
		PromotedBy: req.Caller.Email, Retired: retired,
	}
	if err := storeResponse(ctx, tx, req.Caller.Email, req.RequestID, 201, res); err != nil {
		return PromotionResult{}, err
	}
	return res, nil
}
