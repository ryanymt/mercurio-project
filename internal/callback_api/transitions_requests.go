package callbackapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"regexp"
)

// The request log (api_requests) makes every mutating call idempotent (P02 D13). The key is the
// caller's verified email and its Idempotency-Key, claimed in the same transaction as the change
// it records, after authorization. Only a success commits a row: every refusal returns an error,
// and the caller rolls the transaction back, releasing the key.

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validRequestID(id string) bool { return uuidPattern.MatchString(id) }

// requestHash fingerprints a request: two requests with the same key must be the same request.
// The claim token is part of it, since a reaped runner and its successor share a service account.
func requestHash(parts map[string]any) string {
	b, _ := json.Marshal(parts) // maps marshal with sorted keys
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonical re-encodes a JSON value with sorted keys, so equal payloads hash equally.
func canonical(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	return v
}

// claimRequest claims (caller, requestID). It returns nil when the key is new, or the stored
// response to replay. A concurrent duplicate waits on the unique index; under READ COMMITTED it
// then sees the first request's committed row, or claims the key itself if that one rolled back.
func claimRequest(ctx context.Context, tx *sql.Tx, caller, requestID, hash string) ([]byte, error) {
	res, err := tx.ExecContext(ctx, `
		INSERT INTO api_requests (caller, request_id, request_hash) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, caller, requestID, hash)
	if err != nil {
		return nil, internal("claim request key", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil, nil
	}
	var stored string
	var response []byte
	if err := tx.QueryRowContext(ctx,
		`SELECT request_hash, response FROM api_requests WHERE caller = $1 AND request_id = $2`,
		caller, requestID).Scan(&stored, &response); err != nil {
		return nil, internal("read request key", err)
	}
	if response == nil {
		// Only a success commits a row, with its response. A row without one is never replayed.
		return nil, internalf("request %s is recorded without a response", requestID)
	}
	if stored != hash {
		return nil, refuse(409, "request id %s was already used for a different request", requestID)
	}
	return response, nil
}

// storeResponse records the response in the same transaction, before commit.
func storeResponse(ctx context.Context, tx *sql.Tx, caller, requestID string, status int, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return internal("encode response", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE api_requests SET status = $3, response = $4 WHERE caller = $1 AND request_id = $2`,
		caller, requestID, status, b); err != nil {
		return internal("store response", err)
	}
	return nil
}
