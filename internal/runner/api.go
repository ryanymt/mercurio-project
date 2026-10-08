package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ryanymt/mercurio-project/internal/capture"
)

// api calls the callback API as the runner: its ID token, its ticket's claim token, and a fresh
// idempotency key for each call, since no call is ever retried.
type api struct {
	base     string
	audience string
	ids      *google
	http     *http.Client
	ticket   int64
	claim    string
}

func (a *api) transition(ctx context.Context, from, to, headSHA string, payload map[string]any) error {
	body := map[string]any{"from": from, "to": to}
	if headSHA != "" {
		body["head_sha"] = headSHA
	}
	if payload != nil {
		body["payload"] = payload
	}
	return a.call(ctx, fmt.Sprintf("/v1/tickets/%d/transitions", a.ticket), body)
}

// Register registers a capture prefix on the ticket through the fenced artifacts endpoint: the api
// is the capture's capture.Registrar.
func (a *api) Register(ctx context.Context, kind capture.Kind, prefix string) error {
	return a.call(ctx, fmt.Sprintf("/v1/tickets/%d/artifacts", a.ticket),
		map[string]string{"kind": string(kind), "gcs_path": prefix})
}

func (a *api) heartbeat(ctx context.Context) error {
	return a.call(ctx, fmt.Sprintf("/v1/tickets/%d/heartbeat", a.ticket), struct{}{})
}

// call makes one POST. An answer other than 2xx is an error naming the path, the status and the
// API's own reason.
func (a *api) call(ctx context.Context, path string, body any) error {
	tok, err := a.ids.idToken(ctx, a.audience)
	if err != nil {
		return err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", newRequestID())
	req.Header.Set("X-Foreman-Claim-Token", a.claim)
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	var refusal struct {
		Error string `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&refusal)
	return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, refusal.Error)
}

// newRequestID is a random (version 4) UUID, the form the API takes as an idempotency key.
func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
