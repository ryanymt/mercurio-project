package viewer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// MetadataHost is the metadata server, which speaks for the service's account.
const MetadataHost = "metadata.google.internal"

// Metadata asks the metadata server for the viewer's own tokens.
type Metadata struct {
	base   string
	client *http.Client
}

// NewMetadata asks host (MetadataHost, or a test's loopback server). With no client, a request
// times out after 10 seconds.
func NewMetadata(host string, client *http.Client) *Metadata {
	if host == "" {
		host = MetadataHost
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Metadata{base: "http://" + host + "/computeMetadata/v1/instance/service-accounts/default/", client: client}
}

func (m *Metadata) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("viewer: the metadata server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("viewer: the metadata server: %s: status %d", strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// IDToken is an ID token for audience. format=full puts the account's email in it, which the
// callback API's verifier requires (P05 R3).
func (m *Metadata) IDToken(ctx context.Context, audience string) (string, error) {
	b, err := m.get(ctx, "identity?"+url.Values{"audience": {audience}, "format": {"full"}}.Encode())
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("viewer: the metadata server answered with no ID token")
	}
	return tok, nil
}

// AccessToken is the viewer's OAuth access token, for Cloud Storage.
func (m *Metadata) AccessToken(ctx context.Context) (string, error) {
	b, err := m.get(ctx, "token")
	if err != nil {
		return "", err
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", errors.New("viewer: the metadata server answered with no access token")
	}
	return t.AccessToken, nil
}

// HTTPRelay sends a person's act to the callback API as the viewer (D4, D20). It builds every
// request from nothing: the viewer's own ID token for the API's audience, the person's assertion in
// callbackapi.RelayHeader, the form's idempotency key and the body. Nothing of the person's own
// request is passed on: not IAP's cookie, its X-Serverless-Authorization, or any other header.
type HTTPRelay struct {
	api     string
	idToken func(ctx context.Context, audience string) (string, error)
	client  *http.Client
}

// RelayTimeout is how long the relay waits for the callback API: past a cold start, which has taken
// 69 seconds in GCP, and well inside Cloud Run's request limit.
const RelayTimeout = 90 * time.Second

// NewHTTPRelay relays to the callback API at apiURL, which is also the ID token's audience. With no
// client, a request times out after RelayTimeout.
func NewHTTPRelay(apiURL string, idToken func(ctx context.Context, audience string) (string, error), client *http.Client) (*HTTPRelay, error) {
	if err := checkEndpoint(apiURL); err != nil {
		return nil, err
	}
	if idToken == nil {
		return nil, errors.New("viewer: the relay needs an ID token source")
	}
	if client == nil {
		client = &http.Client{Timeout: RelayTimeout}
	}
	return &HTTPRelay{api: strings.TrimSuffix(apiURL, "/"), idToken: idToken, client: client}, nil
}

func (h *HTTPRelay) Send(ctx context.Context, method, path, assertion, key string, body any) (int, string, map[string]any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, "", nil, fmt.Errorf("viewer: encode the request: %w", err)
	}
	token, err := h.idToken(ctx, h.api)
	if err != nil {
		return 0, "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, h.api+path, bytes.NewReader(payload))
	if err != nil {
		return 0, "", nil, err
	}
	req.Header = http.Header{}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(callbackapi.RelayHeader, assertion)
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "foreman-viewer")
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("viewer: the callback API: %w", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return resp.StatusCode, "", nil, fmt.Errorf("viewer: the callback API: status %d, an unreadable answer", resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		reason, _ := out["error"].(string)
		return resp.StatusCode, reason, nil, nil
	}
	return resp.StatusCode, "", out, nil
}
