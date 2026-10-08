package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// GCSEndpoint is Cloud Storage's JSON API.
const GCSEndpoint = "https://storage.googleapis.com"

// TokenSource gives the job's OAuth access token, from the metadata server in production.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenFunc is a function as a TokenSource.
type TokenFunc func(ctx context.Context) (string, error)

// Token calls f.
func (f TokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)

// GCS creates objects in one bucket through Cloud Storage's JSON API, each only if no object of its
// name exists (ifGenerationMatch=0): the runner's objectCreator right cannot overwrite, and the
// precondition makes a second create of a name a 412 rather than a new version (D9). It uses the
// job's own token and no client library.
type GCS struct {
	endpoint, bucket string
	tokens           TokenSource
	client           *http.Client
}

// NewGCS returns a store for bucket at endpoint (GCSEndpoint, or a test's loopback server). With
// no client, requests time out after 30 seconds.
func NewGCS(endpoint, bucket string, tokens TokenSource, client *http.Client) (*GCS, error) {
	if err := checkEndpoint(endpoint); err != nil {
		return nil, err
	}
	if !bucketPattern.MatchString(bucket) {
		return nil, fmt.Errorf("capture: bad bucket name %q", bucket)
	}
	if tokens == nil {
		return nil, errors.New("capture: a token source is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &GCS{endpoint: endpoint, bucket: bucket, tokens: tokens, client: client}, nil
}

// checkEndpoint accepts https, or plain http to a loopback address (the tests' fakes).
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" && u.User == nil {
		if u.Scheme == "https" {
			return nil
		}
		if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("capture: the storage endpoint %q is not an https URL", raw)
}

// Create uploads data as the object name, refusing to replace one: ErrExists when it exists. An
// error names the status, never the token or the response.
func (g *GCS) Create(ctx context.Context, name string, data []byte) error {
	token, err := g.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("capture: the access token: %w", err)
	}
	q := url.Values{"uploadType": {"media"}, "name": {name}, "ifGenerationMatch": {"0"}}
	u := g.endpoint + "/upload/storage/v1/b/" + url.PathEscape(g.bucket) + "/o?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("capture: create %s: %w", name, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("capture: create %s: %w", name, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusPreconditionFailed:
		return ErrExists
	}
	return fmt.Errorf("capture: create %s: status %d", name, resp.StatusCode)
}
