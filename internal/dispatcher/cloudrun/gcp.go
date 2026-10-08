package cloudrun

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The Google APIs' public endpoints, and the metadata server's host.
const (
	DefaultMetadataHost  = "metadata.google.internal"
	DefaultSecretManager = "https://secretmanager.googleapis.com"
	DefaultRun           = "https://run.googleapis.com"
)

// callTimeout bounds each call, well inside the ten minutes a claim gives its runner's first call.
const callTimeout = 30 * time.Second

// Endpoints are where the calls go; empty means the default. Anything but the metadata server is
// https, or plain http to a loopback address (CheckEndpoint).
type Endpoints struct {
	MetadataHost  string // host[:port], as GCE_METADATA_HOST names it
	SecretManager string
	Run           string
}

// GCP calls Secret Manager and the Cloud Run Admin API as the account the metadata server
// speaks for: the job's own.
type GCP struct {
	ep   Endpoints
	http *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewGCP checks the endpoints. A nil httpClient gets one bounded by callTimeout.
func NewGCP(ep Endpoints, httpClient *http.Client) (*GCP, error) {
	if ep.MetadataHost == "" {
		ep.MetadataHost = DefaultMetadataHost
	}
	if ep.SecretManager == "" {
		ep.SecretManager = DefaultSecretManager
	}
	if ep.Run == "" {
		ep.Run = DefaultRun
	}
	if err := checkHost(ep.MetadataHost); err != nil {
		return nil, fmt.Errorf("the metadata server: %w", err)
	}
	if err := CheckEndpoint(ep.SecretManager); err != nil {
		return nil, fmt.Errorf("the Secret Manager endpoint: %w", err)
	}
	if err := CheckEndpoint(ep.Run); err != nil {
		return nil, fmt.Errorf("the Cloud Run endpoint: %w", err)
	}
	ep.SecretManager = strings.TrimSuffix(ep.SecretManager, "/")
	ep.Run = strings.TrimSuffix(ep.Run, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: callTimeout}
	}
	return &GCP{ep: ep, http: httpClient}, nil
}

// CheckEndpoint accepts an API's base URL: https, or plain http to a loopback address; no user,
// path, query or fragment.
func CheckEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%q is not an API's base URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%q: plain http only to a loopback address", raw)
	}
	return fmt.Errorf("%q is not https", raw)
}

func checkHost(h string) error {
	if h == "" || strings.ContainsAny(h, "/@?# \t\\") {
		return fmt.Errorf("%q is not a host[:port]", h)
	}
	return nil
}

var (
	secretPattern  = regexp.MustCompile(`^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]+$`)
	versionPattern = regexp.MustCompile(`^projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]+/versions/(latest|[1-9][0-9]*)$`)
	jobPattern     = regexp.MustCompile(`^projects/[a-z0-9-]+/locations/[a-z0-9-]+/jobs/[a-z0-9-]+$`)
	statusPattern  = regexp.MustCompile(`^[A-Z_]{1,40}$`)
)

// apiError is a call's refusal: the call, its HTTP status and Google's status name, never the
// answer's message (the fakes echo the request there, and so might a proxy).
type apiError struct {
	call   string
	code   int
	status string
}

func (e *apiError) Error() string {
	if e.status == "" {
		return fmt.Sprintf("%s: status %d", e.call, e.code)
	}
	return fmt.Sprintf("%s: status %d (%s)", e.call, e.code, e.status)
}

func refusal(call string, resp *http.Response) *apiError {
	var body struct {
		Error struct {
			Status string `json:"status"`
		} `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
	e := &apiError{call: call, code: resp.StatusCode}
	if statusPattern.MatchString(body.Error.Status) {
		e.status = body.Error.Status
	}
	return e
}

// accessToken is the job's own OAuth access token from the metadata server, reused until a
// minute before it expires.
func (g *GCP) accessToken(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && time.Now().Before(g.expires) {
		return g.token, nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://"+g.ep.MetadataHost+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := g.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("the dispatcher's access token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the dispatcher's access token: status %d", resp.StatusCode)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&t); err != nil || t.AccessToken == "" {
		return "", errors.New("the dispatcher's access token: the metadata server answered with none")
	}
	g.token, g.expires = t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second-time.Minute)
	return g.token, nil
}

// do makes one call as the job's account; trace, when set, watches the request go out.
func (g *GCP) do(ctx context.Context, method, rawURL string, body any, trace *httptrace.ClientTrace) (*http.Response, error) {
	tok, err := g.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	if trace != nil {
		ctx = httptrace.WithClientTrace(ctx, trace)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return g.http.Do(req)
}

// call makes one call and decodes a 2xx answer into out.
func (g *GCP) call(ctx context.Context, name, method, rawURL string, body, out any) error {
	resp, err := g.do(ctx, method, rawURL, body, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return refusal(name, resp)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("%s: an unreadable answer: %w", name, err)
	}
	return nil
}

// AccessSecret reads one version of a secret (projects/P/secrets/S/versions/N or latest).
func (g *GCP) AccessSecret(ctx context.Context, version string) ([]byte, error) {
	if !versionPattern.MatchString(version) {
		return nil, fmt.Errorf("%q is not a secret version's name", version)
	}
	var got struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := g.call(ctx, "access "+version, "GET", g.ep.SecretManager+"/v1/"+version+":access", nil, &got); err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(got.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("access %s: the payload is not base64", version)
	}
	return data, nil
}

// versionNumber is N from a version's name, .../versions/N, whatever the project is named by.
func versionNumber(name string) (int64, error) {
	i := strings.LastIndex(name, "/versions/")
	if i < 0 {
		return 0, fmt.Errorf("%q names no version", name)
	}
	n, err := strconv.ParseInt(name[i+len("/versions/"):], 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%q names no version number", name)
	}
	return n, nil
}

// AddSecretVersion adds data as a new version of secret (projects/P/secrets/S) and returns its
// number.
func (g *GCP) AddSecretVersion(ctx context.Context, secret string, data []byte) (int64, error) {
	if !secretPattern.MatchString(secret) {
		return 0, fmt.Errorf("%q is not a secret's name", secret)
	}
	body := map[string]any{"payload": map[string]string{"data": base64.StdEncoding.EncodeToString(data)}}
	var got struct {
		Name string `json:"name"`
	}
	call := "addVersion " + secret
	if err := g.call(ctx, call, "POST", g.ep.SecretManager+"/v1/"+secret+":addVersion", body, &got); err != nil {
		return 0, err
	}
	n, err := versionNumber(got.Name)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", call, err)
	}
	return n, nil
}

// maxPages bounds a listing; each page holds up to pageSize versions.
const (
	maxPages = 20
	pageSize = 100
)

// EnabledVersions lists the numbers of a secret's enabled versions, following every page.
func (g *GCP) EnabledVersions(ctx context.Context, secret string) ([]int64, error) {
	if !secretPattern.MatchString(secret) {
		return nil, fmt.Errorf("%q is not a secret's name", secret)
	}
	var out []int64
	token := ""
	for page := 0; page < maxPages; page++ {
		q := url.Values{"filter": {"state:ENABLED"}, "pageSize": {strconv.Itoa(pageSize)}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var got struct {
			Versions []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"versions"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := g.call(ctx, "list "+secret, "GET", g.ep.SecretManager+"/v1/"+secret+"/versions?"+q.Encode(), nil, &got); err != nil {
			return nil, err
		}
		for _, v := range got.Versions {
			if v.State != "ENABLED" {
				continue
			}
			n, err := versionNumber(v.Name)
			if err != nil {
				return nil, fmt.Errorf("list %s: %w", secret, err)
			}
			out = append(out, n)
		}
		if got.NextPageToken == "" {
			return out, nil
		}
		token = got.NextPageToken
	}
	return nil, fmt.Errorf("list %s: more than %d pages", secret, maxPages)
}

// DestroySecretVersion destroys version n of secret.
func (g *GCP) DestroySecretVersion(ctx context.Context, secret string, n int64) error {
	if !secretPattern.MatchString(secret) || n < 1 {
		return fmt.Errorf("%q version %d is not a secret version", secret, n)
	}
	v := secret + "/versions/" + strconv.FormatInt(n, 10)
	return g.call(ctx, "destroy "+v, "POST", g.ep.SecretManager+"/v1/"+v+":destroy", map[string]any{}, nil)
}

// EnvVar is one environment variable a run sets on the job's container.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// UncertainError is a jobs.run whose outcome is unknown: the request was sent, and then the call
// timed out or the server failed. An execution may exist.
type UncertainError struct{ Err error }

func (e *UncertainError) Error() string { return "the outcome is unknown: " + e.Err.Error() }
func (e *UncertainError) Unwrap() error { return e.Err }

// RunJob starts one execution of job (projects/P/locations/L/jobs/J) with env added to its
// container's environment, and returns the execution's name (the operation's, if the answer names
// no execution). An *UncertainError means the request went out and no answer said whether an
// execution was created; any other error means none was.
func (g *GCP) RunJob(ctx context.Context, job string, env []EnvVar) (string, error) {
	if !jobPattern.MatchString(job) {
		return "", fmt.Errorf("%q is not a job's name", job)
	}
	body := map[string]any{"overrides": map[string]any{"containerOverrides": []any{map[string]any{"env": env}}}}
	var sent atomic.Bool
	trace := &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }}
	resp, err := g.do(ctx, "POST", g.ep.Run+"/v2/"+job+":run", body, trace)
	if err != nil {
		if sent.Load() {
			return "", &UncertainError{Err: err}
		}
		return "", fmt.Errorf("not sent: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 4:
		return "", refusal("jobs.run", resp)
	case resp.StatusCode/100 != 2:
		return "", &UncertainError{Err: refusal("jobs.run", resp)}
	}
	var op struct {
		Name     string `json:"name"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&op)
	if op.Metadata.Name != "" {
		return op.Metadata.Name, nil
	}
	return op.Name, nil
}
