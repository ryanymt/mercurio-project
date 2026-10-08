package viewer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Object is one stored chunk.
type Object struct {
	Name string
	Size int64
}

// Chunks reads the artifacts bucket: a registered prefix's objects, and each object, bounded.
type Chunks interface {
	// List returns at most max objects under prefix + "/", in name order, and whether there are more.
	List(ctx context.Context, prefix string, max int) ([]Object, bool, error)
	// Read returns at most max bytes of an object, and whether it holds more.
	Read(ctx context.Context, name string, max int64) ([]byte, bool, error)
}

// GCSEndpoint is Cloud Storage's JSON API.
const GCSEndpoint = "https://storage.googleapis.com"

// GCSChunks reads the bucket through Cloud Storage's JSON API as the viewer's account, which holds
// objectViewer on it (P06 Approach 9): list and get, nothing more.
type GCSChunks struct {
	endpoint, bucket string
	tokens           func(context.Context) (string, error)
	client           *http.Client
}

// NewGCSChunks reads bucket at endpoint (GCSEndpoint, or a test's loopback server). With no client,
// a request times out after 30 seconds.
func NewGCSChunks(endpoint, bucket string, tokens func(context.Context) (string, error), client *http.Client) (*GCSChunks, error) {
	if err := checkEndpoint(endpoint); err != nil {
		return nil, err
	}
	if bucket == "" || tokens == nil {
		return nil, errors.New("viewer: a bucket and a token source are required")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &GCSChunks{endpoint: strings.TrimSuffix(endpoint, "/"), bucket: bucket, tokens: tokens, client: client}, nil
}

// checkEndpoint accepts https, or plain http to a loopback address (the tests').
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
	return fmt.Errorf("viewer: the endpoint %q is not an https URL", raw)
}

func (g *GCSChunks) get(ctx context.Context, u string) (*http.Response, error) {
	token, err := g.tokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("viewer: the access token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("viewer: storage: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("viewer: storage: status %d", resp.StatusCode)
	}
	return resp, nil
}

func (g *GCSChunks) List(ctx context.Context, prefix string, max int) ([]Object, bool, error) {
	q := url.Values{"prefix": {prefix + "/"}, "maxResults": {strconv.Itoa(max + 1)}, "fields": {"items(name,size),nextPageToken"}}
	resp, err := g.get(ctx, g.endpoint+"/storage/v1/b/"+url.PathEscape(g.bucket)+"/o?"+q.Encode())
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	var page struct {
		Items []struct {
			Name string `json:"name"`
			Size string `json:"size"`
		} `json:"items"`
		Next string `json:"nextPageToken"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&page); err != nil {
		return nil, false, fmt.Errorf("viewer: storage: an unreadable listing")
	}
	more := page.Next != "" || len(page.Items) > max
	if len(page.Items) > max {
		page.Items = page.Items[:max]
	}
	out := make([]Object, 0, len(page.Items))
	for _, it := range page.Items {
		size, _ := strconv.ParseInt(it.Size, 10, 64)
		out = append(out, Object{Name: it.Name, Size: size})
	}
	return out, more, nil
}

func (g *GCSChunks) Read(ctx context.Context, name string, max int64) ([]byte, bool, error) {
	resp, err := g.get(ctx, g.endpoint+"/storage/v1/b/"+url.PathEscape(g.bucket)+"/o/"+url.PathEscape(name)+"?alt=media")
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, false, fmt.Errorf("viewer: storage: read %s: %w", name, err)
	}
	if int64(len(b)) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}
