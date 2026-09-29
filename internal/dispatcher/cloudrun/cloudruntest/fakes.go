// Package cloudruntest fakes the Google and GitHub APIs the Cloud Run launcher calls, for tests
// only: the command must never link it (cmd/foreman's TestTheCommandLinksNoFake).
package cloudruntest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// DispatcherToken is the access token the fake metadata server hands the dispatcher; every other
// call to the fake must carry it.
const DispatcherToken = "ya29.fake-dispatcher-token"

// ProjectNumber is the number the fake names every secret by in its answers, as Secret Manager
// does whatever the request named the project by.
const ProjectNumber = "123456789012"

// PageSize is the most versions one page of a listing holds, so a caller must follow pages.
const PageSize = 4

// GCP fakes the metadata server, Secret Manager and the Cloud Run Admin API, all on one server.
// Every error answer echoes the request's body, so a caller that passes an answer on leaks what it
// sent. Secrets are keyed by their short name; the project in a request's path is not checked.
type GCP struct {
	srv *httptest.Server

	mu          sync.Mutex
	secrets     map[string]map[int64]*version
	requests    int
	events      []string  // "add N", "run", "destroy N", in order, for the calls that succeeded
	runs        []RunCall // every jobs.run received, answered or not
	destroys    map[string]int
	redestroyed []string // "secret/N" for every destroy of a version already destroyed

	// Behaviour, set by the test before it calls.
	AddStatus     int           // addVersion answers this status when set
	AddDelay      time.Duration // before addVersion answers
	RunStatus     int           // jobs.run answers this status when set
	RunDelay      time.Duration // before jobs.run answers (after recording it)
	RunNoMetadata bool          // jobs.run answers 200 with an operation naming no execution
	DestroyStatus int           // destroy answers this status when set
}

type version struct {
	data      []byte
	destroyed bool
}

// RunCall is one jobs.run request, as received.
type RunCall struct {
	Job    string            // projects/P/locations/L/jobs/J
	Path   string            // the request's path and query
	Header http.Header       // the request's headers
	Body   string            // the request's body
	Env    map[string]string // the environment overrides of its containers
}

// NewGCP starts the fake.
func NewGCP(t testing.TB) *GCP {
	g := &GCP{secrets: map[string]map[int64]*version{}, destroys: map[string]int{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

// URL is the fake's base URL, for Secret Manager and Cloud Run alike.
func (g *GCP) URL() string { return g.srv.URL }

// MetadataHost is the fake's host and port, as GCE_METADATA_HOST names a metadata server.
func (g *GCP) MetadataHost() string { return strings.TrimPrefix(g.srv.URL, "http://") }

// SetSecret gives the secret named short one version, 1, holding data.
func (g *GCP) SetSecret(short string, data []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.secrets[short] = map[int64]*version{1: {data: append([]byte(nil), data...)}}
}

// Version returns a version's payload (nil once destroyed), whether it is destroyed, and whether
// it exists.
func (g *GCP) Version(short string, n int64) (data []byte, destroyed, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.secrets[short][n]
	if !ok {
		return nil, false, false
	}
	return v.data, v.destroyed, true
}

// Enabled lists a secret's enabled versions, ascending.
func (g *GCP) Enabled(short string) []int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []int64
	for n, v := range g.secrets[short] {
		if !v.destroyed {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Requests counts every request the fake received, the metadata server's included.
func (g *GCP) Requests() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests
}

// Events lists the calls that succeeded, in order: "add N", "run", "destroy N".
func (g *GCP) Events() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.events...)
}

// Runs lists every jobs.run received.
func (g *GCP) Runs() []RunCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]RunCall(nil), g.runs...)
}

// Destroys counts the destroy calls on a version, refused ones included.
func (g *GCP) Destroys(short string, n int64) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.destroys[fmt.Sprintf("%s/%d", short, n)]
}

// Redestroyed lists "secret/N" for every destroy of a version already destroyed.
func (g *GCP) Redestroyed() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.redestroyed...)
}

var (
	addPath     = regexp.MustCompile(`^/v1/projects/[^/]+/secrets/([^/:]+):addVersion$`)
	listPath    = regexp.MustCompile(`^/v1/projects/[^/]+/secrets/([^/:]+)/versions$`)
	destroyPath = regexp.MustCompile(`^/v1/projects/[^/]+/secrets/([^/:]+)/versions/(\d+):destroy$`)
	accessPath  = regexp.MustCompile(`^/v1/projects/[^/]+/secrets/([^/:]+)/versions/(latest|\d+):access$`)
	runPath     = regexp.MustCompile(`^/v2/(projects/[^/]+/locations/[^/]+/jobs/[^/:]+):run$`)
)

const metadataTokenPath = "/computeMetadata/v1/instance/service-accounts/default/token"

func versionName(short string, n int64) string {
	return fmt.Sprintf("projects/%s/secrets/%s/versions/%d", ProjectNumber, short, n)
}

var statusNames = map[int]string{
	400: "INVALID_ARGUMENT", 401: "UNAUTHENTICATED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND",
	409: "ABORTED", 429: "RESOURCE_EXHAUSTED", 500: "INTERNAL", 503: "UNAVAILABLE",
}

// fail answers an error in Google's shape, its message echoing the request's body.
func fail(w http.ResponseWriter, code int, status string, body []byte) {
	if status == "" {
		status = statusNames[code]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	msg, _ := json.Marshal("refused; the request was " + string(body))
	fmt.Fprintf(w, `{"error": {"code": %d, "status": %q, "message": %s}}`, code, status, msg)
}

func (g *GCP) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests++
	if r.URL.Path == metadataTokenPath {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			fail(w, http.StatusForbidden, "", body)
			return
		}
		fmt.Fprintf(w, `{"access_token": %q, "expires_in": 3599, "token_type": "Bearer"}`, DispatcherToken)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+DispatcherToken {
		fail(w, http.StatusUnauthorized, "", body)
		return
	}
	// sleep waits with the lock released, so the test can read the fake meanwhile.
	sleep := func(d time.Duration) {
		g.mu.Unlock()
		time.Sleep(d)
		g.mu.Lock()
	}
	switch {
	case r.Method == "POST" && addPath.MatchString(r.URL.Path):
		short := addPath.FindStringSubmatch(r.URL.Path)[1]
		if g.AddDelay > 0 {
			sleep(g.AddDelay)
		}
		if g.AddStatus != 0 {
			fail(w, g.AddStatus, "", body)
			return
		}
		var req struct {
			Payload struct {
				Data string `json:"data"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			fail(w, http.StatusBadRequest, "", body)
			return
		}
		data, err := base64.StdEncoding.DecodeString(req.Payload.Data)
		if err != nil || len(data) == 0 {
			fail(w, http.StatusBadRequest, "", body)
			return
		}
		if g.secrets[short] == nil {
			g.secrets[short] = map[int64]*version{}
		}
		n := int64(len(g.secrets[short]) + 1)
		g.secrets[short][n] = &version{data: data}
		g.events = append(g.events, fmt.Sprintf("add %d", n))
		fmt.Fprintf(w, `{"name": %q, "state": "ENABLED"}`, versionName(short, n))
	case r.Method == "GET" && listPath.MatchString(r.URL.Path):
		short := listPath.FindStringSubmatch(r.URL.Path)[1]
		q := r.URL.Query()
		if f := q.Get("filter"); f != "" && f != "state:ENABLED" {
			fail(w, http.StatusBadRequest, "", []byte(f))
			return
		}
		var ns []int64
		for n, v := range g.secrets[short] {
			if q.Get("filter") == "" || !v.destroyed {
				ns = append(ns, n)
			}
		}
		sort.Slice(ns, func(i, j int) bool { return ns[i] > ns[j] }) // newest first, as Secret Manager lists
		start, _ := strconv.Atoi(q.Get("pageToken"))
		end := min(start+PageSize, len(ns))
		var vs []string
		for _, n := range ns[min(start, end):end] {
			state := "ENABLED"
			if g.secrets[short][n].destroyed {
				state = "DESTROYED"
			}
			vs = append(vs, fmt.Sprintf(`{"name": %q, "state": %q}`, versionName(short, n), state))
		}
		next := ""
		if end < len(ns) {
			next = strconv.Itoa(end)
		}
		fmt.Fprintf(w, `{"versions": [%s], "nextPageToken": %q, "totalSize": %d}`, strings.Join(vs, ","), next, len(ns))
	case r.Method == "POST" && destroyPath.MatchString(r.URL.Path):
		m := destroyPath.FindStringSubmatch(r.URL.Path)
		n, _ := strconv.ParseInt(m[2], 10, 64)
		key := fmt.Sprintf("%s/%d", m[1], n)
		g.destroys[key]++
		v := g.secrets[m[1]][n]
		switch {
		case v == nil:
			fail(w, http.StatusNotFound, "", body)
		case v.destroyed:
			g.redestroyed = append(g.redestroyed, key)
			fail(w, http.StatusBadRequest, "FAILED_PRECONDITION", body)
		case g.DestroyStatus != 0:
			fail(w, g.DestroyStatus, "", body)
		default:
			v.destroyed, v.data = true, nil
			g.events = append(g.events, fmt.Sprintf("destroy %d", n))
			fmt.Fprintf(w, `{"name": %q, "state": "DESTROYED"}`, versionName(m[1], n))
		}
	case r.Method == "GET" && accessPath.MatchString(r.URL.Path):
		m := accessPath.FindStringSubmatch(r.URL.Path)
		var n int64
		if m[2] == "latest" {
			for k, v := range g.secrets[m[1]] {
				if !v.destroyed && k > n {
					n = k
				}
			}
		} else {
			n, _ = strconv.ParseInt(m[2], 10, 64)
		}
		v := g.secrets[m[1]][n]
		if v == nil || v.destroyed {
			fail(w, http.StatusNotFound, "", body)
			return
		}
		fmt.Fprintf(w, `{"name": %q, "payload": {"data": %q}}`, versionName(m[1], n), base64.StdEncoding.EncodeToString(v.data))
	case r.Method == "POST" && runPath.MatchString(r.URL.Path):
		job := runPath.FindStringSubmatch(r.URL.Path)[1]
		call := RunCall{Job: job, Path: r.URL.RequestURI(), Header: r.Header.Clone(), Body: string(body), Env: map[string]string{}}
		var req struct {
			Overrides struct {
				ContainerOverrides []struct {
					Env []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"env"`
				} `json:"containerOverrides"`
			} `json:"overrides"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			fail(w, http.StatusBadRequest, "", body)
			return
		}
		for _, c := range req.Overrides.ContainerOverrides {
			for _, e := range c.Env {
				call.Env[e.Name] = e.Value
			}
		}
		g.runs = append(g.runs, call)
		if g.RunDelay > 0 {
			sleep(g.RunDelay)
		}
		if g.RunStatus != 0 {
			fail(w, g.RunStatus, "", body)
			return
		}
		g.events = append(g.events, "run")
		location := job[:strings.Index(job, "/jobs/")]
		if g.RunNoMetadata {
			fmt.Fprintf(w, `{"name": "%s/operations/op-%d"}`, location, len(g.runs))
			return
		}
		fmt.Fprintf(w, `{"name": "%s/operations/op-%d", "metadata": {"@type": "type.googleapis.com/google.cloud.run.v2.Execution", "name": "%s/executions/ex-%d"}}`,
			location, len(g.runs), job, len(g.runs))
	default:
		fail(w, http.StatusNotFound, "", body)
	}
}

// Repo is the one repository the fake GitHub has the App installed on.
const Repo = "your-org/sandbox-repo"

// GitHub fakes the two calls that mint an installation token.
type GitHub struct {
	srv      *httptest.Server
	mu       sync.Mutex
	asked    []string
	requests int
	down     bool
}

// NewGitHub starts the fake.
func NewGitHub(t testing.TB) *GitHub {
	f := &GitHub{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// URL is the fake's base URL.
func (f *GitHub) URL() string { return f.srv.URL }

// SetDown makes every call fail with 503.
func (f *GitHub) SetDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// Asked lists the contents permission of every token minted, in order.
func (f *GitHub) Asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

// Requests counts every request the fake received.
func (f *GitHub) Requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// TokenFor is the token the fake mints the n-th time, from 1.
func TokenFor(n int) string { return fmt.Sprintf("ghs_fakeInstallationToken%010d", n) }

func (f *GitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.down || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/repos/"+Repo+"/installation":
		fmt.Fprint(w, `{"id": 7}`)
	case r.Method == "POST" && r.URL.Path == "/app/installations/7/access_tokens":
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.asked = append(f.asked, body.Permissions["contents"])
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"token": %q, "expires_at": %q, "permissions": {"contents": %q, "metadata": "read"},
			"repositories": [{"name": "sandbox-repo", "full_name": %q}]}`,
			TokenFor(len(f.asked)), time.Now().Add(time.Hour).UTC().Format(time.RFC3339), body.Permissions["contents"], Repo)
	default:
		http.NotFound(w, r)
	}
}

// AppKey returns a fresh RSA key, PEM-encoded, to stand for the App's.
func AppKey(t testing.TB) []byte {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// Leaks names the forms of token found in s: the token itself, and its standard or URL-safe
// base64 wherever it sits in an encoded blob. At each of the three byte offsets the token can
// start at, the run of base64 characters that encodes only the token's own bytes is searched for,
// so padding, and whatever precedes or follows it, make no difference.
func Leaks(s, token string) []string {
	var found []string
	if strings.Contains(s, token) {
		found = append(found, "the token")
	}
	for _, enc := range []struct {
		name string
		e    *base64.Encoding
	}{{"its standard base64", base64.StdEncoding}, {"its URL-safe base64", base64.URLEncoding}} {
		for k := 0; k < 3; k++ {
			blob := enc.e.EncodeToString(append(make([]byte, k), token...))
			first, last := (k+2)/3, (k+len(token))/3 // the groups holding token bytes only
			if last > first && strings.Contains(s, blob[4*first:4*last]) {
				found = append(found, fmt.Sprintf("%s (at offset %d)", enc.name, k))
			}
		}
	}
	return found
}
