// Package capturetest is a fake of Cloud Storage's JSON API for the capture package's tests and
// the runner's: object creation with ifGenerationMatch=0, as a runner's objectCreator right allows
// it, with failures to order.
package capturetest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
)

// GCS is an in-process stand-in for https://storage.googleapis.com, holding one bucket.
type GCS struct {
	srv    *httptest.Server
	bucket string
	token  string // the bearer token every request must carry; empty accepts any

	mu       sync.Mutex
	objects  map[string][]byte
	failNext int  // creates answered 503 without storing
	loseNext int  // creates stored, then answered 503: the response lost on the way back
	down     bool // every request answered 503
	requests []Request
}

// Request is one request the fake received.
type Request struct {
	Method, Path string
	Query        url.Values
	Auth         string
	Body         string
}

// NewGCS serves a bucket named bucket, requiring token (when not empty) on every request.
func NewGCS(t testing.TB, bucket, token string) *GCS {
	g := &GCS{bucket: bucket, token: token, objects: map[string][]byte{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

// URL is the fake's endpoint, in place of https://storage.googleapis.com.
func (g *GCS) URL() string { return g.srv.URL }

// Object returns a stored object's data.
func (g *GCS) Object(name string) ([]byte, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	b, ok := g.objects[name]
	return b, ok
}

// Names lists the stored objects' names, sorted.
func (g *GCS) Names() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var names []string
	for n := range g.objects {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// FailNext answers the next n creates with 503, storing nothing.
func (g *GCS) FailNext(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failNext = n
}

// LoseNext stores the next n creates and answers them 503, as if the response were lost.
func (g *GCS) LoseNext(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.loseNext = n
}

// SetDown answers every request 503 while down.
func (g *GCS) SetDown(down bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.down = down
}

// Requests returns every request received, in order.
func (g *GCS) Requests() []Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Request(nil), g.requests...)
}

func (g *GCS) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(),
		Auth: r.Header.Get("Authorization"), Body: string(body)})
	if g.down {
		http.Error(w, `{"error":{"code":503}}`, http.StatusServiceUnavailable)
		return
	}
	if g.token != "" && r.Header.Get("Authorization") != "Bearer "+g.token {
		http.Error(w, `{"error":{"code":401}}`, http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/upload/storage/v1/b/"+g.bucket+"/o" {
		http.Error(w, `{"error":{"code":404}}`, http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	name := q.Get("name")
	if q.Get("uploadType") != "media" || name == "" || strings.HasPrefix(name, "/") {
		http.Error(w, `{"error":{"code":400}}`, http.StatusBadRequest)
		return
	}
	if g.failNext > 0 {
		g.failNext--
		http.Error(w, `{"error":{"code":503}}`, http.StatusServiceUnavailable)
		return
	}
	if _, exists := g.objects[name]; exists && q.Get("ifGenerationMatch") == "0" {
		http.Error(w, `{"error":{"code":412,"message":"conditionNotMet"}}`, http.StatusPreconditionFailed)
		return
	}
	g.objects[name] = body
	if g.loseNext > 0 {
		g.loseNext--
		http.Error(w, `{"error":{"code":503}}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"bucket": g.bucket, "name": name, "generation": "1"})
}
