package capture_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanymt/mercurio-project/internal/capture"
	"github.com/ryanymt/mercurio-project/internal/capture/capturetest"
	"github.com/ryanymt/mercurio-project/internal/dispatcher/cloudrun/cloudruntest"
)

const (
	bucket      = "your-project-id-artifacts"
	accessToken = "ya29.fake-access-token-for-the-runner"
)

func init() { capture.SetRetryBackoff(time.Millisecond) }

// registrar stands in for the callback API's fenced artifacts endpoint.
type registrar struct {
	mu    sync.Mutex
	calls []string // kind + " " + prefix
	err   error
}

func (r *registrar) Register(_ context.Context, kind capture.Kind, prefix string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.calls = append(r.calls, string(kind)+" "+prefix)
	return nil
}

func (r *registrar) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// lockedBuffer is a log sink the test reads while the background flush writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type rig struct {
	gcs  *capturetest.GCS
	reg  *registrar
	logs *lockedBuffer
	cfg  capture.Config
}

func newRig(t *testing.T) *rig {
	t.Helper()
	g := capturetest.NewGCS(t, bucket, accessToken)
	store, err := capture.NewGCS(g.URL(), bucket, capture.TokenFunc(func(context.Context) (string, error) { return accessToken, nil }), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{gcs: g, reg: &registrar{}, logs: &lockedBuffer{}}
	r.cfg = capture.Config{
		Project: "sandbox", Ticket: 7, Attempt: 1, Role: "dev", Run: capture.NewRun(),
		Store: store, Registrar: r.reg, Interval: time.Hour,
		Log: slog.New(slog.NewJSONHandler(r.logs, nil)),
	}
	return r
}

func (r *rig) start(t *testing.T) *capture.Capture {
	t.Helper()
	c, err := capture.Start(context.Background(), r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *rig) chunk(t *testing.T, kind capture.Kind, seq int) (string, bool) {
	t.Helper()
	b, ok := r.gcs.Object(fmt.Sprintf("sandbox/7/1/dev-%s/%s/%06d.jsonl", r.cfg.Run, kind, seq))
	return string(b), ok
}

// A run id is 32 lowercase hex characters, new for each runner start (P06 Approach 3).
func TestARunIDIsRandomHex(t *testing.T) {
	a, b := capture.NewRun(), capture.NewRun()
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(a) || a == b {
		t.Fatalf("run ids %q and %q", a, b)
	}
}

// Start registers each kind's prefix, {project}/{ticket}/{attempt}/{role}-{run}/{kind} with no
// trailing slash, once, before any chunk is written.
func TestStartRegistersEachKindBeforeAnyChunk(t *testing.T) {
	r := newRig(t)
	c := r.start(t)
	want := []string{
		"transcript sandbox/7/1/dev-" + r.cfg.Run + "/transcript",
		"test_report sandbox/7/1/dev-" + r.cfg.Run + "/test_report",
	}
	if got := r.reg.Calls(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("registered %v, want %v", got, want)
	}
	if n := len(r.gcs.Names()); n != 0 {
		t.Fatalf("%d objects before any line", n)
	}
	if p := c.Prefix(capture.Transcript); p != "sandbox/7/1/dev-"+r.cfg.Run+"/transcript" {
		t.Fatalf("prefix %q", p)
	}
	c.Line(capture.Transcript, `{"step":"one"}`)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(r.reg.Calls()); n != 2 {
		t.Fatalf("%d registrations after writing, want the 2 made at the start", n)
	}
}

// A registration the callback API refuses is an error from Start: nothing is captured that the
// ticket would not list.
func TestARefusedRegistrationStopsTheStart(t *testing.T) {
	r := newRig(t)
	r.reg.err = errors.New("409: the lease has expired")
	if _, err := capture.Start(context.Background(), r.cfg); err == nil {
		t.Fatal("Start succeeded with registration refused")
	}
	if n := len(r.gcs.Names()); n != 0 {
		t.Fatalf("%d objects written", n)
	}
}

// What Start refuses: a malformed run id, project, role, ticket or attempt, or no store or
// registrar.
func TestStartRefusesABadConfig(t *testing.T) {
	r := newRig(t)
	for name, mutate := range map[string]func(*capture.Config){
		"run not hex":        func(c *capture.Config) { c.Run = strings.Repeat("Z", 32) },
		"run too short":      func(c *capture.Config) { c.Run = "abc" },
		"project with slash": func(c *capture.Config) { c.Project = "a/b" },
		"no project":         func(c *capture.Config) { c.Project = "" },
		"role with dash":     func(c *capture.Config) { c.Role = "dev-x" },
		"no ticket":          func(c *capture.Config) { c.Ticket = 0 },
		"no attempt":         func(c *capture.Config) { c.Attempt = 0 },
		"no store":           func(c *capture.Config) { c.Store = nil },
		"no registrar":       func(c *capture.Config) { c.Registrar = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := r.cfg
			mutate(&cfg)
			if _, err := capture.Start(context.Background(), cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if n := len(r.reg.Calls()); n != 0 {
		t.Fatalf("%d registrations from refused configs", n)
	}
}

// Lines are uploaded as numbered chunks on demand and on Close; a flush with nothing new writes
// nothing. Each create carries ifGenerationMatch=0 and the job's token.
func TestChunksOnFlushAndOnClose(t *testing.T) {
	r := newRig(t)
	c := r.start(t)
	ctx := context.Background()
	c.Line(capture.Transcript, `{"step":"one"}`)
	c.Line(capture.Transcript, `{"step":"two"}`)
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	c.Line(capture.Transcript, `{"step":"three"}`)
	c.Line(capture.TestReport, `{"test":"echo file","ok":true}`)
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	one, ok1 := r.chunk(t, capture.Transcript, 1)
	two, ok2 := r.chunk(t, capture.Transcript, 2)
	report, ok3 := r.chunk(t, capture.TestReport, 1)
	if !ok1 || !ok2 || !ok3 || one != "{\"step\":\"one\"}\n{\"step\":\"two\"}\n" || two != "{\"step\":\"three\"}\n" ||
		report != "{\"test\":\"echo file\",\"ok\":true}\n" {
		t.Fatalf("chunks %q %q %q (names %v)", one, two, report, r.gcs.Names())
	}
	if n := len(r.gcs.Names()); n != 3 {
		t.Fatalf("%d objects, want 3: an empty flush writes nothing", n)
	}
	for _, q := range r.gcs.Requests() {
		if q.Query.Get("ifGenerationMatch") != "0" || q.Auth != "Bearer "+accessToken {
			t.Fatalf("a create without the precondition or the token: %+v", q)
		}
	}
}

// Event encodes a value as one JSON line, with no HTML escaping.
func TestEventIsOneJSONLine(t *testing.T) {
	r := newRig(t)
	c := r.start(t)
	if err := c.Event(capture.Transcript, map[string]any{"cmd": "a && b <c>"}); err != nil {
		t.Fatal(err)
	}
	c.Close(context.Background())
	if got, _ := r.chunk(t, capture.Transcript, 1); got != "{\"cmd\":\"a && b <c>\"}\n" {
		t.Fatalf("chunk %q", got)
	}
}

// Without a flush asked for, lines still go up at least every interval (the Anchor's two minutes).
func TestFlushesAtLeastEveryInterval(t *testing.T) {
	r := newRig(t)
	r.cfg.Interval = 50 * time.Millisecond
	c := r.start(t)
	defer c.Close(context.Background())
	c.Line(capture.Transcript, `{"step":"waiting"}`)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, ok := r.chunk(t, capture.Transcript, 1); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no chunk within the interval")
		}
	}
}

// A runner killed between flushes leaves every chunk it flushed.
func TestAKilledRunnerLeavesWhatItFlushed(t *testing.T) {
	r := newRig(t)
	c := r.start(t)
	c.Line(capture.Transcript, `{"step":"flushed"}`)
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Line(capture.Transcript, `{"step":"lost with the process"}`)
	// Killed: no Close.
	if got, ok := r.chunk(t, capture.Transcript, 1); !ok || got != "{\"step\":\"flushed\"}\n" {
		t.Fatalf("chunk 1 %q, %v", got, ok)
	}
}

// A failed upload keeps its lines for the next chunk, under a new number; the flush says it failed.
func TestAFailedUploadIsCarriedIntoTheNextChunk(t *testing.T) {
	r := newRig(t)
	c := r.start(t)
	ctx := context.Background()
	c.Line(capture.Transcript, `{"step":"one"}`)
	r.gcs.SetDown(true) // every retry of this flush fails
	if err := c.Flush(ctx); err == nil {
		t.Fatal("a flush whose upload failed reported success")
	}
	r.gcs.SetDown(false)
	c.Line(capture.Transcript, `{"step":"two"}`)
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.chunk(t, capture.Transcript, 1); ok {
		t.Fatal("chunk 1 exists, though its upload failed")
	}
	if got, ok := r.chunk(t, capture.Transcript, 2); !ok || got != "{\"step\":\"one\"}\n{\"step\":\"two\"}\n" {
		t.Fatalf("chunk 2 %q, %v: want both lines", got, ok)
	}
}

// An upload whose response was lost is retried under the same name; the retry's 412 means the
// first landed, and counts as success: no second copy.
func TestA412OnARetryIsSuccess(t *testing.T) {
	r := newRig(t)
	c := r.start(t)
	c.Line(capture.Transcript, `{"step":"one"}`)
	r.gcs.LoseNext(1)
	if err := c.Flush(context.Background()); err != nil {
		t.Fatalf("the retry's 412 was not taken as success: %v", err)
	}
	c.Line(capture.Transcript, `{"step":"two"}`)
	c.Close(context.Background())
	one, _ := r.chunk(t, capture.Transcript, 1)
	two, _ := r.chunk(t, capture.Transcript, 2)
	if one != "{\"step\":\"one\"}\n" || two != "{\"step\":\"two\"}\n" {
		t.Fatalf("chunks %q and %q: want each line once", one, two)
	}
}

// A chunk is never overwritten: a name already taken on the first try is a failure (not success),
// and the lines go into the next number.
func TestAChunkIsNeverOverwritten(t *testing.T) {
	r := newRig(t)
	first := r.start(t)
	first.Line(capture.Transcript, `{"from":"the first"}`)
	if err := first.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A second capture under the same run (it cannot happen with random runs; the store still holds).
	second := r.start(t)
	second.Line(capture.Transcript, `{"from":"the second"}`)
	if err := second.Flush(context.Background()); err == nil {
		t.Fatal("a create over an existing chunk reported success")
	}
	if got, _ := r.chunk(t, capture.Transcript, 1); got != "{\"from\":\"the first\"}\n" {
		t.Fatalf("chunk 1 was overwritten: %q", got)
	}
	if err := second.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.chunk(t, capture.Transcript, 2); got != "{\"from\":\"the second\"}\n" {
		t.Fatalf("chunk 2 %q", got)
	}
}

// Two runners of one attempt (a QA runner after the dev runner, or a runner after a reap from
// claimed) write apart: their roles and runs differ.
func TestTwoRunnersOfOneAttemptWriteApart(t *testing.T) {
	r := newRig(t)
	dev := r.start(t)
	r.cfg.Run = capture.NewRun()
	again := r.start(t)
	r.cfg.Role, r.cfg.Run = "qa", capture.NewRun()
	qa := r.start(t)
	for i, c := range []*capture.Capture{dev, again, qa} {
		c.Line(capture.Transcript, fmt.Sprintf(`{"runner":%d}`, i))
		if err := c.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if names := r.gcs.Names(); len(names) != 3 {
		t.Fatalf("objects %v, want three apart", names)
	}
}

// Every line is scrubbed before it leaves the process: patterns and the runner's own token, whose
// value and base64 forms never reach the bucket (P05's leak check).
func TestUploadsAreScrubbed(t *testing.T) {
	r := newRig(t)
	token := "ghs_" + "fakeInstallationToken" + "0000000007"
	r.cfg.Known = []string{token, accessToken}
	c := r.start(t)
	c.Line(capture.Transcript, `{"cmd":"git push https://x-access-token:`+token+`@github.com/ryanymt/sandbox.git"}`)
	c.Line(capture.Transcript, `{"env":"GITHUB_TOKEN=`+token+`"}`)
	c.Line(capture.Transcript, `{"output":"remote: `+token+` rejected"}`) // only the known value catches this
	c.Line(capture.TestReport, `{"output":"key `+"AIza"+strings.Repeat("q", 35)+`"}`)
	c.Close(context.Background())
	for _, name := range r.gcs.Names() {
		b, _ := r.gcs.Object(name)
		for _, secret := range []string{token, accessToken} {
			if leaks := cloudruntest.Leaks(string(b), secret); len(leaks) > 0 {
				t.Errorf("%s holds %v", name, leaks)
			}
		}
		if !strings.Contains(string(b), "[redacted:") {
			t.Errorf("%s shows no redaction: %s", name, b)
		}
	}
	if leaks := cloudruntest.Leaks(r.logs.String(), token); len(leaks) > 0 {
		t.Errorf("the log holds %v", leaks)
	}
}

// With the store down, a flush is an error the runner can log, the background flush logs it, and
// Close reports it: nothing panics, and the lines are kept for a later flush.
func TestAnUploadFailureIsAnErrorNotACrash(t *testing.T) {
	r := newRig(t)
	r.cfg.Interval = 20 * time.Millisecond
	c := r.start(t)
	r.gcs.SetDown(true)
	c.Line(capture.Transcript, `{"step":"one"}`)
	time.Sleep(150 * time.Millisecond) // a few background flushes fail
	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("a flush to a store that is down reported success")
	}
	if !strings.Contains(r.logs.String(), `"level":"ERROR"`) {
		t.Fatalf("the background flush's failure was not logged: %s", r.logs.String())
	}
	r.gcs.SetDown(false)
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close after the store came back: %v", err)
	}
	found := false
	for _, name := range r.gcs.Names() {
		if b, _ := r.gcs.Object(name); string(b) == "{\"step\":\"one\"}\n" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the line was lost: %v", r.gcs.Names())
	}
}

// The GCS client: an http endpoint is refused unless it is loopback (the tests'), a 412 is
// ErrExists, and an error names the status, never the token.
func TestTheGCSClient(t *testing.T) {
	tokens := capture.TokenFunc(func(context.Context) (string, error) { return accessToken, nil })
	for _, u := range []string{"http://storage.googleapis.com", "ftp://x", ""} {
		if _, err := capture.NewGCS(u, bucket, tokens, nil); err == nil {
			t.Errorf("endpoint %q accepted", u)
		}
	}
	if _, err := capture.NewGCS(capture.GCSEndpoint, bucket, tokens, nil); err != nil {
		t.Errorf("Google's endpoint refused: %v", err)
	}
	if _, err := capture.NewGCS(capture.GCSEndpoint, "", tokens, nil); err == nil {
		t.Error("no bucket accepted")
	}

	g := capturetest.NewGCS(t, bucket, accessToken)
	store, err := capture.NewGCS(g.URL(), bucket, tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Create(ctx, "a/b.jsonl", []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, "a/b.jsonl", []byte("y\n")); !errors.Is(err, capture.ErrExists) {
		t.Fatalf("a second create: %v, want ErrExists", err)
	}
	g.SetDown(true)
	err = store.Create(ctx, "a/c.jsonl", []byte("z\n"))
	if err == nil || !strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), accessToken) {
		t.Fatalf("an error from a store that is down: %v", err)
	}
	bad := capture.TokenFunc(func(context.Context) (string, error) { return "", errors.New("metadata server down") })
	nostore, _ := capture.NewGCS(g.URL(), bucket, bad, nil)
	if err := nostore.Create(ctx, "a/d.jsonl", nil); err == nil {
		t.Fatal("a create without a token succeeded")
	}
}
