// Package capture records what a runner did, its transcript and its test output, into the private
// artifacts bucket, scrubbed of secrets, in chunks that are never overwritten (P06 Approach 3, D9,
// D10). The echo runner uses it now, and P07's runner later.
//
// A capture belongs to one runner start: {project}/{ticket}/{attempt}/{role}-{run}, run being
// random, so two runners of one attempt (a re-claim after a reap from claimed, or QA after dev)
// write apart. Each kind's prefix, {role}-{run}/{kind}, is registered on the ticket through the
// callback API's fenced artifacts endpoint before anything is written, so the viewer, which lists
// registered prefixes only, finds every chunk. Lines are scrubbed as they arrive; at least every
// interval, on demand before a transition that ends the runner's lease, and on Close, the new ones
// are uploaded as the next numbered chunk, {seq}.jsonl, created only if no object has that name.
package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Kind is what a chunk holds, and the artifact kind its prefix is registered as.
type Kind string

const (
	Transcript Kind = "transcript"
	TestReport Kind = "test_report"
)

var kinds = []Kind{Transcript, TestReport}

// DefaultInterval is the longest a line waits before it is uploaded (the Anchor's two minutes).
const DefaultInterval = 2 * time.Minute

const (
	maxAttempts  = 3                // tries of one chunk, under one name
	flushTimeout = 30 * time.Second // a background flush's bound
)

var retryBackoff = time.Second // between tries; shortened by the tests

// ErrExists is a create refused because an object of that name exists (412).
var ErrExists = errors.New("capture: an object of that name already exists")

// Store creates objects, never overwriting one. *GCS is the production one.
type Store interface {
	Create(ctx context.Context, name string, data []byte) error
}

// Registrar registers a kind's prefix on the runner's ticket, with its claim token: the callback
// API's fenced artifacts endpoint, through the runner's client.
type Registrar interface {
	Register(ctx context.Context, kind Kind, prefix string) error
}

// Config is one runner start's capture.
type Config struct {
	Project string // the ticket's project
	Ticket  int64
	Attempt int    // the ticket's dev attempt count, which the artifacts endpoint files under
	Role    string // the runner's role: dev, qa, integrator
	Run     string // 32 lowercase hex characters, new for each runner start (NewRun)

	Store     Store
	Registrar Registrar
	Known     []string      // values redacted wherever they appear: the runner's tokens
	Interval  time.Duration // default DefaultInterval
	Log       *slog.Logger  // for the background flushes' failures; default slog.Default
}

var (
	runPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	projectPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	rolePattern    = regexp.MustCompile(`^[a-z][a-z_]*$`) // no dash: the segment is {role}-{run}
)

// NewRun returns a run id: 32 random lowercase hex characters.
func NewRun() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Capture is one runner start's capture. Its methods are safe for concurrent use.
type Capture struct {
	base     string // {project}/{ticket}/{attempt}/{role}-{run}
	store    Store
	scrubber *Scrubber
	log      *slog.Logger

	mu      sync.Mutex
	pending map[Kind][]string // scrubbed lines not yet uploaded
	seq     map[Kind]int      // the last chunk number used

	flushMu   sync.Mutex
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// Start checks the configuration, registers each kind's prefix, and starts the background flush.
// A refused registration is an error, and nothing is captured.
func Start(ctx context.Context, cfg Config) (*Capture, error) {
	switch {
	case !projectPattern.MatchString(cfg.Project):
		return nil, fmt.Errorf("capture: bad project %q", cfg.Project)
	case cfg.Ticket <= 0 || cfg.Attempt <= 0:
		return nil, fmt.Errorf("capture: ticket %d and attempt %d must be positive", cfg.Ticket, cfg.Attempt)
	case !rolePattern.MatchString(cfg.Role):
		return nil, fmt.Errorf("capture: bad role %q", cfg.Role)
	case !runPattern.MatchString(cfg.Run):
		return nil, errors.New("capture: a run id is 32 lowercase hex characters")
	case cfg.Store == nil || cfg.Registrar == nil:
		return nil, errors.New("capture: a store and a registrar are required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	c := &Capture{
		base:  fmt.Sprintf("%s/%d/%d/%s-%s", cfg.Project, cfg.Ticket, cfg.Attempt, cfg.Role, cfg.Run),
		store: cfg.Store, scrubber: NewScrubber(cfg.Known...), log: cfg.Log,
		pending: map[Kind][]string{}, seq: map[Kind]int{},
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	for _, k := range kinds {
		if err := cfg.Registrar.Register(ctx, k, c.Prefix(k)); err != nil {
			return nil, fmt.Errorf("capture: register the %s prefix: %w", k, err)
		}
	}
	go c.loop(cfg.Interval)
	return c, nil
}

// Prefix is a kind's registered prefix, with no trailing slash.
func (c *Capture) Prefix(k Kind) string { return c.base + "/" + string(k) }

// Line records text as lines of kind, scrubbed now; text holding newlines is several lines.
func (c *Capture) Line(k Kind, text string) {
	if k != Transcript && k != TestReport {
		c.log.Error("capture: a line of an unknown kind was dropped", "kind", string(k))
		return
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i := range lines {
		lines[i] = c.scrubber.Scrub(lines[i])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[k] = append(c.pending[k], lines...)
}

// Event records v as one JSON line of kind, without HTML escaping.
func (c *Capture) Event(k Kind, v any) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("capture: encode an event: %w", err)
	}
	c.Line(k, b.String())
	return nil
}

// Flush uploads each kind's new lines as its next chunk. A chunk that cannot be uploaded keeps its
// lines for the next flush, under a new number, and the error says which; a runner logs it and
// goes on.
func (c *Capture) Flush(ctx context.Context) error {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	var errs []error
	for _, k := range kinds {
		c.mu.Lock()
		lines := c.pending[k]
		c.pending[k] = nil
		if len(lines) > 0 {
			c.seq[k]++
		}
		seq := c.seq[k]
		c.mu.Unlock()
		if len(lines) == 0 {
			continue
		}
		name := fmt.Sprintf("%s/%06d.jsonl", c.Prefix(k), seq)
		if err := c.upload(ctx, name, []byte(strings.Join(lines, "\n")+"\n")); err != nil {
			c.mu.Lock()
			c.pending[k] = append(lines, c.pending[k]...)
			c.mu.Unlock()
			errs = append(errs, fmt.Errorf("capture: %s chunk %d: %w", k, seq, err))
		}
	}
	return errors.Join(errs...)
}

// upload creates one chunk, trying up to maxAttempts times under the same name. A 412 on a retry
// means an earlier try landed and only its response was lost: that is success. A 412 on the first
// try means the name was already taken: never overwritten, it is a failure.
func (c *Capture) upload(ctx context.Context, name string, data []byte) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			case <-time.After(retryBackoff):
			}
		}
		err = c.store.Create(ctx, name, data)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, ErrExists) && attempt > 0:
			return nil
		case errors.Is(err, ErrExists):
			return err
		}
	}
	return err
}

func (c *Capture) loop(interval time.Duration) {
	defer close(c.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
			if err := c.Flush(ctx); err != nil {
				c.log.Error("capture: a flush failed; its lines wait for the next", "error", err)
			}
			cancel()
		}
	}
}

// Close stops the background flush and flushes what is left. Calling it again only flushes.
func (c *Capture) Close(ctx context.Context) error {
	c.closeOnce.Do(func() {
		close(c.stop)
		<-c.done
	})
	return c.Flush(ctx)
}
