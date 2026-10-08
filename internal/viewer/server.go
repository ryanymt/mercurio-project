package viewer

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

//go:embed templates/*.html static/style.css
var assets embed.FS

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"ts":    func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) },
	"short": func(s string) string { return shortSHA(s) },
	"lower": strings.ToLower,
}).ParseFS(assets, "templates/*.html"))

// Relay sends a person's act to the callback API as the viewer, with their IAP assertion (D4). It
// answers the API's status, its reason when it refused, and its body when it did not.
type Relay interface {
	Send(ctx context.Context, method, path, assertion, key string, body any) (status int, reason string, out map[string]any, err error)
}

// Diffs reads base...head from a project's repository.
type Diffs interface {
	Compare(ctx context.Context, repoURL, base, head string) (Diff, error)
}

// DiffStatus says what GitHub could give.
type DiffStatus string

const (
	DiffOK       DiffStatus = "ok"
	DiffTooLarge DiffStatus = "too-large" // a 5xx or a timeout: the diff format has no pagination
	DiffNotFound DiffStatus = "not-found" // a 404 or 422: a commit GitHub does not know
)

// Diff is a compare's outcome.
type Diff struct {
	Status     DiffStatus
	Base, Head string
	Text       string   // the unified diff, when Status is DiffOK
	Files      []string // the changed files, at most 300 (GitHub's JSON compare), when too large
	CompareURL string   // GitHub's own compare page
}

// Config is the viewer's.
type Config struct {
	DB       *sql.DB // as the read-only `viewer` user
	Identify func(ctx context.Context, assertion string) (callbackapi.Caller, error)
	Chunks   Chunks
	Diffs    Diffs
	Relay    Relay
	CSRFKey  []byte   // at least 32 bytes, the same in every instance (Secret Manager)
	Origins  []string // the viewer's own origins, for a POST that sends Origin and no Sec-Fetch-Site

	MaxChunks     int   // objects read per prefix; DefaultMaxChunks when 0
	MaxChunkBytes int64 // bytes read per object; DefaultMaxChunkBytes when 0
	MaxPageBytes  int64 // bytes read per artifact page, across its objects; DefaultMaxPageBytes when 0
	Now           func() time.Time
	Log           *slog.Logger
}

const (
	DefaultMaxChunks     = 200
	DefaultMaxChunkBytes = 1 << 20
	// DefaultMaxPageBytes keeps one page well inside the instance's memory (512 MiB), whatever a
	// session wrote: the counts above alone would allow 200 MiB.
	DefaultMaxPageBytes = 16 << 20
)

// Server is the viewer.
type Server struct {
	cfg Config
	log *slog.Logger
}

// New checks the configuration.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.DB == nil || cfg.Identify == nil || cfg.Chunks == nil || cfg.Diffs == nil || cfg.Relay == nil:
		return nil, errors.New("viewer: a database, an identifier, a bucket, diffs and a relay are required")
	case len(cfg.CSRFKey) < 32:
		return nil, errors.New("viewer: the CSRF key must be at least 32 bytes")
	case len(cfg.Origins) == 0:
		return nil, errors.New("viewer: its own origin is required")
	}
	if cfg.MaxChunks <= 0 {
		cfg.MaxChunks = DefaultMaxChunks
	}
	if cfg.MaxChunkBytes <= 0 {
		cfg.MaxChunkBytes = DefaultMaxChunkBytes
	}
	if cfg.MaxPageBytes <= 0 {
		cfg.MaxPageBytes = DefaultMaxPageBytes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Server{cfg: cfg, log: cfg.Log}, nil
}

// Handler routes the viewer, every route behind the assertion's check.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.list)
	mux.HandleFunc("GET /tickets/{id}", s.ticketPage)
	mux.HandleFunc("GET /tickets/{id}/artifacts/{aid}", s.artifactPage)
	mux.HandleFunc("GET /tickets/{id}/diff", s.diffPage)
	mux.Handle("GET /whoami", WhoAmI(s.log))
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		b, _ := assets.ReadFile("static/style.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(b)
	})
	s.actionRoutes(mux)
	return s.guard(mux)
}

type personKey struct{}

// visitor is the person a request is from, and the assertion that says so.
type visitor struct {
	caller    callbackapi.Caller
	assertion string
}

func visitorOf(r *http.Request) visitor { v, _ := r.Context().Value(personKey{}).(visitor); return v }

// guard sets the security headers and verifies IAP's assertion on every request, as the callback API
// does (D17): IAP is in front, and the viewer does not trust that alone.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w.Header())
		raw := r.Header.Get(assertionHeader)
		if raw == "" {
			http.Error(w, "no IAP assertion: the viewer is reached only through IAP", http.StatusUnauthorized)
			return
		}
		person, err := s.cfg.Identify(r.Context(), raw)
		if err != nil {
			status := callbackapi.StatusOf(err)
			if status != http.StatusForbidden {
				status = http.StatusUnauthorized
			}
			http.Error(w, "the IAP assertion was not accepted", status)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), personKey{}, visitor{caller: person, assertion: raw})))
	})
}

// render executes a page template; a failure is logged and answered 500 with nothing of it shown.
func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var b strings.Builder
	if err := pages.ExecuteTemplate(&b, name, data); err != nil {
		s.log.Error("viewer: render a page", "page", name, "error", err)
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(b.String()))
}

func (s *Server) fail(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, "message.html", map[string]any{"Title": http.StatusText(status), "Message": msg})
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
