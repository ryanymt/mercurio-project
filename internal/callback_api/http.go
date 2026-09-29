package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Routing and JSON only. Every decision is in the protected files: authentication and the
// per-route mapping in transitions_http.go, the rules in the engine.

// Server is the callback API's HTTP front.
type Server struct {
	db     *sql.DB
	engine *Engine
	auth   Authenticator
	log    *slog.Logger
}

// NewServer returns the callback API over db, using engine for every change and auth for every
// caller.
func NewServer(db *sql.DB, engine *Engine, auth Authenticator, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{db: db, engine: engine, auth: auth, log: log}
}

// Handler routes the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("POST /v1/tickets", s.handle(s.create))
	mux.Handle("POST /v1/tickets/{id}/transitions", s.handle(s.transition))
	mux.Handle("POST /v1/tickets/{id}/decompose", s.handle(s.decompose))
	mux.Handle("POST /v1/tickets/{id}/heartbeat", s.handle(s.heartbeat))
	mux.Handle("POST /v1/tickets/{id}/artifacts", s.handle(s.artifact))
	mux.Handle("POST /v1/tickets/{id}/rate-limit", s.handle(s.rateLimit))
	mux.Handle("PUT /v1/tickets/{id}/parking", s.handle(s.park))
	mux.Handle("POST /v1/promotions", s.handle(s.promote))
	return mux
}

// health answers 200 when the database answers, 503 otherwise.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "database unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError answers with a refusal's status and reason. An internal error's detail is logged,
// never sent.
func (s *Server) writeError(w http.ResponseWriter, err error) {
	status := StatusOf(err)
	msg := err.Error()
	if status >= 500 {
		s.log.Error("callback api internal error", "error", err)
		msg = "internal error"
	} else if e := (*Error)(nil); errors.As(err, &e) {
		msg = e.Reason
	}
	writeJSON(w, status, map[string]any{"error": msg, "status": status})
}
