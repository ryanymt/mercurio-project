package callbackapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The HTTP layer's decisions: who the caller is (its verified token, and nothing else, or the
// person whose IAP assertion the viewer relays), which channel a route is (every HTTP transition is
// ChannelHTTP, so the dispatcher's rows, the internal rows and `ready -> decomposed` are refused on
// /transitions), and which request fields exist (the body is decoded strictly, so an unknown field
// is refused). Routing and JSON are in http.go.

// Authenticator turns a bearer token into a verified caller, and a relayed IAP assertion into the
// person it names. *Verifier is the production one.
type Authenticator interface {
	Verify(ctx context.Context, raw string) (Caller, error)
	VerifyRelayed(ctx context.Context, raw string) (Caller, error)
}

// RelayHeader carries a person's IAP assertion, relayed by the viewer with its own token (P06 D4).
const RelayHeader = "X-Foreman-IAP-Assertion"

// relay says whether a route takes a person relayed by the viewer. Only creating a ticket, a
// transition and parking do (P06 D20): a person's other acts, a promotion among them, have no HTTP
// path through the relay.
type relay bool

const (
	direct    relay = false
	relayable relay = true
)

const maxBody = 1 << 20

// input is one authenticated request, ready for an operation.
type input struct {
	r      *http.Request
	caller Caller
	key    string // Idempotency-Key
	claim  string // X-Foreman-Claim-Token
	id     int64  // {id} in the path, when the route has one
}

// operation runs in one READ COMMITTED transaction and returns the status and body of a success.
type operation func(ctx context.Context, tx *sql.Tx, in *input) (int, any, error)

// handle authenticates, decodes the path, runs the operation in its own transaction, commits on
// success and rolls back on any error, so a refusal leaves nothing behind.
func (s *Server) handle(op operation, rl relay) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, err := s.authenticate(r, rl)
		if err != nil {
			s.writeError(w, err)
			return
		}
		in := &input{r: r, caller: caller, key: r.Header.Get("Idempotency-Key"),
			claim: r.Header.Get("X-Foreman-Claim-Token")}
		if raw := r.PathValue("id"); raw != "" {
			if in.id, err = strconv.ParseInt(raw, 10, 64); err != nil || in.id <= 0 {
				s.writeError(w, refuse(400, "bad ticket id"))
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		tx, err := BeginTx(r.Context(), s.db)
		if err != nil {
			s.writeError(w, internal("begin", err))
			return
		}
		status, body, err := op(r.Context(), tx, in)
		if err != nil {
			tx.Rollback()
			s.writeError(w, err)
			return
		}
		if err := tx.Commit(); err != nil {
			s.writeError(w, internal("commit", err))
			return
		}
		writeJSON(w, status, body)
	})
}

// authenticate verifies the bearer token. Only the viewer may send RelayHeader, and the viewer is
// nobody by itself: on a relayable route it must relay exactly one assertion, and the caller is the
// person it names; on any other route it is refused (403), as is any other caller sending the
// header, even empty.
func (s *Server) authenticate(r *http.Request, rl relay) (Caller, error) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || token == "" {
		return Caller{}, refuse(401, "a bearer token is required")
	}
	caller, err := s.auth.Verify(r.Context(), token)
	if err != nil {
		return Caller{}, err
	}
	assertions := r.Header.Values(RelayHeader)
	if caller.Role != RoleViewer {
		if len(assertions) > 0 {
			return Caller{}, refuse(403, "only the viewer relays a person's assertion")
		}
		return caller, nil
	}
	if rl != relayable {
		return Caller{}, refuse(403, "the viewer relays a person only to create tickets, make transitions and park")
	}
	if len(assertions) != 1 {
		return Caller{}, refuse(401, "the viewer must relay exactly one IAP assertion")
	}
	return s.auth.VerifyRelayed(r.Context(), assertions[0])
}

// decode reads a JSON body strictly: unknown fields are refused, so the struct is the allowlist.
// An empty body decodes to the zero value.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return refuse(400, "bad request body: %v", err)
	}
	if dec.More() {
		return refuse(400, "bad request body: trailing data")
	}
	return nil
}

func noNull(raw json.RawMessage) json.RawMessage {
	if string(raw) == "null" {
		return nil
	}
	return raw
}

func (s *Server) transition(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct {
		From               State           `json:"from"`
		To                 State           `json:"to"`
		Payload            json.RawMessage `json:"payload"`
		AcceptanceCriteria []Criterion     `json:"acceptance_criteria"`
		HeadSHA            string          `json:"head_sha"`
		EscalatedAt        *time.Time      `json:"escalated_at"`
	}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.Transition(ctx, tx, TransitionRequest{
		TicketID: in.id, From: body.From, To: body.To, Caller: in.caller, Channel: ChannelHTTP,
		RequestID: in.key, ClaimToken: in.claim, Payload: noNull(body.Payload),
		AcceptanceCriteria: body.AcceptanceCriteria, HeadSHA: body.HeadSHA, EscalatedAt: body.EscalatedAt,
		Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 200, res, err
}

func (s *Server) create(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct {
		Project            string      `json:"project"`
		Title              string      `json:"title"`
		Body               string      `json:"body"`
		Priority           int         `json:"priority"`
		AcceptanceCriteria []Criterion `json:"acceptance_criteria"`
	}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.Create(ctx, tx, CreateRequest{
		Caller: in.caller, Project: body.Project, Title: body.Title, Body: body.Body, Priority: body.Priority,
		AcceptanceCriteria: body.AcceptanceCriteria, RequestID: in.key, Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 201, res, err
}

func (s *Server) decompose(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct {
		Children []ChildSpec `json:"children"`
	}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.Decompose(ctx, tx, DecomposeRequest{
		TicketID: in.id, Caller: in.caller, Children: body.Children, RequestID: in.key,
		Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 200, res, err
}

func (s *Server) heartbeat(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct{}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.Heartbeat(ctx, tx, HeartbeatRequest{
		TicketID: in.id, Caller: in.caller, RequestID: in.key, ClaimToken: in.claim,
		Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 200, res, err
}

func (s *Server) artifact(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct {
		Kind    string `json:"kind"`
		GCSPath string `json:"gcs_path"`
	}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.RegisterArtifact(ctx, tx, ArtifactRequest{
		TicketID: in.id, Caller: in.caller, Kind: body.Kind, GCSPath: body.GCSPath,
		RequestID: in.key, ClaimToken: in.claim, Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 201, res, err
}

// rateLimit's body names the reset time and nothing else: the provider is the caller's own
// attempt's, never one it names (P04 Approach 7).
func (s *Server) rateLimit(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct {
		ResetAt time.Time `json:"reset_at"`
	}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.RateLimit(ctx, tx, RateLimitRequest{
		TicketID: in.id, Caller: in.caller, RequestID: in.key, ClaimToken: in.claim, ResetAt: body.ResetAt,
		Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 200, res, err
}

func (s *Server) park(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct {
		Parked      bool       `json:"parked"`
		Reason      string     `json:"reason"`
		Until       *time.Time `json:"until"`
		EscalatedAt *time.Time `json:"escalated_at"`
	}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.Park(ctx, tx, ParkingRequest{
		TicketID: in.id, Caller: in.caller, Parked: body.Parked, Reason: body.Reason, Until: body.Until,
		EscalatedAt: body.EscalatedAt, RequestID: in.key, Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 200, res, err
}

func (s *Server) promote(ctx context.Context, tx *sql.Tx, in *input) (int, any, error) {
	var body struct {
		Component   string `json:"component"`
		ImageDigest string `json:"image_digest"`
		GitSHA      string `json:"git_sha"`
	}
	if err := decode(in.r, &body); err != nil {
		return 0, nil, err
	}
	res, err := s.engine.Promote(ctx, tx, PromotionRequest{
		Caller: in.caller, Component: body.Component, ImageDigest: body.ImageDigest, GitSHA: body.GitSHA,
		RequestID: in.key, Method: in.r.Method, Path: in.r.URL.Path,
	})
	return 201, res, err
}
