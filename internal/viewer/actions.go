package viewer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// A person's acts (P06 Approach 4 and 5): create a ticket, decide an escalated one, park it, abandon
// an unfinished one. Each is a form rendered with what the page showed (the state, the escalation,
// the head) and an idempotency key, posted back here, checked (the origin, the CSRF token) and
// relayed to the callback API with the person's assertion. The viewer never re-reads the ticket
// when a form is posted: the API holds a decision to what its form names, and refuses it (409) when
// the ticket has changed (D19, red team R5#2). A double tap sends the same key, so it replays.

// maxForm bounds a posted form.
const maxForm = 64 << 10

type field struct{ Name, Value string }

// actionForm is one rendered act.
type actionForm struct {
	Action string // where it posts
	Label  string
	Risky  bool
	Fields []field // hidden: what the page showed, the CSRF token and the idempotency key
	Reason bool    // an optional reason
	Park   bool    // parking: a required reason and an optional date
}

// actions are a ticket's acts, and why any are withheld.
type actions struct {
	Forms []actionForm
	Notes []string
}

var decisionLabels = map[callbackapi.State]string{
	callbackapi.StateReady:          "send back to ready",
	callbackapi.StateApproved:       "approve",
	callbackapi.StateAwaitingReview: "send to QA",
	callbackapi.StateDone:           "mark done",
	callbackapi.StateFailed:         "mark failed",
	callbackapi.StateAbandoned:      "abandon",
}

// actionsFor is what a person may do with t from its page: the human rows of the ownership table
// from its state, less what the engine would refuse for what the page shows.
func (s *Server) actionsFor(r *http.Request, t ticket) actions {
	email := visitorOf(r).caller.Email
	state := callbackapi.State(t.State)
	escalated := state == callbackapi.StateEscalated
	var out actions
	if escalated && t.EscalatedAt == nil {
		out.Notes = append(out.Notes, "this ticket is escalated with no time recorded, so no decision can name the escalation")
		return out
	}
	headKnown := false
	if escalated && !t.HasChildren {
		var why string
		if headKnown, why = s.headKnown(r.Context(), t); !headKnown {
			out.Notes = append(out.Notes, why)
		}
	}
	for _, row := range callbackapi.Table() {
		if row.Actor != callbackapi.RoleHuman || row.Channel != callbackapi.ChannelHTTP || row.From != state {
			continue
		}
		to := row.To
		bound := to == callbackapi.StateApproved || to == callbackapi.StateAwaitingReview
		if escalated && t.HasChildren && (bound || to == callbackapi.StateReady) {
			continue // a parent leaves escalated only to end
		}
		if bound && !headKnown {
			continue
		}
		f := actionForm{Action: fmt.Sprintf("/tickets/%d/decide", t.ID), Label: decisionLabels[to],
			Fields: []field{{"from", t.State}, {"to", string(to)}}}
		if escalated {
			f.Fields = append(f.Fields, field{"escalated_at", t.EscalatedAt.UTC().Format(time.RFC3339Nano)})
		}
		if bound {
			f.Fields = append(f.Fields, field{"head_sha", t.HeadSHA})
		}
		switch to {
		case callbackapi.StateReady:
			// At the cap the engine turns a return to ready into failed (escalation.go), and says so.
			if t.Attempts >= callbackapi.AttemptCap {
				f.Label = fmt.Sprintf("send back to ready: its %d attempts are used, so this fails the ticket", t.Attempts)
				f.Risky = true
			}
		case callbackapi.StateApproved:
			if verdictFor(t) == nil {
				f.Label, f.Risky = "approve without QA or risk evaluation", true
			}
		case callbackapi.StateFailed, callbackapi.StateAbandoned:
			f.Reason, f.Risky = true, true
		}
		f.Fields = append(f.Fields, field{"csrf", s.csrfToken(email, actDecide, t.ID)}, field{"key", newKey()})
		out.Forms = append(out.Forms, f)
	}
	if escalated {
		f := actionForm{Action: fmt.Sprintf("/tickets/%d/park", t.ID), Label: "park", Park: true,
			Fields: []field{{"parked", "true"}}}
		if t.Parked {
			f = actionForm{Action: f.Action, Label: "unpark", Fields: []field{{"parked", "false"}}}
		}
		f.Fields = append(f.Fields, field{"escalated_at", t.EscalatedAt.UTC().Format(time.RFC3339Nano)},
			field{"csrf", s.csrfToken(email, actPark, t.ID)}, field{"key", newKey()})
		out.Forms = append(out.Forms, f)
	}
	return out
}

// headKnown says whether GitHub knows the ticket's head, which a commit-bound action needs (critique
// G3, red team R3#2), and when it does not, why.
func (s *Server) headKnown(ctx context.Context, t ticket) (bool, string) {
	const withheld = "so approving or sending to QA is not offered"
	switch {
	case t.HeadSHA == "":
		return false, "no commit submitted yet, " + withheld
	case t.BaseSHA == "":
		return false, "no base commit is recorded, so the head cannot be compared, and approving or sending to QA is not offered"
	}
	d, err := s.cfg.Diffs.Compare(ctx, t.RepoURL, t.BaseSHA, t.HeadSHA)
	if err != nil {
		s.log.Warn("viewer: compare for the actions", "ticket", t.ID, "error", err)
		return false, fmt.Sprintf("GitHub could not be asked about commit %s, %s: reload to try again", shortSHA(t.HeadSHA), withheld)
	}
	if d.Status == DiffNotFound {
		return false, fmt.Sprintf("GitHub does not know commit %s, %s", shortSHA(t.HeadSHA), withheld)
	}
	return true, ""
}

// newKey is a random (version 4) UUID, the form the API takes as an idempotency key.
func newKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (s *Server) actionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /new", s.newPage)
	mux.HandleFunc("POST /create", s.create)
	mux.HandleFunc("POST /tickets/{id}/decide", s.decide)
	mux.HandleFunc("POST /tickets/{id}/park", s.park)
	// An expired IAP session's login redirect turns a form's POST into a GET of its URL (consult 1).
	for _, p := range []string{"GET /create", "GET /tickets/{id}/decide", "GET /tickets/{id}/park"} {
		mux.HandleFunc(p, s.expired)
	}
}

func (s *Server) newPage(w http.ResponseWriter, r *http.Request) {
	projects, err := s.projects(r.Context())
	if err != nil {
		s.log.Error("viewer: list projects", "error", err)
		s.fail(w, http.StatusInternalServerError, "the projects could not be read")
		return
	}
	email := visitorOf(r).caller.Email
	s.render(w, http.StatusOK, "new.html", map[string]any{"Projects": projects, "CSRF": s.csrfToken(email, actCreate, 0),
		"Key": newKey(), "Person": email})
}

func (s *Server) expired(w http.ResponseWriter, r *http.Request) {
	back := "/"
	if id, ok := pathID(r, "id"); ok {
		back = fmt.Sprintf("/tickets/%d", id)
	}
	s.render(w, http.StatusOK, "message.html", map[string]any{"Title": "Nothing was done",
		"Message": "Your session expired before this was sent; nothing was done.",
		"Detail":  "You are signed in again: reload the page and act again.", "Back": back})
}

// sameOrigin: a POST is the viewer's own when the browser says so in Sec-Fetch-Site, or, from a
// browser that sends none, when its Origin is the viewer's (D17).
func (s *Server) sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "":
		o := r.Header.Get("Origin")
		return o != "" && slices.Contains(s.cfg.Origins, o)
	}
	return false
}

// accept checks a posted form: the viewer's own origin, a readable body, and a CSRF token for this
// person, act and ticket. A refusal is answered here.
func (s *Server) accept(w http.ResponseWriter, r *http.Request, act string, ticket int64) bool {
	if !s.sameOrigin(r) {
		s.fail(w, http.StatusForbidden, "this form was not sent from the viewer's own page; nothing was done")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		s.fail(w, http.StatusBadRequest, "the form could not be read; nothing was done")
		return false
	}
	if !s.csrfValid(r.PostFormValue("csrf"), visitorOf(r).caller.Email, act, ticket) {
		s.fail(w, http.StatusForbidden, "this form's token is missing, for another act, or more than an hour old; nothing was done. Reload the page and act again.")
		return false
	}
	return true
}

// relay sends an act and, unless it succeeded, answers the person: what the API said, and whether
// anything was done.
func (s *Server) relay(w http.ResponseWriter, r *http.Request, method, path string, body any, back string) (map[string]any, bool) {
	v := visitorOf(r)
	status, reason, out, err := s.cfg.Relay.Send(r.Context(), method, path, v.assertion, r.PostFormValue("key"), body)
	s.log.Info("viewer: relayed an act", "path", path, "person", v.caller.Email, "status", status, "error", err)
	page := map[string]any{"Title": "Nothing was done", "Back": back}
	switch {
	case err != nil || status >= 500:
		page["Title"] = "Not known whether it was done"
		page["Message"] = "The callback API did not answer clearly, so it is not known whether this was done."
		page["Detail"] = "Reload the ticket to see. Sending this form again is safe: it carries the same idempotency key, so it is done at most once."
		s.render(w, http.StatusBadGateway, "message.html", page)
		return nil, false
	case status == http.StatusConflict:
		page["Message"] = "The ticket changed since this page was loaded; nothing was done. Reload it and decide again."
		page["Detail"] = "The callback API said: " + reason
		s.render(w, http.StatusConflict, "message.html", page)
		return nil, false
	case status >= 300:
		page["Message"] = "The callback API refused this; nothing was done."
		page["Detail"] = "It said: " + reason
		s.render(w, status, "message.html", page)
		return nil, false
	}
	return out, true
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	if !s.accept(w, r, actCreate, 0) {
		return
	}
	var criteria []callbackapi.Criterion
	for _, line := range strings.Split(r.PostFormValue("criteria"), "\n") {
		if text := strings.TrimSpace(line); text != "" {
			criteria = append(criteria, callbackapi.Criterion{ID: fmt.Sprintf("AC%d", len(criteria)+1), Text: text})
		}
	}
	body := map[string]any{"project": r.PostFormValue("project"), "title": strings.TrimSpace(r.PostFormValue("title")),
		"body": r.PostFormValue("body")}
	if len(criteria) > 0 {
		body["acceptance_criteria"] = criteria // created ready; without, a draft
	}
	out, ok := s.relay(w, r, http.MethodPost, "/v1/tickets", body, "/new")
	if !ok {
		return
	}
	to := "/"
	if id, _ := out["ticket_id"].(float64); id > 0 {
		to = fmt.Sprintf("/tickets/%d", int64(id))
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// escalationOf reads the form's escalated_at, as the page showed it; absent is nil.
func escalationOf(r *http.Request) (*time.Time, bool) {
	raw := r.PostFormValue("escalated_at")
	if raw == "" {
		return nil, true
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	return &at, err == nil
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, http.StatusNotFound, "no such ticket")
		return
	}
	if !s.accept(w, r, actDecide, id) {
		return
	}
	at, ok := escalationOf(r)
	if !ok {
		s.fail(w, http.StatusBadRequest, "the form's escalation time could not be read; nothing was done")
		return
	}
	body := map[string]any{"from": r.PostFormValue("from"), "to": r.PostFormValue("to")}
	if at != nil {
		body["escalated_at"] = at
	}
	if head := r.PostFormValue("head_sha"); head != "" {
		body["head_sha"] = head
	}
	if reason := strings.TrimSpace(r.PostFormValue("reason")); reason != "" {
		body["payload"] = map[string]any{"reason": reason}
	}
	back := fmt.Sprintf("/tickets/%d", id)
	if _, ok := s.relay(w, r, http.MethodPost, fmt.Sprintf("/v1/tickets/%d/transitions", id), body, back); ok {
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}

func (s *Server) park(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, http.StatusNotFound, "no such ticket")
		return
	}
	if !s.accept(w, r, actPark, id) {
		return
	}
	at, ok := escalationOf(r)
	if !ok {
		s.fail(w, http.StatusBadRequest, "the form's escalation time could not be read; nothing was done")
		return
	}
	parked := r.PostFormValue("parked") == "true"
	body := map[string]any{"parked": parked, "escalated_at": at}
	if parked {
		body["reason"] = strings.TrimSpace(r.PostFormValue("reason"))
		if raw := r.PostFormValue("until"); raw != "" {
			until, err := time.Parse(time.DateOnly, raw)
			if err != nil {
				s.fail(w, http.StatusBadRequest, "the date could not be read; nothing was done")
				return
			}
			body["until"] = until
		}
	}
	back := fmt.Sprintf("/tickets/%d", id)
	if _, ok := s.relay(w, r, http.MethodPut, fmt.Sprintf("/v1/tickets/%d/parking", id), body, back); ok {
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}
