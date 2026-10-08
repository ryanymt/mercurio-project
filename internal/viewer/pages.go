package viewer

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

// list shows tickets by project and state, filtered by ?project= and ?state=.
func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	project, state := r.URL.Query().Get("project"), r.URL.Query().Get("state")
	ts, err := s.tickets(r.Context(), project, state)
	if err != nil {
		s.log.Error("viewer: list tickets", "error", err)
		s.fail(w, http.StatusInternalServerError, "the tickets could not be read")
		return
	}
	projects, _ := s.projects(r.Context())
	s.render(w, http.StatusOK, "list.html", map[string]any{"Tickets": ts, "Projects": projects, "Project": project,
		"State": state, "Person": visitorOf(r).caller.Email})
}

// ticketPage shows a ticket: its fields and last escalation, its events, attempts and runs, the
// verdict for its commit, and the acts its state allows.
func (s *Server) ticketPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.fail(w, http.StatusNotFound, "no such ticket")
		return
	}
	data, err := s.ticketData(r, id)
	if errors.Is(err, errNotFound) {
		s.fail(w, http.StatusNotFound, "no such ticket")
		return
	}
	if err != nil {
		s.log.Error("viewer: read a ticket", "ticket", id, "error", err)
		s.fail(w, http.StatusInternalServerError, "the ticket could not be read")
		return
	}
	s.render(w, http.StatusOK, "ticket.html", data)
}

func (s *Server) ticketData(r *http.Request, id int64) (map[string]any, error) {
	ctx := r.Context()
	t, err := s.ticket(ctx, id)
	if err != nil {
		return nil, err
	}
	events, err := s.events(ctx, id)
	if err != nil {
		return nil, err
	}
	attempts, err := s.attempts(ctx, id)
	if err != nil {
		return nil, err
	}
	runs, err := s.artifacts(ctx, id)
	if err != nil {
		return nil, err
	}
	// Who gave the last escalation's reason: the actor of the last move into escalated from another
	// state. A person's parking is a same-state event, and gives no escalation reason.
	escalatedBy := ""
	for _, e := range events {
		if e.To == "escalated" && e.From != "escalated" {
			escalatedBy = e.Actor
		}
	}
	return map[string]any{
		"T": t, "Events": events, "Attempts": attempts, "Runs": runs,
		"Verdict": verdictFor(t), "StaleVerdict": t.Verdict != nil && verdictFor(t) == nil,
		"EscalatedBy": escalatedBy, "ReasonByRunner": runnerRoles[escalatedBy],
		"Actions": s.actionsFor(r, t), "Person": visitorOf(r).caller.Email,
	}, nil
}

// artifactPage shows one registered artifact: its chunks read in order, bounded in count, in size
// each and in size together, through the transcript's adapter (D22), filtered by ?q=.
func (s *Server) artifactPage(w http.ResponseWriter, r *http.Request) {
	id, ok1 := pathID(r, "id")
	aid, ok2 := pathID(r, "aid")
	if !ok1 || !ok2 {
		s.fail(w, http.StatusNotFound, "no such artifact")
		return
	}
	ctx := r.Context()
	a, err := s.artifact(ctx, id, aid)
	if errors.Is(err, errNotFound) {
		s.fail(w, http.StatusNotFound, "no such artifact on this ticket")
		return
	}
	if err != nil {
		s.log.Error("viewer: read an artifact", "artifact", aid, "error", err)
		s.fail(w, http.StatusInternalServerError, "the artifact could not be read")
		return
	}
	objects, more, err := s.cfg.Chunks.List(ctx, a.Path, s.cfg.MaxChunks)
	if err != nil {
		s.log.Error("viewer: list chunks", "artifact", aid, "error", err)
		s.fail(w, http.StatusBadGateway, "the artifact's chunks could not be listed")
		return
	}
	var notes []string
	if more {
		notes = append(notes, fmt.Sprintf("only the first %d chunks are read: more chunks not shown", s.cfg.MaxChunks))
	}
	var lines []string
	budget := s.cfg.MaxPageBytes
	for _, o := range objects {
		if budget <= 0 {
			notes = append(notes, fmt.Sprintf("only the first %d bytes of this artifact are read: the rest is not shown", s.cfg.MaxPageBytes))
			break
		}
		limit := min(s.cfg.MaxChunkBytes, budget)
		data, cut, err := s.cfg.Chunks.Read(ctx, o.Name, limit)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s could not be read", o.Name))
			continue
		}
		budget -= int64(len(data))
		if cut {
			notes = append(notes, fmt.Sprintf("%s truncated at %d bytes", o.Name, limit))
		}
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if l != "" {
				lines = append(lines, l)
			}
		}
	}
	q := r.URL.Query().Get("q")
	tl := ParseTranscript(lines).Filter(q)
	t, _ := s.ticket(ctx, id)
	s.render(w, http.StatusOK, "timeline.html", map[string]any{"A": a, "T": t, "Timeline": tl, "Q": q, "Notes": notes,
		"Chunks": len(objects), "Person": visitorOf(r).caller.Email})
}
