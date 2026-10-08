package viewer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// The viewer's reads, as `viewer`. Every query names its columns: tickets and attempts are granted
// column by column, claim_token never (D7).

var errNotFound = errors.New("not found")

type ticketRow struct {
	ID        int64
	Project   string
	Title     string
	State     string
	Priority  int
	Parked    bool
	UpdatedAt time.Time
}

func (s *Server) tickets(ctx context.Context, project, state string) ([]ticketRow, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, `
		SELECT id, project_id, title, state, priority, parked, updated_at FROM tickets
		WHERE ($1 = '' OR project_id = $1) AND ($2 = '' OR state::text = $2)
		ORDER BY project_id, state, priority DESC, id
		LIMIT 500`, project, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ticketRow
	for rows.Next() {
		var t ticketRow
		if err := rows.Scan(&t.ID, &t.Project, &t.Title, &t.State, &t.Priority, &t.Parked, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Server) projects(ctx context.Context) ([]string, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, `SELECT id FROM projects ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ticket is one ticket, as its page shows it.
type ticket struct {
	ID               int64
	Project          string
	RepoURL          string
	Title            string
	Body             string
	State            string
	Priority         int
	Attempts         int
	Branch           string
	BaseSHA          string
	HeadSHA          string
	Criteria         []callbackapi.Criterion
	EscalatedAt      *time.Time
	EscalationReason string
	Parked           bool
	ParkedReason     string
	ParkedUntil      *time.Time
	FailureReason    string
	HasChildren      bool
	Verdict          *callbackapi.Verdict // the stored verdict, whatever commit it names
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (s *Server) ticket(ctx context.Context, id int64) (ticket, error) {
	var t ticket
	var body, branch, base, head, reason, parkedReason, failure sql.NullString
	var criteria, verdict []byte
	var escalated, parkedUntil sql.NullTime
	err := s.cfg.DB.QueryRowContext(ctx, `
		SELECT t.id, t.project_id, p.repo_url, t.title, t.body, t.state, t.priority, t.attempt_count, t.branch,
		  t.base_sha, t.head_sha, coalesce(t.acceptance_criteria, 'null'::jsonb), t.escalated_at, t.escalation_reason,
		  t.parked, t.parked_reason, t.parked_until, t.failure_reason,
		  EXISTS (SELECT 1 FROM tickets c WHERE c.parent_ticket_id = t.id), coalesce(t.risk_verdict, 'null'::jsonb),
		  t.created_at, t.updated_at
		FROM tickets t JOIN projects p ON p.id = t.project_id WHERE t.id = $1`, id).
		Scan(&t.ID, &t.Project, &t.RepoURL, &t.Title, &body, &t.State, &t.Priority, &t.Attempts, &branch, &base, &head,
			&criteria, &escalated, &reason, &t.Parked, &parkedReason, &parkedUntil, &failure, &t.HasChildren, &verdict,
			&t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return t, errNotFound
	}
	if err != nil {
		return t, err
	}
	t.Body, t.Branch, t.BaseSHA, t.HeadSHA = body.String, branch.String, base.String, head.String
	t.EscalationReason, t.ParkedReason, t.FailureReason = reason.String, parkedReason.String, failure.String
	if escalated.Valid {
		t.EscalatedAt = &escalated.Time
	}
	if parkedUntil.Valid {
		t.ParkedUntil = &parkedUntil.Time
	}
	json.Unmarshal(criteria, &t.Criteria)
	var v callbackapi.Verdict
	if string(verdict) != "null" && json.Unmarshal(verdict, &v) == nil {
		t.Verdict = &v
	}
	return t, nil
}

// verdictFor is the stored verdict when it names exactly this ticket's commit: its base, its head,
// and the head as the commit tested. Otherwise there is no verdict for this commit (red team R1,
// R9#2). It never comes from an event's payload, which a runner can shape ([P03/review2]).
func verdictFor(t ticket) *callbackapi.Verdict {
	v := t.Verdict
	if v == nil || t.HeadSHA == "" || v.BaseSHA != t.BaseSHA || v.HeadSHA != t.HeadSHA || v.TestedSHA != t.HeadSHA {
		return nil
	}
	return v
}

type event struct {
	ID       int64
	From     string
	To       string
	Actor    string
	ActorID  string
	Reason   string // the payload's reason, when it has one
	ByRunner bool   // the actor is a runner, so the reason is its own words
	Payload  string // the payload as indented JSON, shown as data, never as a verdict
	At       time.Time
}

var runnerRoles = map[string]bool{"dev": true, "qa": true, "integrator": true, "spec": true, "architect": true}

func (s *Server) events(ctx context.Context, id int64) ([]event, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, `
		SELECT id, coalesce(from_state::text, ''), to_state, actor, coalesce(actor_id, ''), coalesce(payload, '{}'::jsonb), created_at
		FROM ticket_events WHERE ticket_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event
	for rows.Next() {
		var e event
		var payload []byte
		if err := rows.Scan(&e.ID, &e.From, &e.To, &e.Actor, &e.ActorID, &payload, &e.At); err != nil {
			return nil, err
		}
		var p map[string]any
		if json.Unmarshal(payload, &p) == nil {
			e.Reason, _ = p["reason"].(string)
			if b, err := json.MarshalIndent(p, "", "  "); err == nil && len(p) > 0 {
				e.Payload = string(b)
			}
		}
		e.ByRunner = runnerRoles[e.Actor]
		out = append(out, e)
	}
	return out, rows.Err()
}

type attempt struct {
	Attempt       int
	Role          string
	Provider      string
	Model         string
	Tier          string
	StartedAt     time.Time
	EndedAt       *time.Time
	Outcome       string
	TokensIn, Out int64
}

func (s *Server) attempts(ctx context.Context, id int64) ([]attempt, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, `
		SELECT attempt, role, coalesce(provider, ''), coalesce(model, ''), coalesce(tier, ''), started_at, ended_at,
		  coalesce(outcome, ''), coalesce(input_tokens, 0), coalesce(output_tokens, 0)
		FROM attempts WHERE ticket_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []attempt
	for rows.Next() {
		var a attempt
		var ended sql.NullTime
		if err := rows.Scan(&a.Attempt, &a.Role, &a.Provider, &a.Model, &a.Tier, &a.StartedAt, &ended, &a.Outcome,
			&a.TokensIn, &a.Out); err != nil {
			return nil, err
		}
		if ended.Valid {
			a.EndedAt = &ended.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type artifact struct {
	ID      int64
	Ticket  int64
	Attempt int
	Kind    string
	Path    string
	At      time.Time
}

// runPath reads a registered path's {role}-{run} segment (P06 R4#2): the run's label.
var runPath = regexp.MustCompile(`/([a-z_]+-[0-9a-f]{32})/[a-z_]+$`)

// run is one runner start's artifacts.
type run struct {
	Attempt   int
	Label     string // {role}-{run}, as the callback API enforced it
	Artifacts []artifact
}

func (s *Server) artifacts(ctx context.Context, id int64) ([]run, error) {
	rows, err := s.cfg.DB.QueryContext(ctx, `
		SELECT id, ticket_id, attempt, kind, gcs_path, created_at FROM artifacts WHERE ticket_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byRun := map[string]*run{}
	var order []string
	for rows.Next() {
		var a artifact
		if err := rows.Scan(&a.ID, &a.Ticket, &a.Attempt, &a.Kind, &a.Path, &a.At); err != nil {
			return nil, err
		}
		label := "unlabelled"
		if m := runPath.FindStringSubmatch(a.Path); m != nil {
			label = m[1]
		}
		key := label
		if _, ok := byRun[key]; !ok {
			byRun[key] = &run{Attempt: a.Attempt, Label: label}
			order = append(order, key)
		}
		byRun[key].Artifacts = append(byRun[key].Artifacts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(order, func(i, j int) bool { return byRun[order[i]].Attempt < byRun[order[j]].Attempt })
	var out []run
	for _, k := range order {
		out = append(out, *byRun[k])
	}
	return out, nil
}

func (s *Server) artifact(ctx context.Context, ticketID, id int64) (artifact, error) {
	var a artifact
	err := s.cfg.DB.QueryRowContext(ctx, `
		SELECT id, ticket_id, attempt, kind, gcs_path, created_at FROM artifacts WHERE id = $1 AND ticket_id = $2`, id, ticketID).
		Scan(&a.ID, &a.Ticket, &a.Attempt, &a.Kind, &a.Path, &a.At)
	if errors.Is(err, sql.ErrNoRows) {
		return a, errNotFound
	}
	return a, err
}
