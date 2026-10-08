-- +goose Up
-- Migration 00008: what `viewer`, the viewer's database user, may do (P06 D7).
--
-- The viewer reads; it writes nothing, and a person's acts go through the callback API. It may
-- SELECT projects, ticket_events and artifacts whole, and tickets and attempts column by column,
-- leaving out claim_token, which holds a live lease's fence. It gets nothing on api_requests, whose
-- stored responses hold claim tokens too, nor on budget, promotions or goose's version table, and
-- no default privileges: a later table, or a later column of tickets or attempts, is readable only
-- by a grant of its own. Guarded on the role existing, like 00007: the tests' server creates it
-- (internal/testdb), Terraform creates it in Cloud SQL before this runs (docs/gcp-bootstrap.md),
-- and a database without it gets nothing; the viewer checks its own rights at startup.
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'viewer') THEN
    GRANT SELECT ON projects, ticket_events, artifacts TO viewer;
    GRANT SELECT (id, project_id, state, title, body, acceptance_criteria, parent_ticket_id, depth,
      priority, branch, base_sha, merge_commit_sha, claimed_by, claimed_at, lease_expires_at,
      attempt_count, risk_verdict, qa_report_path, escalated_at, escalation_reason, parked,
      parked_reason, parked_until, failure_reason, retained_until, created_at, updated_at,
      parent_depth, head_sha)
      ON tickets TO viewer;
    GRANT SELECT (id, ticket_id, attempt, role, provider, model, tier, started_at, ended_at, outcome,
      input_tokens, output_tokens, launch_id)
      ON attempts TO viewer;
  END IF;
END
$$;
-- +goose StatementEnd
