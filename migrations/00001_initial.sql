-- +goose Up
-- Migration 00001: the initial schema. A verbatim transcription of docs/schema.sql as of the P01
-- plan (commit 92f3204); plans/P01-foundation/evidence/ holds the pg_dump comparison that proved
-- it before that file was retired. Migrations are additive and up-only: never edit this file once
-- applied; change the schema with a new one. Rollback is a restore, not a down migration.

-- foreman schema
-- Postgres. See docs/state-machine.md for the semantics of every state field.
--
-- Chosen over Firestore specifically for the atomic claim in
-- docs/state-machine.md ("Atomic claim"). Do not migrate away without solving
-- that first.

CREATE TYPE ticket_state AS ENUM (
  'draft',
  'ready',
  'claimed',
  'in_progress',
  'awaiting_review',
  'in_qa',
  'approved',
  'merging',
  'merged',
  'done',
  'decomposed',
  'escalated',   -- no 'blocked': a runner that must stop for a human escalates
  'failed',
  'abandoned'
);

CREATE TYPE actor_role AS ENUM (
  'human',
  'dispatcher',
  'callback_api',   -- deterministic transitions made inside the API itself
  'spec',
  'architect',
  'dev',
  'qa',
  'risk_evaluator',
  'integrator',
  'housekeeping'
);


-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
-- Projects run sequentially. Exactly one may be active at a time; this is
-- enforced by the partial unique index below.

CREATE TABLE projects (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  repo_url          TEXT NOT NULL,
  default_branch    TEXT NOT NULL DEFAULT 'main',
  is_active         BOOLEAN NOT NULL DEFAULT false,
  is_meta           BOOLEAN NOT NULL DEFAULT false,  -- true for foreman itself
  -- Path INSIDE the promoted image, never inside the project being evaluated.
  -- Every project's policy lives in this repository and ships in the image.
  risk_policy_path  TEXT NOT NULL DEFAULT 'risk-policy.yml',
  last_activated_at TIMESTAMPTZ,
  reoriented_at     TIMESTAMPTZ,  -- last successful activation reorientation pass
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX one_active_project
  ON projects (is_active) WHERE is_active = true;


-- ---------------------------------------------------------------------------
-- tickets
-- ---------------------------------------------------------------------------

CREATE TABLE tickets (
  id                  BIGSERIAL PRIMARY KEY,
  project_id          TEXT NOT NULL REFERENCES projects(id),
  state               ticket_state NOT NULL DEFAULT 'draft',

  title               TEXT NOT NULL,
  body                TEXT,
  acceptance_criteria JSONB,        -- array of {id, text}; required to reach 'ready'

  -- decomposition; depth is capped at 1 in code, see state-machine.md
  parent_ticket_id    BIGINT REFERENCES tickets(id),
  depth               SMALLINT NOT NULL DEFAULT 0,

  priority            SMALLINT NOT NULL DEFAULT 0,

  -- workspace; the dispatcher shares no disk with a runner, so it records the
  -- branch name and the sha of main at claim time and the runner clones itself.
  -- base_sha is what "approved against" means when the integrator rebases.
  branch              TEXT,
  base_sha            TEXT,
  merge_commit_sha    TEXT,

  -- leasing; liveness is lease expiry, there is no watcher process
  claimed_by          TEXT,
  claimed_at          TIMESTAMPTZ,
  lease_expires_at    TIMESTAMPTZ,

  -- gating
  -- dev sessions started; increments on claimed -> in_progress and nowhere else.
  -- Cap is 2: a return to 'ready' at the cap is diverted to 'failed'.
  attempt_count       SMALLINT NOT NULL DEFAULT 0,
  risk_verdict        JSONB,        -- {cleared: bool, matched_rules: [rule_id], evaluated_at}
  qa_report_path      TEXT,         -- GCS path

  -- escalation and parking; parked is writable by human identity only
  escalated_at        TIMESTAMPTZ,
  escalation_reason   TEXT,
  parked              BOOLEAN NOT NULL DEFAULT false,
  parked_reason       TEXT,
  parked_until        TIMESTAMPTZ,

  -- failure forensics
  failure_reason      TEXT,
  retained_until      TIMESTAMPTZ,  -- default now() + 30d on entering failed/abandoned

  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT depth_capped        CHECK (depth <= 1),
  CONSTRAINT child_has_parent    CHECK ((depth = 0) = (parent_ticket_id IS NULL)),
  CONSTRAINT attempts_bounded    CHECK (attempt_count >= 0 AND attempt_count <= 2)
);

-- Supports the atomic claim query.
CREATE INDEX tickets_claimable
  ON tickets (project_id, priority DESC, created_at)
  WHERE state = 'ready';

-- Supports the escalation-blocking precondition.
CREATE INDEX tickets_blocking_escalations
  ON tickets (project_id)
  WHERE state = 'escalated' AND parked = false;

-- Supports lease reaping. Every state in which something is running is leased:
-- a dev session, a QA session, or an integration.
CREATE INDEX tickets_leased
  ON tickets (lease_expires_at)
  WHERE state IN ('claimed', 'in_progress', 'in_qa', 'merging');

CREATE INDEX tickets_children ON tickets (parent_ticket_id);


-- ---------------------------------------------------------------------------
-- ticket_events
-- ---------------------------------------------------------------------------
-- Append-only. Never update a ticket's state without writing here. This is the
-- audit trail and the dataset the self-improvement loop reads. Rows are never
-- deleted, including by housekeeping.

CREATE TABLE ticket_events (
  id           BIGSERIAL PRIMARY KEY,
  ticket_id    BIGINT NOT NULL REFERENCES tickets(id),
  from_state   ticket_state,
  to_state     ticket_state NOT NULL,
  actor        actor_role NOT NULL,
  actor_id     TEXT,        -- service account email, or human identity
  request_id   TEXT,        -- for idempotent retries
  payload      JSONB,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ticket_events_by_ticket ON ticket_events (ticket_id, created_at);
CREATE UNIQUE INDEX ticket_events_idempotent
  ON ticket_events (ticket_id, request_id) WHERE request_id IS NOT NULL;


-- ---------------------------------------------------------------------------
-- budget
-- ---------------------------------------------------------------------------
-- Rate-limit accounting, one row per model provider. Capacity comes from
-- flat-rate subscriptions with independent rolling windows, so a pause on one
-- provider must not stop work whose tier uses the other. The dispatcher checks
-- the row for the provider the launch would use.

CREATE TABLE budget (
  provider            TEXT PRIMARY KEY,   -- 'anthropic', 'zai', ...
  window_started_at   TIMESTAMPTZ NOT NULL,
  window_resets_at    TIMESTAMPTZ NOT NULL,
  consumed_estimate   NUMERIC NOT NULL DEFAULT 0,
  window_capacity     NUMERIC NOT NULL,
  reserve_fraction    NUMERIC NOT NULL DEFAULT 0.15,
  paused_until        TIMESTAMPTZ,
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ---------------------------------------------------------------------------
-- attempts
-- ---------------------------------------------------------------------------
-- One row per runner execution. This is what makes "is the cheap tier good
-- enough for dev tickets?" a query instead of an opinion, and it is the
-- self-improvement loop's dataset alongside ticket_events.

CREATE TABLE attempts (
  id            BIGSERIAL PRIMARY KEY,
  ticket_id     BIGINT NOT NULL REFERENCES tickets(id),
  attempt       SMALLINT NOT NULL,
  role          actor_role NOT NULL,     -- dev, qa, spec, architect
  provider      TEXT NOT NULL,           -- 'anthropic', 'zai', ...
  model         TEXT NOT NULL,
  tier          TEXT NOT NULL,           -- the tier-table entry that chose it
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ,
  outcome       TEXT,                    -- 'completed' | 'failed' | 'rate_limited' | 'reaped'
  input_tokens  BIGINT,
  output_tokens BIGINT
);

CREATE INDEX attempts_by_ticket ON attempts (ticket_id, attempt);
CREATE INDEX attempts_by_tier ON attempts (provider, model, started_at);


-- ---------------------------------------------------------------------------
-- promotions
-- ---------------------------------------------------------------------------
-- The self-deploy tripwire. The dispatcher refuses to launch if its own running
-- image digest does not match the current promoted digest here.
-- Promotion is always a human act; merge is not deploy.

CREATE TABLE promotions (
  id             BIGSERIAL PRIMARY KEY,
  component      TEXT NOT NULL,      -- 'dispatcher', 'callback-api', 'integrator', ...
  image_digest   TEXT NOT NULL,
  git_sha        TEXT NOT NULL,
  promoted_by    TEXT NOT NULL,      -- human identity; no agent may write here
  is_current     BOOLEAN NOT NULL DEFAULT true,
  promoted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX one_current_promotion_per_component
  ON promotions (component) WHERE is_current = true;


-- ---------------------------------------------------------------------------
-- artifacts
-- ---------------------------------------------------------------------------
-- Postgres stores only the GCS path. Bucket is private; transcripts may contain
-- secrets the agent read incidentally and are scrubbed on upload.

CREATE TABLE artifacts (
  id          BIGSERIAL PRIMARY KEY,
  ticket_id   BIGINT NOT NULL REFERENCES tickets(id),
  attempt     SMALLINT NOT NULL,
  kind        TEXT NOT NULL,   -- 'transcript' | 'diff' | 'test_report' | 'qa_report' | 'log'
  gcs_path    TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX artifacts_by_ticket ON artifacts (ticket_id, attempt);
