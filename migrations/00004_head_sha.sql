-- +goose Up
-- Migration 00004: what the risk evaluator (P03) needs from the schema. Additive only.

-- ---------------------------------------------------------------------------
-- The submitted commit (P03 D3, D10)
-- ---------------------------------------------------------------------------
-- Named by the dev runner on in_progress -> awaiting_review; QA must name the same commit when it
-- approves; the risk evaluator diffs base_sha to it on the server. Cleared on every move to ready
-- (a new attempt is a new commit) and on a QA sha mismatch; kept through merging and merged for
-- the integrator. A full SHA-1 in lowercase hex, or nothing: SHA-256 repositories are out of scope.
ALTER TABLE tickets ADD COLUMN head_sha TEXT
  CONSTRAINT head_sha_format CHECK (head_sha ~ '^[0-9a-f]{40}$');
