-- +goose Up
-- Migration 00005: what the dispatcher (P04) needs from the schema.

-- ---------------------------------------------------------------------------
-- attempts: one row per launch, linked to its lease (P04 D13)
-- ---------------------------------------------------------------------------
-- Written by the dispatcher in the claim's transaction, with the claim token the claim issued; the
-- rate-limit endpoint finds the caller's provider by it, and the core ends the row (ended_at,
-- outcome) wherever it clears that token. The launch id is what the launcher returned.
ALTER TABLE attempts
  ADD COLUMN claim_token TEXT CONSTRAINT attempts_claim_token_unique UNIQUE,
  ADD COLUMN launch_id   TEXT;

-- The integrator runs no model, so its attempt names no provider, model or tier; every other
-- role's names all three.
ALTER TABLE attempts
  ALTER COLUMN provider DROP NOT NULL,
  ALTER COLUMN model    DROP NOT NULL,
  ALTER COLUMN tier     DROP NOT NULL,
  ADD CONSTRAINT attempts_model_by_role CHECK (
    CASE WHEN role = 'integrator'
      THEN provider IS NULL AND model IS NULL AND tier IS NULL
      ELSE provider IS NOT NULL AND model IS NOT NULL AND tier IS NOT NULL
    END);

-- How the attempt ended: a runner's own move (completed, failed), a rate limit it reported, the
-- dispatcher's return (reaped, launch_failed), or a human's move out of the leased state.
ALTER TABLE attempts ADD CONSTRAINT attempts_outcome_known CHECK (
  outcome IN ('completed', 'failed', 'rate_limited', 'reaped', 'launch_failed', 'abandoned'));


-- ---------------------------------------------------------------------------
-- A leased ticket has a lease expiry
-- ---------------------------------------------------------------------------
-- The reap selects leases whose expiry is not after now(); a NULL expiry would never match, and
-- the ticket would never be reaped. The core sets the expiry in the same UPDATE that enters a
-- leased state and clears it in the one that leaves the set.
ALTER TABLE tickets ADD CONSTRAINT leased_has_expiry CHECK (
  state NOT IN ('claimed', 'in_progress', 'in_qa', 'merging') OR lease_expires_at IS NOT NULL);
