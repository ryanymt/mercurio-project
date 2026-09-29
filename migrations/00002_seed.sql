-- +goose Up
-- Migration 00002: seed data. Every environment, tests included, starts from these rows (D5);
-- a test that depends on them says so.

-- foreman's first project is foreman itself: the meta-project, and the one active project.
INSERT INTO projects (id, name, repo_url, is_active, is_meta)
VALUES ('foreman', 'foreman', 'https://github.com/ryanymt/mercurio-project', true, true);

-- One budget row per model provider. Both subscriptions meter in rolling five-hour windows.
-- PLACEHOLDERS: window_capacity (and so consumed_estimate) is in the dispatcher's estimate units,
-- which P04 defines; the value here is only a starting point, to tune from observed rate limits.
INSERT INTO budget (provider, window_started_at, window_resets_at, window_capacity)
VALUES
  ('anthropic', now(), now() + interval '5 hours', 100),
  ('zai',       now(), now() + interval '5 hours', 100);
