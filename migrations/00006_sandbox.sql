-- +goose Up
-- Migration 00006: the sandbox project (P05 D2, D14), the echo runner's private repository.
-- Inactive: making it the active project is an operator's step, `foreman project activate sandbox`
-- (D18).
INSERT INTO projects (id, name, repo_url, default_branch, is_active, is_meta)
VALUES ('sandbox', 'sandbox', 'https://github.com/your-org/sandbox-repo', 'main', false, false);
