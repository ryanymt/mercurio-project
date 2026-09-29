-- +goose Up
-- Migration 00007: what `app`, the deployed components' database user, may do (P05 D11).
--
-- The migrations run as `migrator`, which owns every table; the callback API and the dispatcher
-- connect as `app`, which may read, insert and update the application's rows and nothing more: no
-- DELETE (nothing deletes; ticket_events is append-only), nothing on goose's version table, no
-- objects of its own. The default privileges carry the same rights to tables and sequences later
-- migrations create, for the role running them (`migrator` on Cloud SQL, the server's own user in
-- tests). Everything is guarded on the role existing: the tests' server creates it (internal/testdb),
-- and a database without it gets nothing.
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'app') THEN
    GRANT SELECT, INSERT, UPDATE
      ON projects, tickets, ticket_events, budget, attempts, promotions, artifacts, api_requests
      TO app;
    GRANT USAGE, SELECT
      ON SEQUENCE tickets_id_seq, ticket_events_id_seq, attempts_id_seq, promotions_id_seq, artifacts_id_seq
      TO app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app;
  END IF;
END
$$;
-- +goose StatementEnd
