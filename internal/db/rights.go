package db

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Rights is what the connected database user can do, as `foreman db rights` reports it (P05 D11):
// the deployed `app` user should hold row rights and nothing more.
type Rights struct {
	User               string `json:"user"`
	CloudSQLSuperuser  bool   `json:"cloudsqlsuperuser"` // a member of Cloud SQL's cloudsqlsuperuser
	CreateRole         bool   `json:"createrole"`
	CreateDB           bool   `json:"createdb"`
	CreateTableRefused bool   `json:"create_table_refused"` // in the public schema
}

// ReportRights reads the connected user's rights, changing nothing: the CREATE TABLE is tried
// inside a transaction that is always rolled back.
func ReportRights(ctx context.Context, conn *sql.DB) (Rights, error) {
	var r Rights
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `
		SELECT current_user, rolcreaterole, rolcreatedb,
		  coalesce((SELECT pg_has_role(current_user, oid, 'MEMBER') FROM pg_roles WHERE rolname = 'cloudsqlsuperuser'), false)
		FROM pg_roles WHERE rolname = current_user`).Scan(&r.User, &r.CreateRole, &r.CreateDB, &r.CloudSQLSuperuser); err != nil {
		return r, err
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT probe`); err != nil {
		return r, err
	}
	_, err = tx.ExecContext(ctx, `CREATE TABLE public.foreman_rights_probe (id int)`)
	var pg *pgconn.PgError
	switch {
	case err == nil:
	case errors.As(err, &pg) && pg.Code == "42501":
		r.CreateTableRefused = true
	default:
		return r, err
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT probe`); err != nil {
		return r, err
	}
	return r, nil
}
