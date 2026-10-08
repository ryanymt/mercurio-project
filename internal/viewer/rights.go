package viewer

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/ryanymt/mercurio-project/internal/db"
)

// The columns the viewer reads, by table: every one 00008 grants, none other. Queries name them,
// since tickets and attempts are granted column by column and a SELECT * is refused.
var (
	ticketColumns = []string{"id", "project_id", "state", "title", "body", "acceptance_criteria", "parent_ticket_id",
		"depth", "priority", "branch", "base_sha", "merge_commit_sha", "claimed_by", "claimed_at", "lease_expires_at",
		"attempt_count", "risk_verdict", "qa_report_path", "escalated_at", "escalation_reason", "parked",
		"parked_reason", "parked_until", "failure_reason", "retained_until", "created_at", "updated_at",
		"parent_depth", "head_sha"}
	attemptColumns = []string{"id", "ticket_id", "attempt", "role", "provider", "model", "tier", "started_at",
		"ended_at", "outcome", "input_tokens", "output_tokens", "launch_id"}
	readTables = []struct {
		name    string
		columns []string // nil: the whole table
	}{
		{"projects", nil}, {"tickets", ticketColumns}, {"ticket_events", nil}, {"attempts", attemptColumns}, {"artifacts", nil},
	}
)

// Rights is what the viewer's database user was found able to do.
type Rights struct {
	User   string   `json:"user"`
	Reads  []string `json:"reads"`  // the five tables it read
	Writes []string `json:"writes"` // anything it could change: empty, or it refuses to start
}

// CheckRights checks, changing nothing, that the connected user reads the five tables and can
// write nothing (P06 D7): no superuser, no role or database creation, no table creation, and no
// write privilege on any table, view or sequence outside the system's schemas, however granted:
// whole or column by column, to it, a role it is in, or PUBLIC. It returns what it found, and an
// error when the viewer must not start.
func CheckRights(ctx context.Context, conn *sql.DB) (Rights, error) {
	var r Rights
	report, err := db.ReportRights(ctx, conn)
	if err != nil {
		return r, fmt.Errorf("read the database user's rights: %w", err)
	}
	r.User = report.User
	if report.CloudSQLSuperuser {
		r.Writes = append(r.Writes, "cloudsqlsuperuser")
	}
	if report.CreateRole {
		r.Writes = append(r.Writes, "createrole")
	}
	if report.CreateDB {
		r.Writes = append(r.Writes, "createdb")
	}
	if !report.CreateTableRefused {
		r.Writes = append(r.Writes, "create table")
	}
	var unread []string
	for _, t := range readTables {
		cols := "*"
		if t.columns != nil {
			cols = strings.Join(t.columns, ", ")
		}
		if _, err := conn.ExecContext(ctx, `SELECT `+cols+` FROM `+t.name+` LIMIT 1`); err != nil {
			unread = append(unread, t.name)
		} else {
			r.Reads = append(r.Reads, t.name)
		}
	}
	writes, err := writePrivileges(ctx, conn)
	if err != nil {
		return r, err
	}
	r.Writes = append(r.Writes, writes...)
	switch {
	case len(r.Writes) > 0:
		return r, fmt.Errorf("the viewer's database user %s can write (%s): it must read only", r.User, strings.Join(r.Writes, "; "))
	case len(unread) > 0:
		return r, fmt.Errorf("the viewer's database user %s cannot read %s", r.User, strings.Join(unread, ", "))
	}
	return r, nil
}

// writePrivileges lists every write privilege the connected user holds, as "PRIVILEGE on name":
// INSERT, UPDATE, DELETE, TRUNCATE and TRIGGER on a table, view or foreign table (INSERT and UPDATE
// on any one column), and USAGE or UPDATE on a sequence, which nextval and setval need. The has_*
// functions count grants to the user, to the roles it is in, and to PUBLIC.
func writePrivileges(ctx context.Context, conn *sql.DB) ([]string, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT p.priv || ' on ' || c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN unnest(CASE WHEN c.relkind = 'S' THEN ARRAY['USAGE', 'UPDATE']
		                       ELSE ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER'] END) AS p(priv)
		WHERE c.relkind IN ('r', 'p', 'v', 'f', 'S')
		  AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%'
		  AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, p.priv)
		           WHEN p.priv IN ('INSERT', 'UPDATE') THEN has_any_column_privilege(c.oid, p.priv)
		           ELSE has_table_privilege(c.oid, p.priv) END
		ORDER BY c.relname, p.priv`)
	if err != nil {
		return nil, fmt.Errorf("read the database user's privileges: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var w string
		if err := rows.Scan(&w); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
