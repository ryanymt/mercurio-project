package db

import (
	"context"
	"database/sql"
	"fmt"
)

// ActivateProject makes the project id the only active one (P05 D18), in one transaction: every
// other active project is deactivated first, then id is activated and its last_activated_at set.
// The unique index one_active_project is checked row by row, so a single UPDATE of both rows would
// fail in one direction. The updates wait for a dispatcher tick holding the active project's row.
func ActivateProject(ctx context.Context, conn *sql.DB, id string) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no project %q", id)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE projects SET is_active = false WHERE is_active AND id <> $1`, id); err != nil {
		return fmt.Errorf("deactivate the other projects: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE projects SET is_active = true, last_activated_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("activate %s: %w", id, err)
	}
	return tx.Commit()
}
