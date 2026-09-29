// Package migrations holds foreman's schema as numbered goose SQL migrations, embedded in the
// binary. It is the schema's only source of truth (D4): change the schema with a new file, never
// by editing one that has been applied. Migrations are up-only; rollback is a restore.
package migrations

import "embed"

// FS holds every migration file.
//
//go:embed *.sql
var FS embed.FS
