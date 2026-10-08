package callbackapi_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// testRun is a runner start's id, as internal/capture makes them: 32 lowercase hex characters.
const testRun = "0123456789abcdef0123456789abcdef"

// runPath is where a runner of role registers kind for ticket id's attempt (P06 R4#2).
func runPath(project string, id int64, attempt int, role callbackapi.Role, kind string) string {
	return fmt.Sprintf("%s/%d/%d/%s-%s/%s", project, id, attempt, role, testRun, kind)
}

func register(t *testing.T, conn *sql.DB, id int64, c callbackapi.Caller, kind, path string) error {
	t.Helper()
	_, err := inTx(t, conn, func(ctx context.Context, tx *sql.Tx) (callbackapi.ArtifactResult, error) {
		return newEngine(nil).RegisterArtifact(ctx, tx, callbackapi.ArtifactRequest{
			TicketID: id, Caller: c, Kind: kind, GCSPath: path, ClaimToken: liveToken, RequestID: newRequestID(),
			Method: "POST", Path: fmt.Sprintf("/v1/tickets/%d/artifacts", id),
		})
	})
	return err
}

// A registered path names the runner that wrote it: {project}/{ticket}/{attempt}/{role}-{run}/{kind},
// the role the caller's own, the run 32 lowercase hex, the last segment the kind. The viewer labels
// runs by it, so a runner cannot pass its output off as another role's (red team R4#2).
func TestArtifactPathsNameTheirRunner(t *testing.T) {
	conn := fresh(t)
	id := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	for _, kind := range []string{"transcript", "test_report", "diff", "log"} {
		if err := register(t, conn, id, dev, kind, runPath("foreman", id, 1, callbackapi.RoleDev, kind)); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	base := fmt.Sprintf("foreman/%d/1/", id)
	for name, c := range map[string]struct{ kind, path string }{
		"the old shape, a file":          {"transcript", base + "transcript.jsonl"},
		"no run segment":                 {"transcript", base + "transcript"},
		"another role's segment":         {"transcript", base + "qa-" + testRun + "/transcript"},
		"the integrator's segment":       {"log", base + "integrator-" + testRun + "/log"},
		"no role":                        {"transcript", base + "-" + testRun + "/transcript"},
		"a run id too short":             {"transcript", base + "dev-0123abcd/transcript"},
		"a run id in capitals":           {"transcript", base + "dev-" + strings.ToUpper(testRun) + "/transcript"},
		"a run id too long":              {"transcript", base + "dev-" + testRun + "0/transcript"},
		"a last segment not the kind":    {"transcript", base + "dev-" + testRun + "/test_report"},
		"a chunk under the kind":         {"transcript", base + "dev-" + testRun + "/transcript/000001.jsonl"},
		"the kind with an extension":     {"transcript", base + "dev-" + testRun + "/transcript.jsonl"},
		"a segment between run and kind": {"transcript", base + "dev-" + testRun + "/x/transcript"},
	} {
		t.Run(name, func(t *testing.T) {
			before := count(t, conn, `SELECT count(*) FROM artifacts`)
			wantStatus(t, register(t, conn, id, dev, c.kind, c.path), 400)
			if n := count(t, conn, `SELECT count(*) FROM artifacts`); n != before {
				t.Fatalf("%d artifacts after a refusal, want %d", n, before)
			}
		})
	}
}

// A QA report comes from QA alone: a dev runner registering one is refused (403), whatever its
// path; QA registers its report and its own transcript.
func TestOnlyQARegistersAQAReport(t *testing.T) {
	conn := fresh(t)
	work := seed(t, conn, fixture{state: sInProgress, attempts: 1})
	wantStatus(t, register(t, conn, work, dev, "qa_report", runPath("foreman", work, 1, callbackapi.RoleDev, "qa_report")), 403)
	wantStatus(t, register(t, conn, work, dev, "qa_report", runPath("foreman", work, 1, callbackapi.RoleQA, "qa_report")), 403)

	review := seed(t, conn, fixture{state: sInQA, attempts: 1})
	for _, kind := range []string{"qa_report", "transcript"} {
		if err := register(t, conn, review, qa, kind, runPath("foreman", review, 1, callbackapi.RoleQA, kind)); err != nil {
			t.Fatalf("QA's %s: %v", kind, err)
		}
	}
	if n := count(t, conn, `SELECT count(*) FROM artifacts WHERE kind = 'qa_report'`); n != 1 {
		t.Fatalf("%d QA reports, want QA's one", n)
	}
}
