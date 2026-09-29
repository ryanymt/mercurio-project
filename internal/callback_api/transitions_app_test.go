package callbackapi_test

import (
	"testing"

	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// The transition core runs as `app`, the deployed callback API's database user, which holds row
// rights only (P05 D11): a runner's start, a heartbeat and a submission all go through.
func TestTheCoreRunsAsApp(t *testing.T) {
	owner, app := testdb.NewAsApp(t)
	e := newEngine(nil)
	id := seed(t, owner, fixture{state: sClaimed})
	mustDo(t, e, app, request(id, sClaimed, sInProgress, dev, chHTTP))
	if _, err := doHeartbeat(t, app, heartbeat(id, dev, liveToken)); err != nil {
		t.Fatalf("heartbeat as app: %v", err)
	}
	mustDo(t, e, app, request(id, sInProgress, sAwaiting, dev, chHTTP))
	if s := state(t, owner, id); s != sAwaiting {
		t.Fatalf("state %s, want awaiting_review", s)
	}
}
