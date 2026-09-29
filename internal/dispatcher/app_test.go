package dispatcher_test

import (
	"context"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
	"github.com/ryanymt/mercurio-project/internal/testdb"
)

// A tick runs as `app`, the deployed dispatcher's database user, which holds row rights only (P05
// D11): a reap, a claim with its charge and attempts row, and a failed launch's return and refund.
func TestATickRunsAsApp(t *testing.T) {
	owner, app := testdb.NewAsApp(t)
	e := &env{t: t, db: owner, remote: &fakeRemote{sha: baseSHA}, launcher: &fakeLauncher{}}
	tiers, err := dispatcher.EmbeddedTiers()
	if err != nil {
		t.Fatal(err)
	}
	d := dispatcher.New(app, callbackapi.NewEngine(nil, quietLog()), tiers, e.remote, e.launcher, quietLog())

	reaped := e.seed(fixture{state: sInQA, attempts: 1, expired: true})
	work := e.seed(fixture{state: sReady, priority: 9})
	out, err := d.Tick(context.Background())
	if err != nil {
		t.Fatalf("tick as app: %v", err)
	}
	if len(out.Reaped) != 1 || out.Reaped[0] != reaped || out.Claimed != reaped {
		t.Fatalf("outcome %+v: want %d reaped and then claimed again for QA", out, reaped)
	}

	e.launcher.fail = func(r dispatcher.LaunchRequest) bool { return true }
	e.exec(`UPDATE tickets SET lease_expires_at = now() - interval '1 second' WHERE id = $1`, reaped)
	out, err = d.Tick(context.Background())
	if err != nil {
		t.Fatalf("second tick as app: %v", err)
	}
	if !out.LaunchFailed || out.Claimed != reaped || e.state(work) != sReady {
		t.Fatalf("outcome %+v: want the QA ticket reaped, claimed again, its launch failed and returned", out)
	}
	if e.consumed("anthropic") != 1 {
		t.Fatalf("anthropic consumed %v, want the QA claim's unit only (the failed launch refunded)", e.consumed("anthropic"))
	}
}
