package dispatcher_test

import (
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
)

// Every account the dispatcher can hand a runner of foreman or the sandbox is in the callback API's
// identity map, with the same role and project, so a launched runner is always recognised (P04
// Approach 6; P05 T1).
func TestEveryAccountIsInTheIdentityMap(t *testing.T) {
	ids, err := callbackapi.EmbeddedIdentityMap()
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"foreman", "sandbox"} {
		for _, role := range []callbackapi.Role{
			callbackapi.RoleDev, callbackapi.RoleQA, callbackapi.RoleIntegrator, callbackapi.RoleSpec, callbackapi.RoleArchitect,
		} {
			email, err := dispatcher.ServiceAccount(role, project)
			if err != nil {
				t.Fatalf("%s in %s: %v", role, project, err)
			}
			c, ok := ids.Lookup(email)
			if !ok || c.Role != role || c.Project != project {
				t.Errorf("%s in %s runs as %s, which the identity map gives %+v (found %v)", role, project, email, c, ok)
			}
		}
	}
}

// Only runner roles have per-project accounts, and a project id is never spliced into an email
// unchecked.
func TestServiceAccountRefusals(t *testing.T) {
	for _, role := range []callbackapi.Role{
		callbackapi.RoleDispatcher, callbackapi.RoleHuman, callbackapi.RoleCallbackAPI,
		callbackapi.RoleRiskEvaluator, callbackapi.RoleHousekeeping, "",
	} {
		if email, err := dispatcher.ServiceAccount(role, "foreman"); err == nil {
			t.Errorf("role %q got an account %s", role, email)
		}
	}
	for _, project := range []string{"", "Foreman", "fore man", "../x", "foreman@evil.example", "-foreman", "foreman.", "a/b"} {
		if email, err := dispatcher.ServiceAccount(callbackapi.RoleDev, project); err == nil {
			t.Errorf("project %q got an account %s", project, email)
		}
	}
}
