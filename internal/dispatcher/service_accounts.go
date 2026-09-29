package dispatcher

import (
	"fmt"
	"regexp"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// Service accounts (P04 Approach 6): a runner runs as its role's account for its project,
// <role>-<project>@your-project-id.iam.gserviceaccount.com, the account the callback API's
// identity map knows it by. Selecting the account decides what a runner may do, so it is
// protected, and a test checks every account it produces for foreman is in the identity map with
// the same role and project.

const serviceAccountDomain = "your-project-id.iam.gserviceaccount.com"

var projectID = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)

// ServiceAccount is the account a runner of role runs as for project.
func ServiceAccount(role callbackapi.Role, project string) (string, error) {
	if !role.IsRunner() {
		return "", fmt.Errorf("%q is not a runner role, so it has no per-project account", role)
	}
	if !projectID.MatchString(project) {
		return "", fmt.Errorf("%q is not a project id", project)
	}
	return fmt.Sprintf("%s-%s@%s", role, project, serviceAccountDomain), nil
}
