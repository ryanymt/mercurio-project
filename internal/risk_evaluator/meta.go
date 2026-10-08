// Package riskevaluator is the risk evaluator (docs/risk-policy.md): a pure function from changed
// paths, ticket metadata and a project's policy to a verdict; a git adapter that computes the
// changed paths on the server; and the Evaluator the callback API calls on `in_qa -> approved`.
// Anything but a clear verdict, every error included, escalates.
package riskevaluator

// What is compiled in rather than read from a policy file, so no policy file can drop it (P03 D4,
// D6, D13). Functions return fresh slices: the package holds no mutable state.

// isMetaProject reports whether a project id is compiled in as the meta-project. The database's
// `projects.is_meta` can add a project, never remove this one (D6).
func isMetaProject(id string) bool {
	switch id {
	case "foreman":
		return true
	}
	return false
}

// metaProtectedPaths are protected for every meta-project, added to `protected_paths` whatever the
// policy file says: the evaluator and its policies, every file of the callback API and dispatcher
// packages, the command, the package every write goes through, the build and what builds the
// images, the viewer, the transcript capture and its scrubber, the runner, and the documents and
// settings an agent session reads (docs/CLAUDE.md, "Protected paths").
func metaProtectedPaths() []string {
	return []string{
		"**/risk_evaluator/**",
		"**/callback_api/**",
		"cmd/foreman/**",
		"internal/db/**",
		"Makefile",
		"cloudbuild.yaml",
		"**/dispatcher/**",
		"**/viewer/**",
		"**/capture/**",
		"**/runner/**",
		"**/rollback.sh",
		"**/escalation*",
		"**/escalation*/**",
		"**/parking*",
		"**/parking*/**",
		"**/CLAUDE.md",
		"docs/architecture.md",
		"docs/state-machine.md",
		"docs/risk-policy.md",
		"**/model-policy.yml",
		"**/.gitattributes",
		".claude/**",
		".mcp.json",
	}
}

// requiredRuleIDs must all be present in a production policy (the starter rules; D2, D4).
func requiredRuleIDs() []string {
	return []string{"protected_paths", "size", "dependency_change", "test_integrity", "surface_change", "scope_drift"}
}

// isLateRule reports the rules whose logic arrives in P08. Until then they always match (D2).
func isLateRule(id string) bool {
	switch id {
	case "test_integrity", "surface_change", "scope_drift":
		return true
	}
	return false
}

// Verdict ids the evaluator uses itself, for inputs no rule can judge. A policy may not use them.
const (
	idEmptyDiff      = "empty_diff"
	idUnreadablePath = "unreadable_path"
	idQAShaMismatch  = "qa_sha_mismatch"
)

func isInternalID(id string) bool {
	return id == idEmptyDiff || id == idUnreadablePath || id == idQAShaMismatch
}

// lateReason is the reason a rule gives when it is not evaluated yet.
const lateReason = "not evaluated until P08"
