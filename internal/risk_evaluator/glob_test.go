package riskevaluator

import (
	"strings"
	"testing"
)

// Glob semantics (docs/risk-policy.md, "Matching"; P03 D8): anchored at the root, `*` within one
// segment, `**` any number of segments including none, ASCII case ignored.
func TestMatchSemantics(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		// anchoring
		{"auth/**", "auth/login.py", true},
		{"auth/**", "src/auth/login.py", false},
		{"docs/architecture.md", "docs/architecture.md", true},
		{"docs/architecture.md", "x/docs/architecture.md", false},
		{"Makefile", "Makefile", true},
		{"Makefile", "sub/Makefile", false},
		{"*.pem", "b.pem", true},
		{"*.pem", "a/b.pem", false},
		// ** spans zero or more segments
		{"**/auth/**", "src/auth/login.py", true},
		{"**/auth/**", "auth/login.py", true},
		{"**/secrets*", "secrets.env", true},
		{"**/secrets*", "a/b/secrets.json", true},
		{"**/secrets*", "a/secretsx/y", false},
		{"**/*.pem", "b.pem", true},
		{"**/*.pem", "deep/er/b.pem", true},
		{"**/CLAUDE.md", "CLAUDE.md", true},
		{"**/CLAUDE.md", "docs/CLAUDE.md", true},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/c", false},
		{"**/**/x", "x", true},
		{"**", "anything/at/all", true},
		{"infra/**", "infra", true}, // a trailing ** matches no segment too: a file named infra is caught
		{"infra/**", "infrastructure/main.tf", false},
		{"cmd/foreman/**", "cmd/foreman/main.go", true},
		{"cmd/foreman/**", "cmd/foremanx/main.go", false},
		// * and ? never cross a slash
		{"a?c", "abc", true},
		{"a?c", "a/c", false},
		{"a*", "a/b", false},
		{"[a-c]x", "bx", true},
		{"[a-c]x", "dx", false},
		// ASCII case is ignored, on both sides
		{"auth/**", "Auth/login.py", true},
		{"AUTH/**", "auth/x", true},
		{"**/Dockerfile", "svc/dockerfile", true},
		{"Makefile", "MAKEFILE", true},
		{"é/**", "É/x", false}, // only ASCII letters fold
		// escapes and literal dots
		{"a.b", "axb", false},
		{`a\*b`, "a*b", true},
		{`a\*b`, "axb", false},
	}
	for _, c := range cases {
		if err := validPattern(c.pattern); err != nil {
			t.Fatalf("%q: a valid pattern was refused: %v", c.pattern, err)
		}
		if got := matchPath(c.pattern, c.path); got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// A pattern that would silently never match, or match something unexpected, refuses the policy
// at load (red team round 2, R5).
func TestPatternRefusals(t *testing.T) {
	for _, p := range []string{
		"",
		"/CLAUDE.md", // the gitignore habit for anchoring: here it would match nothing
		"infra/",     // trailing slash
		"auth//x",    // empty segment
		"./infra/**", // . segment
		"a/./b",      // . segment
		"a/../b",     // .. segment
		"..",         // .. segment
		"auth/[",     // malformed class
		`a\`,         // dangling escape
		"foo/**bar",  // ** inside a segment is ambiguous
		"**x/y",      // ** inside a segment is ambiguous
		"x/[]",       // empty class
	} {
		if err := validPattern(p); err == nil {
			t.Errorf("pattern %q was accepted", p)
		}
	}
	for _, p := range []string{"**", "auth/**", "**/*.pem", "a/**/b", "[a-c]x", "Makefile", ".github/**", "**/.gitattributes"} {
		if err := validPattern(p); err != nil {
			t.Errorf("pattern %q was refused: %v", p, err)
		}
	}
}

// The compiled-in meta list covers the real files it exists for (round 1 R4 and R5, round 2 R1).
func TestMetaListCoversTheRealPaths(t *testing.T) {
	for _, p := range metaProtectedPaths() {
		if err := validPattern(p); err != nil {
			t.Fatalf("compiled-in pattern %q is invalid: %v", p, err)
		}
	}
	for _, path := range []string{
		"CLAUDE.md", "docs/CLAUDE.md", "docs/architecture.md", "docs/state-machine.md", "docs/risk-policy.md",
		"cmd/foreman/main.go", "internal/callback_api/http.go", "internal/callback_api/transitions_engine.go",
		"internal/callback_api/a_new_file.go", "internal/db/db.go", "internal/db/migrate.go", "Makefile",
		"internal/risk_evaluator/rules.go", "internal/risk_evaluator/policies/foreman.yml",
		"internal/risk_evaluator/gitfixture/fixture.go", "internal/dispatcher/service_accounts.go",
		"internal/dispatcher/tick.go", "internal/dispatcher/model-policy.yml", "internal/dispatcher/a_new_file.go",
		"cloudbuild.yaml",
		"rollback.sh", "scripts/rollback.sh", "model-policy.yml", "config/model-policy.yml",
		".gitattributes", "sub/.gitattributes", ".claude/settings.json", ".claude/commands/plan.md", ".mcp.json",
		"internal/escalation/x.go", "web/parking_view.go",
	} {
		if !matchesAny(metaProtectedPaths(), path) {
			t.Errorf("%s is not protected by the compiled-in meta list", path)
		}
	}
	for _, path := range []string{"README.md", "internal/testdb/testdb.go", "docs/bootstrap-plan.md", "scripts/dev/land-main.sh"} {
		if matchesAny(metaProtectedPaths(), path) {
			t.Errorf("%s matches the meta list, which it should not need to", path)
		}
	}
	if !isMetaProject("foreman") || isMetaProject("other") || isMetaProject("Foreman") {
		t.Fatal("the compiled-in meta project set is exactly {foreman}")
	}
}

func matchesAny(patterns []string, path string) bool {
	for _, p := range patterns {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// The matcher never panics, is deterministic, and ignores ASCII case, for any pattern that loads.
// Run long with: go test -fuzz=FuzzMatch -fuzztime=60s ./internal/risk_evaluator/
func FuzzMatch(f *testing.F) {
	for _, s := range [][2]string{
		{"**/secrets*", "a/secrets.env"}, {"auth/**", "Auth/x"}, {"a/**/b/**/c", "a/x/b/y/z/c"},
		{"[a-c]x", "bx"}, {`a\*b`, "a*b"}, {"**", ""}, {"x", strings.Repeat("a/", 50) + "x"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, path string) {
		if validPattern(pattern) != nil {
			return
		}
		got := matchPath(pattern, path)
		if again := matchPath(pattern, path); again != got {
			t.Fatalf("matchPath(%q, %q) is not deterministic", pattern, path)
		}
		if upper := matchPath(upperASCII(pattern), upperASCII(path)); upper != got {
			t.Fatalf("matchPath(%q, %q) = %v but %v in upper case", pattern, path, got, upper)
		}
	})
}
