package riskevaluator

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// A complete, valid policy: the six starter rules. Each refusal case below changes one thing.
const validPolicy = `version: 1
fail_closed: true
rules:
  - id: protected_paths
    reason: "Touches a path that requires human review"
    match:
      any_path: ["auth/**", "infra/**"]
  - id: size
    reason: "Large"
    match:
      files_changed_gt: 15
      lines_changed_gt: 600
  - id: dependency_change
    reason: "Dependencies"
    match:
      any_path: ["**/go.mod"]
  - id: test_integrity
    reason: "Tests"
    match:
      test_file_deleted: true
      test_skipped_or_pending_added: true
      coverage_drop_pct_gt: 1.0
  - id: surface_change
    reason: "Surface"
    match:
      any_path: ["**/*.proto"]
  - id: scope_drift
    reason: "Scope"
    match:
      unimplicated_files_gt: 0
`

func replace(t *testing.T, doc, old, new string) string {
	t.Helper()
	if !strings.Contains(doc, old) {
		t.Fatalf("test bug: %q not in the policy", old)
	}
	return strings.Replace(doc, old, new, 1)
}

func TestValidPolicyLoads(t *testing.T) {
	p, err := LoadPolicy("foreman", []byte(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.RuleIDs(); !slices.Equal(got, []string{"protected_paths", "size", "dependency_change", "test_integrity", "surface_change", "scope_drift"}) {
		t.Fatalf("rule ids %v: want the six, in the file's order", got)
	}
	sum := sha256.Sum256([]byte(validPolicy))
	if p.Project() != "foreman" || p.SHA256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("identity %s %s", p.Project(), p.SHA256())
	}
	for _, r := range p.rules {
		late := r.id == "test_integrity" || r.id == "surface_change" || r.id == "scope_drift"
		if r.evaluated == late {
			t.Errorf("rule %s: evaluated = %v", r.id, r.evaluated)
		}
	}
}

// Every refusal in Approach 4 (round 2 R5 included). Each must fail the load.
func TestPolicyRefusals(t *testing.T) {
	v := validPolicy
	cases := map[string]string{
		"unknown top-level key":  v + "extra: 1\n",
		"unknown rule key":       replace(t, v, `reason: "Large"`, "reason: \"Large\"\n    weight: 2"),
		"unknown matcher key":    replace(t, v, `any_path: ["**/go.mod"]`, `any_file: ["**/go.mod"]`),
		"duplicate key":          replace(t, v, "fail_closed: true\n", "fail_closed: false\nfail_closed: true\n"),
		"fail_closed yes":        replace(t, v, "fail_closed: true", "fail_closed: yes"),
		"fail_closed on":         replace(t, v, "fail_closed: true", "fail_closed: on"),
		"fail_closed True":       replace(t, v, "fail_closed: true", "fail_closed: True"),
		"fail_closed quoted":     replace(t, v, "fail_closed: true", `fail_closed: "true"`),
		"fail_closed tagged":     replace(t, v, "fail_closed: true", "fail_closed: !!bool true"),
		"fail_closed anchored":   replace(t, v, "fail_closed: true", "fail_closed: &t true"),
		"fail_closed false":      replace(t, v, "fail_closed: true", "fail_closed: false"),
		"fail_closed absent":     replace(t, v, "fail_closed: true\n", ""),
		"fail_closed alias":      replace(t, replace(t, v, "fail_closed: true\n", ""), "test_file_deleted: true", "test_file_deleted: &t true") + "fail_closed: *t\n",
		"second document":        v + "---\nversion: 1\nfail_closed: false\n",
		"version 2":              replace(t, v, "version: 1", "version: 2"),
		"version absent":         replace(t, v, "version: 1\n", ""),
		"empty document":         "",
		"not a mapping":          "- 1\n- 2\n",
		"rules not a list":       "version: 1\nfail_closed: true\nrules: {}\n",
		"missing rule id":        replace(t, v, "  - id: scope_drift\n    reason: \"Scope\"\n    match:\n      unimplicated_files_gt: 0\n", ""),
		"duplicate rule id":      v + "  - id: size\n    reason: again\n    match:\n      files_changed_gt: 1\n",
		"internal id empty_diff": v + "  - id: empty_diff\n    reason: x\n    match:\n      files_changed_gt: 1\n",
		"internal id qa_sha":     v + "  - id: qa_sha_mismatch\n    reason: x\n    match:\n      files_changed_gt: 1\n",
		"internal id unreadable": v + "  - id: unreadable_path\n    reason: x\n    match:\n      files_changed_gt: 1\n",
		"rule without id":        v + "  - reason: x\n    match:\n      files_changed_gt: 1\n",
		"rule without reason":    v + "  - id: extra\n    match:\n      files_changed_gt: 1\n",
		"rule without match":     v + "  - id: extra\n    reason: x\n",
		"match null":             v + "  - id: extra\n    reason: x\n    match: ~\n",
		"match empty":            v + "  - id: extra\n    reason: x\n    match: {}\n",
		"any_path null only":     v + "  - id: extra\n    reason: x\n    match:\n      any_path: ~\n",
		"any_path empty list":    replace(t, v, `any_path: ["**/go.mod"]`, "any_path: []"),
		"any_path a string":      replace(t, v, `any_path: ["**/go.mod"]`, `any_path: "**/go.mod"`),
		"malformed pattern":      replace(t, v, `"auth/**"`, `"auth/["`),
		"empty pattern":          replace(t, v, `"auth/**"`, `""`),
		"leading slash":          replace(t, v, `"auth/**"`, `"/CLAUDE.md"`),
		"trailing slash":         replace(t, v, `"auth/**"`, `"infra/"`),
		"empty segment":          replace(t, v, `"auth/**"`, `"auth//x"`),
		"dot segment":            replace(t, v, `"auth/**"`, `"./infra/**"`),
		"dotdot segment":         replace(t, v, `"auth/**"`, `"a/../b"`),
		"negative files":         replace(t, v, "files_changed_gt: 15", "files_changed_gt: -5"),
		"negative lines":         replace(t, v, "lines_changed_gt: 600", "lines_changed_gt: -1"),
		"files a string":         replace(t, v, "files_changed_gt: 15", `files_changed_gt: "15"`),
		"coverage NaN":           replace(t, v, "coverage_drop_pct_gt: 1.0", "coverage_drop_pct_gt: .nan"),
		"coverage infinity":      replace(t, v, "coverage_drop_pct_gt: 1.0", "coverage_drop_pct_gt: .inf"),
		"coverage negative":      replace(t, v, "coverage_drop_pct_gt: 1.0", "coverage_drop_pct_gt: -1.0"),
		"unimplicated negative":  replace(t, v, "unimplicated_files_gt: 0", "unimplicated_files_gt: -1"),
		"late bool a string":     replace(t, v, "test_file_deleted: true", `test_file_deleted: "yes"`),
		"meta unknown key":       v + "meta_project:\n  paths: [\"x\"]\n",
		"meta bad pattern":       v + "meta_project:\n  protected_paths: [\"/x\"]\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPolicy("foreman", []byte(doc)); err == nil {
				t.Fatalf("the policy loaded:\n%s", doc)
			}
		})
	}
}

// Rules may be added; what decides whether one is evaluated is its id and its matchers.
func TestAddedRules(t *testing.T) {
	doc := validPolicy +
		"  - id: no_vendor\n    reason: vendored code\n    match:\n      any_path: [\"vendor/**\"]\n" +
		"  - id: tiny_limit\n    reason: tiny\n    match:\n      files_changed_gt: 3\n" +
		"  - id: late_matcher\n    reason: late\n    match:\n      test_file_deleted: true\n" +
		"  - id: mixed\n    reason: mixed\n    match:\n      any_path: [\"x/**\"]\n      coverage_drop_pct_gt: 0.5\n" +
		"meta_project:\n  protected_paths: [\"extra/**\"]\n"
	p, err := LoadPolicy("foreman", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"no_vendor": true, "tiny_limit": true, "late_matcher": false, "mixed": false}
	for _, r := range p.rules {
		if w, ok := want[r.id]; ok && r.evaluated != w {
			t.Errorf("added rule %s: evaluated = %v, want %v", r.id, r.evaluated, w)
		}
	}
	if !slices.Equal(p.metaPaths, []string{"extra/**"}) {
		t.Errorf("meta paths from the file: %v", p.metaPaths)
	}
}

// Test policies may omit the late rules, through the lax path only; the production path refuses.
func TestTestPoliciesMayOmitLateRules(t *testing.T) {
	doc := "version: 1\nfail_closed: true\nrules:\n  - id: protected_paths\n    reason: r\n    match:\n      any_path: [\"auth/**\"]\n"
	if _, err := LoadPolicy("foreman", []byte(doc)); err == nil {
		t.Fatal("the production loader accepted a policy without the six rule ids")
	}
	p, err := LoadTestPolicy("foreman", []byte(doc))
	if err != nil || !slices.Equal(p.RuleIDs(), []string{"protected_paths"}) {
		t.Fatalf("the test loader: %v, %v", p, err)
	}
	// Everything but the rule-id check still applies to it.
	if _, err := LoadTestPolicy("foreman", []byte(strings.Replace(doc, "fail_closed: true", "fail_closed: on", 1))); err == nil {
		t.Fatal("the test loader accepted fail_closed: on")
	}
}

// Outside `go test` the lax path refuses to run (round 2 R4): a real binary built from
// testdata/laxmain calls it and must be refused.
func TestLaxPathRefusedOutsideTests(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("this test builds a binary and needs the go command:", err)
	}
	bin := filepath.Join(t.TempDir(), "laxmain")
	build := exec.Command(gobin, "build", "-o", bin, "./testdata/laxmain")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(string(out), "refused") {
		t.Fatalf("the lax path ran outside a test binary: err=%v output=%s", err, out)
	}
}

// The embedded production policy for foreman loads under the strict loader.
func TestEmbeddedFormanPolicy(t *testing.T) {
	set := EmbeddedPolicies()
	p, err := set.For("foreman")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.RuleIDs(); !slices.Equal(got[:6], []string{"protected_paths", "size", "dependency_change", "test_integrity", "surface_change", "scope_drift"}) {
		t.Fatalf("foreman.yml rule ids %v", got)
	}
	raw, err := os.ReadFile("policies/foreman.yml")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if p.SHA256() != hex.EncodeToString(sum[:]) {
		t.Fatal("the policy's identity is not the SHA-256 of its file")
	}
	for _, path := range []string{"go.work", "go.work.sum", "vendor/modules.txt", "go.mod", "sub/go.sum"} {
		if !p.matchesRuleAnyPath("dependency_change", path) {
			t.Errorf("dependency_change does not catch %s", path)
		}
	}
	for _, path := range []string{".github/workflows/ci.yml", "migrations/00004_head_sha.sql", "infra/main.tf", "auth/login.py"} {
		if !p.matchesRuleAnyPath("protected_paths", path) {
			t.Errorf("protected_paths does not catch %s", path)
		}
	}
	if _, err := set.For("nope"); err == nil {
		t.Fatal("a project with no policy got one")
	}
}

// Policies load once; one that fails is kept as its error, and the others still work.
func TestPolicySetKeepsEachFilesError(t *testing.T) {
	set := loadSet(fstest.MapFS{
		"policies/good.yml":     {Data: []byte(validPolicy)},
		"policies/bad.yml":      {Data: []byte(strings.Replace(validPolicy, "fail_closed: true", "fail_closed: no", 1))},
		"policies/Bad Name.yml": {Data: []byte(validPolicy)},
		"policies/notes.txt":    {Data: []byte("ignored")},
	})
	if _, err := set.For("good"); err != nil {
		t.Fatal(err)
	}
	if _, err := set.For("bad"); err == nil || !strings.Contains(err.Error(), "fail_closed") {
		t.Fatalf("bad.yml: %v", err)
	}
	if _, err := set.For("Bad Name"); err == nil {
		t.Fatal("a policy file whose name is not a project id loaded")
	}
	if got := set.Projects(); !slices.Equal(got, []string{"Bad Name", "bad", "good"}) {
		t.Fatalf("projects %v", got)
	}
}

// No input panics the loader.
// Run long with: go test -fuzz=FuzzLoadPolicy -fuzztime=60s ./internal/risk_evaluator/
func FuzzLoadPolicy(f *testing.F) {
	f.Add([]byte(validPolicy))
	f.Add([]byte("version: 1\nfail_closed: *x\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Fuzz(func(t *testing.T, doc []byte) {
		LoadPolicy("foreman", doc)
		LoadTestPolicy("foreman", doc)
	})
}

// matchesRuleAnyPath reports whether the named rule's any_path catches a path: a test helper.
func (p *Policy) matchesRuleAnyPath(id, path string) bool {
	for _, r := range p.rules {
		if r.id == id && matchesAny(r.anyPath, path) {
			return true
		}
	}
	return false
}
