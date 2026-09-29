package riskevaluator

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The production policy for foreman, as embedded.
func foremanPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := EmbeddedPolicies().For("foreman")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A test policy with the three rules evaluated in P03 and none of the late ones.
func earlyPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := LoadTestPolicy("foreman", []byte(`version: 1
fail_closed: true
rules:
  - id: protected_paths
    reason: "Touches a path that requires human review"
    match:
      any_path: ["auth/**", "**/auth/**", "infra/**", "**/secrets*"]
  - id: size
    reason: "Change is large enough to warrant a human read"
    match:
      files_changed_gt: 15
      lines_changed_gt: 600
  - id: dependency_change
    reason: "Adds, removes, or bumps a dependency"
    match:
      any_path: ["**/go.mod", "**/go.sum"]
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func edit(path string, added, removed int64) Change {
	return Change{Path: path, Status: 'M', OldMode: "100644", NewMode: "100644", Added: added, Removed: removed}
}

func net(cs ...Change) Changes {
	var r []string
	for _, c := range cs {
		r = append(r, c.Path)
	}
	return Changes{Net: cs, Range: r}
}

var plain = Subject{Project: "other"}

func wantRules(t *testing.T, got Result, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got.MatchedRules == nil || !slices.Equal(got.MatchedRules, want) || got.Cleared != (len(want) == 0) {
		t.Fatalf("matched %v (cleared %v), want %v", got.MatchedRules, got.Cleared, want)
	}
	for _, id := range want {
		if got.Reasons[id] == "" {
			t.Errorf("rule %s matched with no reason", id)
		}
	}
}

// Chunk 3's cases (docs/bootstrap-plan.md).
func TestChunkThreeCases(t *testing.T) {
	p := earlyPolicy(t)
	t.Run("a diff touching auth/login.py escalates", func(t *testing.T) {
		wantRules(t, Evaluate(net(edit("auth/login.py", 1, 0)), plain, p), "protected_paths")
		wantRules(t, Evaluate(net(edit("auth/login.py", 1, 0)), plain, foremanPolicy(t)),
			"protected_paths", "test_integrity", "surface_change", "scope_drift")
	})
	t.Run("a 20-file diff escalates", func(t *testing.T) {
		var cs []Change
		for i := range 20 {
			cs = append(cs, edit(fmt.Sprintf("pkg/f%02d.go", i), 1, 0))
		}
		wantRules(t, Evaluate(net(cs...), plain, p), "size")
	})
	t.Run("a one-line diff in an unprotected path clears", func(t *testing.T) {
		r := Evaluate(net(edit("pkg/util.go", 1, 0)), plain, p)
		wantRules(t, r)
		if len(r.Reasons) != 0 {
			t.Fatalf("a cleared verdict carries reasons %v", r.Reasons)
		}
	})
}

// What each kind of change touches (Anchor, "Rules").
func TestWhatAChangeTouches(t *testing.T) {
	p := earlyPolicy(t)
	cases := []struct {
		name    string
		changes Changes
		want    []string
	}{
		{"deleting a protected file", net(Change{Path: "infra/main.tf", Status: 'D', OldMode: "100644", NewMode: "000000", Removed: 3}), []string{"protected_paths"}},
		{"renaming out of a protected path", net(
			Change{Path: "infra/main.tf", Status: 'D', OldMode: "100644", NewMode: "000000", Removed: 3},
			Change{Path: "moved.tf", Status: 'A', OldMode: "000000", NewMode: "100644", Added: 3}), []string{"protected_paths"}},
		{"a mode-only change on a protected path", net(Change{Path: "infra/run.sh", Status: 'M', OldMode: "100644", NewMode: "100755"}), []string{"protected_paths"}},
		{"a symlink on a protected path", net(Change{Path: "auth/link", Status: 'A', OldMode: "000000", NewMode: "120000", Added: 1}), []string{"protected_paths"}},
		{"a submodule on a protected path", net(Change{Path: "infra/vendored", Status: 'A', OldMode: "000000", NewMode: "160000", Added: 1}), []string{"protected_paths"}},
		{"a type change on a protected path", net(Change{Path: "auth/x", Status: 'T', OldMode: "100644", NewMode: "120000", Added: 1, Removed: 1}), []string{"protected_paths"}},
		{"a binary counts as exceeding the line threshold", net(Change{Path: "img/logo.png", Status: 'M', OldMode: "100644", NewMode: "100644", Binary: true}), []string{"size"}},
		{"no changed paths", Changes{}, []string{"empty_diff"}},
		{"an empty net diff whose range touched a protected file", Changes{Range: []string{"auth/login.py", "auth/login.py"}}, []string{"empty_diff", "protected_paths"}},
		{"a path that is not UTF-8", net(edit("pkg/\xff\xfe.go", 1, 0)), []string{"unreadable_path"}},
		{"a range path that is not UTF-8", Changes{Net: []Change{edit("pkg/a.go", 1, 0)}, Range: []string{"pkg/a.go", "x/\xc3"}}, []string{"unreadable_path"}},
		{"a protected path present only in the range", Changes{Net: []Change{edit("README.md", 1, 0)}, Range: []string{"auth/login.py", "README.md", "auth/login.py"}}, []string{"protected_paths"}},
		{"a dependency changed only in the range", Changes{Net: []Change{edit("README.md", 1, 0)}, Range: []string{"go.mod", "README.md"}}, []string{"dependency_change"}},
		{"secrets at the root", net(edit("secrets.env", 1, 0)), []string{"protected_paths"}},
		{"case does not hide a protected path", net(edit("Auth/Login.py", 1, 0)), []string{"protected_paths"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantRules(t, Evaluate(c.changes, plain, p), c.want...) })
	}
}

// size reads the net diff only; its thresholds are "more than".
func TestSizeThresholds(t *testing.T) {
	p := earlyPolicy(t)
	files := func(n int) []Change {
		var cs []Change
		for i := range n {
			cs = append(cs, edit(fmt.Sprintf("pkg/f%02d.go", i), 1, 0))
		}
		return cs
	}
	wantRules(t, Evaluate(net(files(15)...), plain, p))
	wantRules(t, Evaluate(net(files(16)...), plain, p), "size")
	wantRules(t, Evaluate(net(edit("pkg/a.go", 300, 300)), plain, p))
	wantRules(t, Evaluate(net(edit("pkg/a.go", 300, 301)), plain, p), "size")
	// A long range does not count towards size.
	long := Changes{Net: []Change{edit("pkg/a.go", 1, 0)}}
	for i := range 40 {
		long.Range = append(long.Range, fmt.Sprintf("pkg/r%02d.go", i))
	}
	wantRules(t, Evaluate(long, plain, p))
}

// The late rules always match under the production policy (D2), whatever the diff.
func TestLateRulesAlwaysMatch(t *testing.T) {
	r := Evaluate(net(edit("pkg/util.go", 1, 0)), plain, foremanPolicy(t))
	wantRules(t, r, "test_integrity", "surface_change", "scope_drift")
	for _, id := range r.MatchedRules {
		if r.Reasons[id] != lateReason {
			t.Errorf("%s: reason %q, want %q", id, r.Reasons[id], lateReason)
		}
	}
}

// The meta paths apply to a meta subject even when the policy omits them (D6).
func TestMetaPathsApplyToMetaSubjects(t *testing.T) {
	p := earlyPolicy(t) // protects auth, infra and secrets only
	touch := net(edit("cmd/foreman/main.go", 1, 0))
	wantRules(t, Evaluate(touch, Subject{Project: "foreman", Meta: true}, p), "protected_paths")
	wantRules(t, Evaluate(touch, Subject{Project: "other", Meta: false}, p))

	// With no protected_paths rule at all (possible only in a test policy), a meta subject still gets them.
	bare, err := LoadTestPolicy("foreman", []byte("version: 1\nfail_closed: true\nrules:\n  - id: size\n    reason: r\n    match:\n      files_changed_gt: 15\n"))
	if err != nil {
		t.Fatal(err)
	}
	wantRules(t, Evaluate(touch, Subject{Project: "foreman", Meta: true}, bare), "protected_paths")

	// The file's own meta_project list adds, for meta subjects only.
	extra, err := LoadTestPolicy("foreman", []byte("version: 1\nfail_closed: true\nrules:\n  - id: protected_paths\n    reason: r\n    match:\n      any_path: [\"auth/**\"]\nmeta_project:\n  protected_paths: [\"tools/**\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	wantRules(t, Evaluate(net(edit("tools/x.go", 1, 0)), Subject{Project: "foreman", Meta: true}, extra), "protected_paths")
	wantRules(t, Evaluate(net(edit("tools/x.go", 1, 0)), plain, extra))
}

// Added rules are evaluated like the built-in ones, and reported in the policy's order.
func TestAddedRulesInPolicyOrder(t *testing.T) {
	p, err := LoadTestPolicy("foreman", []byte(`version: 1
fail_closed: true
rules:
  - id: no_vendor
    reason: vendored code
    match:
      any_path: ["vendor/**"]
  - id: protected_paths
    reason: protected
    match:
      any_path: ["auth/**"]
  - id: waits_for_p08
    reason: late
    match:
      test_file_deleted: true
`))
	if err != nil {
		t.Fatal(err)
	}
	r := Evaluate(net(edit("auth/a.go", 1, 0), edit("vendor/x/y.go", 1, 0)), plain, p)
	wantRules(t, r, "no_vendor", "protected_paths", "waits_for_p08")
	if !strings.Contains(r.Reasons["no_vendor"], "vendor/x/y.go") || !strings.Contains(r.Reasons["protected_paths"], "auth/a.go") {
		t.Fatalf("reasons do not name the paths: %v", r.Reasons)
	}
}

// Same input, same cleared and matched rules (Anchor, "Fail closed, by test").
func TestDeterministic(t *testing.T) {
	p := foremanPolicy(t)
	in := Changes{Net: []Change{edit("auth/a.go", 3, 1), edit("go.mod", 1, 1), {Path: "b.bin", Status: 'A', NewMode: "100644", Binary: true}},
		Range: []string{"auth/a.go", "go.mod", "b.bin", "infra/x.tf"}}
	first := Evaluate(in, Subject{Project: "foreman", Meta: true}, p)
	for range 20 {
		if again := Evaluate(in, Subject{Project: "foreman", Meta: true}, p); !reflect.DeepEqual(first, again) {
			t.Fatalf("%+v then %+v", first, again)
		}
	}
}

// No input panics the rules; a result is always cleared exactly when nothing matched, and a
// protected path in the input never clears. Run long with:
// go test -fuzz=FuzzEvaluate -fuzztime=60s ./internal/risk_evaluator/
func FuzzEvaluate(f *testing.F) {
	f.Add("auth/login.py", "pkg/a.go", int64(1), int64(0), false, uint8('M'))
	f.Add("", "\xff", int64(-5), int64(1<<62), true, uint8('D'))
	f.Add("x/y/z", "Infra/Main.TF", int64(700), int64(0), false, uint8('T'))
	p, err := LoadTestPolicy("foreman", []byte(`version: 1
fail_closed: true
rules:
  - id: protected_paths
    reason: protected
    match:
      any_path: ["auth/**", "infra/**"]
  - id: size
    reason: size
    match:
      files_changed_gt: 15
      lines_changed_gt: 600
`))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, a, b string, added, removed int64, binary bool, status uint8) {
		in := Changes{Net: []Change{{Path: a, Status: status, Added: added, Removed: removed, Binary: binary}}, Range: []string{b}}
		r := Evaluate(in, Subject{Project: "foreman", Meta: true}, p)
		if r.Cleared != (len(r.MatchedRules) == 0) {
			t.Fatalf("cleared %v with matches %v", r.Cleared, r.MatchedRules)
		}
		for _, path := range []string{a, b} {
			if r.Cleared && (matchPath("auth/**", path) || matchPath("infra/**", path)) {
				t.Fatalf("%q is protected but the result cleared", path)
			}
		}
		if again := Evaluate(in, Subject{Project: "foreman", Meta: true}, p); !reflect.DeepEqual(r, again) {
			t.Fatal("not deterministic")
		}
	})
}
