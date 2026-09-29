package riskevaluator

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// The pure function (docs/risk-policy.md; P03 Approach 2): changed paths, the subject and the
// policy in, a result out. No context, no I/O, no clock. Boolean OR: any match escalates.

// Change is one record of the net diff from base to head. With rename detection off, a rename is
// a deletion of the old path plus an addition of the new one, so every record has one path.
type Change struct {
	Path             string
	Status           byte   // git's raw status letter: A, D, M or T
	OldMode, NewMode string // as git prints them: 100644, 100755, 120000 (symlink), 160000 (submodule), 000000
	Added, Removed   int64
	Binary           bool // git could not count lines
}

// Changes is what the rules read: the net diff, and every path changed by any commit in the range
// (merges against each parent), which shows what the net diff can hide (D12).
type Changes struct {
	Net   []Change
	Range []string
}

// Subject is what the rules need to know about the ticket.
type Subject struct {
	Project string
	Meta    bool // the compiled-in meta set or projects.is_meta: either adds, neither removes (D6)
}

// Result is the pure function's answer. MatchedRules is in a fixed order: the evaluator's own ids
// first, then the policy's rules in the file's order.
type Result struct {
	Cleared      bool
	MatchedRules []string
	Reasons      map[string]string
}

// Evaluate applies the policy. It clears only when no rule matches.
func Evaluate(changes Changes, subject Subject, policy *Policy) Result {
	res := Result{MatchedRules: []string{}, Reasons: map[string]string{}}
	add := func(id, reason string) {
		res.MatchedRules = append(res.MatchedRules, id)
		res.Reasons[id] = reason
	}

	paths := make([]string, 0, len(changes.Net)+len(changes.Range))
	for _, c := range changes.Net {
		paths = append(paths, c.Path)
	}
	paths = append(paths, changes.Range...)

	// Inputs no rule can judge escalate on their own; the rules still run, so the human sees why.
	if len(changes.Net) == 0 {
		add(idEmptyDiff, "the submitted commit changes nothing against its base")
	}
	if bad := unreadable(paths); len(bad) > 0 {
		add(idUnreadablePath, "paths that are not valid UTF-8 cannot be matched: "+examples(bad))
	}

	sawProtected := false
	for _, r := range policy.rules {
		if r.id == "protected_paths" {
			sawProtected = true
		}
		if !r.evaluated {
			add(r.id, lateReason)
			continue
		}
		var why []string
		patterns := r.anyPath
		if r.id == "protected_paths" && subject.Meta {
			patterns = append(append(append([]string{}, patterns...), metaProtectedPaths()...), policy.metaPaths...)
		}
		if len(patterns) > 0 {
			if hit := matching(patterns, paths); len(hit) > 0 {
				why = append(why, examples(hit))
			}
		}
		if r.filesGT != nil && int64(len(changes.Net)) > *r.filesGT {
			why = append(why, fmt.Sprintf("%d files", len(changes.Net)))
		}
		if r.linesGT != nil {
			if lines, unknown := countLines(changes.Net); unknown != "" {
				why = append(why, unknown)
			} else if lines > *r.linesGT {
				why = append(why, fmt.Sprintf("%d lines", lines))
			}
		}
		if len(why) > 0 {
			add(r.id, r.reason+": "+strings.Join(why, "; "))
		}
	}
	// A meta subject gets the compiled-in paths even under a policy with no protected_paths rule,
	// which only a test policy can be.
	if subject.Meta && !sawProtected {
		if hit := matching(append(metaProtectedPaths(), policy.metaPaths...), paths); len(hit) > 0 {
			add("protected_paths", "Touches a path the meta-project protects: "+examples(hit))
		}
	}
	res.Cleared = len(res.MatchedRules) == 0
	return res
}

// unreadable lists the paths no pattern can judge: empty ones and ones that are not UTF-8.
func unreadable(paths []string) []string {
	var bad []string
	for _, p := range paths {
		if p == "" || !utf8.ValidString(p) {
			bad = append(bad, p)
		}
	}
	return bad
}

// matching lists the paths, in input order, that match any of the patterns.
func matching(patterns, paths []string) []string {
	var hit []string
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			continue
		}
		for _, pat := range patterns {
			if matchPath(pat, p) {
				hit = append(hit, p)
				seen[p] = true
				break
			}
		}
	}
	return hit
}

// countLines sums lines added and removed. A binary, or a count that cannot be right, makes the
// size unknown, which counts as exceeding the threshold: fail closed.
func countLines(net []Change) (int64, string) {
	var total int64
	for _, c := range net {
		if c.Binary {
			return 0, "a binary file, whose size in lines is unknown (" + fmt.Sprintf("%q", c.Path) + ")"
		}
		if c.Added < 0 || c.Removed < 0 {
			return 0, "a line count that is not a count (" + fmt.Sprintf("%q", c.Path) + ")"
		}
		for _, n := range []int64{c.Added, c.Removed} {
			if total > math.MaxInt64-n {
				return 0, "more lines than can be counted"
			}
			total += n
		}
	}
	return total, ""
}

// examples names up to three paths, quoted, and how many more there are.
func examples(paths []string) string {
	const shown = 3
	var b strings.Builder
	for i, p := range paths {
		if i == shown {
			fmt.Fprintf(&b, " and %d more", len(paths)-shown)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", p)
	}
	return b.String()
}
