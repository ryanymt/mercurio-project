package riskevaluator

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// Policies are embedded in the binary, one file per project, and chosen by project id: never read
// from a working tree, never chosen by a database column (P03 D5; docs/risk-policy.md, "The policy
// is loaded from the promoted image").
//
//go:embed policies/*.yml
var policyFiles embed.FS

// Policy is a loaded, validated policy. Its fields are unexported, so nothing outside this package
// can build or change one except through the loaders below.
type Policy struct {
	project   string
	sha256    string
	rules     []rule
	metaPaths []string // the file's own meta_project.protected_paths, added to the compiled-in list
}

type rule struct {
	id, reason string
	anyPath    []string
	filesGT    *int64
	linesGT    *int64
	evaluated  bool // false: the rule always matches, "not evaluated until P08"
}

// Project is the project the policy belongs to.
func (p *Policy) Project() string { return p.project }

// SHA256 is the hex SHA-256 of the policy file's bytes: with the project, the policy's identity.
func (p *Policy) SHA256() string { return p.sha256 }

// RuleIDs lists the rule ids in the file's order.
func (p *Policy) RuleIDs() []string {
	ids := make([]string, len(p.rules))
	for i, r := range p.rules {
		ids[i] = r.id
	}
	return ids
}

// LoadPolicy is the production loader: strict, and every starter rule id must be present.
func LoadPolicy(project string, data []byte) (*Policy, error) {
	return load(project, data, true)
}

// LoadTestPolicy loads a policy that may omit rule ids, the late rules included, for tests. It
// refuses to run outside `go test`, so a policy without the late rules exists only inside tests
// (P03 D13; red team round 2, R4). Tests reach it through package riskevaltest.
func LoadTestPolicy(project string, data []byte) (*Policy, error) {
	if !testing.Testing() {
		return nil, errors.New("the lax policy loader is refused outside go test: production policies must hold every starter rule")
	}
	return load(project, data, false)
}

// The file's shape. Unknown keys anywhere are refused (KnownFields), and so are duplicate keys.
type policyFile struct {
	Version     *int       `yaml:"version"`
	FailClosed  strictBool `yaml:"fail_closed"`
	Rules       []ruleFile `yaml:"rules"`
	MetaProject *metaFile  `yaml:"meta_project"`
}

type metaFile struct {
	ProtectedPaths []string `yaml:"protected_paths"`
}

type ruleFile struct {
	ID     string     `yaml:"id"`
	Reason string     `yaml:"reason"`
	Match  *matchFile `yaml:"match"`
}

// The closed set of matchers (docs/risk-policy.md, "Matchers"). The first three are evaluated from
// P03; the rest are known and type-checked, and a rule using one always matches until P08.
type matchFile struct {
	AnyPath        []string `yaml:"any_path"`
	FilesChangedGT *int64   `yaml:"files_changed_gt"`
	LinesChangedGT *int64   `yaml:"lines_changed_gt"`

	TestFileDeleted           *strictBool `yaml:"test_file_deleted"`
	TestSkippedOrPendingAdded *strictBool `yaml:"test_skipped_or_pending_added"`
	CoverageDropPctGT         *float64    `yaml:"coverage_drop_pct_gt"`
	UnimplicatedFilesGT       *int64      `yaml:"unimplicated_files_gt"`
}

// strictBool accepts only the plain scalars true and false: the YAML library would also decode
// yes, on, True and some quoted strings into a bool.
type strictBool bool

func (b *strictBool) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Style != 0 || n.Anchor != "" || n.Tag != "!!bool" ||
		(n.Value != "true" && n.Value != "false") {
		return fmt.Errorf("line %d: a boolean must be the plain scalar true or false", n.Line)
	}
	*b = strictBool(n.Value == "true")
	return nil
}

var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func load(project string, data []byte, requireAll bool) (*Policy, error) {
	if !validProjectID(project) {
		return nil, fmt.Errorf("%q is not a project id", project)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("the policy is empty")
	}
	if err := checkFailClosed(data); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f policyFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the policy does not decode: %w", err)
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return nil, errors.New("the policy holds more than one YAML document")
	}
	if f.Version == nil || *f.Version != 1 {
		return nil, errors.New("the policy must declare version: 1")
	}
	if !f.FailClosed {
		return nil, errors.New("fail_closed must be true")
	}
	if len(f.Rules) == 0 {
		return nil, errors.New("the policy has no rules")
	}

	p := &Policy{project: project}
	seen := map[string]bool{}
	for i, rf := range f.Rules {
		r, err := checkRule(rf)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i+1, rf.ID, err)
		}
		if seen[r.id] {
			return nil, fmt.Errorf("rule id %q appears twice", r.id)
		}
		seen[r.id] = true
		p.rules = append(p.rules, r)
	}
	if requireAll {
		for _, id := range requiredRuleIDs() {
			if !seen[id] {
				return nil, fmt.Errorf("the policy lacks the rule %q: rules may be added, never removed", id)
			}
		}
	}
	if f.MetaProject != nil {
		if len(f.MetaProject.ProtectedPaths) == 0 {
			return nil, errors.New("meta_project.protected_paths is empty")
		}
		for _, pat := range f.MetaProject.ProtectedPaths {
			if err := validPattern(pat); err != nil {
				return nil, fmt.Errorf("meta_project.protected_paths: %w", err)
			}
		}
		p.metaPaths = slices.Clone(f.MetaProject.ProtectedPaths)
	}
	sum := sha256.Sum256(data)
	p.sha256 = hex.EncodeToString(sum[:])
	return p, nil
}

// checkFailClosed requires `fail_closed` to be the plain scalar `true`: the YAML library would also
// decode `yes`, `on`, `True`, an alias or a tagged value into true.
func checkFailClosed(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("the policy does not decode: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("the policy is not a mapping")
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "fail_closed" {
			continue
		}
		v := root.Content[i+1]
		if v.Kind != yaml.ScalarNode || v.Style != 0 || v.Anchor != "" || v.Tag != "!!bool" || v.Value != "true" {
			return errors.New("fail_closed must be the plain scalar true")
		}
		return nil
	}
	return errors.New("the policy must declare fail_closed: true")
}

func checkRule(rf ruleFile) (rule, error) {
	r := rule{id: rf.ID, reason: rf.Reason}
	switch {
	case !ruleIDPattern.MatchString(rf.ID):
		return r, errors.New("a rule needs an id of lower-case letters, digits and underscores")
	case isInternalID(rf.ID):
		return r, fmt.Errorf("%q is an id the evaluator uses itself", rf.ID)
	case strings.TrimSpace(rf.Reason) == "":
		return r, errors.New("a rule needs a reason")
	case rf.Match == nil:
		return r, errors.New("a rule needs a match with at least one matcher")
	}
	m := *rf.Match
	matchers, late := 0, false

	if m.AnyPath != nil {
		matchers++
		if len(m.AnyPath) == 0 {
			return r, errors.New("any_path is empty")
		}
		for _, pat := range m.AnyPath {
			if err := validPattern(pat); err != nil {
				return r, err
			}
		}
		r.anyPath = slices.Clone(m.AnyPath)
	}
	for _, n := range []struct {
		name string
		v    *int64
		dst  **int64
	}{{"files_changed_gt", m.FilesChangedGT, &r.filesGT}, {"lines_changed_gt", m.LinesChangedGT, &r.linesGT}} {
		if n.v == nil {
			continue
		}
		matchers++
		if *n.v < 0 {
			return r, fmt.Errorf("%s is negative", n.name)
		}
		v := *n.v
		*n.dst = &v
	}
	if m.TestFileDeleted != nil {
		matchers, late = matchers+1, true
	}
	if m.TestSkippedOrPendingAdded != nil {
		matchers, late = matchers+1, true
	}
	if m.CoverageDropPctGT != nil {
		matchers, late = matchers+1, true
		if c := *m.CoverageDropPctGT; math.IsNaN(c) || math.IsInf(c, 0) || c < 0 {
			return r, errors.New("coverage_drop_pct_gt must be a finite, non-negative number")
		}
	}
	if m.UnimplicatedFilesGT != nil {
		matchers, late = matchers+1, true
		if *m.UnimplicatedFilesGT < 0 {
			return r, errors.New("unimplicated_files_gt is negative")
		}
	}
	if matchers == 0 {
		return r, errors.New("a rule needs at least one matcher")
	}
	r.evaluated = !late && !isLateRule(rf.ID)
	return r, nil
}

var projectIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// validProjectID is the shape of a project id: it names a policy file and a repository directory.
func validProjectID(id string) bool { return projectIDPattern.MatchString(id) }

// PolicySet holds every embedded policy, each loaded once: a file that fails to load is kept as
// its error, so every evaluation for that project escalates naming it, and the others still work.
type PolicySet struct {
	byProject map[string]policyResult
}

type policyResult struct {
	policy *Policy
	err    error
}

// EmbeddedPolicies loads the policies compiled into the binary.
func EmbeddedPolicies() *PolicySet { return loadSet(policyFiles) }

func loadSet(fsys fs.FS) *PolicySet {
	s := &PolicySet{byProject: map[string]policyResult{}}
	names, _ := fs.Glob(fsys, "policies/*.yml")
	for _, name := range names {
		project := strings.TrimSuffix(path.Base(name), ".yml")
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			s.byProject[project] = policyResult{err: err}
			continue
		}
		p, err := LoadPolicy(project, data)
		s.byProject[project] = policyResult{policy: p, err: err}
	}
	return s
}

// For returns the project's policy, or why there is none.
func (s *PolicySet) For(project string) (*Policy, error) {
	r, ok := s.byProject[project]
	if !ok {
		return nil, fmt.Errorf("no risk policy for project %q", project)
	}
	if r.err != nil {
		return nil, fmt.Errorf("the risk policy for %q does not load: %w", project, r.err)
	}
	return r.policy, nil
}

// Projects lists the projects that have a policy file, loaded or not, sorted.
func (s *PolicySet) Projects() []string {
	ps := make([]string, 0, len(s.byProject))
	for p := range s.byProject {
		ps = append(ps, p)
	}
	slices.Sort(ps)
	return ps
}
