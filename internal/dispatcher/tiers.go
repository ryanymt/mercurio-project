// Package dispatcher is foreman's dispatcher (docs/architecture.md, "Dispatcher";
// docs/state-machine.md, "Atomic claim"): a stateless tick with no model in it that reaps expired
// leases, checks the gates, claims one ticket through the transition core, chooses the model tier
// from a protected table and hands a launch request to a launcher. The whole package is a
// protected path.
package dispatcher

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"sort"

	"go.yaml.in/yaml/v3"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
)

// The tier table (P04 D11): embedded, decoded strictly, and checked when it loads.

//go:embed model-policy.yml
var embeddedTiers []byte

// Tier is what a runner of one role gets on one attempt.
type Tier struct {
	Role       callbackapi.Role
	Attempt    int    // dev: the attempt it starts; QA: the dev attempt it judges
	Name       string // the tier's name, recorded on the attempt
	Provider   string // a `budget` row
	Model      string
	Rank       int    // QA's must be at least the dev tier's for the same attempt
	Credential string // the name of the one secret a launch injects
}

// Tiers is a loaded tier table.
type Tiers struct {
	byKey     map[tierKey]Tier
	providers []string
}

type tierKey struct {
	role    callbackapi.Role
	attempt int
}

// tieredRoles are the roles the table must cover, each for every attempt up to the cap. The
// integrator runs no model.
var tieredRoles = []callbackapi.Role{callbackapi.RoleSpec, callbackapi.RoleArchitect, callbackapi.RoleDev, callbackapi.RoleQA}

// knownProviders are the providers with a `budget` row in the schema's seed; a tier naming any
// other is refused. Whether each row exists is checked again at every tick.
var knownProviders = map[string]bool{"anthropic": true, "zai": true}

type tableFile struct {
	Version *int       `yaml:"version"`
	Tiers   []tierFile `yaml:"tiers"`
}

type tierFile struct {
	Role       string    `yaml:"role"`
	Attempt    strictInt `yaml:"attempt"`
	Tier       string    `yaml:"tier"`
	Provider   string    `yaml:"provider"`
	Model      string    `yaml:"model"`
	Rank       strictInt `yaml:"rank"`
	Credential string    `yaml:"credential"`
}

// strictInt accepts only a plain YAML integer: the decoder would otherwise truncate 1.5 to 1.
type strictInt int

func (s *strictInt) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" {
		return fmt.Errorf("line %d: %q is not an integer", n.Line, n.Value)
	}
	var i int
	if err := n.Decode(&i); err != nil {
		return err
	}
	*s = strictInt(i)
	return nil
}

// EmbeddedTiers loads the table compiled into the binary.
func EmbeddedTiers() (*Tiers, error) { return LoadTiers(embeddedTiers) }

// LoadTiers decodes and checks a tier table. It refuses unknown keys, duplicate keys and more than
// one document; a tier for any role but spec, architect, dev and QA, for an attempt outside 1 to
// the cap, or given twice; a missing one; an unknown provider; an empty name, model or
// credential; a rank that is not a positive integer; and QA ranked below the dev tier it judges.
func LoadTiers(data []byte) (*Tiers, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("the tier table is empty")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f tableFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the tier table does not decode: %w", err)
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return nil, errors.New("the tier table holds more than one YAML document")
	}
	if f.Version == nil || *f.Version != 1 {
		return nil, errors.New("the tier table must declare version: 1")
	}

	t := &Tiers{byKey: map[tierKey]Tier{}}
	tiered := map[callbackapi.Role]bool{}
	for _, r := range tieredRoles {
		tiered[r] = true
	}
	providers := map[string]bool{}
	for i, tf := range f.Tiers {
		role, attempt, rank := callbackapi.Role(tf.Role), int(tf.Attempt), int(tf.Rank)
		switch {
		case !tiered[role]:
			return nil, fmt.Errorf("tier %d: role %q has no tier (the integrator runs no model)", i+1, tf.Role)
		case attempt < 1 || attempt > callbackapi.AttemptCap:
			return nil, fmt.Errorf("tier %d: attempt %d is outside 1 to %d", i+1, attempt, callbackapi.AttemptCap)
		case !knownProviders[tf.Provider]:
			return nil, fmt.Errorf("tier %d: provider %q has no budget", i+1, tf.Provider)
		case tf.Tier == "" || tf.Model == "" || tf.Credential == "":
			return nil, fmt.Errorf("tier %d: the tier's name, model and credential are required", i+1)
		case rank < 1:
			return nil, fmt.Errorf("tier %d: the rank must be a positive integer", i+1)
		}
		k := tierKey{role, attempt}
		if _, dup := t.byKey[k]; dup {
			return nil, fmt.Errorf("%s attempt %d is given twice", role, attempt)
		}
		t.byKey[k] = Tier{Role: role, Attempt: attempt, Name: tf.Tier, Provider: tf.Provider,
			Model: tf.Model, Rank: rank, Credential: tf.Credential}
		providers[tf.Provider] = true
	}
	for _, role := range tieredRoles {
		for a := 1; a <= callbackapi.AttemptCap; a++ {
			if _, ok := t.byKey[tierKey{role, a}]; !ok {
				return nil, fmt.Errorf("%s has no tier for attempt %d", role, a)
			}
		}
	}
	// QA is never weaker than the dev runner whose work it judges (docs/architecture.md).
	for a := 1; a <= callbackapi.AttemptCap; a++ {
		dev, qa := t.byKey[tierKey{callbackapi.RoleDev, a}], t.byKey[tierKey{callbackapi.RoleQA, a}]
		if qa.Rank < dev.Rank {
			return nil, fmt.Errorf("QA on attempt %d (%s, rank %d) is ranked below the dev tier it judges (%s, rank %d)",
				a, qa.Model, qa.Rank, dev.Model, dev.Rank)
		}
	}
	for p := range providers {
		t.providers = append(t.providers, p)
	}
	sort.Strings(t.providers)
	return t, nil
}

// For returns the tier of a role on an attempt.
func (t *Tiers) For(role callbackapi.Role, attempt int) (Tier, bool) {
	tier, ok := t.byKey[tierKey{role, attempt}]
	return tier, ok
}

// Providers returns every provider the table names, sorted.
func (t *Tiers) Providers() []string { return append([]string(nil), t.providers...) }
