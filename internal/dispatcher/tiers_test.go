package dispatcher_test

import (
	"strings"
	"testing"

	callbackapi "github.com/ryanymt/mercurio-project/internal/callback_api"
	"github.com/ryanymt/mercurio-project/internal/dispatcher"
)

// The tier table (P04 D11; docs/architecture.md, "Model backends"): role and attempt to provider,
// model, tier, rank and credential, refusing to load if QA is ever ranked below the dev tier it
// judges.

const (
	devFlash  = "  - {role: dev, attempt: 1, tier: dev-glm-flash, provider: zai, model: glm-5.3-flash, rank: 1, credential: zai-api-key}\n"
	devSonnet = "  - {role: dev, attempt: 2, tier: dev-sonnet, provider: anthropic, model: claude-sonnet-5, rank: 3, credential: claude-oauth-token}\n"
	qa1       = "  - {role: qa, attempt: 1, tier: qa-opus, provider: anthropic, model: claude-opus-5-5, rank: 4, credential: claude-oauth-token}\n"
	qa2       = "  - {role: qa, attempt: 2, tier: qa-opus, provider: anthropic, model: claude-opus-5-5, rank: 4, credential: claude-oauth-token}\n"
	arch      = "  - {role: architect, attempt: 1, tier: architect-opus, provider: anthropic, model: claude-opus-5-5, rank: 4, credential: claude-oauth-token}\n" +
		"  - {role: architect, attempt: 2, tier: architect-opus, provider: anthropic, model: claude-opus-5-5, rank: 4, credential: claude-oauth-token}\n"
	spec = "  - {role: spec, attempt: 1, tier: spec-opus, provider: anthropic, model: claude-opus-5-5, rank: 4, credential: claude-oauth-token}\n" +
		"  - {role: spec, attempt: 2, tier: spec-opus, provider: anthropic, model: claude-opus-5-5, rank: 4, credential: claude-oauth-token}\n"
	goodTable = "version: 1\ntiers:\n" + spec + arch + devFlash + devSonnet + qa1 + qa2
)

// The embedded table holds the tiers decided with the user (2026-09-26): dev on GLM-5.3 Flash,
// then Claude Sonnet 5; QA, spec and architect on Claude Opus 5.5; the integrator on no model.
func TestEmbeddedTableHoldsTheDecidedTiers(t *testing.T) {
	tiers, err := dispatcher.EmbeddedTiers()
	if err != nil {
		t.Fatal(err)
	}
	want := map[callbackapi.Role][2]struct {
		provider, model string
		rank            int
	}{
		callbackapi.RoleDev:       {{"zai", "glm-5.3-flash", 1}, {"anthropic", "claude-sonnet-5", 3}},
		callbackapi.RoleQA:        {{"anthropic", "claude-opus-5-5", 4}, {"anthropic", "claude-opus-5-5", 4}},
		callbackapi.RoleSpec:      {{"anthropic", "claude-opus-5-5", 4}, {"anthropic", "claude-opus-5-5", 4}},
		callbackapi.RoleArchitect: {{"anthropic", "claude-opus-5-5", 4}, {"anthropic", "claude-opus-5-5", 4}},
	}
	for role, attempts := range want {
		for i, w := range attempts {
			got, ok := tiers.For(role, i+1)
			if !ok || got.Provider != w.provider || got.Model != w.model || got.Rank != w.rank || got.Credential == "" || got.Name == "" {
				t.Errorf("%s attempt %d = %+v (found %v), want %s %s rank %d", role, i+1, got, ok, w.provider, w.model, w.rank)
			}
		}
	}
	if got, ok := tiers.For(callbackapi.RoleIntegrator, 1); ok {
		t.Errorf("the integrator has a tier %+v; it runs no model", got)
	}
	if _, ok := tiers.For(callbackapi.RoleDev, 3); ok {
		t.Error("dev has a third attempt; the cap is 2")
	}
	if got := strings.Join(tiers.Providers(), ","); got != "anthropic,zai" {
		t.Errorf("providers %s, want anthropic,zai", got)
	}
}

func TestTableRefusals(t *testing.T) {
	if _, err := dispatcher.LoadTiers([]byte(goodTable)); err != nil {
		t.Fatalf("control: the good table is refused: %v", err)
	}
	replace := func(old, new string) string {
		if strings.Count(goodTable, old) != 1 {
			t.Fatalf("test anchor %q is not unique", old)
		}
		return strings.Replace(goodTable, old, new, 1)
	}
	cases := map[string]string{
		"QA below dev on the retry": replace(qa2, strings.Replace(qa2, "rank: 4", "rank: 2", 1)),
		"QA below dev on attempt 1": replace(devFlash, strings.Replace(devFlash, "rank: 1", "rank: 5", 1)),
		"a missing attempt":         replace(devSonnet, ""),
		"a third attempt":           replace(devSonnet, devSonnet+strings.Replace(devSonnet, "attempt: 2", "attempt: 3", 1)),
		"an attempt given twice":    replace(qa1, qa1+qa1),
		"a missing role":            replace(arch, ""),
		"the integrator":            goodTable + "  - {role: integrator, attempt: 1, tier: i, provider: anthropic, model: m, rank: 1, credential: c}\n",
		"an unknown role":           goodTable + "  - {role: reviewer, attempt: 1, tier: r, provider: anthropic, model: m, rank: 4, credential: c}\n",
		"an unknown provider":       replace(devFlash, strings.Replace(devFlash, "provider: zai", "provider: deepseek", 1)),
		"an unknown key in a tier":  replace(devFlash, strings.Replace(devFlash, "rank: 1,", "rank: 1, temperature: 0,", 1)),
		"an unknown top-level key":  goodTable + "extra: 1\n",
		"a fractional rank":         replace(devFlash, strings.Replace(devFlash, "rank: 1,", "rank: 1.5,", 1)),
		"a fractional attempt":      replace(devSonnet, strings.Replace(devSonnet, "attempt: 2,", "attempt: 2.0,", 1)),
		"a quoted rank":             replace(devFlash, strings.Replace(devFlash, "rank: 1,", `rank: "1",`, 1)),
		"a rank below one":          replace(devFlash, strings.Replace(devFlash, "rank: 1,", "rank: 0,", 1)),
		"no model":                  replace(devFlash, strings.Replace(devFlash, "model: glm-5.3-flash", `model: ""`, 1)),
		"no credential":             replace(devFlash, strings.Replace(devFlash, "credential: zai-api-key", `credential: ""`, 1)),
		"no tier name":              replace(devFlash, strings.Replace(devFlash, "tier: dev-glm-flash", `tier: ""`, 1)),
		"a duplicate key":           replace(devFlash, strings.Replace(devFlash, "role: dev,", "role: dev, role: qa,", 1)),
		"no version":                strings.TrimPrefix(goodTable, "version: 1\n"),
		"version 2":                 strings.Replace(goodTable, "version: 1", "version: 2", 1),
		"no tiers":                  "version: 1\n",
		"two documents":             goodTable + "---\n" + goodTable,
		"empty":                     "",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := dispatcher.LoadTiers([]byte(doc)); err == nil {
				t.Fatalf("the table loaded:\n%s", doc)
			}
		})
	}
}
