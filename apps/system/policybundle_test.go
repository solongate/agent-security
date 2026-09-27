package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/policyjson"
)

// The bundle is stored and then hidden. These are the tests for the hiding,
// because the failure mode is not an error anywhere: a document that reaches a
// guard with its rules still inside a variants array compiles to an empty rule
// set, and an empty denylist allows everything while an empty whitelist denies
// everything. Nothing reports either.

const bundleDoc = `{"id":"p1","name":"Production","version":3,"mode":"denylist","agents":["*"],` +
	`"rules":[{"id":"mirror","effect":"DENY","toolPattern":"*"}],` +
	`"defaultVariant":"base",` +
	`"variants":[` +
	`{"id":"base","name":"Base","rules":[{"id":"r-base","effect":"DENY","toolPattern":"Bash"}],` +
	`"security":{"dlp":{"mode":"detect","patterns":["JWT"]},"rateLimit":{"mode":"detect","perMinute":90}}},` +
	`{"id":"strict","name":"Strict","rules":[{"id":"r-strict","effect":"DENY","toolPattern":"*"}],` +
	`"security":{"dlp":{"mode":"block","patterns":["JWT"]},"rateLimit":{"mode":"block","perMinute":10}}}` +
	`],` +
	`"security":{"dlp":{"mode":"off","patterns":[]},"rateLimit":{"mode":"off"}}}`

func TestAPolicyWithNoBundleIsHandedBackUntouched(t *testing.T) {
	stored := `{"id":"p1","name":"Old","rules":[{"id":"r1"}],"mode":"denylist","agents":["*"]}`
	got := policyProject([]byte(stored), "")
	if string(got.Document) != stored {
		t.Errorf("the document was rewritten.\n got %s\nwant %s", got.Document, stored)
	}
	if got.HasLayers {
		t.Error("a policy that says nothing about DLP must leave the project's own setting alone")
	}
	if got.VariantID != "" {
		t.Errorf("VariantID = %q for a policy with no variants", got.VariantID)
	}
}

func TestTheProjectedDocumentCarriesNoBundleKeys(t *testing.T) {
	got := policyProject([]byte(bundleDoc), "")
	for _, key := range []string{"variants", "defaultVariant", `"security"`} {
		if strings.Contains(string(got.Document), key) {
			t.Errorf("%s reached the guard:\n%s", key, got.Document)
		}
	}
	// And it is still a policy, with the keys every installed reader takes.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got.Document, &doc); err != nil {
		t.Fatalf("the projection is not JSON: %v", err)
	}
	for _, key := range []string{"id", "name", "version", "rules", "mode", "agents"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("the projection dropped %q, which a guard reads", key)
		}
	}
}

// The rules a guard enforces are the chosen variant's, not the mirror at the
// top of the stored document. This is the substitution the whole file exists
// for.
func TestTheChosenVariantsRulesBecomeTheTopLevelRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pin    string
		wantID string
		rule   string
	}{
		{"no pin takes the default", "", "base", "r-base"},
		{"the host's pin wins", "strict", "strict", "r-strict"},
		{"a deleted pin falls back to the default", "gone", "base", "r-base"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := policyProject([]byte(bundleDoc), tc.pin)
			if got.VariantID != tc.wantID {
				t.Errorf("VariantID = %q, want %q", got.VariantID, tc.wantID)
			}
			if !strings.Contains(string(got.Document), tc.rule) {
				t.Errorf("the document does not carry %s:\n%s", tc.rule, got.Document)
			}
			if strings.Contains(string(got.Document), `"mirror"`) {
				t.Error("the stored top-level rules survived, so the variant did not replace them")
			}
		})
	}
}

// A variant's own DLP beats the policy's, and the policy's is what a variant
// with none inherits. Without this the strict variant would be strict about
// rules and identical about secrets.
func TestTheVariantsSecurityBeatsThePolicys(t *testing.T) {
	base := policyProject([]byte(bundleDoc), "base")
	if !base.HasLayers {
		t.Fatal("the bundle carries a security block and it was not read")
	}
	if base.Layers.DLP.Mode != "detect" || base.Layers.RateLimit.PerMinute != 90 {
		t.Errorf("base layers = %+v, want the variant's detect/90 rather than the policy's off", base.Layers)
	}
	strict := policyProject([]byte(bundleDoc), "strict")
	if strict.Layers.DLP.Mode != "block" || strict.Layers.RateLimit.PerMinute != 10 {
		t.Errorf("strict layers = %+v, want the variant's block/10", strict.Layers)
	}

	// A variant with no block of its own inherits the policy's.
	doc := `{"id":"p","name":"P","rules":[],"defaultVariant":"only",` +
		`"variants":[{"id":"only","name":"Only","rules":[]}],` +
		`"security":{"dlp":{"mode":"block","patterns":["JWT"]}}}`
	inherited := policyProject([]byte(doc), "")
	if !inherited.HasLayers || inherited.Layers.DLP.Mode != "block" {
		t.Errorf("layers = %+v, want the policy's block inherited by the variant", inherited.Layers)
	}
}

// A bundle whose variants are unusable must still hand a guard something to
// enforce, and it must be the stored rules rather than nothing.
func TestAnUnusableVariantsArrayLeavesTheStoredRules(t *testing.T) {
	doc := `{"id":"p","name":"P","rules":[{"id":"kept"}],"variants":[{"name":"no id"},"nonsense"]}`
	got := policyProject([]byte(doc), "")
	if got.VariantID != "" {
		t.Errorf("VariantID = %q, want empty: neither entry is a variant anyone could pin", got.VariantID)
	}
	if !strings.Contains(string(got.Document), `"kept"`) {
		t.Errorf("the stored rules were dropped:\n%s", got.Document)
	}
	if strings.Contains(string(got.Document), "variants") {
		t.Error("the variants key still reached the guard")
	}
}

// The hash spelling. A bundle must not go through the property-list
// projection, because a variant's security members are not top-level policy
// keys and would be filtered out of the hash entirely: two policies differing
// only in a variant's DLP patterns would hash the same, and a guard decides
// whether to reload by comparing that hash.
func TestOnlyABundleChangesTheHashSpelling(t *testing.T) {
	plain, _ := policyjson.ParseObject([]byte(`{"id":"p","name":"P","rules":[]}`))
	if policyCarriesBundle(plain) {
		t.Error("a policy with none of the three keys was read as a bundle, which changes its hash")
	}
	for _, key := range []string{
		`{"id":"p","name":"P","rules":[],"variants":[]}`,
		`{"id":"p","name":"P","rules":[],"security":{}}`,
		`{"id":"p","name":"P","rules":[],"defaultVariant":"v1"}`,
	} {
		o, ok := policyjson.ParseObject([]byte(key))
		if !ok {
			t.Fatalf("could not parse %s", key)
		}
		if !policyCarriesBundle(o) {
			t.Errorf("%s was not read as a bundle", key)
		}
	}
}

// The top-level rules are kept equal to the default variant's, because three
// readers in the field take only $.rules and an empty rule set is silently a
// denylist that denies nothing.
func TestNormalizingABundleMirrorsTheDefaultVariantsRules(t *testing.T) {
	o, ok := policyjson.ParseObject([]byte(`{"id":"p","name":"P","rules":[],"defaultVariant":"two",` +
		`"variants":[{"id":"one","rules":[{"id":"r1","effect":"DENY"}]},` +
		`{"id":"two","rules":[{"id":"r2","effect":"DENY"}]}]}`))
	if !ok {
		t.Fatal("could not parse the bundle")
	}
	policyNormalizeBundle(o)
	mirrored := policyjson.Stringify(o.Get("rules"), nil)
	if !strings.Contains(mirrored, `"r2"`) {
		t.Errorf("top-level rules = %s, want the default variant's r2", mirrored)
	}
	// And every variant has been through NormalizeRules, which writes `enabled`
	// explicitly. Without it the Rego compiler reads an absent enabled as
	// disabled and the deterministic evaluator reads it as enabled.
	whole := policyjson.Stringify(o, nil)
	if strings.Count(whole, `"enabled"`) < 3 {
		t.Errorf("not every rule carries an explicit enabled:\n%s", whole)
	}
}

// With no defaultVariant named, the first variant is the mirror. A bundle
// halfway through being written must still enforce something.
func TestABundleWithNoDefaultMirrorsTheFirstVariant(t *testing.T) {
	o, _ := policyjson.ParseObject([]byte(`{"id":"p","name":"P","rules":[],` +
		`"variants":[{"id":"one","rules":[{"id":"r1","effect":"DENY"}]}]}`))
	policyNormalizeBundle(o)
	if !strings.Contains(policyjson.Stringify(o.Get("rules"), nil), `"r1"`) {
		t.Error("the first variant's rules were not mirrored to the top level")
	}
}
