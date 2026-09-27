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
	got := policyProject([]byte(stored))
	if string(got.Document) != stored {
		t.Errorf("the document was rewritten.\n got %s\nwant %s", got.Document, stored)
	}
	if got.HasLayers {
		t.Error("a policy that says nothing about DLP must leave the project's own setting alone")
	}
}

func TestTheProjectedDocumentCarriesNoBundleKeys(t *testing.T) {
	got := policyProject([]byte(bundleDoc))
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
// A variant's own DLP beats the policy's, and the policy's is what a variant
// with none inherits. Without this the strict variant would be strict about
// rules and identical about secrets.
// A bundle whose variants are unusable must still hand a guard something to
// enforce, and it must be the stored rules rather than nothing.
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
// With no defaultVariant named, the first variant is the mirror. A bundle
// halfway through being written must still enforce something.
