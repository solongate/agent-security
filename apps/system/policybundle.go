package main

import (
	"encoding/json"

	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// The bundle: a policy that carries its own DLP and rate limit.
//
// A policy used to be a rule list, with the DLP and rate-limit configuration
// living beside it as a project-wide setting. That meant switching policies
// changed what was blocked and left what was watched exactly as it was, which
// is not what anyone reading "switch to the strict policy" expects. A policy
// now carries all three, and a host can keep several variations of them under
// one name and hand a different one to each developer.
//
// THE ENTIRE POINT OF THIS FILE is that none of that reaches an installed
// guard. Every machine in the field parses a policy document of exactly one
// shape, and three of its readers take only `$.rules`:
// policycompile.rulesOf, the CLI's PolicySet, and sgshared.Policy. A document
// whose rules live inside a variants array compiles to an EMPTY rule set, which
// for a denylist means nothing is denied and for a whitelist means everything
// is, and nothing anywhere reports it.
//
// So the bundle is stored and then PROJECTED away: policyProject hands back the
// stored document with the chosen variant's rules moved to the top level and
// the three bundle keys removed. What a guard caches is byte-for-byte the shape
// it cached last week.

// The three top-level keys a bundle adds. They are named here rather than
// spelled inline because the projection has to remove exactly the set the
// editor writes, and a key that is written under one spelling and stripped
// under another is a key that reaches a guard.
const (
	policyKeySecurity = "security"
	policyKeyRules    = "rules"
	policyKeyID       = "id"
	policyKeyName     = "name"

	// The two keys a previous version wrote. NOTHING PRODUCES THEM ANY MORE,
	// and they are still named here because a document stored by that version
	// must not reach a guard carrying them: rules that live only inside a
	// variants array compile to an EMPTY rule set, and an empty denylist allows
	// everything while an empty whitelist denies everything. Neither reports an
	// error anywhere. So they are stripped on the way out like the security
	// block, and a document that has them is projected for that reason alone.
	policyKeyLegacyVariants = "variants"
	policyKeyLegacyDefault  = "defaultVariant"
)

// policyCarriesBundle reports whether a document about to be written carries a
// bundle.
//
// It decides which of the two hash spellings the write uses, and that is the
// one genuinely dangerous detail in the bundle. The POST/PUT hash is
// Stringify(body, body.SortedKeys()) — a JavaScript ARRAY REPLACER, which is a
// property allow-list applied at EVERY nesting level rather than a sort. Under
// it a nested object keeps only the members whose names are also top-level
// policy keys, so the security block, whose members are rateLimit, dlp and
// ghost, would vanish from the hash entirely. Two policies differing only in
// their DLP patterns would hash the same, and a guard decides whether its
// cached policy changed by comparing that hash.
//
// So a bundle hashes over its whole serialisation, which is the spelling
// rollback and the rules routes already use. A document with no bundle keys
// hashes exactly as it does today, byte for byte, so nothing already stored
// changes hash when it is saved again unchanged.
func policyCarriesBundle(o *policyjson.Object) bool {
	if o == nil {
		return false
	}
	return o.Has(policyKeySecurity) || o.Has(policyKeyLegacyVariants) || o.Has(policyKeyLegacyDefault)
}

// policyNormalizeBundle normalises every variant's rules and mirrors the
// default variant's onto the top-level `rules`.
//
// The mirror is not a convenience. Three readers in the field take only
// `$.rules` — the Rego compiler, the CLI's PolicySet and sgshared.Policy — and
// a document whose rules live only inside variants gives all three an empty
// rule set with no error anywhere. Keeping the top level equal to the default
// variant means the worst case for anything that has not learned about
// variants is that it enforces the default, which is the right worst case.
//
// policyProjection is what one poll needs to know about a stored document.
type policyProjection struct {
	// Document is what the guard caches: the stored policy with the bundle keys
	// gone. It is the stored bytes unchanged when there is nothing to project.
	Document json.RawMessage
	// Layers is the DLP and rate-limit configuration this policy asks for, and
	// HasLayers reports whether it asked at all. A policy that says nothing
	// leaves the project's own setting in place.
	Layers    store.SecurityLayers
	HasLayers bool
}

// policyProject reduces a stored document to what a guard is allowed to see.
//
// A document with no bundle keys comes back untouched, bytes and all. That is
// not an optimisation: it is the guarantee that this file cannot change what a
// policy written before today means, and it makes the whole path a no-op for
// every project that has not opened the new editor.
func policyProject(policyData []byte) policyProjection {
	out := policyProjection{Document: policyData}
	if len(policyData) == 0 {
		return out
	}
	doc, ok := policyjson.ParseObject(policyData)
	if !ok {
		return out
	}
	hasBundle := doc.Has(policyKeySecurity) || doc.Has(policyKeyLegacyVariants) || doc.Has(policyKeyLegacyDefault)
	if !hasBundle {
		return out
	}

	// The policy's own block first, so a variant that carries none inherits it
	// rather than falling all the way back to the project.
	if sec := doc.Get(policyKeySecurity); sec != nil {
		if layers, found := store.SecurityLayersFrom([]byte(policyjson.Stringify(sec, nil))); found {
			out.Layers, out.HasLayers = layers, true
		}
	}

	// Undef rather than a nil value: policyjson omits an undefined property and
	// writes a nil one as null, and `"security": null` on the wire is a key an
	// older guard would still cache.
	doc.Set(policyKeySecurity, policyjson.Undef)
	doc.Set(policyKeyLegacyVariants, policyjson.Undef)
	doc.Set(policyKeyLegacyDefault, policyjson.Undef)

	out.Document = json.RawMessage(policyjson.Stringify(doc, nil))
	return out
}
