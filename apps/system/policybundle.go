package main

import (
	"encoding/json"

	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// The bundle: a policy that carries its own DLP and rate limit, and more than
// one named variant of the pair.
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
	policyKeyVariants       = "variants"
	policyKeyDefaultVariant = "defaultVariant"
	policyKeySecurity       = "security"
	policyKeyRules          = "rules"
	policyKeyID             = "id"
	policyKeyName           = "name"
)

// policyVariant is one interchangeable setting of a policy.
//
// Rules is kept as the raw decoded array rather than as a typed slice: it is
// about to be written back into a document whose bytes are hashed, and a
// round trip through a Go struct would drop every field this binary does not
// know about. That is the same reason policyjson exists.
type policyVariant struct {
	ID       string
	Name     string
	Rules    any
	Security []byte
}

// policyBundleVariants reads the variants array off a stored document.
//
// An entry that is not an object, or that has no id, is skipped rather than
// defaulted. A variant with no id cannot be pinned to a guest, so it is not a
// variant anyone could have chosen on purpose.
func policyBundleVariants(doc *policyjson.Object) []policyVariant {
	arr, ok := policyjson.Array(doc.Get(policyKeyVariants))
	if !ok {
		return nil
	}
	out := make([]policyVariant, 0, len(arr))
	for _, entry := range arr {
		obj, isObj := entry.(*policyjson.Object)
		if !isObj {
			continue
		}
		id := policyjson.Str(obj.Get(policyKeyID))
		if id == "" {
			continue
		}
		v := policyVariant{
			ID:    id,
			Name:  policyjson.Str(obj.Get(policyKeyName)),
			Rules: obj.Get(policyKeyRules),
		}
		if sec := obj.Get(policyKeySecurity); sec != nil {
			// Re-serialised rather than carried as a value, because the layer
			// coercion in the store reads JSON and is the only thing that knows
			// how to read the eight older spellings of this block.
			v.Security = []byte(policyjson.Stringify(sec, nil))
		}
		out = append(out, v)
	}
	return out
}

// policyPickVariant is which variant a given machine enforces.
//
// The order is the host's choice first and the document's own default second,
// because the pin on a fleet grant is an instruction about one developer and
// the default is what everybody else gets. A pin naming a variant that has been
// deleted falls through to the default rather than to nothing: a variant
// removed from a policy must not silently disarm the machines that were pinned
// to it.
func policyPickVariant(variants []policyVariant, pinned, fallback string) (policyVariant, bool) {
	if len(variants) == 0 {
		return policyVariant{}, false
	}
	for _, want := range []string{pinned, fallback} {
		if want == "" {
			continue
		}
		for _, v := range variants {
			if v.ID == want {
				return v, true
			}
		}
	}
	// First rather than none. A bundle with variants and no usable default is a
	// policy somebody is midway through writing, and the first entry is the one
	// the editor draws first.
	return variants[0], true
}

// policyCarriesBundle reports whether a document about to be written has the
// new keys on it.
//
// It decides which of the two hash spellings the write uses, and that is the
// one genuinely dangerous detail in the bundle. The POST/PUT hash is
// Stringify(body, body.SortedKeys()) — a JavaScript ARRAY REPLACER, which is a
// property allow-list applied at EVERY nesting level rather than a sort. Under
// it a nested object keeps only the members whose names are also top-level
// policy keys, so a variant's security block, whose members are rateLimit, dlp
// and ghost, would vanish from the hash entirely. Two policies differing only
// in a variant's DLP patterns would hash the same, and a guard decides whether
// its cached policy changed by comparing that hash.
//
// So a bundle hashes over its whole serialisation, which is the spelling
// rollback and the rules routes already use. A document with no bundle keys
// hashes exactly as it does today, byte for byte, so nothing already stored
// changes hash when it is saved again unchanged.
func policyCarriesBundle(o *policyjson.Object) bool {
	if o == nil {
		return false
	}
	return o.Has(policyKeyVariants) || o.Has(policyKeySecurity) || o.Has(policyKeyDefaultVariant)
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
// NormalizeRules is applied per variant for the reason it is applied at all: an
// ABSENT `enabled` is read as disabled by the Rego compiler and as enabled by
// the deterministic evaluator, so a rule that has never been through it decides
// differently depending on which engine ran.
func policyNormalizeBundle(o *policyjson.Object) {
	if o == nil || !o.Has(policyKeyVariants) {
		return
	}
	arr, ok := policyjson.Array(o.Get(policyKeyVariants))
	if !ok {
		return
	}
	def := policyjson.Str(o.Get(policyKeyDefaultVariant))
	var first, defaultRules any
	for _, entry := range arr {
		obj, isObj := entry.(*policyjson.Object)
		if !isObj {
			continue
		}
		rules, isArr := policyjson.Array(obj.Get(policyKeyRules))
		if !isArr {
			continue
		}
		normalised := policyjson.NormalizeRules(rules)
		obj.Set(policyKeyRules, normalised)
		if first == nil {
			first = normalised
		}
		if id := policyjson.Str(obj.Get(policyKeyID)); id != "" && id == def {
			defaultRules = normalised
		}
	}
	if defaultRules == nil {
		defaultRules = first
	}
	if defaultRules != nil {
		o.Set(policyKeyRules, defaultRules)
	}
}

// policyProjection is what one poll needs to know about a stored document.
type policyProjection struct {
	// Document is what the guard caches: the stored policy with the chosen
	// variant's rules at the top level and the bundle keys gone. It is the
	// stored bytes unchanged when there is nothing to project.
	Document json.RawMessage
	// VariantID is the variant that was chosen, or empty for a policy that
	// carries none. It goes on the wire in a field new clients can read and
	// old ones ignore.
	VariantID string
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
func policyProject(policyData []byte, pinnedVariant string) policyProjection {
	out := policyProjection{Document: policyData}
	if len(policyData) == 0 {
		return out
	}
	doc, ok := policyjson.ParseObject(policyData)
	if !ok {
		return out
	}
	hasBundle := doc.Has(policyKeyVariants) || doc.Has(policyKeySecurity) || doc.Has(policyKeyDefaultVariant)
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

	variants := policyBundleVariants(doc)
	if chosen, found := policyPickVariant(variants, pinnedVariant, policyjson.Str(doc.Get(policyKeyDefaultVariant))); found {
		out.VariantID = chosen.ID
		if chosen.Rules != nil {
			doc.Set(policyKeyRules, chosen.Rules)
		}
		if layers, hasOwn := store.SecurityLayersFrom(chosen.Security); hasOwn {
			out.Layers, out.HasLayers = layers, true
		}
	}

	// Undef rather than a nil value: policyjson omits an undefined property and
	// writes a nil one as null, and `"variants": null` on the wire is a key an
	// older guard would still cache.
	doc.Set(policyKeyVariants, policyjson.Undef)
	doc.Set(policyKeyDefaultVariant, policyjson.Undef)
	doc.Set(policyKeySecurity, policyjson.Undef)

	out.Document = json.RawMessage(policyjson.Stringify(doc, nil))
	return out
}
