// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/core/client"
)

func TestFoldCreatesBaseVariantWhenNoneExist(t *testing.T) {
	p := &Policies{
		rules:      []ruleDoc{{rule: client.PolicyRule{ID: "r1"}}},
		sec:        normaliseLayers(client.SecurityLayers{}),
		unreadable: 2,
	}
	p.fold()
	if len(p.variants) != 1 {
		t.Fatalf("expected one Base variant, got %d", len(p.variants))
	}
	if p.variants[0].name != "Base" {
		t.Errorf("name=%q, want Base", p.variants[0].name)
	}
	if len(p.variants[0].rules) != 1 || p.variants[0].unreadable != 2 {
		t.Errorf("fold did not fold current rules/unreadable into the new Base variant: %+v", p.variants[0])
	}
	if p.vi != 0 {
		t.Errorf("vi=%d, want 0", p.vi)
	}
}

func TestFoldStoresCurrentStateIntoSelectedVariant(t *testing.T) {
	p := &Policies{
		variants: []variantDraft{{id: "v0", name: "Base"}, {id: "v1", name: "Variant 2"}},
		vi:       1,
		rules:    []ruleDoc{{rule: client.PolicyRule{ID: "r1"}}, {rule: client.PolicyRule{ID: "r2"}}},
	}
	p.fold()
	if len(p.variants[1].rules) != 2 {
		t.Errorf("expected current rules folded into variant 1, got %+v", p.variants[1])
	}
	if len(p.variants[0].rules) != 0 {
		t.Errorf("expected variant 0 to remain untouched, got %+v", p.variants[0])
	}
}

func TestFoldIsNoOpWhenIndexOutOfRange(t *testing.T) {
	p := &Policies{
		variants: []variantDraft{{id: "v0", name: "Base"}},
		vi:       5,
		rules:    []ruleDoc{{rule: client.PolicyRule{ID: "r1"}}},
	}
	p.fold()
	if len(p.variants[0].rules) != 0 {
		t.Errorf("expected fold to skip out-of-range vi, got %+v", p.variants[0])
	}
}

func TestUnfoldOutOfRangeResetsToEmpty(t *testing.T) {
	p := &Policies{vi: 3}
	p.unfold()
	if p.rules != nil {
		t.Errorf("expected nil rules, got %v", p.rules)
	}
	if p.unreadable != 0 {
		t.Errorf("expected unreadable reset to 0, got %d", p.unreadable)
	}
	if p.sec.DLP.Mode != client.LayerOff || p.sec.RateLimit.Mode != client.LayerOff {
		t.Errorf("expected normalised empty layers, got %+v", p.sec)
	}
}

func TestUnfoldAdoptsSelectedVariant(t *testing.T) {
	p := &Policies{
		variants: []variantDraft{{
			id: "v0", name: "Base",
			rules:      []ruleDoc{{rule: client.PolicyRule{ID: "r1"}}},
			unreadable: 1,
		}},
		vi: 0,
		ri: 50,
	}
	p.unfold()
	if len(p.rules) != 1 || p.unreadable != 1 {
		t.Errorf("unfold did not adopt variant state: rules=%v unreadable=%d", p.rules, p.unreadable)
	}
	if p.ri != 0 {
		t.Errorf("expected ri clamped to 0 for a single rule, got %d", p.ri)
	}
}

func TestSwitchVariantNoOpWithFewerThanTwo(t *testing.T) {
	p := &Policies{variants: []variantDraft{{id: "v0", name: "Base"}}, vi: 0, status: "kept"}
	p.switchVariant(1)
	if p.vi != 0 || p.status != "kept" {
		t.Errorf("expected no-op switch, got vi=%d status=%q", p.vi, p.status)
	}
}

func TestSwitchVariantWrapsAround(t *testing.T) {
	p := &Policies{
		variants: []variantDraft{{id: "v0", name: "Base"}, {id: "v1", name: "Variant 2"}},
		vi:       0,
		status:   "stale",
	}
	p.switchVariant(-1)
	if p.vi != 1 {
		t.Errorf("expected wraparound to index 1, got %d", p.vi)
	}
	if p.status != "" {
		t.Errorf("expected status cleared, got %q", p.status)
	}
}

func TestAddVariantCopiesCurrentAsDraft(t *testing.T) {
	p := &Policies{
		variants: []variantDraft{{
			id: "v0", name: "Base",
			rules: []ruleDoc{{rule: client.PolicyRule{ID: "r1"}, edited: false}},
			sec:   normaliseLayers(client.SecurityLayers{}),
		}},
		vi: 0,
	}
	p.unfold()
	p.addVariant()
	if len(p.variants) != 2 {
		t.Fatalf("expected 2 variants after add, got %d", len(p.variants))
	}
	if p.vi != 1 {
		t.Errorf("expected vi moved to new variant, got %d", p.vi)
	}
	newVariant := p.variants[1]
	if len(newVariant.rules) != 1 || !newVariant.rules[0].edited {
		t.Errorf("expected copied rule marked edited, got %+v", newVariant.rules)
	}
	if !p.dirty {
		t.Errorf("expected addVariant to mark policy dirty")
	}
	if !strings.Contains(p.status, newVariant.name) {
		t.Errorf("expected status to mention new variant name %q, got %q", newVariant.name, p.status)
	}
}

func TestAddVariantRejectsPastLimit(t *testing.T) {
	variants := make([]variantDraft, polMaxVariants)
	for i := range variants {
		variants[i] = variantDraft{id: polVariantID(i), name: polVariantName(variants[:i])}
	}
	p := &Policies{variants: variants, vi: 0}
	before := len(p.variants)
	p.addVariant()
	if len(p.variants) != before {
		t.Errorf("expected addVariant to refuse past the limit, got %d variants", len(p.variants))
	}
	if !strings.HasPrefix(p.status, "✗") {
		t.Errorf("expected an error status, got %q", p.status)
	}
}

func TestDropVariantRejectsLastOne(t *testing.T) {
	p := &Policies{variants: []variantDraft{{id: "v0", name: "Base"}}, vi: 0}
	p.dropVariant()
	if len(p.variants) != 1 {
		t.Errorf("expected drop to be refused, got %d variants", len(p.variants))
	}
	if !strings.HasPrefix(p.status, "✗") {
		t.Errorf("expected an error status, got %q", p.status)
	}
}

func TestDropVariantRemovesSelectedAndFallsBack(t *testing.T) {
	p := &Policies{
		variants: []variantDraft{{id: "v0", name: "Base"}, {id: "v1", name: "Variant 2"}},
		vi:       1,
	}
	p.dropVariant()
	if len(p.variants) != 1 {
		t.Fatalf("expected one variant remaining, got %d", len(p.variants))
	}
	if p.vi != 0 {
		t.Errorf("expected vi clamped to 0, got %d", p.vi)
	}
	if !p.dirty {
		t.Errorf("expected dropVariant to mark policy dirty")
	}
	if !strings.Contains(p.status, "Base") {
		t.Errorf("expected status to mention the fallback variant, got %q", p.status)
	}
}

func TestPolDefaultFirst(t *testing.T) {
	list := []client.PolicyVariant{{ID: "a"}, {ID: "b"}, {ID: "c"}}

	if got := polDefaultFirst(list, ""); len(got) != 3 || got[0].ID != "a" {
		t.Errorf("empty defaultID should return list unchanged, got %v", got)
	}
	if got := polDefaultFirst(list[:1], "a"); len(got) != 1 {
		t.Errorf("single-element list should return unchanged, got %v", got)
	}
	if got := polDefaultFirst(list, "a"); got[0].ID != "a" || len(got) != 3 {
		t.Errorf("default already first should stay unchanged, got %v", got)
	}
	if got := polDefaultFirst(list, "missing"); len(got) != 3 || got[0].ID != "a" {
		t.Errorf("unknown defaultID should return list unchanged, got %v", got)
	}

	got := polDefaultFirst(list, "c")
	want := []string{"c", "a", "b"}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("polDefaultFirst reorder[%d]=%q, want %q (full=%v)", i, got[i].ID, id, got)
		}
	}
}

func TestPolVariantID(t *testing.T) {
	id := polVariantID(2)
	if !strings.HasPrefix(id, "variant-") {
		t.Errorf("polVariantID=%q, want variant- prefix", id)
	}
	if !strings.HasSuffix(id, "-3") {
		t.Errorf("polVariantID(2)=%q, want suffix -3 (1-based index)", id)
	}
}

func TestPolVariantNameEmptyIsBase(t *testing.T) {
	if got := polVariantName(nil); got != "Base" {
		t.Errorf("polVariantName(nil)=%q, want Base", got)
	}
}

func TestPolVariantNameSkipsTakenNames(t *testing.T) {
	existing := []variantDraft{{name: "Base"}, {name: "variant 2"}}
	got := polVariantName(existing)
	if got != "Variant 3" {
		t.Errorf("polVariantName()=%q, want %q", got, "Variant 3")
	}
}