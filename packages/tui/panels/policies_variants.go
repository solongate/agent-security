// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
)

// Split from policies.go: variant switching and the fold/unfold window onto
// the visible variant.

// fold writes the visible half back into the variant it came from, and unfold
// takes the next one out. Every edit between the two happens on p.rules and
// p.sec, which is why a variant switch is the only place either is called.
func (p *Policies) fold() {
	if len(p.variants) == 0 {
		// A draft that was never adopted still has one variant: the rules on
		// screen are it. Creating it here rather than refusing means there is
		// no path through this panel that saves a policy with no variants.
		p.variants = []variantDraft{{id: polVariantID(0), name: "Base"}}
		p.vi = 0
	}
	if p.vi < 0 || p.vi >= len(p.variants) {
		return
	}
	p.variants[p.vi].rules = p.rules
	p.variants[p.vi].sec = p.sec
	p.variants[p.vi].unreadable = p.unreadable
}

func (p *Policies) unfold() {
	if p.vi < 0 || p.vi >= len(p.variants) {
		p.rules, p.sec, p.unreadable = nil, normaliseLayers(client.SecurityLayers{}), 0
		return
	}
	v := p.variants[p.vi]
	p.rules, p.sec, p.unreadable = v.rules, v.sec, v.unreadable
	p.ri = min(p.ri, max(0, len(p.rules)-1))
}

// switchVariant folds the visible half back before taking the next one out. A
// switch that forgot the fold would discard every edit made since the last one.
func (p *Policies) switchVariant(d int) {
	if len(p.variants) < 2 {
		return
	}
	p.fold()
	p.vi = (p.vi + d + len(p.variants)) % len(p.variants)
	p.unfold()
	p.status = ""
}

// addVariant copies the visible one rather than starting empty.
//
// A second variant is almost always "the same policy, with one thing different"
// , a contractor on a whitelist, everybody else on a denylist, and starting
// from nothing means retyping a rule set to change one rule in it.
func (p *Policies) addVariant() {
	if len(p.variants) >= polMaxVariants {
		p.status = "✗ " + itoa(polMaxVariants) + " variants is the limit, a tab strip past that is a list"
		return
	}
	p.fold()
	src := variantDraft{sec: normaliseLayers(p.fallback)}
	if p.vi < len(p.variants) {
		src = p.variants[p.vi]
	}
	next := variantDraft{
		id:   polVariantID(len(p.variants)),
		name: polVariantName(p.variants),
		sec:  normaliseLayers(src.sec),
	}
	// The rules are copied WITHOUT their original bytes: those bytes belong to
	// a rule that is already in the document, and two variants handing the same
	// object to the server is how one edit lands in both.
	for _, d := range src.rules {
		next.rules = append(next.rules, ruleDoc{rule: d.rule, edited: true})
	}
	p.variants = append(p.variants, next)
	p.vi = len(p.variants) - 1
	p.unfold()
	p.mutate()
	p.status = "added " + next.name + ", a copy of what you were looking at"
}

// dropVariant refuses to remove the last one. A policy with no variants is a
// policy with no rules, and that is a thing to notice rather than a thing to do
// with one keystroke.
func (p *Policies) dropVariant() {
	if len(p.variants) < 2 {
		p.status = "✗ a policy needs one variant, this is it"
		return
	}
	name := p.variants[p.vi].name
	p.variants = append(p.variants[:p.vi:p.vi], p.variants[p.vi+1:]...)
	p.vi = max(0, min(p.vi, len(p.variants)-1))
	p.unfold()
	p.mutate()
	p.status = "removed " + name + ", anybody pinned to it falls back to " + p.variants[0].name
}

// polDefaultFirst puts the default variant at index 0.
//
// The editor treats "first" and "default" as the same thing, which is one fewer
// piece of state to keep true and one fewer way for a policy to name a default
// that has been deleted. The dashboard reorders on the way in for the same
// reason, and the two must agree: the top level of a saved document carries the
// first variant's rules, so a terminal that ordered them differently would
// hand every unpinned machine a different variant than the dashboard did.
func polDefaultFirst(list []client.PolicyVariant, defaultID string) []client.PolicyVariant {
	if defaultID == "" || len(list) < 2 {
		return list
	}
	for i, v := range list {
		if v.ID != defaultID || i == 0 {
			continue
		}
		out := append([]client.PolicyVariant{v}, list[:i]...)
		return append(out, list[i+1:]...)
	}
	return list
}

// polVariantID is the id a variant gets when it arrives without one, in the
// dashboard's spelling.
//
// It is generated rather than derived from the name or the position: the name
// is editable, the position is not stable across a removal, and this string is
// what a host's pin on a developer points AT. The index is in it because two
// variants added in the same millisecond would otherwise collide, which is
// exactly what pressing v twice does.
func polVariantID(i int) string {
	return "variant-" + itoa(int(time.Now().UnixMilli())) + "-" + itoa(i+1)
}

// polVariantName is the first free "Variant N", so adding, removing and adding
// again does not produce two tabs with one name. The first is Base rather than
// Default: a reader seeing two tabs called Default and Strict has to work out
// which is which, and Base says what it is.
func polVariantName(existing []variantDraft) string {
	if len(existing) == 0 {
		return "Base"
	}
	taken := map[string]bool{}
	for _, v := range existing {
		taken[strings.ToLower(strings.TrimSpace(v.name))] = true
	}
	for n := len(existing) + 1; n < len(existing)+polMaxVariants+2; n++ {
		name := "Variant " + itoa(n)
		if !taken[strings.ToLower(name)] {
			return name
		}
	}
	return "Variant " + itoa(len(existing)+1)
}

// polMaxVariants is the dashboard's bound, for the same reason: eight is far
// past any policy anyone has written and small enough that the tab strip stays
// a strip.
const polMaxVariants = 8