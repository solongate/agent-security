// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
)

func (p *Policies) fold() {
	if len(p.variants) == 0 {

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

func (p *Policies) switchVariant(d int) {
	if len(p.variants) < 2 {
		return
	}
	p.fold()
	p.vi = (p.vi + d + len(p.variants)) % len(p.variants)
	p.unfold()
	p.status = ""
}

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

	for _, d := range src.rules {
		next.rules = append(next.rules, ruleDoc{rule: d.rule, edited: true})
	}
	p.variants = append(p.variants, next)
	p.vi = len(p.variants) - 1
	p.unfold()
	p.mutate()
	p.status = "added " + next.name + ", a copy of what you were looking at"
}

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

func polVariantID(i int) string {
	return "variant-" + itoa(int(time.Now().UnixMilli())) + "-" + itoa(i+1)
}

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

const polMaxVariants = 8