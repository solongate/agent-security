// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

// Split from policies.go: the two bound layer editors (DLP, rate limit) and
// the sync between their drafts and this panel's.

// forwardToLayers hands a message to both bound editors.
//
// Both, rather than the one on screen: each child's messages are its own types,
// so the other one drops it, and the alternative is a child whose ticker stops
// being fed the moment somebody opens the other fold.
func (p *Policies) forwardToLayers(msg tea.Msg) tea.Cmd {
	if _, isKey := msg.(tea.KeyMsg); isKey {
		return nil
	}
	ctx := p.childCtx()
	var cmds []tea.Cmd
	if p.dlpPanel != nil {
		next, cmd := p.dlpPanel.Update(msg, ctx)
		p.storeLayer(next)
		cmds = append(cmds, cmd)
	}
	if p.ratePanel != nil {
		next, cmd := p.ratePanel.Update(msg, ctx)
		p.storeLayer(next)
		cmds = append(cmds, cmd)
	}
	return tea.Batch(cmds...)
}

// layersOf is which block a variant edits: its own, then the policy's, then the
// project-wide row the old sections wrote. The order is the dashboard's.
func (p *Policies) layersOf(set client.PolicySet, v client.PolicyVariant) client.SecurityLayers {
	switch {
	case v.Security != nil:
		return normaliseLayers(*v.Security)
	case set.Security != nil:
		return normaliseLayers(*set.Security)
	default:
		return normaliseLayers(p.fallback)
	}
}

// normaliseLayers fills in the modes a document can be missing and copies the
// slices, so editing a draft cannot reach back into what it was adopted from.
func normaliseLayers(l client.SecurityLayers) client.SecurityLayers {
	out := l
	if out.DLP.Mode == "" {
		out.DLP.Mode = client.LayerOff
	}
	if out.RateLimit.Mode == "" {
		out.RateLimit.Mode = client.LayerOff
	}
	out.DLP.Patterns = append([]string(nil), l.DLP.Patterns...)
	out.DLP.Custom = append([]client.CustomPattern(nil), l.DLP.Custom...)
	return out
}

// layerKey drives the two bound editors next door.
//
// The draft goes in before the key and comes back after, so there is one copy
// of a variant's layers and it is this panel's. Save, discard and back are
// taken first because they belong to the policy; everything else is the
// child's, including the keys that would mean something else here.
func (p *Policies) layerKey(k tea.KeyMsg, s string) tea.Cmd {
	child := p.layerPanel()
	if child == nil {
		p.view = viewPolicy
		return nil
	}
	if !p.childCapturing() {
		switch s {
		case "s":
			p.syncFromLayer()
			return p.save()
		case "x":
			p.discard()
			return nil
		case "left":
			if !p.layerWantsLeft() {
				p.syncFromLayer()
				p.view = viewPolicy
				return nil
			}
		case "esc":
			// esc steps the level back unconditionally. ← cannot: both children
			// spend it on editing (±1 on a rate-limit field, one cell left in the
			// DLP grid), and the rate limit spends it on EVERY field, so a panel
			// with no bursts recorded had no key at all that left it. Every other
			// level here already treats esc this way.
			p.syncFromLayer()
			p.view = viewPolicy
			return nil
		}
	}
	p.syncToLayer()
	before := p.sec
	next, cmd := child.Update(k, p.childCtx())
	p.storeLayer(next)
	p.syncFromLayer()
	if !layersEqual(before, p.sec) {
		p.mutate()
	}
	return cmd
}

// ── the two bound editors ──────────────────────────────────────────────────

func (p *Policies) layerPanel() tui.Panel {
	switch p.view {
	case viewDLP:
		return p.dlpPanel
	case viewRate:
		return p.ratePanel
	}
	return nil
}

// storeLayer puts back whatever Update returned. Both children return
// themselves today; taking the answer rather than assuming it means a child
// that starts replacing itself does not silently stop receiving keys.
func (p *Policies) storeLayer(next tui.Panel) {
	switch v := next.(type) {
	case *DLP:
		p.dlpPanel = v
	case *RateLimit:
		p.ratePanel = v
	}
}

// polLayerHeader is how many lines the policy/variant header takes above a
// bound editor. The child is given the rest, and it clips itself to exactly
// that: a header that grew without this number growing would push the child's
// last line past the frame. See the frame-height rule in the package comment.
const polLayerHeader = 3

// childCtx is the box a bound editor draws in: this panel's, minus the two
// lines of policy/variant header above it.
func (p *Policies) childCtx() tui.PanelContext {
	return tui.PanelContext{
		Deps:    p.deps,
		Cols:    p.cols,
		Rows:    max(1, p.rows-polLayerHeader),
		Focused: p.focused,
		Gen:     p.gen,
	}
}

func (p *Policies) childCapturing() bool {
	switch p.view {
	case viewDLP:
		return p.dlpPanel.CapturingKeys()
	case viewRate:
		return p.ratePanel.CapturingKeys()
	}
	return false
}

func (p *Policies) layerWantsLeft() bool {
	switch p.view {
	case viewRate:
		return p.ratePanel.WantsLeft()
	case viewDLP:
		return p.dlpPanel.WantsLeft()
	}
	return false
}

func (p *Policies) syncToLayer() {
	switch p.view {
	case viewDLP:
		p.dlpPanel.SetBound(p.sec, p.available, p.dirty)
	case viewRate:
		p.ratePanel.SetBound(p.sec, p.dirty)
	}
}

// syncFromLayer takes the child's edit back. Each child owns ONE part of the
// block, so only that part is copied: the DLP editor must not write back a rate
// limit it was handed and never touched.
func (p *Policies) syncFromLayer() {
	switch p.view {
	case viewDLP:
		p.sec.DLP = p.dlpPanel.Bound().DLP
	case viewRate:
		p.sec.RateLimit = p.ratePanel.Bound().RateLimit
	}
}

// layersEqual is what decides a keystroke was an EDIT. Comparing the block
// rather than trusting the child's own dirty flag keeps one definition of
// unsaved on this panel, and means a key that moved a cursor is not a change.
func layersEqual(a, b client.SecurityLayers) bool {
	if a.RateLimit != b.RateLimit || a.DLP.Mode != b.DLP.Mode {
		return false
	}
	if !sameStrings(a.DLP.Patterns, b.DLP.Patterns) {
		return false
	}
	if len(a.DLP.Custom) != len(b.DLP.Custom) {
		return false
	}
	for i := range a.DLP.Custom {
		if a.DLP.Custom[i] != b.DLP.Custom[i] {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}