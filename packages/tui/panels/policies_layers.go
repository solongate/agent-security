// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

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

func (p *Policies) layerPanel() tui.Panel {
	switch p.view {
	case viewDLP:
		return p.dlpPanel
	case viewRate:
		return p.ratePanel
	}
	return nil
}

func (p *Policies) storeLayer(next tui.Panel) {
	switch v := next.(type) {
	case *DLP:
		p.dlpPanel = v
	case *RateLimit:
		p.ratePanel = v
	}
}

const polLayerHeader = 3

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

func (p *Policies) syncFromLayer() {
	switch p.view {
	case viewDLP:
		p.sec.DLP = p.dlpPanel.Bound().DLP
	case viewRate:
		p.sec.RateLimit = p.ratePanel.Bound().RateLimit
	}
}

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