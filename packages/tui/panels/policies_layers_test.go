// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

func newTestPolicies(t *testing.T) *Policies {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return NewPolicies(tui.Deps{Client: client.New()})
}

func TestLayersOfPrefersVariantSecurity(t *testing.T) {
	p := &Policies{}
	variantSec := client.SecurityLayers{}
	variantSec.DLP.Mode = client.LayerBlock
	setSec := client.SecurityLayers{}
	setSec.DLP.Mode = client.LayerRedact
	p.fallback.DLP.Mode = client.LayerDetect

	got := p.layersOf(client.PolicySet{Security: &setSec}, client.PolicyVariant{Security: &variantSec})
	if got.DLP.Mode != client.LayerBlock {
		t.Errorf("expected variant security to win, got %v", got.DLP.Mode)
	}
}

func TestLayersOfFallsBackToSetSecurity(t *testing.T) {
	p := &Policies{}
	setSec := client.SecurityLayers{}
	setSec.DLP.Mode = client.LayerRedact
	p.fallback.DLP.Mode = client.LayerDetect

	got := p.layersOf(client.PolicySet{Security: &setSec}, client.PolicyVariant{})
	if got.DLP.Mode != client.LayerRedact {
		t.Errorf("expected set security to win over fallback, got %v", got.DLP.Mode)
	}
}

func TestLayersOfFallsBackToPolicyFallback(t *testing.T) {
	p := &Policies{}
	p.fallback.DLP.Mode = client.LayerDetect

	got := p.layersOf(client.PolicySet{}, client.PolicyVariant{})
	if got.DLP.Mode != client.LayerDetect {
		t.Errorf("expected fallback security, got %v", got.DLP.Mode)
	}
}

func TestNormaliseLayersDefaultsAndDeepCopies(t *testing.T) {
	src := client.SecurityLayers{}
	src.DLP.Patterns = []string{"ssn"}
	src.DLP.Custom = []client.CustomPattern{{Name: "x", Re: "y"}}

	out := normaliseLayers(src)
	if out.DLP.Mode != client.LayerOff || out.RateLimit.Mode != client.LayerOff {
		t.Errorf("expected default Off modes, got dlp=%v rate=%v", out.DLP.Mode, out.RateLimit.Mode)
	}

	out.DLP.Patterns[0] = "mutated"
	if src.DLP.Patterns[0] != "ssn" {
		t.Errorf("normaliseLayers should deep-copy Patterns, mutation leaked into source: %v", src.DLP.Patterns)
	}
}

func TestNormaliseLayersPreservesExplicitModes(t *testing.T) {
	src := client.SecurityLayers{}
	src.DLP.Mode = client.LayerBlock
	src.RateLimit.Mode = client.LayerDetect
	out := normaliseLayers(src)
	if out.DLP.Mode != client.LayerBlock || out.RateLimit.Mode != client.LayerDetect {
		t.Errorf("expected explicit modes preserved, got dlp=%v rate=%v", out.DLP.Mode, out.RateLimit.Mode)
	}
}

func TestLayersEqual(t *testing.T) {
	a := client.SecurityLayers{}
	a.DLP.Mode = client.LayerBlock
	a.DLP.Patterns = []string{"ssn"}
	b := a
	b.DLP.Patterns = append([]string(nil), a.DLP.Patterns...)
	if !layersEqual(a, b) {
		t.Errorf("expected equal layers to compare equal")
	}

	c := a
	c.DLP.Patterns = []string{"different"}
	if layersEqual(a, c) {
		t.Errorf("expected differing patterns to compare unequal")
	}

	d := a
	d.RateLimit.PerMinute = 5
	if layersEqual(a, d) {
		t.Errorf("expected differing rate limit to compare unequal")
	}

	e := a
	e.DLP.Custom = []client.CustomPattern{{Name: "n", Re: "r"}}
	if layersEqual(a, e) {
		t.Errorf("expected differing custom pattern length to compare unequal")
	}
}

func TestSameStrings(t *testing.T) {
	if !sameStrings([]string{"a", "b"}, []string{"a", "b"}) {
		t.Errorf("expected equal slices to match")
	}
	if sameStrings([]string{"a"}, []string{"a", "b"}) {
		t.Errorf("expected different lengths to not match")
	}
	if sameStrings([]string{"a", "x"}, []string{"a", "b"}) {
		t.Errorf("expected different contents to not match")
	}
	if !sameStrings(nil, nil) {
		t.Errorf("expected two nils to match")
	}
}

func TestLayerPanelAndStoreLayer(t *testing.T) {
	p := newTestPolicies(t)

	p.view = viewDLP
	if p.layerPanel() != p.dlpPanel {
		t.Errorf("expected layerPanel() to return dlpPanel in viewDLP")
	}
	p.view = viewRate
	if p.layerPanel() != p.ratePanel {
		t.Errorf("expected layerPanel() to return ratePanel in viewRate")
	}
	p.view = viewPolicy
	if p.layerPanel() != nil {
		t.Errorf("expected layerPanel() to return nil outside DLP/Rate views")
	}

	newDLP := NewDLP(tui.Deps{Client: client.New()})
	p.storeLayer(newDLP)
	if p.dlpPanel != newDLP {
		t.Errorf("storeLayer did not replace dlpPanel")
	}
}

func TestChildCtxDerivesFromParentMinusHeader(t *testing.T) {
	p := newTestPolicies(t)
	p.cols, p.rows, p.focused, p.gen = 80, 20, true, 3
	ctx := p.childCtx()
	if ctx.Cols != 80 {
		t.Errorf("Cols=%d, want 80", ctx.Cols)
	}
	if ctx.Rows != 20-polLayerHeader {
		t.Errorf("Rows=%d, want %d", ctx.Rows, 20-polLayerHeader)
	}
	if !ctx.Focused || ctx.Gen != 3 {
		t.Errorf("expected Focused/Gen propagated, got %+v", ctx)
	}
}

func TestChildCtxClampsRowsToOne(t *testing.T) {
	p := newTestPolicies(t)
	p.rows = 1
	if got := p.childCtx().Rows; got != 1 {
		t.Errorf("Rows=%d, want clamped to 1", got)
	}
}

func TestChildCapturingDelegatesToActivePanel(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewRate
	if p.childCapturing() {
		t.Errorf("expected RateLimit.CapturingKeys() to be false")
	}
	p.view = viewPolicy
	if p.childCapturing() {
		t.Errorf("expected no capturing outside DLP/Rate views")
	}
}

func TestLayerWantsLeftDelegatesToActivePanel(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewPolicy
	if p.layerWantsLeft() {
		t.Errorf("expected false outside DLP/Rate views")
	}
}

func TestSyncToLayerAndSyncFromLayerRoundTrip(t *testing.T) {
	p := newTestPolicies(t)
	p.sec = normaliseLayers(client.SecurityLayers{})
	p.sec.DLP.Mode = client.LayerBlock
	p.available = []string{"ssn"}

	p.view = viewDLP
	p.syncToLayer()
	if p.dlpPanel.Bound().DLP.Mode != client.LayerBlock {
		t.Errorf("expected DLP panel bound with mode Block, got %v", p.dlpPanel.Bound().DLP.Mode)
	}

	p.sec.DLP.Mode = client.LayerOff
	p.syncFromLayer()
	if p.sec.DLP.Mode != client.LayerBlock {
		t.Errorf("expected syncFromLayer to pull DLP.Mode back from the bound panel, got %v", p.sec.DLP.Mode)
	}
}

func TestLayerKeyWithNoActivePanelResetsToPolicyView(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewRules
	cmd := p.layerKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")}, "s")
	if cmd != nil {
		t.Errorf("expected nil cmd when there is no active layer panel")
	}
	if p.view != viewPolicy {
		t.Errorf("expected view reset to viewPolicy, got %v", p.view)
	}
}

func TestLayerKeyXDiscardsWithoutDetail(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewDLP
	p.dirty = true
	cmd := p.layerKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")}, "x")
	if cmd != nil {
		t.Errorf("expected nil cmd from discard")
	}
	if p.dirty {
		t.Errorf("expected discard to clear dirty flag")
	}
	if p.status != "discarded" {
		t.Errorf("status=%q, want discarded", p.status)
	}
}

func TestLayerKeyLeftReturnsToPolicyWhenChildDoesNotWantIt(t *testing.T) {
	p := newTestPolicies(t)
	// A freshly constructed, unbound DLP panel has no available patterns, so
	// WantsLeft() is false and "left" should pop back to the policy view
	// instead of being forwarded to the child panel.
	p.view = viewDLP
	cmd := p.layerKey(tea.KeyMsg{Type: tea.KeyLeft}, "left")
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
	if p.view != viewPolicy {
		t.Errorf("expected view to pop back to viewPolicy, got %v", p.view)
	}
}