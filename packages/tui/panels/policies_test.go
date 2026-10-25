// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

func testCtx(p *Policies) tui.PanelContext {
	return tui.PanelContext{Deps: p.deps, Cols: p.cols, Rows: p.rows, Focused: p.focused, Gen: p.gen}
}

func TestFieldsForExcludesPermsExceptForPathAndFilename(t *testing.T) {
	cases := []struct {
		name     string
		rule     client.PolicyRule
		wantPerm bool
		wantLen  int
	}{
		{"none", client.PolicyRule{}, false, len(polFields) - 1},
		{"command", client.PolicyRule{CommandConstraints: &client.Constraint{}}, false, len(polFields) - 1},
		{"url", client.PolicyRule{URLConstraints: &client.Constraint{}}, false, len(polFields) - 1},
		{"path", client.PolicyRule{PathConstraints: &client.PathConstraint{}}, true, len(polFields)},
		{"filename", client.PolicyRule{FilenameConstraints: &client.Constraint{}}, true, len(polFields)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fieldsFor(tc.rule)
			if len(got) != tc.wantLen {
				t.Fatalf("fieldsFor() len=%d, want %d (%v)", len(got), tc.wantLen, got)
			}
			hasPerm := false
			for _, f := range got {
				if f.kind == "perms" {
					hasPerm = true
				}
			}
			if hasPerm != tc.wantPerm {
				t.Errorf("fieldsFor() hasPerm=%v, want %v", hasPerm, tc.wantPerm)
			}
		})
	}
}

func TestNewPoliciesDefaults(t *testing.T) {
	p := newTestPolicies(t)
	if !p.listLoading || !p.activeLoad {
		t.Errorf("expected listLoading and activeLoad to start true")
	}
	if p.mode != client.ModeDenylist {
		t.Errorf("mode=%v, want ModeDenylist", p.mode)
	}
	if p.dlpPanel == nil || p.ratePanel == nil {
		t.Errorf("expected dlpPanel and ratePanel constructed")
	}
	if p.cols != 60 || p.rows != 12 {
		t.Errorf("cols/rows=%d/%d, want 60/12", p.cols, p.rows)
	}
}

func TestPoliciesCapturingKeys(t *testing.T) {
	p := newTestPolicies(t)

	p.creating = true
	if !p.CapturingKeys() {
		t.Errorf("expected CapturingKeys() true while creating")
	}
	p.creating = false

	p.editing = true
	if !p.CapturingKeys() {
		t.Errorf("expected CapturingKeys() true while editing")
	}
	p.editing = false

	p.view = viewPolicy
	if p.CapturingKeys() {
		t.Errorf("expected CapturingKeys() false in viewPolicy")
	}

	p.view = viewDLP
	if p.CapturingKeys() {
		t.Errorf("expected CapturingKeys() false for a fresh DLP panel")
	}

	p.view = viewRate
	if p.CapturingKeys() {
		t.Errorf("expected CapturingKeys() false for the RateLimit panel")
	}
}

func TestPoliciesSelected(t *testing.T) {
	p := &Policies{}
	if _, ok := p.selected(); ok {
		t.Errorf("expected ok=false for an empty policy list")
	}

	p.policies = []client.PolicyListEntry{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	p.pi = 1
	sel, ok := p.selected()
	if !ok || sel.ID != "b" {
		t.Errorf("selected()=%+v ok=%v, want id b", sel, ok)
	}

	p.pi = 99
	sel, ok = p.selected()
	if !ok || sel.ID != "c" {
		t.Errorf("expected pi clamped to last entry, got %+v ok=%v", sel, ok)
	}
}

func TestEnsureDetailNoSelection(t *testing.T) {
	p := newTestPolicies(t)
	if cmd := p.ensureDetail(); cmd != nil {
		t.Errorf("expected nil cmd with no policies")
	}
}

func TestEnsureDetailSkipsWhenAlreadyLoaded(t *testing.T) {
	p := newTestPolicies(t)
	p.policies = []client.PolicyListEntry{{ID: "local"}}
	p.detailID = "local"
	if cmd := p.ensureDetail(); cmd != nil {
		t.Errorf("expected nil cmd when detail already matches selection")
	}
}

func TestEnsureDetailFetchesNewSelection(t *testing.T) {
	p := newTestPolicies(t)
	p.policies = []client.PolicyListEntry{{ID: "local"}}
	p.haveDetail = true
	cmd := p.ensureDetail()
	if cmd == nil {
		t.Fatalf("expected non-nil cmd for a new selection")
	}
	if p.detailID != "local" || !p.detailLoading || p.haveDetail {
		t.Errorf("expected detail state reset, got detailID=%q loading=%v haveDetail=%v", p.detailID, p.detailLoading, p.haveDetail)
	}
	msg := cmd()
	dm, ok := msg.(polDetailMsg)
	if !ok {
		t.Fatalf("expected polDetailMsg, got %T", msg)
	}
	// No policy exists on this machine yet, so the fetch should fail with
	// resolveID's "no policy" error rather than silently succeeding.
	if dm.err == nil {
		t.Errorf("expected an error fetching a nonexistent policy")
	}
}

func TestLoadListEmptyStore(t *testing.T) {
	p := newTestPolicies(t)
	msg := p.loadList()()
	lm, ok := msg.(polListMsg)
	if !ok {
		t.Fatalf("expected polListMsg, got %T", msg)
	}
	if lm.err != nil {
		t.Errorf("unexpected error: %v", lm.err)
	}
	if len(lm.data) != 0 {
		t.Errorf("expected empty policy list, got %v", lm.data)
	}
}

func TestLoadListAfterCreate(t *testing.T) {
	p := newTestPolicies(t)
	if _, err := p.deps.Client.Policies.Create(bg(), client.PolicySet{Name: "mine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	msg := p.loadList()()
	lm := msg.(polListMsg)
	if lm.err != nil || len(lm.data) != 1 || lm.data[0].Name != "mine" {
		t.Errorf("loadList()=%+v", lm)
	}
}

func TestUpdatePolListMsgError(t *testing.T) {
	p := newTestPolicies(t)
	p.listLoading = true
	p.policies = []client.PolicyListEntry{{ID: "keep"}}
	_, cmd := p.Update(polListMsg{genTag: p.tag(), err: errTest("boom")}, testCtx(p))
	if p.listLoading {
		t.Errorf("expected listLoading cleared")
	}
	if p.listErr == nil {
		t.Errorf("expected listErr set")
	}
	if len(p.policies) != 1 {
		t.Errorf("expected policies left untouched on error, got %v", p.policies)
	}
	if cmd != nil {
		t.Errorf("expected nil cmd on error")
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

func TestUpdatePolListMsgSuccessResetsBusyCreate(t *testing.T) {
	p := newTestPolicies(t)
	p.busyCreate = true
	data := []client.PolicyListEntry{{ID: "local", Name: "mine"}}
	_, cmd := p.Update(polListMsg{genTag: p.tag(), data: data}, testCtx(p))
	if p.busyCreate {
		t.Errorf("expected busyCreate cleared once policies are non-empty")
	}
	if len(p.policies) != 1 {
		t.Errorf("expected policies set, got %v", p.policies)
	}
	if cmd == nil {
		t.Errorf("expected ensureDetail() to return a cmd for the new selection")
	}
}

func TestUpdatePolActiveMsg(t *testing.T) {
	p := newTestPolicies(t)
	p.activeLoad = true
	set := client.PolicySet{ID: "p1"}
	_, _ = p.Update(polActiveMsg{genTag: p.tag(), data: client.ActivePolicy{Policy: &set, MatchedBy: "pinned"}}, testCtx(p))
	if p.activeLoad {
		t.Errorf("expected activeLoad cleared")
	}
	if p.activeID != "p1" || p.activeBy != "pinned" {
		t.Errorf("activeID=%q activeBy=%q", p.activeID, p.activeBy)
	}

	_, _ = p.Update(polActiveMsg{genTag: p.tag(), data: client.ActivePolicy{Policy: nil}}, testCtx(p))
	if p.activeID != "" {
		t.Errorf("expected activeID cleared when Policy is nil, got %q", p.activeID)
	}
}

func TestUpdatePolDetailMsgIgnoresStaleID(t *testing.T) {
	p := newTestPolicies(t)
	p.detailID = "current"
	_, cmd := p.Update(polDetailMsg{genTag: p.tag(), id: "stale", data: client.PolicyDetail{}}, testCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd for a stale detail message")
	}
	if p.haveDetail {
		t.Errorf("expected haveDetail to remain false for a stale message")
	}
}

func TestUpdatePolDetailMsgSuccess(t *testing.T) {
	p := newTestPolicies(t)
	p.detailID = "local"
	p.ri = 7
	detail := client.PolicyDetail{PolicySet: client.PolicySet{ID: "local", Name: "mine", Mode: client.ModeWhitelist}}
	_, cmd := p.Update(polDetailMsg{genTag: p.tag(), id: "local", data: detail}, testCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
	if !p.haveDetail {
		t.Errorf("expected haveDetail true")
	}
	if p.dirty {
		t.Errorf("expected dirty cleared")
	}
	if p.ri != 0 {
		t.Errorf("expected ri reset to 0, got %d", p.ri)
	}
	if p.mode != client.ModeWhitelist {
		t.Errorf("expected adoptPolicy to apply mode, got %v", p.mode)
	}
}

func TestUpdatePolLayersMsg(t *testing.T) {
	p := newTestPolicies(t)
	layers := client.SecurityLayersResponse{AvailablePatterns: []string{"ssn", "email"}}
	layers.Layers.DLP.Mode = client.LayerDetect
	_, cmd := p.Update(polLayersMsg{genTag: p.tag(), data: layers}, testCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
	if !p.layersLoaded {
		t.Errorf("expected layersLoaded true")
	}
	if len(p.available) != 2 {
		t.Errorf("expected available patterns copied, got %v", p.available)
	}
	if p.fallback.DLP.Mode != client.LayerDetect {
		t.Errorf("expected fallback stored, got %v", p.fallback.DLP.Mode)
	}
}

func TestUpdatePolSavedMsgError(t *testing.T) {
	p := newTestPolicies(t)
	_, cmd := p.Update(polSavedMsg{genTag: p.tag(), err: errTest("nope")}, testCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd on save error")
	}
	if !strings.HasPrefix(p.status, "✗") {
		t.Errorf("status=%q, want an error status", p.status)
	}
}

func TestUpdatePolSavedMsgSuccess(t *testing.T) {
	p := newTestPolicies(t)
	p.dirty = true
	p.detailID = "local"
	_, cmd := p.Update(polSavedMsg{genTag: p.tag()}, testCtx(p))
	if p.dirty {
		t.Errorf("expected dirty cleared")
	}
	if p.status != "✓ Saved" {
		t.Errorf("status=%q, want success message", p.status)
	}
	if cmd == nil {
		t.Errorf("expected a reload batch cmd")
	}
}

func TestUpdatePolActionMsg(t *testing.T) {
	p := newTestPolicies(t)
	p.pi = 3
	p.detailID = "local"
	_, cmd := p.Update(polActionMsg{
		genTag: p.tag(), status: "✓ deleted", refreshList: true, refreshActive: true, resetCursor: true,
	}, testCtx(p))
	if p.status != "✓ deleted" {
		t.Errorf("status=%q", p.status)
	}
	if p.pi != 0 || p.detailID != "" {
		t.Errorf("expected cursor reset, got pi=%d detailID=%q", p.pi, p.detailID)
	}
	if cmd == nil {
		t.Errorf("expected refresh cmds")
	}
}

func TestUpdatePolTickMsgIgnoresStaleToken(t *testing.T) {
	p := newTestPolicies(t)
	_, cmd := p.Update(polTickMsg{genTag: genTag{gen: p.gen, tok: p.tok + 1000}}, testCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd for a stale token")
	}
}

func TestUpdatePolTickMsgRefreshesWhenIdle(t *testing.T) {
	p := newTestPolicies(t)
	_, cmd := p.Update(polTickMsg{genTag: p.tag()}, testCtx(p))
	if cmd == nil {
		t.Fatalf("expected a batched refresh cmd")
	}
	bm, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatalf("expected tea.BatchMsg, got %T", cmd())
	}
	if len(bm) != 3 {
		t.Errorf("expected 3 batched commands (tick, loadList, loadActive), got %d", len(bm))
	}
}

func TestUpdatePolTickMsgSkipsRefreshWhileEditing(t *testing.T) {
	p := newTestPolicies(t)
	p.editing = true
	_, cmd := p.Update(polTickMsg{genTag: p.tag()}, testCtx(p))
	if cmd == nil {
		t.Fatalf("expected the tick to still reschedule itself")
	}
	// When editing, only the self-rescheduling tea.Tick command is returned
	// (not wrapped in a batch), so it must never be invoked here: calling it
	// would block on the real 3-second timer. The nil-check above is as far
	// as this test can safely go.
}

func TestUpdateKeyMsgDispatch(t *testing.T) {
	p := newTestPolicies(t)
	p.focused = false
	if _, cmd := p.Update(tea.KeyMsg{Type: tea.KeyUp}, testCtx(p)); cmd != nil {
		t.Errorf("expected nil cmd when unfocused")
	}

	p.focused = true
	p.creating = true
	p.input.SetValue("x")
	if _, cmd := p.Update(tea.KeyMsg{Type: tea.KeyEsc}, testCtx(p)); cmd != nil || p.creating {
		t.Errorf("expected esc to cancel creating, cmd=%v creating=%v", cmd, p.creating)
	}

	p.editing = true
	if _, cmd := p.Update(tea.KeyMsg{Type: tea.KeyEsc}, testCtx(p)); cmd != nil || p.editing {
		t.Errorf("expected esc to cancel editing, cmd=%v editing=%v", cmd, p.editing)
	}

	p.view = viewList
	p.policies = []client.PolicyListEntry{{ID: "a"}, {ID: "b"}}
	p.pi = 0
	if _, _ = p.Update(tea.KeyMsg{Type: tea.KeyDown}, testCtx(p)); p.pi != 1 {
		t.Errorf("expected plain key() dispatch to move pi down, got %d", p.pi)
	}
}

func TestUpdateUnrecognisedMsgForwardsToLayers(t *testing.T) {
	p := newTestPolicies(t)
	// Should not panic, and should leave the child panels in place.
	_, _ = p.Update(tea.WindowSizeMsg{Width: 80, Height: 24}, testCtx(p))
	if p.dlpPanel == nil || p.ratePanel == nil {
		t.Errorf("expected panels to remain set after forwarding an unrelated msg")
	}
}

func TestMutateSetsDirtyAndClearsStatus(t *testing.T) {
	p := &Policies{status: "old"}
	p.mutate()
	if !p.dirty || p.status != "" {
		t.Errorf("mutate() dirty=%v status=%q", p.dirty, p.status)
	}
}

func TestAdoptRules(t *testing.T) {
	raws := []client.PolicyRule{{ID: "r1"}, {ID: "r2"}}
	rawJSON := []json.RawMessage{json.RawMessage(`{"id":"r1"}`), json.RawMessage(`{"id":"r2"}`)}
	out := adoptRules(client.Rules{Items: raws, Raw: rawJSON})
	if len(out) != 2 {
		t.Fatalf("adoptRules len=%d, want 2", len(out))
	}
	if out[0].rule.ID != "r1" || out[1].rule.ID != "r2" {
		t.Errorf("adoptRules did not preserve rule content: %+v", out)
	}
	if string(out[0].raw) != `{"id":"r1"}` {
		t.Errorf("adoptRules did not preserve raw JSON: %q", out[0].raw)
	}
}

func TestAdoptRulesSkipsRawWhenUnreadable(t *testing.T) {
	out := adoptRules(client.Rules{Items: []client.PolicyRule{{ID: "r1"}}, Unreadable: 1})
	if len(out) != 1 || out[0].raw != nil {
		t.Errorf("expected raw left nil when Unreadable>0, got %+v", out)
	}
}

func TestAdoptPolicySetsModeAndVariants(t *testing.T) {
	p := newTestPolicies(t)
	set := client.PolicySet{
		ID:   "local",
		Name: "mine",
		Mode: client.ModeWhitelist,
		Variants: []client.PolicyVariant{
			{ID: "v1", Name: "First", Rules: client.Rules{Items: []client.PolicyRule{{ID: "r1"}}}},
		},
		DefaultVariant: "v1",
	}
	p.adoptPolicy(set)
	if p.mode != client.ModeWhitelist {
		t.Errorf("mode=%v", p.mode)
	}
	if len(p.variants) != 1 || p.variants[0].name != "First" {
		t.Errorf("variants=%+v", p.variants)
	}
	if len(p.rules) != 1 {
		t.Errorf("expected unfold to populate rules, got %v", p.rules)
	}
}

func TestAdoptPolicyDefaultsEmptyMode(t *testing.T) {
	p := newTestPolicies(t)
	p.adoptPolicy(client.PolicySet{ID: "local"})
	if p.mode != client.ModeDenylist {
		t.Errorf("mode=%v, want default ModeDenylist", p.mode)
	}
}