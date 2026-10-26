// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

func krune(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func TestKeyCtrlRTriggersRefreshBatch(t *testing.T) {
	p := newTestPolicies(t)
	cmd := p.key(krune("ctrl+r"))
	if cmd == nil {
		t.Fatalf("expected a non-nil refresh cmd")
	}
	if !strings.HasPrefix(p.status, "⟳ refreshed") {
		t.Errorf("status=%q", p.status)
	}
	msg := cmd()
	if _, ok := msg.(tea.BatchMsg); !ok {
		t.Errorf("expected tea.BatchMsg (loadList+loadActive), got %T", msg)
	}
}

func TestKeyDispatchesByView(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewList
	p.policies = []client.PolicyListEntry{{ID: "a"}, {ID: "b"}}
	p.key(krune("down"))
	if p.pi != 1 {
		t.Errorf("expected listKey dispatch to move pi, got %d", p.pi)
	}

	p.view = viewPolicy
	p.key(krune("m"))
	if p.mode != client.ModeWhitelist {
		t.Errorf("expected policyKey dispatch to flip mode, got %v", p.mode)
	}

	p.view = viewRules
	p.rules = []ruleDoc{{rule: client.PolicyRule{Effect: "DENY"}}}
	p.key(krune("e"))
	if p.rules[0].rule.Effect != "ALLOW" {
		t.Errorf("expected rulesKey dispatch to flip effect, got %v", p.rules[0].rule.Effect)
	}

	p.view = viewMatch
	p.ri = 0
	p.key(krune("left"))
	if p.view != viewRule {
		t.Errorf("expected matchKey dispatch for left, got view=%v", p.view)
	}
}

func TestPolicyKeyNavigationAndActions(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewPolicy

	if cmd := p.policyKey("left"); cmd != nil || p.view != viewList {
		t.Errorf("left should return to viewList, got view=%v cmd=%v", p.view, cmd)
	}

	p.view = viewPolicy
	p.li = layerDLP
	p.policyKey("up")
	if p.li != layerRules {
		t.Errorf("expected li to move up to layerRules, got %d", p.li)
	}
	p.policyKey("down")
	if p.li != layerDLP {
		t.Errorf("expected li to move back down, got %d", p.li)
	}

	p.li = layerRules
	p.policyKey("enter")
	if p.view != viewRules {
		t.Errorf("expected entering layerRules to switch to viewRules, got %v", p.view)
	}

	p.view = viewPolicy
	p.li = layerRate
	if p.rateStarted {
		t.Fatalf("expected rateStarted initially false")
	}
	cmd := p.policyKey("enter")
	if !p.rateStarted {
		t.Errorf("expected rateStarted set true")
	}
	if cmd == nil {
		t.Errorf("expected ratePanel.Init() cmd on first entry to viewRate")
	}
	if p.view != viewRate {
		t.Errorf("expected view=viewRate, got %v", p.view)
	}

	// Second entry should not re-trigger Init().
	p.view = viewPolicy
	cmd = p.policyKey("enter")
	if cmd != nil {
		t.Errorf("expected nil cmd on subsequent entry to viewRate")
	}
}

func TestPolicyKeyVariantAndSaveDiscard(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewPolicy
	p.variants = []variantDraft{{id: "v0", name: "Base"}, {id: "v1", name: "Variant 2"}}
	p.vi = 0
	p.policyKey("tab")
	if p.vi != 1 {
		t.Errorf("expected tab to advance variant, got vi=%d", p.vi)
	}
	p.policyKey("shift+tab")
	if p.vi != 0 {
		t.Errorf("expected shift+tab to go back, got vi=%d", p.vi)
	}

	p.policyKey("v")
	if len(p.variants) != 3 {
		t.Errorf("expected addVariant dispatch, got %d variants", len(p.variants))
	}
	p.policyKey("V")
	if len(p.variants) != 2 {
		t.Errorf("expected dropVariant dispatch, got %d variants", len(p.variants))
	}

	p.haveDetail = false
	if cmd := p.policyKey("s"); cmd != nil {
		t.Errorf("expected save() to refuse without haveDetail")
	}

	p.dirty = true
	p.policyKey("x")
	if p.dirty {
		t.Errorf("expected discard dispatch to clear dirty")
	}
}

func TestFlipMode(t *testing.T) {
	p := &Policies{mode: client.ModeDenylist}
	p.flipMode()
	if p.mode != client.ModeWhitelist {
		t.Errorf("expected flip to whitelist, got %v", p.mode)
	}
	if !p.dirty {
		t.Errorf("expected flipMode to mark dirty")
	}
	p.flipMode()
	if p.mode != client.ModeDenylist {
		t.Errorf("expected flip back to denylist, got %v", p.mode)
	}
}

func TestListKeyNavigationClampsAndLoadsDetail(t *testing.T) {
	p := newTestPolicies(t)
	p.policies = []client.PolicyListEntry{{ID: "a"}, {ID: "b"}}
	p.pi = 1
	p.pendingDel = "stale"
	cmd := p.listKey("up")
	if p.pi != 0 {
		t.Errorf("expected pi to move up to 0, got %d", p.pi)
	}
	if p.pendingDel != "" {
		t.Errorf("expected pendingDel reset on navigation")
	}
	if cmd == nil {
		t.Errorf("expected ensureDetail() cmd from up/down navigation")
	}

	cmd = p.listKey("down")
	if p.pi != 1 {
		t.Errorf("expected pi to move down to 1, got %d", p.pi)
	}
	_ = cmd

	// down beyond bounds should clamp.
	p.listKey("down")
	if p.pi != 1 {
		t.Errorf("expected pi clamped at last index, got %d", p.pi)
	}
}

func TestListKeyEnterEntersPolicyView(t *testing.T) {
	p := newTestPolicies(t)
	p.policies = []client.PolicyListEntry{{ID: "a"}}
	p.status = "stale"
	cmd := p.listKey("enter")
	if cmd != nil {
		t.Errorf("expected nil cmd from enter")
	}
	if p.view != viewPolicy || p.li != layerRules {
		t.Errorf("expected view=viewPolicy li=layerRules, got view=%v li=%d", p.view, p.li)
	}
	if p.status != "" {
		t.Errorf("expected status cleared")
	}
}

func TestListKeyActivateWithNoSelection(t *testing.T) {
	p := newTestPolicies(t)
	if cmd := p.listKey("a"); cmd != nil {
		t.Errorf("expected nil cmd with no policies selected")
	}
}

func TestListKeyActivateInvokesSetActive(t *testing.T) {
	p := newTestPolicies(t)
	if _, err := p.deps.Client.Policies.Create(bg(), client.PolicySet{ID: "local", Name: "mine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	p.policies = []client.PolicyListEntry{{ID: "local", Name: "mine"}}
	cmd := p.listKey("a")
	if cmd == nil {
		t.Fatalf("expected an activation cmd")
	}
	msg := cmd()
	am, ok := msg.(polActionMsg)
	if !ok {
		t.Fatalf("expected polActionMsg, got %T", msg)
	}
	if !strings.HasPrefix(am.status, "✓") || !am.refreshActive {
		t.Errorf("activation result=%+v", am)
	}
}

func TestListKeyDeactivate(t *testing.T) {
	// client.Policies.SetActive rejects an empty policyID unconditionally by
	// design (see packages/core/client/resources_policy.go SetActive) — the
	// local policy file is always the enforcement baseline, so "x" always
	// surfaces that explanatory error.
	p := newTestPolicies(t)
	cmd := p.listKey("x")
	if cmd == nil {
		t.Fatalf("expected a deactivation cmd")
	}
	msg := cmd().(polActionMsg)
	if !strings.HasPrefix(msg.status, "✗") || !strings.Contains(msg.status, "nothing to switch off") {
		t.Errorf("deactivation status=%q, want the SetActive(\"\") error", msg.status)
	}
}

func TestListKeyNewBeginsCreating(t *testing.T) {
	p := newTestPolicies(t)
	p.input.SetValue("leftover")
	cmd := p.listKey("n")
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
	if !p.creating {
		t.Errorf("expected creating=true")
	}
	if p.input.Value() != "" {
		t.Errorf("expected input cleared, got %q", p.input.Value())
	}
}

func TestListKeyDeleteRequiresConfirmation(t *testing.T) {
	p := newTestPolicies(t)
	if _, err := p.deps.Client.Policies.Create(bg(), client.PolicySet{ID: "a", Name: "mine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	p.policies = []client.PolicyListEntry{{ID: "a", Name: "mine"}}

	cmd := p.listKey("d")
	if cmd != nil {
		t.Errorf("expected nil cmd on first 'd' press")
	}
	if p.pendingDel != "a" {
		t.Errorf("expected pendingDel set, got %q", p.pendingDel)
	}
	if !strings.Contains(p.status, "again to DELETE") {
		t.Errorf("status=%q", p.status)
	}

	cmd = p.listKey("d")
	if cmd == nil {
		t.Fatalf("expected a delete cmd on second 'd' press")
	}
	if p.pendingDel != "" {
		t.Errorf("expected pendingDel cleared after confirming")
	}
	msg := cmd().(polActionMsg)
	if !strings.HasPrefix(msg.status, "✓ deleted") || !msg.refreshList || !msg.resetCursor {
		t.Errorf("delete result=%+v", msg)
	}
}

func TestRulesKeyNavigationAndToggle(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewRules
	p.rules = []ruleDoc{
		{rule: client.PolicyRule{ID: "r1", Enabled: true}},
		{rule: client.PolicyRule{ID: "r2", Enabled: true}},
	}

	cmd := p.rulesKey("left")
	if cmd != nil || p.view != viewPolicy {
		t.Errorf("expected left to pop to viewPolicy")
	}

	p.view = viewRules
	p.ri = 0
	p.rulesKey("down")
	if p.ri != 1 {
		t.Errorf("expected ri to move down, got %d", p.ri)
	}
	p.rulesKey("up")
	if p.ri != 0 {
		t.Errorf("expected ri to move up, got %d", p.ri)
	}

	p.rulesKey("enter")
	if p.view != viewRule || p.fi != 0 {
		t.Errorf("expected enter to open viewRule, got view=%v fi=%d", p.view, p.fi)
	}

	p.view = viewRules
	p.rulesKey(" ")
	if p.rules[0].rule.Enabled {
		t.Errorf("expected space to toggle Enabled off")
	}
	if !p.rules[0].edited {
		t.Errorf("expected rule marked edited")
	}
}

func TestRulesKeyEffectDeleteModeNewSave(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewRules
	p.rules = []ruleDoc{
		{rule: client.PolicyRule{ID: "r1", Effect: "DENY"}},
		{rule: client.PolicyRule{ID: "r2", Effect: "ALLOW"}},
	}
	p.ri = 0
	p.rulesKey("e")
	if p.rules[0].rule.Effect != "ALLOW" {
		t.Errorf("expected effect flipped, got %v", p.rules[0].rule.Effect)
	}

	p.rulesKey("d")
	if len(p.rules) != 1 || p.rules[0].rule.ID != "r2" {
		t.Errorf("expected rule 0 deleted, got %+v", p.rules)
	}

	p.rulesKey("m")
	if p.mode != client.ModeWhitelist {
		t.Errorf("expected rulesKey 'm' to flip mode, got %v", p.mode)
	}

	p.rulesKey("n")
	if len(p.rules) != 2 || p.view != viewRule || p.ri != 0 || p.fi != 0 {
		t.Errorf("expected a new rule prepended and viewRule opened, got rules=%d view=%v ri=%d fi=%d",
			len(p.rules), p.view, p.ri, p.fi)
	}
	if p.rules[0].rule.Effect != "DENY" || p.rules[0].rule.ToolPattern != "*" {
		t.Errorf("new rule defaults unexpected: %+v", p.rules[0].rule)
	}

	p.view = viewRules
	p.haveDetail = false
	if cmd := p.rulesKey("s"); cmd != nil {
		t.Errorf("expected save() refused without haveDetail")
	}

	p.dirty = true
	p.rulesKey("x")
	if p.dirty {
		t.Errorf("expected discard dispatch")
	}
}

func TestRulesKeyOutOfRangeNavigationIsSafe(t *testing.T) {
	p := newTestPolicies(t)
	p.view = viewRules
	p.rules = nil
	p.ri = 0
	// None of these should panic on an empty rule list.
	p.rulesKey("enter")
	p.rulesKey(" ")
	p.rulesKey("e")
	p.rulesKey("d")
	if p.view != viewRules {
		t.Errorf("expected view to remain viewRules, got %v", p.view)
	}
}

func TestMatchKeyOutOfRangeResetsToRules(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = nil
	p.ri = 0
	p.matchKey("left")
	if p.view != viewRules {
		t.Errorf("expected view reset to viewRules, got %v", p.view)
	}
}

func TestMatchKeyNavigationAddEditDelete(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{
		CommandConstraints: &client.Constraint{Denied: []string{"rm", "curl"}},
	}}}
	p.ri = 0
	p.view = viewMatch
	p.matchSel = 0

	p.matchKey("down")
	if p.matchSel != 1 {
		t.Errorf("expected matchSel to move down, got %d", p.matchSel)
	}
	p.matchKey("up")
	if p.matchSel != 0 {
		t.Errorf("expected matchSel to move up, got %d", p.matchSel)
	}

	p.matchKey("a")
	items := matchItems(p.rules[0].rule)
	if len(items) != 3 || items[2] != "" {
		t.Errorf("expected a new blank item appended, got %v", items)
	}
	if !p.editing {
		t.Errorf("expected 'a' to begin editing")
	}
	p.editing = false

	p.matchSel = 0
	p.matchKey("[")
	items = matchItems(p.rules[0].rule)
	if items[0] != "*rm" {
		t.Errorf("expected [ to prefix a star, got %v", items)
	}

	p.matchKey("d")
	items = matchItems(p.rules[0].rule)
	if len(items) != 2 {
		t.Errorf("expected delete to remove matchSel item, got %v", items)
	}
}

func TestMatchKeyEnterOnEmptyBeginsEdit(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{CommandConstraints: &client.Constraint{}}}}
	p.ri = 0
	p.view = viewMatch
	p.matchKey("enter")
	if !p.editing {
		t.Errorf("expected enter on an empty match list to begin editing")
	}
	items := matchItems(p.rules[0].rule)
	if len(items) != 1 || items[0] != "" {
		t.Errorf("expected a placeholder blank item, got %v", items)
	}
}

func TestMatchKeySave(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{}}}
	p.haveDetail = false
	if cmd := p.matchKey("s"); cmd != nil {
		t.Errorf("expected save() to refuse without haveDetail")
	}
}

func TestRuleKeyOutOfRangeResetsToRules(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = nil
	p.view = viewRule
	p.ruleKey(krune("esc"), "esc")
	if p.view != viewRules {
		t.Errorf("expected view reset to viewRules, got %v", p.view)
	}
}

func TestRuleKeyNavigationAndFieldFlipping(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{Effect: "DENY", CommandConstraints: &client.Constraint{}}}}
	p.ri = 0
	p.view = viewRule
	p.fi = 0 // "effect" field in fieldsFor() order

	p.ruleKey(krune(" "), " ")
	if p.rules[0].rule.Effect != "ALLOW" {
		t.Errorf("expected effect flipped via ruleKey space, got %v", p.rules[0].rule.Effect)
	}

	p.fi = min(len(fieldsFor(p.rules[0].rule))-1, p.fi+1)
	p.ruleKey(krune("down"), "down")
	if p.fi == 0 {
		t.Errorf("expected fi to move down")
	}
	p.ruleKey(krune("up"), "up")

	p.ruleKey(krune("esc"), "esc")
	if p.view != viewRules {
		t.Errorf("expected esc to pop to viewRules, got %v", p.view)
	}
}

func TestRuleKeyCTypeCycling(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{}}}
	p.ri = 0
	p.view = viewRule
	fields := fieldsFor(p.rules[0].rule)
	ctypeIdx := -1
	for i, f := range fields {
		if f.kind == "ctype" {
			ctypeIdx = i
		}
	}
	if ctypeIdx < 0 {
		t.Fatalf("expected a ctype field")
	}
	p.fi = ctypeIdx
	p.ruleKey(krune(" "), " ")
	if currentCType(p.rules[0].rule) == cNone {
		t.Errorf("expected cType to advance away from none")
	}
	if !p.rules[0].edited {
		t.Errorf("expected edited flag set")
	}
}

func TestRuleKeyPermsCursorAndToggle(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{PathConstraints: &client.PathConstraint{}}}}
	p.ri = 0
	p.view = viewRule
	fields := fieldsFor(p.rules[0].rule)
	permIdx := -1
	for i, f := range fields {
		if f.kind == "perms" {
			permIdx = i
		}
	}
	if permIdx < 0 {
		t.Fatalf("expected a perms field for a path constraint rule")
	}
	p.fi = permIdx
	p.permCursor = 0

	p.ruleKey(krune("right"), "right")
	if p.permCursor != 1 {
		t.Errorf("expected permCursor to advance, got %d", p.permCursor)
	}
	p.ruleKey(krune("left"), "left")
	if p.permCursor != 0 {
		t.Errorf("expected permCursor to go back, got %d", p.permCursor)
	}

	p.ruleKey(krune(" "), " ")
	if !p.rules[0].edited {
		t.Errorf("expected toggling a permission to mark edited")
	}
}

func TestRuleKeyPriorityAdjust(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{Priority: 10}}}
	p.ri = 0
	p.view = viewRule
	fields := fieldsFor(p.rules[0].rule)
	prioIdx := -1
	for i, f := range fields {
		if f.kind == "priority" {
			prioIdx = i
		}
	}
	p.fi = prioIdx
	p.ruleKey(krune("right"), "right")
	if p.rules[0].rule.Priority != 11 {
		t.Errorf("expected priority incremented, got %d", p.rules[0].rule.Priority)
	}
	p.ruleKey(krune("left"), "left")
	if p.rules[0].rule.Priority != 10 {
		t.Errorf("expected priority decremented, got %d", p.rules[0].rule.Priority)
	}
}

func TestRuleKeyPriorityClampsAtZero(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{Priority: 0}}}
	p.ri = 0
	p.view = viewRule
	fields := fieldsFor(p.rules[0].rule)
	prioIdx := 0
	for i, f := range fields {
		if f.kind == "priority" {
			prioIdx = i
		}
	}
	p.fi = prioIdx
	p.ruleKey(krune("left"), "left")
	if p.rules[0].rule.Priority != 0 {
		t.Errorf("expected priority clamped at 0, got %d", p.rules[0].rule.Priority)
	}
}

func TestRuleKeyMatchFieldOpensMatchView(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{CommandConstraints: &client.Constraint{}}}}
	p.ri = 0
	p.view = viewRule
	fields := fieldsFor(p.rules[0].rule)
	matchIdx := -1
	for i, f := range fields {
		if f.kind == "match" {
			matchIdx = i
		}
	}
	if matchIdx < 0 {
		t.Fatalf("expected a match field")
	}
	p.fi = matchIdx
	p.ruleKey(krune("enter"), "enter")
	if p.view != viewMatch {
		t.Errorf("expected enter on match field to open viewMatch, got %v", p.view)
	}
}

func TestRuleKeyTextFieldBeginsEdit(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{Description: "hello"}}}
	p.ri = 0
	p.view = viewRule
	fields := fieldsFor(p.rules[0].rule)
	textIdx := -1
	for i, f := range fields {
		if f.kind == "text" {
			textIdx = i
		}
	}
	p.fi = textIdx
	p.ruleKey(krune("enter"), "enter")
	if !p.editing || p.input.Value() != "hello" {
		t.Errorf("expected editing begun with current description, editing=%v value=%q", p.editing, p.input.Value())
	}
}

func TestFlipEffect(t *testing.T) {
	p := &Policies{rules: []ruleDoc{{rule: client.PolicyRule{Effect: "DENY"}}}}
	p.flipEffect(0)
	if p.rules[0].rule.Effect != "ALLOW" || !p.rules[0].edited || !p.dirty {
		t.Errorf("flipEffect result=%+v dirty=%v", p.rules[0], p.dirty)
	}
}

func TestSetItems(t *testing.T) {
	p := &Policies{rules: []ruleDoc{{rule: client.PolicyRule{CommandConstraints: &client.Constraint{}}}}}
	p.ri = 0
	p.setItems([]string{"a", "b"})
	if got := matchItems(p.rules[0].rule); len(got) != 2 {
		t.Errorf("setItems did not apply items, got %v", got)
	}
	if !p.rules[0].edited || !p.dirty {
		t.Errorf("expected edited and dirty flags set")
	}
}

func TestBeginEdit(t *testing.T) {
	p := newTestPolicies(t)
	p.beginEdit("hello")
	if !p.editing {
		t.Errorf("expected editing=true")
	}
	if p.input.Value() != "hello" {
		t.Errorf("value=%q, want hello", p.input.Value())
	}
	if !p.input.Focused() {
		t.Errorf("expected input focused")
	}
}

func TestEditingKeyEscCancels(t *testing.T) {
	p := newTestPolicies(t)
	p.beginEdit("x")
	cmd := p.editingKey(krune("esc"))
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
	if p.editing {
		t.Errorf("expected editing cleared")
	}
}

func TestEditingKeyTypingForwardsToTextinput(t *testing.T) {
	p := newTestPolicies(t)
	p.beginEdit("")
	p.editingKey(krune("a"))
	if p.input.Value() != "a" {
		t.Errorf("expected textinput to receive the rune, got %q", p.input.Value())
	}
}

func TestEditingKeyEnterWithoutRuleIsNoOp(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = nil
	p.ri = 0
	p.beginEdit("x")
	cmd := p.editingKey(krune("enter"))
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
	if p.editing {
		t.Errorf("expected editing cleared even with no matching rule")
	}
}

func TestEditingKeyEnterInMatchViewUpdatesItem(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{CommandConstraints: &client.Constraint{Denied: []string{"rm"}}}}}
	p.ri = 0
	p.view = viewMatch
	p.matchSel = 0
	p.beginEdit("rm")
	p.input.SetValue("curl")
	p.editingKey(krune("enter"))
	items := matchItems(p.rules[0].rule)
	if len(items) != 1 || items[0] != "curl" {
		t.Errorf("expected item replaced, got %v", items)
	}
}

func TestEditingKeyEnterInMatchViewEmptyRemovesItem(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{CommandConstraints: &client.Constraint{Denied: []string{"rm", "curl"}}}}}
	p.ri = 0
	p.view = viewMatch
	p.matchSel = 0
	p.beginEdit("rm")
	p.input.SetValue("   ")
	p.editingKey(krune("enter"))
	items := matchItems(p.rules[0].rule)
	if len(items) != 1 || items[0] != "curl" {
		t.Errorf("expected blank submission to remove the item, got %v", items)
	}
}

func TestEditingKeyEnterUpdatesDescription(t *testing.T) {
	p := newTestPolicies(t)
	p.rules = []ruleDoc{{rule: client.PolicyRule{Description: "old"}}}
	p.ri = 0
	p.view = viewRule
	p.beginEdit("old")
	p.input.SetValue("new description")
	p.editingKey(krune("enter"))
	if p.rules[0].rule.Description != "new description" {
		t.Errorf("description=%q, want %q", p.rules[0].rule.Description, "new description")
	}
	if !p.rules[0].edited || !p.dirty {
		t.Errorf("expected edited/dirty set")
	}
}

func TestCreatingKeyEscCancels(t *testing.T) {
	p := newTestPolicies(t)
	p.creating = true
	p.input.SetValue("x")
	cmd := p.creatingKey(krune("esc"))
	if cmd != nil || p.creating {
		t.Errorf("expected esc to cancel creating")
	}
}

func TestCreatingKeyTypingForwardsToTextinput(t *testing.T) {
	p := newTestPolicies(t)
	p.creating = true
	p.input.SetValue("")
	p.input.Focus() // textinput.Update ignores keys while unfocused
	p.creatingKey(krune("x"))
	if p.input.Value() != "x" {
		t.Errorf("expected typed rune forwarded, got %q", p.input.Value())
	}
}

func TestCreatingKeyEnterWithBlankNameIsNoOp(t *testing.T) {
	p := newTestPolicies(t)
	p.creating = true
	p.input.SetValue("   ")
	cmd := p.creatingKey(krune("enter"))
	if cmd != nil {
		t.Errorf("expected nil cmd for a blank name")
	}
	if p.creating {
		t.Errorf("expected creating cleared regardless")
	}
}

func TestCreatingKeyEnterCreatesPolicy(t *testing.T) {
	p := newTestPolicies(t)
	p.creating = true
	p.input.SetValue("My Policy")
	cmd := p.creatingKey(krune("enter"))
	if cmd == nil {
		t.Fatalf("expected a create cmd")
	}
	if !p.busyCreate {
		t.Errorf("expected busyCreate set")
	}
	msg := cmd().(polActionMsg)
	if !strings.Contains(msg.status, "My Policy") || !msg.refreshList {
		t.Errorf("create result=%+v", msg)
	}
	list := p.loadList()().(polListMsg)
	if list.err != nil || len(list.data) != 1 {
		t.Errorf("expected the policy actually persisted, got %+v", list)
	}
}

func TestSaveBodyRefusesWithoutDetail(t *testing.T) {
	p := &Policies{haveDetail: false}
	if _, ok := p.saveBody(); ok {
		t.Errorf("expected saveBody to refuse without haveDetail")
	}
}

func TestSaveBodyRefusesWithoutSelection(t *testing.T) {
	p := &Policies{haveDetail: true}
	if _, ok := p.saveBody(); ok {
		t.Errorf("expected saveBody to refuse without a selected policy")
	}
}

func TestSaveBodyRejectsUnreadableRules(t *testing.T) {
	// fold() (called at the top of saveBody) always overwrites the current
	// variant's rules/unreadable from the top-level p.rules/p.unreadable
	// fields, so the unreadable count must be set there, not directly on the
	// variantDraft, for it to survive into the validation that follows.
	p := &Policies{
		haveDetail: true,
		policies:   []client.PolicyListEntry{{ID: "local"}},
		variants:   []variantDraft{{id: "v0", name: "Base"}},
		vi:         0,
		unreadable: 2,
	}
	_, ok := p.saveBody()
	if ok {
		t.Errorf("expected saveBody to refuse when a variant has unreadable rules")
	}
	if !strings.Contains(p.status, "cannot be read") {
		t.Errorf("status=%q", p.status)
	}
}

func TestSaveBodyRejectsBlanketRule(t *testing.T) {
	p := &Policies{
		haveDetail: true,
		policies:   []client.PolicyListEntry{{ID: "local"}},
		variants:   []variantDraft{{id: "v0", name: "Base"}},
		vi:         0,
		rules:      []ruleDoc{{rule: client.PolicyRule{ToolPattern: "*"}}},
	}
	_, ok := p.saveBody()
	if ok {
		t.Errorf("expected saveBody to refuse a blanket rule")
	}
	if !strings.Contains(p.status, "EVERYTHING") {
		t.Errorf("status=%q", p.status)
	}
}

func TestSaveBodyBuildsPolicySet(t *testing.T) {
	p := &Policies{
		haveDetail: true,
		mode:       client.ModeWhitelist,
		detail:     client.PolicyDetail{PolicySet: client.PolicySet{Name: "mine", Description: "d"}},
		policies:   []client.PolicyListEntry{{ID: "local"}},
		variants: []variantDraft{{
			id:   "v0",
			name: "Base",
			rules: []ruleDoc{{rule: client.PolicyRule{
				ID: "r1", Effect: "DENY", CommandConstraints: &client.Constraint{Denied: []string{"rm"}},
			}}},
		}},
	}
	body, ok := p.saveBody()
	if !ok {
		t.Fatalf("expected saveBody to succeed, status=%q", p.status)
	}
	if body.ID != "local" || body.Name != "mine" || body.Mode != client.ModeWhitelist {
		t.Errorf("unexpected PolicySet header: %+v", body)
	}
	if len(body.Variants) != 1 || body.Variants[0].ID != "v0" {
		t.Errorf("expected one variant with id v0, got %+v", body.Variants)
	}
	if body.DefaultVariant != "v0" {
		t.Errorf("DefaultVariant=%q, want v0", body.DefaultVariant)
	}
}

func TestSaveReturnsNilWhenBodyInvalid(t *testing.T) {
	p := &Policies{haveDetail: false}
	if cmd := p.save(); cmd != nil {
		t.Errorf("expected save() to return nil when saveBody fails")
	}
}

func TestSaveInvokesClientUpdate(t *testing.T) {
	p := newTestPolicies(t)
	if _, err := p.deps.Client.Policies.Create(bg(), client.PolicySet{ID: "local", Name: "mine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	p.haveDetail = true
	p.policies = []client.PolicyListEntry{{ID: "local"}}
	p.detail = client.PolicyDetail{PolicySet: client.PolicySet{ID: "local", Name: "mine"}}
	p.variants = []variantDraft{{id: "v0", name: "Base"}}

	cmd := p.save()
	if cmd == nil {
		t.Fatalf("expected a save cmd")
	}
	if p.status != "Saving…" {
		t.Errorf("status=%q", p.status)
	}
	msg := cmd()
	sm, ok := msg.(polSavedMsg)
	if !ok {
		t.Fatalf("expected polSavedMsg, got %T", msg)
	}
	if sm.err != nil {
		t.Errorf("unexpected save error: %v", sm.err)
	}
}

func TestPolOrID(t *testing.T) {
	if got := polOrID("explicit", 3); got != "explicit" {
		t.Errorf("polOrID with explicit id=%q, want explicit", got)
	}
	if got := polOrID("", 2); got != polVariantID(2) {
		t.Errorf("polOrID fallback=%q, want %q", got, polVariantID(2))
	}
}

func TestDiscard(t *testing.T) {
	p := &Policies{
		haveDetail: true,
		dirty:      true,
		status:     "stale",
		detail:     client.PolicyDetail{PolicySet: client.PolicySet{Mode: client.ModeWhitelist}},
	}
	p.discard()
	if p.dirty {
		t.Errorf("expected dirty cleared")
	}
	if p.status != "discarded" {
		t.Errorf("status=%q, want discarded", p.status)
	}
	if p.mode != client.ModeWhitelist {
		t.Errorf("expected discard to re-adopt the stored detail, mode=%v", p.mode)
	}
}

func TestDiscardWithoutDetailOnlyClearsFlags(t *testing.T) {
	p := &Policies{dirty: true, haveDetail: false}
	p.discard()
	if p.dirty || p.status != "discarded" {
		t.Errorf("expected dirty cleared and status set even without detail")
	}
}