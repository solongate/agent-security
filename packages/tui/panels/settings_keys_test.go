// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/health"
)

func TestSettingsKeyEditingEscCancels(t *testing.T) {
	p := newTestSettings(t)
	p.editing = "path"
	p.input.SetValue("x")
	cmd := p.key(krune("esc"))
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
	if p.editing != "" {
		t.Errorf("expected editing cleared")
	}
}

func TestSettingsKeyEditingTypingForwardsToTextinput(t *testing.T) {
	p := newTestSettings(t)
	p.editing = "path"
	p.beginInput("")
	p.key(krune("z"))
	if p.input.Value() != "z" {
		t.Errorf("expected typed rune forwarded, got %q", p.input.Value())
	}
}

func TestSettingsKeyEditingEnterCallsSubmitInput(t *testing.T) {
	p := newTestSettings(t)
	p.editing = "path"
	p.beginInput("/var/log/x")
	cmd := p.key(krune("enter"))
	if p.editing != "" {
		t.Errorf("expected editing cleared by submitInput")
	}
	if cmd == nil {
		t.Fatalf("expected submitInput to return a save cmd")
	}
	msg := cmd().(setRunMsg)
	if msg.err != nil {
		t.Errorf("unexpected error persisting path: %v", msg.err)
	}
}

func TestSettingsKeyNavigationResetsConfirmDel(t *testing.T) {
	p := newTestSettings(t)
	p.sel = 2
	p.confirmDel = "guard"
	p.key(krune("up"))
	if p.sel != 1 {
		t.Errorf("expected sel to move up, got %d", p.sel)
	}
	if p.confirmDel != "" {
		t.Errorf("expected confirmDel reset on navigation")
	}

	p.key(krune("down"))
	if p.sel != 2 {
		t.Errorf("expected sel to move down, got %d", p.sel)
	}
}

func TestSettingsKeyNavigationClampsAtBounds(t *testing.T) {
	p := newTestSettings(t)
	rows := p.allRows()
	p.sel = 0
	p.key(krune("up"))
	if p.sel != 0 {
		t.Errorf("expected sel clamped at 0, got %d", p.sel)
	}
	p.sel = len(rows) - 1
	p.key(krune("down"))
	if p.sel != len(rows)-1 {
		t.Errorf("expected sel clamped at last row, got %d", p.sel)
	}
}

func TestSettingsKeyEnterDispatchesToActivate(t *testing.T) {
	p := newTestSettings(t)
	// "range" is a safe, purely local activation to use as the dispatch probe.
	for i, r := range p.allRows() {
		if r.kind == "range" {
			p.sel = i
		}
	}
	before := config.UpdateRangeOf(p.deps.Cfg)
	p.key(krune("enter"))
	after := config.UpdateRangeOf(p.deps.Cfg)
	if before == after {
		t.Errorf("expected enter to dispatch to activate() and flip the range, before=%q after=%q", before, after)
	}
}

func TestSettingsKeyMKeyOnlyAppliesToSelfAndLLEnabled(t *testing.T) {
	p := newTestSettings(t)
	p.haveSelf = false
	for i, r := range p.allRows() {
		if r.kind == "self" {
			p.sel = i
		}
	}
	// activate("self") refuses without haveSelf, so this should be a safe no-op.
	if cmd := p.key(krune("m")); cmd != nil {
		t.Errorf("expected nil cmd without haveSelf")
	}

	for i, r := range p.allRows() {
		if r.kind == "guard" {
			p.sel = i
		}
	}
	if cmd := p.key(krune("m")); cmd != nil {
		t.Errorf("expected 'm' on a non-self/ll-enabled row to be ignored")
	}
}

func TestSettingsKeyEKeyOnlyAppliesToLLPath(t *testing.T) {
	p := newTestSettings(t)
	for i, r := range p.allRows() {
		if r.kind == "ll-path" {
			p.sel = i
		}
	}
	p.key(krune("e"))
	if p.editing != "path" {
		t.Errorf("expected 'e' on ll-path to begin editing, got editing=%q", p.editing)
	}

	p2 := newTestSettings(t)
	for i, r := range p2.allRows() {
		if r.kind == "guard" {
			p2.sel = i
		}
	}
	if cmd := p2.key(krune("e")); cmd != nil || p2.editing != "" {
		t.Errorf("expected 'e' on a non-ll-path row to be ignored")
	}
}

func TestSettingsKeyDGuardStartsUninstallWithoutInvokingIt(t *testing.T) {
	// install.Uninstall() performs a real system mutation; this test only
	// checks that the busy flag and message are set and that a cmd is
	// returned, and NEVER invokes the returned tea.Cmd.
	p := newTestSettings(t)
	for i, r := range p.allRows() {
		if r.kind == "guard" {
			p.sel = i
		}
	}
	cmd := p.key(krune("d"))
	if cmd == nil {
		t.Fatalf("expected a non-nil cmd")
	}
	if !p.installBusy {
		t.Errorf("expected installBusy set")
	}
	if p.msg == nil || !strings.Contains(p.msg.text, "removing the guard") {
		t.Errorf("msg=%+v", p.msg)
	}
}

func TestSettingsKeyDGuardRefusesWhenAlreadyBusy(t *testing.T) {
	p := newTestSettings(t)
	for i, r := range p.allRows() {
		if r.kind == "guard" {
			p.sel = i
		}
	}
	p.installBusy = true
	if cmd := p.key(krune("d")); cmd != nil {
		t.Errorf("expected nil cmd while installBusy")
	}
}

func TestSettingsKeyDOnNonGuardRowIsIgnored(t *testing.T) {
	p := newTestSettings(t)
	for i, r := range p.allRows() {
		if r.kind == "self" {
			p.sel = i
		}
	}
	if cmd := p.key(krune("d")); cmd != nil {
		t.Errorf("expected nil cmd for 'd' on a non-guard row")
	}
}

func TestSettingsKeyRReloadsFromDisk(t *testing.T) {
	p := newTestSettings(t)
	cmd := p.key(krune("r"))
	if cmd == nil {
		t.Fatalf("expected a reloadAll() cmd")
	}
	if _, ok := cmd().(tea.BatchMsg); !ok {
		t.Errorf("expected reloadAll() to produce a tea.BatchMsg")
	}
}

func TestBeginInput(t *testing.T) {
	p := newTestSettings(t)
	p.beginInput("hello")
	if p.input.Value() != "hello" {
		t.Errorf("value=%q, want hello", p.input.Value())
	}
	if !p.input.Focused() {
		t.Errorf("expected input focused")
	}
}

func TestActivateRangeTogglesAndPersists(t *testing.T) {
	p := newTestSettings(t)
	before := config.UpdateRangeOf(p.deps.Cfg)
	cmd := p.activate(setRow{kind: "range"})
	if cmd != nil {
		t.Errorf("expected nil cmd (range activation is synchronous)")
	}
	after := config.UpdateRangeOf(p.deps.Cfg)
	if before == after {
		t.Errorf("expected range flipped, before=%q after=%q", before, after)
	}
	if p.msg == nil || p.msg.bad {
		t.Errorf("expected a success message, got %+v", p.msg)
	}

	// Flipping again should go back.
	p.activate(setRow{kind: "range"})
	if got := config.UpdateRangeOf(p.deps.Cfg); got != before {
		t.Errorf("expected range to flip back to %q, got %q", before, got)
	}
}

func TestActivateGuardSetsBusyWithoutInvokingInstall(t *testing.T) {
	p := newTestSettings(t)
	cmd := p.activate(setRow{kind: "guard"})
	if cmd == nil {
		t.Fatalf("expected a non-nil cmd")
	}
	if !p.installBusy {
		t.Errorf("expected installBusy set")
	}
	if p.msg == nil || !strings.Contains(p.msg.text, "installing the guard") {
		t.Errorf("msg=%+v", p.msg)
	}
	// Deliberately never invoke cmd(): it runs the real install.Install().
}

func TestActivateGuardRefusesWhenBusy(t *testing.T) {
	p := newTestSettings(t)
	p.installBusy = true
	if cmd := p.activate(setRow{kind: "guard"}); cmd != nil {
		t.Errorf("expected nil cmd while installBusy")
	}
}

func TestActivateDoctorSetsBusyWithoutInvokingHealthChecks(t *testing.T) {
	p := newTestSettings(t)
	p.diag = []health.Check{{Name: "stale"}}
	p.diagStep = 3
	cmd := p.activate(setRow{kind: "doctor"})
	if cmd == nil {
		t.Fatalf("expected a non-nil cmd")
	}
	if !p.diagBusy {
		t.Errorf("expected diagBusy set")
	}
	if p.diagStep != 0 {
		t.Errorf("expected diagStep reset to 0")
	}
	if len(p.diag) != 0 {
		t.Errorf("expected diag reset to empty")
	}
	// Deliberately never invoke cmd(): it runs the real health.CollectChecks().
}

func TestActivateDoctorRefusesWhenBusy(t *testing.T) {
	p := newTestSettings(t)
	p.diagBusy = true
	if cmd := p.activate(setRow{kind: "doctor"}); cmd != nil {
		t.Errorf("expected nil cmd while diagBusy")
	}
}

func TestActivateRepairSetsBusyWithoutInvokingRepair(t *testing.T) {
	p := newTestSettings(t)
	cmd := p.activate(setRow{kind: "repair"})
	if cmd == nil {
		t.Fatalf("expected a non-nil cmd")
	}
	if !p.installBusy {
		t.Errorf("expected installBusy set")
	}
	if p.repairReport != nil {
		t.Errorf("expected repairReport reset to nil")
	}
	// Deliberately never invoke cmd(): it runs the real install.Repair().
}

func TestActivateRepairRefusesWhenBusy(t *testing.T) {
	p := newTestSettings(t)
	p.installBusy = true
	if cmd := p.activate(setRow{kind: "repair"}); cmd != nil {
		t.Errorf("expected nil cmd while installBusy")
	}
}

func TestActivateSelfRefusesWithoutHaveSelf(t *testing.T) {
	p := newTestSettings(t)
	p.haveSelf = false
	if cmd := p.activate(setRow{kind: "self"}); cmd != nil {
		t.Errorf("expected nil cmd without haveSelf")
	}
}

func TestActivateSelfTogglesAndPersists(t *testing.T) {
	p := newTestSettings(t)
	p.haveSelf = true
	p.selfProt = false
	cmd := p.activate(setRow{kind: "self"})
	if cmd == nil {
		t.Fatalf("expected a non-nil cmd")
	}
	if p.msg == nil || !strings.Contains(p.msg.text, "self-protection enabled") {
		t.Errorf("msg=%+v", p.msg)
	}
	msg := cmd().(setRunMsg)
	if msg.err != nil {
		t.Errorf("unexpected SetSelfProtection error: %v", msg.err)
	}
	if msg.reload != "self" {
		t.Errorf("reload=%q, want self", msg.reload)
	}
}

func TestActivateLLEnabledRefusesWithoutHaveLocal(t *testing.T) {
	p := newTestSettings(t)
	p.haveLocal = false
	if cmd := p.activate(setRow{kind: "ll-enabled"}); cmd != nil {
		t.Errorf("expected nil cmd without haveLocal")
	}
}

func TestActivateLLEnabledRequiresPathFirst(t *testing.T) {
	p := newTestSettings(t)
	p.haveLocal = true
	p.local = client.LocalLogsConfig{Enabled: false, Path: ""}
	cmd := p.activate(setRow{kind: "ll-enabled"})
	if cmd != nil {
		t.Errorf("expected nil cmd when no path is set yet")
	}
	if p.msg == nil || !p.msg.bad || !strings.Contains(p.msg.text, "set a path first") {
		t.Errorf("msg=%+v", p.msg)
	}
}

func TestActivateLLEnabledTogglesAndPersists(t *testing.T) {
	p := newTestSettings(t)
	p.haveLocal = true
	p.local = client.LocalLogsConfig{Enabled: false, Path: "/tmp/x.log"}
	cmd := p.activate(setRow{kind: "ll-enabled"})
	if cmd == nil {
		t.Fatalf("expected a non-nil cmd")
	}
	if !strings.Contains(p.msg.text, "local logs enabled") {
		t.Errorf("msg=%+v", p.msg)
	}
	msg := cmd().(setRunMsg)
	if msg.err != nil {
		t.Errorf("unexpected SetLocalLogs error: %v", msg.err)
	}
}

func TestActivateLLPathBeginsEditingWithCurrentPath(t *testing.T) {
	p := newTestSettings(t)
	p.local = client.LocalLogsConfig{Path: "/var/log/current"}
	cmd := p.activate(setRow{kind: "ll-path"})
	if cmd != nil {
		t.Errorf("expected nil cmd (ll-path only begins editing)")
	}
	if p.editing != "path" {
		t.Errorf("editing=%q, want path", p.editing)
	}
	if p.input.Value() != "/var/log/current" {
		t.Errorf("input value=%q, want the current path prefilled", p.input.Value())
	}
}

func TestActivateUnknownKindIsNoOp(t *testing.T) {
	p := newTestSettings(t)
	if cmd := p.activate(setRow{kind: "bogus"}); cmd != nil {
		t.Errorf("expected nil cmd for an unrecognised row kind")
	}
}

func TestSubmitInputPathSavesNonEmptyValue(t *testing.T) {
	p := newTestSettings(t)
	p.haveLocal = true
	p.local = client.LocalLogsConfig{Enabled: false}
	p.editing = "path"
	p.beginInput("")
	p.input.SetValue("/var/log/new.log")
	cmd := p.submitInput()
	if p.editing != "" {
		t.Errorf("expected editing cleared")
	}
	if cmd == nil {
		t.Fatalf("expected a save cmd")
	}
	if !strings.Contains(p.msg.text, "press enter on enabled to turn on") {
		t.Errorf("msg=%+v, expected a hint since local logs aren't enabled yet", p.msg)
	}
	msg := cmd().(setRunMsg)
	if msg.err != nil {
		t.Errorf("unexpected SetLocalLogs error: %v", msg.err)
	}
}

func TestSubmitInputPathEnabledWhenAlreadyOn(t *testing.T) {
	p := newTestSettings(t)
	p.haveLocal = true
	p.local = client.LocalLogsConfig{Enabled: true}
	p.editing = "path"
	p.beginInput("")
	p.input.SetValue("/var/log/new.log")
	p.submitInput()
	if p.msg.text != "path saved…" {
		t.Errorf("msg.text=%q, want %q", p.msg.text, "path saved…")
	}
}

func TestSubmitInputPathEmptyClearsAndDisables(t *testing.T) {
	p := newTestSettings(t)
	p.haveLocal = true
	p.local = client.LocalLogsConfig{Enabled: true, Path: "/old"}
	p.editing = "path"
	p.beginInput("/old")
	p.input.SetValue("   ")
	cmd := p.submitInput()
	if p.msg.text != "path cleared (local logs off)…" {
		t.Errorf("msg.text=%q", p.msg.text)
	}
	msg := cmd().(setRunMsg)
	if msg.err != nil {
		t.Errorf("unexpected error: %v", msg.err)
	}
}

func TestSubmitInputUnknownEditingKindIsNoOp(t *testing.T) {
	p := newTestSettings(t)
	p.editing = "mystery"
	p.beginInput("x")
	if cmd := p.submitInput(); cmd != nil {
		t.Errorf("expected nil cmd for an unrecognised editing kind")
	}
	if p.editing != "" {
		t.Errorf("expected editing cleared regardless")
	}
}