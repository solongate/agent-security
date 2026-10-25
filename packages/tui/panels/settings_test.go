// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/health"
	"github.com/solongate/agent-security/packages/core/install"
	"github.com/solongate/agent-security/packages/tui"
)

func newTestSettings(t *testing.T) *Settings {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return NewSettings(tui.Deps{Client: client.New()})
}

func settingsCtx(p *Settings) tui.PanelContext {
	return tui.PanelContext{Deps: p.deps, Cols: p.cols, Rows: p.rows, Focused: p.focused, Gen: p.gen}
}

func TestSettingsCapturingKeys(t *testing.T) {
	p := newTestSettings(t)
	if p.CapturingKeys() {
		t.Errorf("expected false with no editing field set")
	}
	p.editing = "path"
	if !p.CapturingKeys() {
		t.Errorf("expected true while editing")
	}
}

func TestSettingsReadDisk(t *testing.T) {
	p := newTestSettings(t)
	p.readDisk() // should not panic against an empty temp HOME
}

func TestSettingsInitSchedulesReloadAndTick(t *testing.T) {
	p := newTestSettings(t)
	cmd := p.Init(settingsCtx(p))
	if cmd == nil {
		t.Fatalf("expected a non-nil Init cmd")
	}
	msg := cmd()
	bm, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("expected tea.BatchMsg (reloadAll + disk tick), got %T", msg)
	}
	if len(bm) != 2 {
		t.Errorf("expected 2 top-level batched items, got %d", len(bm))
	}
	// bm[0] is itself reloadAll()'s tea.Batch(...) of 4 loaders; invoking it
	// is safe since those are all local, non-blocking client calls. bm[1] is
	// the raw tea.Tick for setDiskMsg and must never be invoked directly.
	inner := bm[0]()
	if _, ok := inner.(tea.BatchMsg); !ok {
		t.Errorf("expected reloadAll() to produce its own BatchMsg, got %T", inner)
	}
}

func TestSettingsLoadLocalGuardSelfProtected(t *testing.T) {
	p := newTestSettings(t)

	lm := p.loadLocal()().(setLocalMsg)
	if lm.err != nil {
		t.Errorf("loadLocal err=%v", lm.err)
	}

	gm := p.loadGuard()().(setGuardMsg)
	if gm.err != nil {
		t.Errorf("loadGuard err=%v", gm.err)
	}

	sm := p.loadSelf()().(setSelfMsg)
	if sm.err != nil {
		t.Errorf("loadSelf err=%v", sm.err)
	}

	pm := p.loadProtected()().(setProtectedMsg)
	_ = pm // protected paths list may legitimately be empty in a temp HOME
}

func TestReloadNamed(t *testing.T) {
	p := newTestSettings(t)
	if cmd := p.reloadNamed("local"); cmd == nil {
		t.Errorf("expected a cmd for 'local'")
	}
	if cmd := p.reloadNamed("guard"); cmd == nil {
		t.Errorf("expected a cmd for 'guard'")
	}
	if cmd := p.reloadNamed("self"); cmd == nil {
		t.Errorf("expected a cmd for 'self'")
	}
	if cmd := p.reloadNamed("all"); cmd == nil {
		t.Errorf("expected a cmd for 'all'")
	}
	if cmd := p.reloadNamed("nonsense"); cmd != nil {
		t.Errorf("expected nil cmd for an unknown name")
	}
}

func TestRunRefusesWhenBusy(t *testing.T) {
	p := newTestSettings(t)
	p.busy = true
	if cmd := p.run("label", func() error { return nil }, "local"); cmd != nil {
		t.Errorf("expected run() to refuse while busy")
	}
}

func TestRunSetsBusyAndMessage(t *testing.T) {
	p := newTestSettings(t)
	cmd := p.run("doing thing", func() error { return nil }, "local")
	if cmd == nil {
		t.Fatalf("expected a non-nil cmd")
	}
	if !p.busy {
		t.Errorf("expected busy=true")
	}
	if p.msg == nil || p.msg.text != "doing thing…" {
		t.Errorf("msg=%+v", p.msg)
	}
	msg := cmd().(setRunMsg)
	if msg.label != "doing thing" || msg.err != nil || msg.reload != "local" {
		t.Errorf("setRunMsg=%+v", msg)
	}
}

func TestRunHidingPropagatesHideField(t *testing.T) {
	p := newTestSettings(t)
	cmd := p.runHiding("x", func() error { return nil }, "local", "ll-path")
	msg := cmd().(setRunMsg)
	if msg.hide != "ll-path" {
		t.Errorf("hide=%q, want ll-path", msg.hide)
	}
}

func TestUpdateSetLocalMsg(t *testing.T) {
	p := newTestSettings(t)
	_, _ = p.Update(setLocalMsg{genTag: p.tag(), data: client.LocalLogsConfig{Path: "/x"}}, settingsCtx(p))
	if !p.haveLocal || p.local.Path != "/x" {
		t.Errorf("expected local loaded, got %+v haveLocal=%v", p.local, p.haveLocal)
	}

	_, _ = p.Update(setLocalMsg{genTag: p.tag(), err: errors.New("boom")}, settingsCtx(p))
	if p.localErr == nil {
		t.Errorf("expected localErr set")
	}
}

func TestUpdateSetGuardMsg(t *testing.T) {
	p := newTestSettings(t)
	v := 3
	_, _ = p.Update(setGuardMsg{genTag: p.tag(), data: client.GuardStatus{Installed: &v}}, settingsCtx(p))
	if !p.haveGuard || p.guard.Installed == nil || *p.guard.Installed != 3 {
		t.Errorf("expected guard loaded, got %+v", p.guard)
	}
}

func TestUpdateSetSelfMsg(t *testing.T) {
	p := newTestSettings(t)
	_, _ = p.Update(setSelfMsg{genTag: p.tag(), data: true}, settingsCtx(p))
	if !p.haveSelf || !p.selfProt {
		t.Errorf("expected selfProt loaded true")
	}
}

func TestUpdateSetProtectedMsgIgnoresStaleToken(t *testing.T) {
	p := newTestSettings(t)
	p.protected = []protectedLine{{path: "keep"}}
	_, _ = p.Update(setProtectedMsg{genTag: genTag{gen: p.gen, tok: p.tok + 1}, rows: []protectedLine{{path: "new"}}}, settingsCtx(p))
	if len(p.protected) != 1 || p.protected[0].path != "keep" {
		t.Errorf("expected stale message ignored, got %+v", p.protected)
	}
}

func TestUpdateSetProtectedMsgAccepted(t *testing.T) {
	p := newTestSettings(t)
	_, _ = p.Update(setProtectedMsg{genTag: p.tag(), rows: []protectedLine{{path: "new"}}}, settingsCtx(p))
	if len(p.protected) != 1 || p.protected[0].path != "new" {
		t.Errorf("expected protected rows applied, got %+v", p.protected)
	}
}

func TestUpdateSetRunMsgError(t *testing.T) {
	p := newTestSettings(t)
	p.busy = true
	_, cmd := p.Update(setRunMsg{genTag: p.tag(), err: errors.New("bad")}, settingsCtx(p))
	if p.busy {
		t.Errorf("expected busy cleared")
	}
	if p.msg == nil || !p.msg.bad || !strings.HasPrefix(p.msg.text, "✗") {
		t.Errorf("msg=%+v", p.msg)
	}
	if cmd != nil {
		t.Errorf("expected nil cmd on error")
	}
}

func TestUpdateSetRunMsgSuccessHidesAndReloads(t *testing.T) {
	p := newTestSettings(t)
	p.busy = true
	_, cmd := p.Update(setRunMsg{genTag: p.tag(), label: "did it", reload: "local", hide: "ll-path"}, settingsCtx(p))
	if p.busy {
		t.Errorf("expected busy cleared")
	}
	if p.msg == nil || p.msg.bad || p.msg.text != "✓ did it" {
		t.Errorf("msg=%+v", p.msg)
	}
	if !p.hidden["ll-path"] {
		t.Errorf("expected ll-path hidden")
	}
	if cmd == nil {
		t.Errorf("expected reloadNamed(local) cmd")
	}
}

func TestUpdateSetDiskMsgIgnoresStaleToken(t *testing.T) {
	p := newTestSettings(t)
	_, cmd := p.Update(setDiskMsg{genTag: genTag{gen: p.gen, tok: p.tok + 1}}, settingsCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd for a stale disk message")
	}
}

func TestUpdateSetDiskMsgAcceptedReschedulesTick(t *testing.T) {
	p := newTestSettings(t)
	_, cmd := p.Update(setDiskMsg{genTag: p.tag()}, settingsCtx(p))
	// The returned cmd is a raw tea.Tick; only check it is non-nil, never invoke it.
	if cmd == nil {
		t.Errorf("expected a reschedule cmd")
	}
}

func TestUpdateSetSpinMsgIgnoresStaleToken(t *testing.T) {
	p := newTestSettings(t)
	before := p.spin
	_, cmd := p.Update(setSpinMsg{genTag: genTag{gen: p.gen, tok: p.tok + 1}}, settingsCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd for a stale spin message")
	}
	if p.spin != before {
		t.Errorf("expected spin untouched on a stale message")
	}
}

func TestUpdateSetSpinMsgStopsWhenIdle(t *testing.T) {
	p := newTestSettings(t)
	_, cmd := p.Update(setSpinMsg{genTag: p.tag()}, settingsCtx(p))
	if p.spin != 1 {
		t.Errorf("expected spin incremented, got %d", p.spin)
	}
	if cmd != nil {
		t.Errorf("expected nil cmd when neither busy nor diagBusy")
	}
}

func TestUpdateSetSpinMsgAdvancesDoctorStepAndReschedules(t *testing.T) {
	p := newTestSettings(t)
	p.diagBusy = true
	p.diagStep = 0
	_, cmd := p.Update(setSpinMsg{genTag: p.tag()}, settingsCtx(p))
	if p.spin != 1 {
		t.Errorf("spin=%d, want 1", p.spin)
	}
	if p.diagStep != 0 {
		t.Errorf("expected diagStep unchanged on odd spin, got %d", p.diagStep)
	}
	if cmd == nil {
		t.Errorf("expected a reschedule cmd while diagBusy")
	}

	_, cmd = p.Update(setSpinMsg{genTag: p.tag()}, settingsCtx(p))
	if p.spin != 2 || p.diagStep != 1 {
		t.Errorf("expected diagStep advanced on even spin, got spin=%d diagStep=%d", p.spin, p.diagStep)
	}
	if cmd == nil {
		t.Errorf("expected a reschedule cmd while diagBusy")
	}
}

func TestUpdateSetSpinMsgDiagStepClampsAtLastStep(t *testing.T) {
	p := newTestSettings(t)
	p.diagBusy = true
	p.diagStep = len(doctorSteps) - 1
	_, _ = p.Update(setSpinMsg{genTag: p.tag()}, settingsCtx(p))
	_, _ = p.Update(setSpinMsg{genTag: p.tag()}, settingsCtx(p))
	if p.diagStep != len(doctorSteps)-1 {
		t.Errorf("diagStep=%d, want clamped to %d", p.diagStep, len(doctorSteps)-1)
	}
}

func TestUpdateSetInstallMsg(t *testing.T) {
	p := newTestSettings(t)
	p.installBusy = true
	_, cmd := p.Update(setInstallMsg{genTag: p.tag(), verb: "install", ok: true}, settingsCtx(p))
	if p.installBusy {
		t.Errorf("expected installBusy cleared")
	}
	if p.msg == nil || p.msg.text != "install finished" || p.msg.bad {
		t.Errorf("msg=%+v, want default 'install finished' text", p.msg)
	}
	if cmd == nil {
		t.Errorf("expected loadGuard() cmd returned")
	}
}

func TestUpdateSetInstallMsgWithMessageAndNotes(t *testing.T) {
	p := newTestSettings(t)
	_, _ = p.Update(setInstallMsg{
		genTag: p.tag(), verb: "install", ok: false, message: "failed hard", notes: []string{"n1", "n2"},
	}, settingsCtx(p))
	if p.msg.text != "failed hard · n1 · n2" {
		t.Errorf("msg.text=%q", p.msg.text)
	}
	if !p.msg.bad {
		t.Errorf("expected bad=true for ok=false")
	}
}

func TestUpdateSetInstallMsgRepairStoresReport(t *testing.T) {
	p := newTestSettings(t)
	report := &install.Report{OK: true, Message: "repaired"}
	_, _ = p.Update(setInstallMsg{genTag: p.tag(), verb: "repair", ok: true, repair: report}, settingsCtx(p))
	if p.repairReport != report {
		t.Errorf("expected repairReport stored")
	}
}

func TestUpdateSetDoctorMsgAllGood(t *testing.T) {
	p := newTestSettings(t)
	p.diagBusy = true
	_, cmd := p.Update(setDoctorMsg{genTag: p.tag(), checks: []health.Check{{Name: "a", OK: health.StateOK}}}, settingsCtx(p))
	if p.diagBusy {
		t.Errorf("expected diagBusy cleared")
	}
	if p.msg == nil || p.msg.text != "✓ all good" {
		t.Errorf("msg=%+v", p.msg)
	}
	if cmd != nil {
		t.Errorf("expected nil cmd")
	}
}

func TestUpdateSetDoctorMsgWarningsOnly(t *testing.T) {
	p := newTestSettings(t)
	_, _ = p.Update(setDoctorMsg{genTag: p.tag(), checks: []health.Check{
		{Name: "a", OK: health.StateOK},
		{Name: "b", OK: health.StateWarn},
	}}, settingsCtx(p))
	if !strings.Contains(p.msg.text, "1 warning(s)") || p.msg.bad {
		t.Errorf("msg=%+v", p.msg)
	}
}

func TestUpdateSetDoctorMsgFailuresAndWarnings(t *testing.T) {
	p := newTestSettings(t)
	_, _ = p.Update(setDoctorMsg{genTag: p.tag(), checks: []health.Check{
		{Name: "a", OK: health.StateFail},
		{Name: "b", OK: health.StateWarn},
	}}, settingsCtx(p))
	if !p.msg.bad || !strings.Contains(p.msg.text, "1 problem(s)") || !strings.Contains(p.msg.text, "1 warning(s)") {
		t.Errorf("msg=%+v", p.msg)
	}
}

func TestUpdateKeyMsgIgnoredWhenUnfocused(t *testing.T) {
	p := newTestSettings(t)
	p.focused = false
	_, cmd := p.Update(tea.KeyMsg{Type: tea.KeyDown}, settingsCtx(p))
	if cmd != nil {
		t.Errorf("expected nil cmd when unfocused")
	}
}

func TestUpdateKeyMsgDispatchesNavigation(t *testing.T) {
	p := newTestSettings(t)
	p.focused = true
	p.sel = 0
	_, _ = p.Update(tea.KeyMsg{Type: tea.KeyDown}, settingsCtx(p))
	if p.sel != 1 {
		t.Errorf("expected sel to move down via key() dispatch, got %d", p.sel)
	}
}

func TestAllRowsOrderAndLength(t *testing.T) {
	p := newTestSettings(t)
	rows := p.allRows()
	want := []string{"guard", "self", "doctor", "repair", "ll-enabled", "ll-path", "range"}
	if len(rows) != len(want) {
		t.Fatalf("len(rows)=%d, want %d", len(rows), len(want))
	}
	for i, k := range want {
		if rows[i].kind != k {
			t.Errorf("rows[%d].kind=%q, want %q", i, rows[i].kind, k)
		}
	}
}

func TestCurrentClampsSelection(t *testing.T) {
	p := newTestSettings(t)
	p.sel = 0
	if got := p.current().kind; got != "guard" {
		t.Errorf("current()=%q, want guard", got)
	}
	p.sel = 1000
	if got := p.current().kind; got != "range" {
		t.Errorf("current() with out-of-range sel=%q, want range (last row)", got)
	}
}