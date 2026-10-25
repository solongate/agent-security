// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

func TestSetupPosturesNamesAndOrder(t *testing.T) {
	postures := setupPostures()
	want := []string{"watch", "destructive", "path"}
	if len(postures) != len(want) {
		t.Fatalf("setupPostures() has %d entries, want %d", len(postures), len(want))
	}
	for i, name := range want {
		if postures[i].name != name {
			t.Errorf("postures[%d].name = %q, want %q", i, postures[i].name, name)
		}
	}
}

func TestSetupPostureWatchBuildsAnOpenDenylist(t *testing.T) {
	p := setupPostures()[0]
	set := p.build("")
	if set.Name != "watch" || set.Mode != client.ModeDenylist {
		t.Errorf("watch posture build() = %+v, want Name=watch Mode=denylist", set)
	}
	if len(set.Rules.Items) != 0 {
		t.Errorf("watch posture build() has %d rules, want 0", len(set.Rules.Items))
	}
}

func TestSetupPostureDestructiveBlocksKnownCommands(t *testing.T) {
	p := setupPostures()[1]
	set := p.build("")
	if len(set.Rules.Items) != 1 {
		t.Fatalf("destructive posture build() has %d rules, want 1", len(set.Rules.Items))
	}
	rule := set.Rules.Items[0]
	if rule.ID != "no-unrecoverable-commands" || rule.Effect != "DENY" {
		t.Errorf("destructive rule = %+v, want ID=no-unrecoverable-commands Effect=DENY", rule)
	}
	if rule.CommandConstraints == nil {
		t.Fatal("destructive rule has no CommandConstraints, want the destructive command list")
	}
	if len(rule.CommandConstraints.Denied) != len(setupDestructive) {
		t.Errorf("destructive rule denies %d commands, want %d", len(rule.CommandConstraints.Denied), len(setupDestructive))
	}
}

func TestSetupPosturePathBlocksGivenPath(t *testing.T) {
	p := setupPostures()[2]
	set := p.build("/home/me/game")
	if len(set.Rules.Items) != 1 {
		t.Fatalf("path posture build() has %d rules, want 1", len(set.Rules.Items))
	}
	rule := set.Rules.Items[0]
	if rule.PathConstraints == nil {
		t.Fatal("path rule has no PathConstraints, want the given path denied")
	}
	want := []string{"/home/me/game", "/home/me/game/*"}
	got := rule.PathConstraints.Denied
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("path rule denies %v, want %v", got, want)
	}
}

func TestNewSetupDefaults(t *testing.T) {
	m := newSetup(Deps{})
	if m.step != stepGuard {
		t.Errorf("newSetup() step = %v, want stepGuard", m.step)
	}
	if m.cols != 100 || m.rows != 30 {
		t.Errorf("newSetup() cols,rows = %d,%d, want 100,30", m.cols, m.rows)
	}
	if m.input.Placeholder != "/home/you/game" {
		t.Errorf("newSetup() input placeholder = %q, want /home/you/game", m.input.Placeholder)
	}
}

func TestSetupInitReturnsABatchedCmd(t *testing.T) {
	m := newSetup(Deps{})
	if cmd := m.Init(); cmd == nil {
		t.Error("Init() returned a nil cmd, want the tick+frame+probe batch")
	}
}

func TestSetupUpdateWindowSizeMsg(t *testing.T) {
	m := newSetup(Deps{})
	m.Update(tea.WindowSizeMsg{Width: 70, Height: 24})
	if m.cols != 70 || m.rows != 24 {
		t.Errorf("after WindowSizeMsg cols,rows = %d,%d, want 70,24", m.cols, m.rows)
	}
}

func TestSetupUpdateTickMsg(t *testing.T) {
	m := newSetup(Deps{})
	tick := m.tick
	_, cmd := m.Update(setupTickMsg{})
	if m.tick != tick+1 {
		t.Errorf("tick = %d, want %d", m.tick, tick+1)
	}
	if cmd == nil {
		t.Error("Update(setupTickMsg) returned a nil cmd, want the tick+probe batch")
	}
}

func TestSetupUpdateFrameMsg(t *testing.T) {
	m := newSetup(Deps{})
	frame := m.frame
	_, cmd := m.Update(setupFrameMsg{})
	if m.frame != frame+1 {
		t.Errorf("frame = %d, want %d", m.frame, frame+1)
	}
	if cmd == nil {
		t.Error("Update(setupFrameMsg) returned a nil cmd, want the next frame tick")
	}
}

func TestSetupAdvanceFromGuard(t *testing.T) {
	cases := []struct {
		name       string
		guardReady bool
		hadPolicy  bool
		wantStep   setupStep
	}{
		{"guard not ready stays put", false, false, stepGuard},
		{"guard ready, no policy yet goes to policy step", true, false, stepPolicy},
		{"guard ready and policy already exists skips straight to first call", true, true, stepFirstCall},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newSetup(Deps{})
			m.Update(setupProbeMsg{guardReady: tc.guardReady, hasPolicy: tc.hadPolicy})
			if m.step != tc.wantStep {
				t.Errorf("step = %v, want %v", m.step, tc.wantStep)
			}
		})
	}
}

func TestSetupAdvanceFromPolicy(t *testing.T) {
	t.Run("policy exists and not writing advances", func(t *testing.T) {
		m := newSetup(Deps{})
		m.step = stepPolicy
		m.Update(setupProbeMsg{hasPolicy: true})
		if m.step != stepFirstCall {
			t.Errorf("step = %v, want stepFirstCall", m.step)
		}
	})
	t.Run("still writing holds at policy step", func(t *testing.T) {
		m := newSetup(Deps{})
		m.step = stepPolicy
		m.writing = true
		m.Update(setupProbeMsg{hasPolicy: true})
		if m.step != stepPolicy {
			t.Errorf("step = %v, want stepPolicy while still writing", m.step)
		}
	})
}

func TestSetupAdvanceFromFirstCall(t *testing.T) {
	t.Run("a call arrived finishes setup", func(t *testing.T) {
		m := newSetup(Deps{})
		m.step = stepFirstCall
		rec := &setupCall{Tool: "bash"}
		before := time.Now()
		m.Update(setupProbeMsg{call: rec})
		if m.step != stepFinished {
			t.Errorf("step = %v, want stepFinished", m.step)
		}
		if m.arrived.Before(before) {
			t.Error("arrived was not updated to the time the call was observed")
		}
	})
	t.Run("no call yet stays put", func(t *testing.T) {
		m := newSetup(Deps{})
		m.step = stepFirstCall
		m.Update(setupProbeMsg{call: nil})
		if m.step != stepFirstCall {
			t.Errorf("step = %v, want stepFirstCall", m.step)
		}
	})
}

func TestSetupUpdateWroteMsgError(t *testing.T) {
	m := newSetup(Deps{})
	m.writing = true
	_, cmd := m.Update(setupWroteMsg{err: "boom"})
	if m.writing {
		t.Error("writing is still true after setupWroteMsg, want false")
	}
	if m.writeErr != "boom" {
		t.Errorf("writeErr = %q, want %q", m.writeErr, "boom")
	}
	if cmd != nil {
		t.Error("Update(setupWroteMsg{err}) returned a non-nil cmd, want nil")
	}
}

func TestSetupUpdateWroteMsgSuccess(t *testing.T) {
	m := newSetup(Deps{})
	m.writing = true
	_, cmd := m.Update(setupWroteMsg{name: "watch"})
	if m.writing {
		t.Error("writing is still true after a successful setupWroteMsg, want false")
	}
	if !m.hadPolicy {
		t.Error("hadPolicy was not set after a successful setupWroteMsg")
	}
	if m.wrote != "watch" {
		t.Errorf("wrote = %q, want %q", m.wrote, "watch")
	}
	if m.step != stepFirstCall {
		t.Errorf("step = %v, want stepFirstCall", m.step)
	}
	if cmd == nil {
		t.Error("Update(setupWroteMsg) returned a nil cmd, want the follow-up probe")
	}
}

func TestSetupWriteSetsWritingState(t *testing.T) {
	m := newSetup(Deps{})
	m.writeErr = "stale error"
	cmd := m.write("/some/path")
	if !m.writing {
		t.Error("write() did not set writing = true")
	}
	if m.writeErr != "" {
		t.Error("write() did not clear a stale writeErr")
	}
	if cmd == nil {
		t.Error("write() returned a nil cmd")
	}
	// cmd performs a real network call (client.Policies.Create) when invoked,
	// so it is intentionally never executed here.
}

func TestNeedsSetup(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.TUIConfig
		want bool
	}{
		{"never set up", config.TUIConfig{}, true},
		{"blank setupDoneAt", config.TUIConfig{SetupDoneAt: "   "}, true},
		{"already set up", config.TUIConfig{SetupDoneAt: "2024-01-01T00:00:00Z"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsSetup(tc.cfg); got != tc.want {
				t.Errorf("needsSetup(%+v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}