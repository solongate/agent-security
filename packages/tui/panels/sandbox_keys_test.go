// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/shared"
	"github.com/solongate/agent-security/packages/tui"
)

func sbKeyMsg(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestSandboxKeyEditingModeDelegatesToTextinput(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.beginEdit("001", "/old")

	p.key(sbKeyMsg("x"))
	if p.input.Value() != "/oldx" {
		t.Errorf("a plain rune key while editing should reach textinput, got %q", p.input.Value())
	}

	p.key(sbKeyMsg("esc"))
	if p.editing || p.editID != "" {
		t.Error("esc should cancel editing and clear editID")
	}
}

func TestSandboxKeyEnterWhileEditingSubmits(t *testing.T) {
	c := sbHome(t)
	dir := t.TempDir()
	p := NewSandbox(tui.Deps{Client: c})
	p.beginEdit("", dir)

	cmd := p.key(sbKeyMsg("enter"))
	if cmd == nil {
		t.Fatal("enter while editing should submit and return a command")
	}
	if p.editing {
		t.Error("submit should leave editing mode")
	}
	msg := cmd().(sbDoneMsg)
	if msg.err != nil {
		t.Fatalf("create via submit failed: %v", msg.err)
	}
}

func TestSandboxKeyNavigation(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.boxes = []shared.Sandbox{{ID: "001"}, {ID: "002"}, {ID: "003"}}
	p.sel = 1
	p.confirm = "001"

	p.key(sbKeyMsg("up"))
	if p.sel != 0 {
		t.Errorf("up: sel = %d, want 0", p.sel)
	}
	if p.confirm != "" {
		t.Error("moving the selection should clear any pending delete confirmation")
	}

	p.key(sbKeyMsg("j"))
	if p.sel != 1 {
		t.Errorf("j (down alias): sel = %d, want 1", p.sel)
	}
	p.key(sbKeyMsg("down"))
	if p.sel != 2 {
		t.Errorf("down: sel = %d, want 2", p.sel)
	}
	p.key(sbKeyMsg("down"))
	if p.sel != 2 {
		t.Errorf("down should clamp at the last entry, got sel = %d", p.sel)
	}

	p.sel = 0
	p.key(sbKeyMsg("k"))
	if p.sel != 0 {
		t.Errorf("k (up alias) should floor at 0, got sel = %d", p.sel)
	}
}

func TestSandboxKeyNBeginsEmptyEdit(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.msg = &sbMessage{text: "stale"}
	p.key(sbKeyMsg("n"))
	if !p.editing || p.editID != "" {
		t.Errorf("'n' should begin editing with an empty id, got editing=%v editID=%q", p.editing, p.editID)
	}
	if p.input.Value() != "" {
		t.Errorf("'n' should begin with an empty input, got %q", p.input.Value())
	}
	if p.msg != nil {
		t.Error("beginEdit should clear any existing message")
	}
}

func TestSandboxKeyEnterAndEBeginEditFromCurrent(t *testing.T) {
	for _, key := range []string{"enter", "e"} {
		t.Run(key, func(t *testing.T) {
			p := NewSandbox(tui.Deps{})
			p.boxes = []shared.Sandbox{{ID: "001", Dir: "/srv/app"}}
			p.key(sbKeyMsg(key))
			if !p.editing || p.editID != "001" {
				t.Errorf("%q should begin editing box 001, got editing=%v editID=%q", key, p.editing, p.editID)
			}
			if p.input.Value() != "/srv/app" {
				t.Errorf("%q should preload the box's directory, got %q", key, p.input.Value())
			}
		})
	}

	t.Run("no current entry is a no-op", func(t *testing.T) {
		p := NewSandbox(tui.Deps{})
		p.key(sbKeyMsg("enter"))
		if p.editing {
			t.Error("enter with no boxes should not start editing")
		}
	})
}

func TestSandboxKeyMTogglesNetworkPreservingLabel(t *testing.T) {
	c := sbHome(t)
	dir := t.TempDir()
	p := NewSandbox(tui.Deps{Client: c})
	created := p.create(dir)().(sbDoneMsg)
	if created.err != nil {
		t.Fatalf("create: %v", created.err)
	}
	boxes, err := c.Settings.Sandboxes(context.Background())
	if err != nil || len(boxes) != 1 {
		t.Fatalf("Sandboxes() = %v, %v", boxes, err)
	}
	p.boxes = boxes
	p.sel = 0

	cmd := p.key(sbKeyMsg("m"))
	if cmd == nil {
		t.Fatal("'m' on a current box should return a command")
	}
	done := cmd().(sbDoneMsg)
	if done.err != nil {
		t.Fatalf("save via 'm': %v", done.err)
	}

	again, err := c.Settings.Sandboxes(context.Background())
	if err != nil || len(again) != 1 {
		t.Fatalf("Sandboxes() after toggle = %v, %v", again, err)
	}
	if again[0].Network {
		t.Error("'m' should have toggled network off")
	}
}

func TestSandboxKeyMNoCurrentEntryIsNoOp(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	if cmd := p.key(sbKeyMsg("m")); cmd != nil {
		t.Error("'m' with no boxes should return nil")
	}
}

// TestSandboxKeyMDisarmsPendingDelete guards against a regression where the
// network toggle left a pending delete confirmation armed across keypresses:
// a 'd' pressed after an unrelated 'm' would fire the deletion at once
// instead of asking for confirmation again.
func TestSandboxKeyMDisarmsPendingDelete(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.boxes = []shared.Sandbox{{ID: "001"}}
	p.sel = 0
	p.confirm = "001"

	if cmd := p.key(sbKeyMsg("m")); cmd == nil {
		t.Fatal("'m' on a current box should return a command")
	}
	if p.confirm != "" {
		t.Errorf("'m' should disarm a pending delete confirmation, got confirm = %q", p.confirm)
	}

	if cmd := p.key(sbKeyMsg("d")); cmd != nil {
		t.Error("the 'd' after 'm' should only re-arm confirmation, not return a delete command")
	}
	if p.confirm != "001" {
		t.Errorf("the 'd' after 'm' should re-arm confirmation, got confirm = %q", p.confirm)
	}
}

func TestSandboxKeyDRequiresConfirmation(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.boxes = []shared.Sandbox{{ID: "001"}}
	p.sel = 0

	if cmd := p.key(sbKeyMsg("d")); cmd != nil {
		t.Error("the first 'd' should only arm confirmation, not return a delete command")
	}
	if p.confirm != "001" {
		t.Errorf("confirm = %q, want 001", p.confirm)
	}
	if p.msg == nil {
		t.Error("the first 'd' should set a confirmation prompt message")
	}

	cmd := p.key(sbKeyMsg("d"))
	if cmd == nil {
		t.Fatal("the second 'd' should return the delete command")
	}
	if p.confirm != "" {
		t.Error("confirming delete should clear the pending confirmation")
	}
}

func TestSandboxKeyDNoCurrentEntryIsNoOp(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	if cmd := p.key(sbKeyMsg("d")); cmd != nil {
		t.Error("'d' with no boxes should return nil")
	}
}

func TestSandboxSubmitEmptyValueIsNoOp(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.beginEdit("001", "   ")
	if cmd := p.submit(); cmd != nil {
		t.Error("submit() with a blank value should return nil")
	}
	if p.editing {
		t.Error("submit() should still leave editing mode even on a blank value")
	}
}

func TestSandboxSubmitCreatesWhenNoEditID(t *testing.T) {
	c := sbHome(t)
	dir := t.TempDir()
	p := NewSandbox(tui.Deps{Client: c})
	p.beginEdit("", dir)
	msg := p.submit()().(sbDoneMsg)
	if msg.err != nil {
		t.Fatalf("submit (create path): %v", msg.err)
	}
}

// TestSandboxSubmitPreservesLabelOnEdit guards against a regression where
// editing an existing sandbox's directory via enter/e would wipe its Label
// by passing a hardcoded "" through to save() instead of the box's current
// Label.
func TestSandboxSubmitPreservesLabelOnEdit(t *testing.T) {
	c := sbHome(t)
	dir := t.TempDir()
	p := NewSandbox(tui.Deps{Client: c})
	created := p.create(dir)().(sbDoneMsg)
	if created.err != nil {
		t.Fatalf("create: %v", created.err)
	}
	boxes, err := c.Settings.Sandboxes(context.Background())
	if err != nil || len(boxes) != 1 {
		t.Fatalf("Sandboxes() = %v, %v", boxes, err)
	}
	id := boxes[0].ID

	// Give the box a label directly through the client, bypassing the TUI,
	// then edit its directory through submit() as the 'enter'/'e' flow does.
	if err := c.Settings.SandboxUpdate(context.Background(), id, dir, "important-label", true); err != nil {
		t.Fatalf("SandboxUpdate: %v", err)
	}
	boxes, err = c.Settings.Sandboxes(context.Background())
	if err != nil || len(boxes) != 1 {
		t.Fatalf("Sandboxes() = %v, %v", boxes, err)
	}
	newDir := t.TempDir()
	p.boxes, p.sel = boxes, 0
	p.beginEdit(id, newDir)
	done := p.submit()().(sbDoneMsg)
	if done.err != nil {
		t.Fatalf("submit (edit path): %v", done.err)
	}

	again, err := c.Settings.Sandbox(context.Background(), id)
	if err != nil {
		t.Fatalf("Sandbox(%q): %v", id, err)
	}
	if again.Label != "important-label" {
		t.Fatalf("Label = %q, want it preserved across an edit", again.Label)
	}
}

func TestSandboxCreateDuplicateDirFails(t *testing.T) {
	c := sbHome(t)
	dir := t.TempDir()
	p := NewSandbox(tui.Deps{Client: c})
	if msg := p.create(dir)().(sbDoneMsg); msg.err != nil {
		t.Fatalf("first create: %v", msg.err)
	}
	msg := p.create(dir)().(sbDoneMsg)
	if msg.err == nil {
		t.Error("creating a second sandbox on the same directory should fail")
	}
}

func TestSandboxSaveNetworkMessages(t *testing.T) {
	c := sbHome(t)
	dir := t.TempDir()
	p := NewSandbox(tui.Deps{Client: c})
	created := p.create(dir)().(sbDoneMsg)
	if created.err != nil {
		t.Fatalf("create: %v", created.err)
	}
	boxes, _ := c.Settings.Sandboxes(context.Background())
	id := boxes[0].ID

	onMsg := p.save(id, dir, "", true)().(sbDoneMsg)
	if onMsg.err != nil || onMsg.text == "" {
		t.Fatalf("save(network=true) = %+v", onMsg)
	}

	offMsg := p.save(id, dir, "", false)().(sbDoneMsg)
	if offMsg.err != nil {
		t.Fatalf("save(network=false): %v", offMsg.err)
	}
	if offMsg.text == onMsg.text {
		t.Error("the on/off network messages should differ")
	}
}

func TestSandboxSaveUnknownIDFails(t *testing.T) {
	c := sbHome(t)
	p := NewSandbox(tui.Deps{Client: c})
	msg := p.save("999", t.TempDir(), "", true)().(sbDoneMsg)
	if msg.err == nil {
		t.Error("save() on an unknown id should return an error")
	}
}

func TestSandboxDelSuccessAndUnknownID(t *testing.T) {
	c := sbHome(t)
	dir := t.TempDir()
	p := NewSandbox(tui.Deps{Client: c})
	created := p.create(dir)().(sbDoneMsg)
	if created.err != nil {
		t.Fatalf("create: %v", created.err)
	}
	boxes, _ := c.Settings.Sandboxes(context.Background())
	id := boxes[0].ID

	if msg := p.del(id)().(sbDoneMsg); msg.err != nil {
		t.Fatalf("del: %v", msg.err)
	}
	if msg := p.del(id)().(sbDoneMsg); msg.err == nil {
		t.Error("deleting an already-deleted id should fail")
	}
}