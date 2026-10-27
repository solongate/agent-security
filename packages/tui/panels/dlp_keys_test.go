// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

var dlpNamedKeys = map[string]tea.KeyType{
	"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
	"esc": tea.KeyEsc, "enter": tea.KeyEnter, "ctrl+r": tea.KeyCtrlR,
}

func dlpKeyMsg(s string) tea.KeyMsg {
	if typ, ok := dlpNamedKeys[s]; ok {
		return tea.KeyMsg{Type: typ}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func newDLPWithDraft(t *testing.T) *DLP {
	t.Helper()
	p := NewDLP(tui.Deps{})
	p.available = []string{"ssn", "email", "phone", "ip", "mac"}
	p.adoptServer(client.SecurityLayers{})
	return p
}

func TestDLPKeyRequiresDraft(t *testing.T) {
	p := NewDLP(tui.Deps{})
	if cmd := p.key(dlpKeyMsg("A")); cmd != nil {
		t.Error("key() before a draft is loaded should return nil")
	}
	if len(p.dlp.DLP.Patterns) != 0 {
		t.Error("key() before a draft is loaded should not mutate state")
	}
}

func TestDLPKeyCtrlR(t *testing.T) {
	t.Run("bound panel ignores refresh", func(t *testing.T) {
		p := newDLPWithDraft(t)
		p.bound = true
		if cmd := p.key(dlpKeyMsg("ctrl+r")); cmd != nil {
			t.Error("a bound panel should not reload on ctrl+r")
		}
		if p.status != "" {
			t.Errorf("status = %q, want untouched", p.status)
		}
	})

	t.Run("unbound panel reloads and sets status", func(t *testing.T) {
		p := newDLPWithDraft(t)
		if cmd := p.key(dlpKeyMsg("ctrl+r")); cmd == nil {
			t.Error("ctrl+r should return a reload command")
		}
		if p.status == "" {
			t.Error("ctrl+r should set a status message")
		}
	})
}

func TestDLPKeyNavigation(t *testing.T) {
	// 9 builtins (rows of dlpCols=4: 0-3, 4-7, and a trailing partial row at 8)
	// plus 2 custom entries (9, 10) = 11 total.
	cases := []struct {
		name string
		sel  int
		key  string
		want int
	}{
		{"up within first row clamps to 0", 0, "up", 0},
		{"up moves back a full row", 5, "up", 1},
		{"up from first custom jumps to last builtin", 9, "up", 8},
		{"up within custom entries steps by one", 10, "up", 9},
		{"down within first row", 0, "down", 4},
		{"down from the trailing partial row enters custom", 8, "down", 9},
		{"down from first custom steps by one", 9, "down", 10},
		{"down clamps at the last entry", 10, "down", 10},
		{"left clamps at 0", 0, "left", 0},
		{"left steps back one column", 2, "left", 1},
		{"left on a custom entry is a no-op", 9, "left", 9},
		{"right steps forward one column", 0, "right", 1},
		{"right clamps at the last builtin column", 8, "right", 8},
		{"right on a custom entry is a no-op", 9, "right", 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newDLPWithDraft(t)
			p.available = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
			p.dlp.DLP.Custom = []client.CustomPattern{{Name: "x"}, {Name: "y"}}
			p.sel = tc.sel
			p.key(dlpKeyMsg(tc.key))
			if p.sel != tc.want {
				t.Errorf("sel = %d, want %d", p.sel, tc.want)
			}
		})
	}
}

func TestDLPDownOnEmptyListNeverPanics(t *testing.T) {
	// Issue #150: "down" on an empty list arms a negative selection. Once the
	// list grows again (server refresh or a new custom pattern), the next
	// keypress must fall back to the first entry instead of panicking.
	p := NewDLP(tui.Deps{})
	p.adoptServer(client.SecurityLayers{})
	p.key(dlpKeyMsg("down"))
	if got := p.selClamped(); got != 0 {
		t.Errorf("selClamped() after down on an empty list = %d, want 0", got)
	}
	p.available = []string{"ssn"}
	p.key(dlpKeyMsg(" "))
	cur, ok := p.current()
	if !ok || cur.name != "ssn" {
		t.Errorf("current() = %+v, ok=%v, want entry ssn", cur, ok)
	}
}

func TestDLPKeySelectAllAndUnselectAll(t *testing.T) {
	p := newDLPWithDraft(t)
	p.key(dlpKeyMsg("A"))
	if len(p.dlp.DLP.Patterns) != len(p.available) {
		t.Errorf("'A' selected %d patterns, want %d", len(p.dlp.DLP.Patterns), len(p.available))
	}
	if !p.dirty {
		t.Error("'A' should mark the panel dirty")
	}

	p.key(dlpKeyMsg("U"))
	if p.dlp.DLP.Patterns != nil {
		t.Errorf("'U' should clear all patterns, got %v", p.dlp.DLP.Patterns)
	}
}

func TestDLPKeyCycleMode(t *testing.T) {
	p := newDLPWithDraft(t)
	for i, want := range []client.LayerMode{client.LayerDetect, client.LayerRedact, client.LayerBlock, client.LayerOff} {
		p.key(dlpKeyMsg("m"))
		if p.dlp.DLP.Mode != want {
			t.Errorf("after %d presses of 'm', mode = %q, want %q", i+1, p.dlp.DLP.Mode, want)
		}
	}
}

func TestDLPKeyToggleSpace(t *testing.T) {
	p := newDLPWithDraft(t)
	p.sel = 0 // first builtin, "ssn"
	p.key(dlpKeyMsg(" "))
	if !containsString(p.dlp.DLP.Patterns, "ssn") {
		t.Errorf("space should toggle 'ssn' on, got %v", p.dlp.DLP.Patterns)
	}
	p.key(dlpKeyMsg(" "))
	if containsString(p.dlp.DLP.Patterns, "ssn") {
		t.Errorf("space should toggle 'ssn' back off, got %v", p.dlp.DLP.Patterns)
	}

	p.dlp.DLP.Custom = []client.CustomPattern{{Name: "custom1", Re: "x"}}
	p.sel = len(p.available) // first custom entry
	p.key(dlpKeyMsg(" "))
	if len(p.dlp.DLP.Patterns) != 0 {
		t.Error("space on a custom entry should not touch the builtin patterns list")
	}
}

func TestDLPKeyAddBeginsNameInput(t *testing.T) {
	p := newDLPWithDraft(t)
	p.newName, p.editIdx = "stale", 7
	p.key(dlpKeyMsg("a"))
	if p.adding != dlpAddName {
		t.Errorf("'a' should begin name input, adding = %q", p.adding)
	}
	if p.newName != "" || p.editIdx != -1 {
		t.Errorf("'a' should reset newName/editIdx, got %q/%d", p.newName, p.editIdx)
	}
	if !p.input.Focused() {
		t.Error("'a' should focus the input")
	}
}

func TestDLPKeyDeleteCustom(t *testing.T) {
	empty := NewDLP(tui.Deps{})
	empty.adoptServer(client.SecurityLayers{})
	if cmd := empty.key(dlpKeyMsg("d")); cmd != nil {
		t.Error("'d' with no current entry should return nil")
	}

	p := newDLPWithDraft(t)
	p.dlp.DLP.Custom = []client.CustomPattern{{Name: "one"}, {Name: "two"}}
	p.sel = len(p.available) + 1 // second custom entry
	p.key(dlpKeyMsg("d"))
	if len(p.dlp.DLP.Custom) != 1 || p.dlp.DLP.Custom[0].Name != "one" {
		t.Errorf("'d' should remove the selected custom entry, got %v", p.dlp.DLP.Custom)
	}
	if !p.dirty {
		t.Error("'d' should mark the panel dirty")
	}

	// 'd' on a builtin entry is a no-op: there is no case for dlpBuiltin.
	before := len(p.available)
	p.sel = 0
	p.dirty = false
	p.key(dlpKeyMsg("d"))
	if len(p.available) != before || p.dirty {
		t.Error("'d' on a builtin entry should do nothing")
	}
}

func TestDLPKeyEditEnterCustom(t *testing.T) {
	p := newDLPWithDraft(t)
	p.dlp.DLP.Custom = []client.CustomPattern{{Name: "one", Re: "re1"}}
	p.sel = len(p.available)
	p.key(dlpKeyMsg("e"))
	if p.adding != dlpAddRe || p.editIdx != 0 || p.newName != "one" {
		t.Errorf("'e' on a custom entry should begin editing its regex: adding=%q editIdx=%d newName=%q", p.adding, p.editIdx, p.newName)
	}
	if p.input.Value() != "re1" {
		t.Errorf("input should be preloaded with the existing regex, got %q", p.input.Value())
	}
}

func TestDLPKeySaveAndDiscardRespectBound(t *testing.T) {
	p := newDLPWithDraft(t)
	p.bound = true
	if cmd := p.key(dlpKeyMsg("s")); cmd != nil {
		t.Error("'s' on a bound panel should return nil")
	}
	if cmd := p.key(dlpKeyMsg("x")); cmd != nil {
		t.Error("'x' on a bound panel should return nil")
	}
}

func TestDLPSaveRequiresDraftAndServer(t *testing.T) {
	p := NewDLP(tui.Deps{})
	if cmd := p.save(); cmd != nil {
		t.Error("save() without a draft or server snapshot should return nil")
	}
}

func TestDLPSavePersistsDLPSettings(t *testing.T) {
	c := dlpHome(t)
	p := NewDLP(tui.Deps{Client: c})
	loaded := p.load()().(dlpLoadedMsg)
	if loaded.err != nil {
		t.Fatalf("load: %v", loaded.err)
	}
	p.server, p.haveSrv = loaded.data, true
	p.adoptServer(loaded.data.Layers)
	p.dlp.DLP.Mode = client.LayerBlock
	p.dlp.DLP.Patterns = []string{"ssn"}

	cmd := p.save()
	if cmd == nil {
		t.Fatal("save() should return a command once a draft and server exist")
	}
	saved := cmd().(dlpSavedMsg)
	if saved.err != nil {
		t.Fatalf("save: %v", saved.err)
	}
	if saved.layers.DLP.Mode != client.LayerBlock {
		t.Errorf("saved DLP.Mode = %q, want block", saved.layers.DLP.Mode)
	}

	again := p.load()().(dlpLoadedMsg)
	if again.data.Layers.DLP.Mode != client.LayerBlock {
		t.Errorf("DLP settings did not persist: %+v", again.data.Layers.DLP)
	}
}

func TestDLPDiscard(t *testing.T) {
	p := newDLPWithDraft(t)
	p.discard() // no server snapshot yet: must be a no-op, not a panic.

	server := client.SecurityLayers{}
	server.DLP.Mode = client.LayerDetect
	p.server, p.haveSrv = client.SecurityLayersResponse{Layers: server}, true
	p.dlp.DLP.Mode = client.LayerBlock
	p.dirty = true

	p.discard()
	if p.dlp.DLP.Mode != client.LayerDetect {
		t.Errorf("discard should revert to the server draft, got mode %q", p.dlp.DLP.Mode)
	}
	if p.dirty {
		t.Error("discard should clear dirty")
	}
	if p.status != "discarded" {
		t.Errorf("status = %q, want 'discarded'", p.status)
	}
}

func TestDLPEditKeyEsc(t *testing.T) {
	p := newDLPWithDraft(t)
	p.beginInput(dlpAddName, "partial")
	p.editKey(dlpKeyMsg("esc"))
	if p.adding != dlpAddNone {
		t.Errorf("esc should end input, adding = %q", p.adding)
	}
	if p.input.Value() != "" {
		t.Errorf("esc should clear the input, got %q", p.input.Value())
	}
}

func TestDLPEditKeyNonEnterDelegatesToTextinput(t *testing.T) {
	p := newDLPWithDraft(t)
	p.beginInput(dlpAddName, "")
	p.editKey(dlpKeyMsg("x"))
	if p.input.Value() != "x" {
		t.Errorf("typing should update the text input, got %q", p.input.Value())
	}
}

func TestDLPEditKeyEnterNameStep(t *testing.T) {
	t.Run("blank name ends input", func(t *testing.T) {
		p := newDLPWithDraft(t)
		p.beginInput(dlpAddName, "   ")
		p.editKey(dlpKeyMsg("enter"))
		if p.adding != dlpAddNone {
			t.Errorf("a blank name should cancel, adding = %q", p.adding)
		}
	})

	t.Run("a name advances to the regex step", func(t *testing.T) {
		p := newDLPWithDraft(t)
		p.beginInput(dlpAddName, "MyPattern")
		p.editKey(dlpKeyMsg("enter"))
		if p.adding != dlpAddRe {
			t.Errorf("adding = %q, want dlpAddRe", p.adding)
		}
		if p.newName != "MyPattern" {
			t.Errorf("newName = %q, want MyPattern", p.newName)
		}
		if p.input.Value() != "" {
			t.Errorf("the regex step should start with an empty input, got %q", p.input.Value())
		}
	})
}

func TestDLPEditKeyEnterRegexStep(t *testing.T) {
	t.Run("blank regex ends input without adding a pattern", func(t *testing.T) {
		p := newDLPWithDraft(t)
		p.newName = "Foo"
		p.beginInput(dlpAddRe, "   ")
		p.editKey(dlpKeyMsg("enter"))
		if len(p.dlp.DLP.Custom) != 0 {
			t.Errorf("a blank regex should not add a custom pattern, got %v", p.dlp.DLP.Custom)
		}
		if p.adding != dlpAddNone {
			t.Error("entering a blank regex should end input")
		}
	})

	t.Run("a regex appends a new custom pattern", func(t *testing.T) {
		p := newDLPWithDraft(t)
		p.newName = "Foo"
		p.editIdx = -1
		p.beginInput(dlpAddRe, "abc.*")
		p.editKey(dlpKeyMsg("enter"))
		if len(p.dlp.DLP.Custom) != 1 || p.dlp.DLP.Custom[0] != (client.CustomPattern{Name: "Foo", Re: "abc.*"}) {
			t.Errorf("Custom = %v, want one entry {Foo abc.*}", p.dlp.DLP.Custom)
		}
		if !p.dirty {
			t.Error("adding a custom pattern should mark the panel dirty")
		}
	})

	t.Run("a regex edits an existing custom pattern in place", func(t *testing.T) {
		p := newDLPWithDraft(t)
		p.dlp.DLP.Custom = []client.CustomPattern{{Name: "Old", Re: "old-re"}}
		p.newName = "New"
		p.editIdx = 0
		p.beginInput(dlpAddRe, "new-re")
		p.editKey(dlpKeyMsg("enter"))
		if len(p.dlp.DLP.Custom) != 1 || p.dlp.DLP.Custom[0] != (client.CustomPattern{Name: "New", Re: "new-re"}) {
			t.Errorf("Custom = %v, want one edited entry {New new-re}", p.dlp.DLP.Custom)
		}
	})
}

func TestToggleString(t *testing.T) {
	cases := []struct {
		name string
		list []string
		v    string
		want []string
	}{
		{"adds a missing value", []string{"a"}, "b", []string{"a", "b"}},
		{"removes a present value", []string{"a", "b"}, "a", []string{"b"}},
		{"empty list adds the value", nil, "a", []string{"a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toggleString(tc.list, tc.v)
			if len(got) != len(tc.want) {
				t.Fatalf("toggleString(%v, %q) = %v, want %v", tc.list, tc.v, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("toggleString(%v, %q) = %v, want %v", tc.list, tc.v, got, tc.want)
				}
			}
		})
	}
}