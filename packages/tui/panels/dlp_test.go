// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

var errDLPTestBoom = errors.New("boom")

func dlpHome(t *testing.T) *client.Client {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return client.New()
}

func TestDLPSelClampedAndCurrentWhenEmpty(t *testing.T) {
	p := NewDLP(tui.Deps{})
	if got := p.selClamped(); got != 0 {
		t.Errorf("selClamped() on empty panel = %d, want 0", got)
	}
	if _, ok := p.current(); ok {
		t.Error("current() on an empty panel should report ok=false")
	}
}

func TestDLPEntriesCombinesBuiltinAndCustom(t *testing.T) {
	p := NewDLP(tui.Deps{})
	p.available = []string{"ssn", "email"}
	p.dlp.DLP.Custom = []client.CustomPattern{{Name: "token", Re: "tok-.*"}}

	entries := p.entries()
	if len(entries) != 3 {
		t.Fatalf("entries() len = %d, want 3", len(entries))
	}
	if entries[0].kind != dlpBuiltin || entries[0].name != "ssn" {
		t.Errorf("entries[0] = %+v, want builtin ssn", entries[0])
	}
	if entries[1].kind != dlpBuiltin || entries[1].name != "email" {
		t.Errorf("entries[1] = %+v, want builtin email", entries[1])
	}
	if entries[2].kind != dlpCustom || entries[2].i != 0 {
		t.Errorf("entries[2] = %+v, want custom index 0", entries[2])
	}
}

func TestDLPSelClampedClampsToLastEntry(t *testing.T) {
	p := NewDLP(tui.Deps{})
	p.available = []string{"a", "b", "c"}
	p.sel = 10
	if got := p.selClamped(); got != 2 {
		t.Errorf("selClamped() = %d, want 2 (last index)", got)
	}
	cur, ok := p.current()
	if !ok || cur.name != "c" {
		t.Errorf("current() = %+v, ok=%v, want entry c", cur, ok)
	}
}

func TestDLPSelClampedClampsNegativeSel(t *testing.T) {
	// Issue #150: navigation on an empty list can arm a negative selection;
	// a negative index must never reach the entries() slice.
	p := NewDLP(tui.Deps{})
	p.available = []string{"a", "b", "c"}
	p.sel = -1
	if got := p.selClamped(); got != 0 {
		t.Errorf("selClamped() = %d, want 0 (first index)", got)
	}
	cur, ok := p.current()
	if !ok || cur.name != "a" {
		t.Errorf("current() = %+v, ok=%v, want entry a", cur, ok)
	}
}

func TestDLPWantsLeft(t *testing.T) {
	p := NewDLP(tui.Deps{})
	p.available = []string{"a", "b", "c", "d", "e"}
	p.dlp.DLP.Custom = []client.CustomPattern{{Name: "x"}, {Name: "y"}}

	cases := []struct {
		name string
		sel  int
		want bool
	}{
		{"first column of first row", 0, false},
		{"second column", 1, true},
		{"first column of second row", 4, false},
		{"first custom entry", 5, false},
		{"second custom entry", 6, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p.sel = tc.sel
			if got := p.WantsLeft(); got != tc.want {
				t.Errorf("WantsLeft() at sel=%d = %v, want %v", tc.sel, got, tc.want)
			}
		})
	}
}

func TestDLPAdoptServerDeepCopiesSlicesAndSetsHasDraft(t *testing.T) {
	p := NewDLP(tui.Deps{})
	patterns := []string{"ssn"}
	custom := []client.CustomPattern{{Name: "token", Re: "tok-.*"}}
	src := client.SecurityLayers{}
	src.DLP.Mode = client.LayerBlock
	src.DLP.Patterns = patterns
	src.DLP.Custom = custom

	p.adoptServer(src)

	if !p.hasDraft {
		t.Error("adoptServer should set hasDraft = true")
	}
	if p.dlp.DLP.Mode != client.LayerBlock {
		t.Errorf("DLP.Mode = %q, want block", p.dlp.DLP.Mode)
	}

	// Mutate the original backing arrays; the panel's copies must not change.
	patterns[0] = "mutated"
	custom[0].Name = "mutated"
	if p.dlp.DLP.Patterns[0] != "ssn" {
		t.Errorf("Patterns was not deep-copied: %v", p.dlp.DLP.Patterns)
	}
	if p.dlp.DLP.Custom[0].Name != "token" {
		t.Errorf("Custom was not deep-copied: %v", p.dlp.DLP.Custom)
	}
}

func TestDLPSetBound(t *testing.T) {
	p := NewDLP(tui.Deps{})
	sec := client.SecurityLayers{}
	sec.DLP.Mode = client.LayerDetect
	available := []string{"ssn"}

	p.SetBound(sec, available, true)

	if !p.bound {
		t.Error("SetBound should set bound = true")
	}
	if p.loading {
		t.Error("SetBound should clear loading")
	}
	if len(p.available) != 1 || p.available[0] != "ssn" {
		t.Errorf("available = %v, want [ssn]", p.available)
	}
	if !p.dirty {
		t.Error("SetBound(..., dirty=true) should mark the panel dirty")
	}
	if p.Bound().DLP.Mode != client.LayerDetect {
		t.Errorf("Bound().DLP.Mode = %q, want detect", p.Bound().DLP.Mode)
	}
}

func TestDLPInitWhenBoundReturnsNil(t *testing.T) {
	p := NewDLP(tui.Deps{})
	p.bound = true
	cmd := p.Init(tui.PanelContext{Cols: 10, Rows: 5, Focused: true, Gen: 2})
	if cmd != nil {
		t.Error("Init() on a bound panel should return a nil command")
	}
	if p.cols != 10 || p.rows != 5 || !p.focused || p.gen != 2 {
		t.Errorf("Init did not apply the context: cols=%d rows=%d focused=%v gen=%d", p.cols, p.rows, p.focused, p.gen)
	}
}

func TestDLPInitWhenNotBoundBatchesLoadAndTick(t *testing.T) {
	p := NewDLP(tui.Deps{})
	cmd := p.Init(tui.PanelContext{})
	if cmd == nil {
		t.Fatal("Init() on an unbound panel should return a command")
	}
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("Init() command produced %T, want tea.BatchMsg", msg)
	}
	if len(batch) != 2 {
		t.Errorf("batch has %d commands, want 2 (load + tick)", len(batch))
	}
}

func TestDLPLoadReturnsLayersFromClient(t *testing.T) {
	c := dlpHome(t)
	p := NewDLP(tui.Deps{Client: c})
	p.gen = 3

	msg := p.load()()
	loaded, ok := msg.(dlpLoadedMsg)
	if !ok {
		t.Fatalf("load() produced %T, want dlpLoadedMsg", msg)
	}
	if loaded.err != nil {
		t.Fatalf("unexpected error: %v", loaded.err)
	}
	if loaded.data.Layers.DLP.Mode != client.LayerOff {
		t.Errorf("a fresh machine should have DLP off, got %q", loaded.data.Layers.DLP.Mode)
	}
	if loaded.gen != p.gen {
		t.Errorf("genTag.gen = %d, want %d", loaded.gen, p.gen)
	}
}

func TestDLPUpdateLoadedMsg(t *testing.T) {
	t.Run("success while clean adopts the server draft", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		data := client.SecurityLayersResponse{AvailablePatterns: []string{"ssn", "email"}}
		data.Layers.DLP.Mode = client.LayerRedact

		next, cmd := p.Update(dlpLoadedMsg{data: data}, tui.PanelContext{})
		pp := next.(*DLP)
		if cmd != nil {
			t.Error("handling dlpLoadedMsg should not itself return a command")
		}
		if pp.loading {
			t.Error("loading should be cleared")
		}
		if !pp.haveSrv {
			t.Error("haveSrv should be set")
		}
		if len(pp.available) != 2 {
			t.Errorf("available = %v, want 2 entries", pp.available)
		}
		if pp.dlp.DLP.Mode != client.LayerRedact {
			t.Errorf("dirty panel should adopt the server draft, mode = %q", pp.dlp.DLP.Mode)
		}
	})

	t.Run("success while dirty keeps the local draft", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		p.dirty = true
		p.dlp.DLP.Mode = client.LayerBlock

		data := client.SecurityLayersResponse{AvailablePatterns: []string{"ssn"}}
		data.Layers.DLP.Mode = client.LayerRedact

		next, _ := p.Update(dlpLoadedMsg{data: data}, tui.PanelContext{})
		pp := next.(*DLP)
		if pp.dlp.DLP.Mode != client.LayerBlock {
			t.Errorf("a dirty draft should not be overwritten, got mode %q", pp.dlp.DLP.Mode)
		}
		if !pp.haveSrv || len(pp.available) != 1 {
			t.Errorf("server snapshot should still be recorded even while dirty: haveSrv=%v available=%v", pp.haveSrv, pp.available)
		}
	})

	t.Run("error records loadErr and leaves state alone", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		boom := errDLPTestBoom
		next, _ := p.Update(dlpLoadedMsg{err: boom}, tui.PanelContext{})
		pp := next.(*DLP)
		if pp.loadErr != boom {
			t.Errorf("loadErr = %v, want %v", pp.loadErr, boom)
		}
		if pp.haveSrv {
			t.Error("haveSrv should not be set on error")
		}
	})
}

func TestDLPUpdateSavedMsg(t *testing.T) {
	t.Run("success adopts layers and queues a reload", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		p.dirty = true
		layers := client.SecurityLayers{}
		layers.DLP.Mode = client.LayerBlock

		next, cmd := p.Update(dlpSavedMsg{layers: layers}, tui.PanelContext{})
		pp := next.(*DLP)
		if pp.dirty {
			t.Error("a successful save should clear dirty")
		}
		if pp.status != "✓ Saved" {
			t.Errorf("status = %q, want '✓ Saved'", pp.status)
		}
		if pp.dlp.DLP.Mode != client.LayerBlock {
			t.Errorf("dlp.DLP.Mode = %q, want block", pp.dlp.DLP.Mode)
		}
		if cmd == nil {
			t.Error("a successful save should return a reload command")
		}
	})

	t.Run("error sets a status and returns no command", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		p.dirty = true
		next, cmd := p.Update(dlpSavedMsg{err: errDLPTestBoom}, tui.PanelContext{})
		pp := next.(*DLP)
		if !pp.dirty {
			t.Error("a failed save should leave dirty untouched")
		}
		if pp.status != "✗ "+errDLPTestBoom.Error() {
			t.Errorf("status = %q", pp.status)
		}
		if cmd != nil {
			t.Error("a failed save should not return a command")
		}
	})
}

func TestDLPUpdateTickMsg(t *testing.T) {
	t.Run("stale token is ignored", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		_, cmd := p.Update(dlpTickMsg{genTag{tok: p.tok + 1}}, tui.PanelContext{})
		if cmd != nil {
			t.Error("a tick with a stale token should return no command")
		}
	})

	t.Run("fresh token while clean rearms and reloads", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		_, cmd := p.Update(dlpTickMsg{genTag{tok: p.tok}}, tui.PanelContext{})
		if cmd == nil {
			t.Fatal("expected a batched command")
		}
		msg := cmd()
		if _, ok := msg.(tea.BatchMsg); !ok {
			t.Errorf("command produced %T, want tea.BatchMsg", msg)
		}
	})

	t.Run("fresh token while dirty only rearms the tick", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		p.dirty = true
		_, cmd := p.Update(dlpTickMsg{genTag{tok: p.tok}}, tui.PanelContext{})
		if cmd == nil {
			t.Error("expected the rearmed tick command")
		}
	})
}

func TestDLPUpdateKeyMsgDispatch(t *testing.T) {
	t.Run("ignored when unfocused", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		p.adoptServer(client.SecurityLayers{})
		next, _ := p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("A")}, tui.PanelContext{Focused: false})
		pp := next.(*DLP)
		if len(pp.dlp.DLP.Patterns) != 0 {
			t.Error("a key message while unfocused should not mutate state")
		}
	})

	t.Run("routes to key() when not adding", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		p.available = []string{"ssn"}
		p.adoptServer(client.SecurityLayers{})
		next, _ := p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("A")}, tui.PanelContext{Focused: true})
		pp := next.(*DLP)
		if len(pp.dlp.DLP.Patterns) != 1 {
			t.Errorf("'A' should select all available patterns, got %v", pp.dlp.DLP.Patterns)
		}
	})

	t.Run("routes to editKey() while adding", func(t *testing.T) {
		p := NewDLP(tui.Deps{})
		p.adoptServer(client.SecurityLayers{})
		p.adding = dlpAddName
		p.input.Focus()
		next, _ := p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("z")}, tui.PanelContext{Focused: true})
		pp := next.(*DLP)
		if pp.input.Value() != "z" {
			t.Errorf("input value = %q, want 'z' typed into the text input", pp.input.Value())
		}
	})
}

func TestContainsString(t *testing.T) {
	cases := []struct {
		name string
		list []string
		v    string
		want bool
	}{
		{"present", []string{"a", "b"}, "b", true},
		{"absent", []string{"a", "b"}, "c", false},
		{"empty list", nil, "a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsString(tc.list, tc.v); got != tc.want {
				t.Errorf("containsString(%v, %q) = %v, want %v", tc.list, tc.v, got, tc.want)
			}
		})
	}
}