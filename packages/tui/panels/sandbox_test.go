// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/shared"
	"github.com/solongate/agent-security/packages/tui"
)

var errSBTestBoom = errors.New("boom")

func sbHome(t *testing.T) *client.Client {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return client.New()
}

func TestAtLeastZero(t *testing.T) {
	cases := []struct {
		name string
		n    int
		want int
	}{
		{"negative clamps to zero", -3, 0},
		{"zero stays zero", 0, 0},
		{"positive is unchanged", 5, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := atLeastZero(tc.n); got != tc.want {
				t.Errorf("atLeastZero(%d) = %d, want %d", tc.n, got, tc.want)
			}
		})
	}
}

func TestSandboxCur(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	if _, ok := p.cur(); ok {
		t.Error("cur() with no boxes should report ok=false")
	}

	p.boxes = []shared.Sandbox{{ID: "001", Dir: "/a"}, {ID: "002", Dir: "/b"}}
	p.sel = 1
	b, ok := p.cur()
	if !ok || b.ID != "002" {
		t.Errorf("cur() = %+v, ok=%v, want box 002", b, ok)
	}

	p.sel = -1
	if _, ok := p.cur(); ok {
		t.Error("cur() with a negative sel should report ok=false")
	}

	p.sel = 99
	if _, ok := p.cur(); ok {
		t.Error("cur() past the end of boxes should report ok=false")
	}
}

func TestSandboxInit(t *testing.T) {
	c := sbHome(t)
	p := NewSandbox(tui.Deps{Client: c})
	cmd := p.Init(tui.PanelContext{Deps: tui.Deps{Client: c}, Cols: 8, Rows: 3, Focused: true, Gen: 5})
	if cmd == nil {
		t.Fatal("Init() should return the load command")
	}
	if p.cols != 8 || p.rows != 3 || !p.focused || p.gen != 5 {
		t.Error("Init did not apply the panel context")
	}
	msg, ok := cmd().(sbListMsg)
	if !ok {
		t.Fatalf("Init() command produced %T, want sbListMsg", cmd())
	}
	if msg.gen != 5 || len(msg.boxes) != 0 {
		t.Errorf("sbListMsg = %+v, want gen=5 and no boxes on a fresh machine", msg)
	}
}

func TestSandboxLoadSwallowsErrors(t *testing.T) {
	// load() deliberately drops the error and returns an empty list instead,
	// since the panel has no error-display path for the listing itself.
	// Force readStore()'s error path (not the benign os.ErrNotExist case) by
	// making ~/.solongate a regular file instead of a directory, so reading
	// ~/.solongate/policy.json fails with ENOTDIR.
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".solongate"), []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("HOME", home)

	p := NewSandbox(tui.Deps{Client: client.New()})
	p.gen = 2
	msg := p.load()().(sbListMsg)
	if msg.gen != 2 {
		t.Errorf("gen = %d, want 2", msg.gen)
	}
	if msg.boxes != nil {
		t.Errorf("boxes = %v, want nil on error", msg.boxes)
	}
}

func TestSandboxUpdateListMsg(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.sel = 5
	ctx := tui.PanelContext{Gen: 1}

	next, _ := p.Update(sbListMsg{gen: 2, boxes: []shared.Sandbox{{ID: "001"}}}, ctx)
	pp := next.(*Sandbox)
	if pp.loaded {
		t.Error("a stale generation should be ignored")
	}

	next, _ = pp.Update(sbListMsg{gen: 1, boxes: []shared.Sandbox{{ID: "001"}}}, ctx)
	pp = next.(*Sandbox)
	if !pp.loaded || len(pp.boxes) != 1 {
		t.Errorf("boxes/loaded not updated: loaded=%v boxes=%v", pp.loaded, pp.boxes)
	}
	if pp.sel != 0 {
		t.Errorf("sel = %d, want clamped to 0 (only one box)", pp.sel)
	}
}

func TestSandboxUpdateDoneMsg(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	ctx := tui.PanelContext{Gen: 1}

	next, _ := p.Update(sbDoneMsg{gen: 2, text: "ignored"}, ctx)
	pp := next.(*Sandbox)
	if pp.msg != nil {
		t.Error("a stale generation should be ignored")
	}

	next, _ = pp.Update(sbDoneMsg{gen: 1, err: errSBTestBoom}, ctx)
	pp = next.(*Sandbox)
	if pp.msg == nil || !pp.msg.bad || pp.msg.text != "✗ "+errSBTestBoom.Error() {
		t.Errorf("msg = %+v, want a bad message with the error text", pp.msg)
	}

	next, cmd := pp.Update(sbDoneMsg{gen: 1, text: "box 001 created"}, ctx)
	pp = next.(*Sandbox)
	if pp.msg == nil || pp.msg.bad || pp.msg.text != "✓ box 001 created" {
		t.Errorf("msg = %+v, want a success message", pp.msg)
	}
	if cmd == nil {
		t.Error("a successful operation should trigger a reload")
	}
}

func TestSandboxUpdateKeyMsgDispatch(t *testing.T) {
	p := NewSandbox(tui.Deps{})
	p.boxes = []shared.Sandbox{{ID: "001"}, {ID: "002"}}
	next, _ := p.Update(tea.KeyMsg{Type: tea.KeyDown}, tui.PanelContext{})
	pp := next.(*Sandbox)
	if pp.sel != 1 {
		t.Errorf("sel = %d, want 1 after a down key reaches key()", pp.sel)
	}
}