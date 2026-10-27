// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

func runeKey(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func TestMatches(t *testing.T) {
	e := streamItem{Tool: "Read", Agent: "AgentX", Decision: "DENY", Permission: "fs", Rule: "r1", Detail: "secret stuff"}
	cases := []struct {
		name  string
		query string
		want  bool
	}{
		{"empty query matches anything", "", true},
		{"whitespace-only query matches anything", "   ", true},
		{"matches tool, case-insensitive", "read", true},
		{"matches agent", "AGENTX", true},
		{"matches detail substring", "secret", true},
		{"no match", "nonexistent", false},
	}
	p := &Live{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p.search = tc.query
			if got := p.matches(e); got != tc.want {
				t.Errorf("matches(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestSignalOK(t *testing.T) {
	allow := streamItem{Decision: "ALLOW"}
	deny := streamItem{Decision: "DENY"}
	dlp := streamItem{Decision: "ALLOW", DLP: true}
	burst := streamItem{Decision: "ALLOW", Burst: true}

	p := &Live{}
	cases := []struct {
		signal string
		item   streamItem
		want   bool
	}{
		{"none", allow, true},
		{"", allow, true},
		{"deny", allow, false},
		{"deny", deny, true},
		{"dlp", allow, false},
		{"dlp", dlp, true},
		{"ratelimit", allow, false},
		{"ratelimit", burst, true},
	}
	for _, tc := range cases {
		p.signal = tc.signal
		if got := p.signalOK(tc.item); got != tc.want {
			t.Errorf("signal=%q signalOK(%+v) = %v, want %v", tc.signal, tc.item, got, tc.want)
		}
	}
}

func TestFilteredAndVisibleDesc(t *testing.T) {
	p := &Live{merged: []streamItem{
		{ID: "1", Tool: "Read", Decision: "ALLOW"},
		{ID: "2", Tool: "Write", Decision: "DENY"},
		{ID: "3", Tool: "Read", Decision: "ALLOW", Burst: true},
	}}

	p.search, p.signal = "", "none"
	if got := p.filtered(); len(got) != 3 {
		t.Fatalf("filtered() with no filters = %d items, want 3", len(got))
	}

	p.search, p.signal = "read", "none"
	got := p.filtered()
	if len(got) != 2 || got[0].ID != "1" || got[1].ID != "3" {
		t.Errorf("filtered() by search 'read' = %+v, want ids [1,3] in original order", got)
	}

	p.search, p.signal = "", "deny"
	got = p.filtered()
	if len(got) != 1 || got[0].ID != "2" {
		t.Errorf("filtered() by signal 'deny' = %+v, want id [2]", got)
	}

	p.search, p.signal = "", "none"
	desc := p.visibleDesc()
	if len(desc) != 3 || desc[0].ID != "3" || desc[2].ID != "1" {
		t.Errorf("visibleDesc() = %+v, want reversed order [3,2,1]", desc)
	}
}

func TestSelected(t *testing.T) {
	p := &Live{}
	if _, ok := p.selected(nil); ok {
		t.Error("selected() on an empty slice should return ok=false")
	}

	visible := []streamItem{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	p.sel = 1
	if got, ok := p.selected(visible); !ok || got.ID != "b" {
		t.Errorf("selected() = %+v, want id b", got)
	}

	p.sel = 99
	if got, ok := p.selected(visible); !ok || got.ID != "c" {
		t.Errorf("selected() with sel beyond bounds = %+v, want clamped to last (id c)", got)
	}

	p.sel = -5
	if got, ok := p.selected(visible); !ok || got.ID != "a" {
		t.Errorf("selected() with negative sel = %+v, want clamped to first (id a)", got)
	}
}

func newTestLiveForKeys() *Live {
	p := newLive(tui.Deps{})
	p.mode = "stream"
	return p
}

func TestOnKeyEditingSearchTakesPriorityOverEverythingElse(t *testing.T) {
	p := newTestLiveForKeys()
	p.editingSearch = true
	p.frozen = false

	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}
	p.onKey(tea.KeyMsg{Type: tea.KeySpace}, ctx)

	if p.frozen {
		t.Error("space while editingSearch should be handled by editSearch, not toggle frozen")
	}
}

func TestOnKeySpaceTogglesFrozen(t *testing.T) {
	p := newTestLiveForKeys()
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(tea.KeyMsg{Type: tea.KeySpace}, ctx)
	if !p.frozen {
		t.Fatal("space should freeze the stream")
	}
	p.onKey(tea.KeyMsg{Type: tea.KeySpace}, ctx)
	if p.frozen {
		t.Error("space again should unfreeze the stream")
	}
}

func TestOnKeyIgnoredWhenFrozen(t *testing.T) {
	p := newTestLiveForKeys()
	p.frozen = true
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(runeKey("l"), ctx)
	if p.mode != "stream" {
		t.Errorf("mode = %q, keys other than space should be swallowed while frozen", p.mode)
	}
}

func TestOnKeyHelpToggle(t *testing.T) {
	p := newTestLiveForKeys()
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(runeKey("?"), ctx)
	if !p.help {
		t.Fatal("'?' should open help")
	}

	p.onKey(runeKey("l"), ctx)
	if p.help {
		t.Error("any key should dismiss help")
	}
	if p.mode != "stream" {
		t.Error("the key that dismissed help should not also be processed as a command")
	}
}

func TestOnKeySearchActivation(t *testing.T) {
	p := newTestLiveForKeys()
	p.search = "foo"
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(runeKey("/"), ctx)
	if !p.editingSearch {
		t.Fatal("'/' should enter search editing mode")
	}
	if p.input.Value() != "foo" {
		t.Errorf("input value = %q, want prior search value %q", p.input.Value(), "foo")
	}
	if !p.input.Focused() {
		t.Error("input should be focused after entering search mode")
	}
}

func TestOnKeySearchActivationBlockedInPickMode(t *testing.T) {
	p := newTestLiveForKeys()
	p.mode = "pick"
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(runeKey("/"), ctx)
	if p.editingSearch {
		t.Error("'/' should be ignored while mode is 'pick'")
	}
}

func TestOnKeyInspectModeNavigation(t *testing.T) {
	p := newTestLiveForKeys()
	p.mode = "inspect"
	p.inspect = &streamItem{ID: "x"}
	p.inspectScroll = 5
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(tea.KeyMsg{Type: tea.KeyUp}, ctx)
	if p.inspectScroll != 4 {
		t.Errorf("inspectScroll = %d, want 4", p.inspectScroll)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgUp}, ctx)
	if p.inspectScroll != 0 {
		t.Errorf("inspectScroll = %d, want 0 (floored)", p.inspectScroll)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyDown}, ctx)
	if p.inspectScroll != 1 {
		t.Errorf("inspectScroll = %d, want 1", p.inspectScroll)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgDown}, ctx)
	if p.inspectScroll != 11 {
		t.Errorf("inspectScroll = %d, want 11", p.inspectScroll)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyLeft}, ctx)
	if p.mode != "stream" || p.inspect != nil {
		t.Errorf("left arrow should exit inspect mode and clear inspect, got mode=%q inspect=%v", p.mode, p.inspect)
	}
}

func TestOnKeyLayersModeNavigation(t *testing.T) {
	p := newTestLiveForKeys()
	p.mode = "layers"
	p.layersScroll = 5
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(tea.KeyMsg{Type: tea.KeyUp}, ctx)
	if p.layersScroll != 4 {
		t.Errorf("layersScroll = %d, want 4", p.layersScroll)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgUp}, ctx)
	if p.layersScroll != 0 {
		t.Errorf("layersScroll = %d, want 0 (floored)", p.layersScroll)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyDown}, ctx)
	if p.layersScroll != 1 {
		t.Errorf("layersScroll = %d, want 1", p.layersScroll)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgDown}, ctx)
	if p.layersScroll != 11 {
		t.Errorf("layersScroll = %d, want 11", p.layersScroll)
	}
	p.onKey(runeKey("l"), ctx)
	if p.mode != "stream" {
		t.Errorf("'l' while in layers mode should return to stream, got mode=%q", p.mode)
	}
}

func TestOnKeyEnterOpensInspect(t *testing.T) {
	p := newTestLiveForKeys()
	p.merged = []streamItem{{ID: "only"}}
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(tea.KeyMsg{Type: tea.KeyEnter}, ctx)
	if p.mode != "inspect" {
		t.Fatalf("mode = %q, want inspect", p.mode)
	}
	if p.inspect == nil || p.inspect.ID != "only" {
		t.Errorf("inspect = %v, want the selected item", p.inspect)
	}
}

func TestOnKeyEnterWithNoVisibleItemsIsNoop(t *testing.T) {
	p := newTestLiveForKeys()
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(tea.KeyMsg{Type: tea.KeyEnter}, ctx)
	if p.mode != "stream" || p.inspect != nil {
		t.Errorf("enter with nothing visible should be a no-op, got mode=%q inspect=%v", p.mode, p.inspect)
	}
}

func TestOnKeyStreamNavigationBounds(t *testing.T) {
	p := newTestLiveForKeys()
	for i := 0; i < 10; i++ {
		p.merged = append(p.merged, streamItem{ID: string(rune('0' + i)), At: int64(i)})
	}
	// Rows=10 drives streamRows()=4 and streamBody=max(3,4-1)=3.
	ctx := tui.PanelContext{Rows: 10, Now: time.UnixMilli(1000)}

	p.onKey(tea.KeyMsg{Type: tea.KeyDown}, ctx)
	if p.sel != 1 {
		t.Fatalf("sel = %d, want 1 after one Down", p.sel)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgDown}, ctx)
	if p.sel != 4 {
		t.Fatalf("sel = %d, want 4 after PgDown (+3)", p.sel)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgUp}, ctx)
	if p.sel != 1 {
		t.Fatalf("sel = %d, want 1 after PgUp (-3)", p.sel)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyUp}, ctx)
	if p.sel != 0 {
		t.Fatalf("sel = %d, want 0 after Up", p.sel)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgUp}, ctx)
	if p.sel != 0 {
		t.Fatalf("sel = %d, want 0 (floored)", p.sel)
	}
	for i := 0; i < 5; i++ {
		p.onKey(tea.KeyMsg{Type: tea.KeyPgDown}, ctx)
	}
	if p.sel != 9 {
		t.Fatalf("sel = %d, want 9 (clamped to len-1)", p.sel)
	}
}

func TestOnKeySignalToggle(t *testing.T) {
	p := newTestLiveForKeys()
	p.sel = 5
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}

	p.onKey(runeKey("d"), ctx)
	if p.signal != "deny" || p.sel != 0 {
		t.Fatalf("after 'd': signal=%q sel=%d, want deny/0", p.signal, p.sel)
	}
	p.sel = 3
	p.onKey(runeKey("d"), ctx)
	if p.signal != "none" {
		t.Errorf("pressing 'd' again should toggle it back off, got %q", p.signal)
	}
	p.onKey(runeKey("x"), ctx)
	if p.signal != "dlp" {
		t.Errorf("after 'x': signal=%q, want dlp", p.signal)
	}
	p.onKey(runeKey("d"), ctx)
	if p.signal != "deny" {
		t.Errorf("'d' while signal=dlp should switch to deny, got %q", p.signal)
	}
	p.onKey(runeKey("r"), ctx)
	if p.signal != "ratelimit" {
		t.Errorf("after 'r': signal=%q, want ratelimit", p.signal)
	}
}

func TestEditSearchEnterAndEsc(t *testing.T) {
	for _, kt := range []tea.KeyType{tea.KeyEnter, tea.KeyEsc} {
		p := newTestLiveForKeys()
		p.editingSearch = true
		p.input.Focus()

		cmd := p.editSearch(tea.KeyMsg{Type: kt})
		if p.editingSearch {
			t.Errorf("editingSearch should be false after key type %v", kt)
		}
		if p.input.Focused() {
			t.Errorf("input should be blurred after key type %v", kt)
		}
		if cmd != nil {
			t.Errorf("Enter/Esc should return a nil cmd, got %v for key type %v", cmd, kt)
		}
	}
}

func TestEditSearchTrailingSlashClosesSearch(t *testing.T) {
	p := newTestLiveForKeys()
	p.editingSearch = true
	p.search = "kept"
	p.input.Focus()
	p.input.SetValue("kept")

	p.editSearch(runeKey("/"))

	if p.editingSearch {
		t.Error("a trailing '/' should close search editing")
	}
	if p.input.Value() != "kept" {
		t.Errorf("input value = %q, want the trailing '/' stripped back to %q", p.input.Value(), "kept")
	}
	if p.search != "kept" {
		t.Errorf("p.search = %q, want unchanged %q (updated only on the normal-input path)", p.search, "kept")
	}
}

func TestEditSearchUpdatesSearchAndResetsSel(t *testing.T) {
	p := newTestLiveForKeys()
	p.editingSearch = true
	p.sel = 7
	p.input.Focus()

	p.editSearch(runeKey("a"))

	if p.search != "a" {
		t.Errorf("search = %q, want %q", p.search, "a")
	}
	if p.sel != 0 {
		t.Errorf("sel = %d, want reset to 0 on search change", p.sel)
	}
}

func TestDoActionNoSelection(t *testing.T) {
	p := newTestLiveForKeys()
	if cmd := p.doAction("whitelist", nil, 1000); cmd != nil {
		t.Error("doAction with nothing selected should return nil")
	}
	if p.action != nil {
		t.Error("doAction with nothing selected should not set a flash message")
	}
}

func TestDoActionValidation(t *testing.T) {
	deny := streamItem{ID: "d", Decision: "DENY"}
	allow := streamItem{ID: "a", Decision: "ALLOW"}

	cases := []struct {
		name      string
		act       string
		item      streamItem
		wantCmd   bool
		wantText  string
		wantLevel string
	}{
		{"whitelist a deny is valid", "whitelist", deny, true, "whitelisting…", "ok"},
		{"whitelist an allow is invalid", "whitelist", allow, false, "select a DENY to whitelist (w)", "bad"},
		{"block an allow is valid", "block", allow, true, "blocking…", "ok"},
		{"block a deny is invalid", "block", deny, false, "select an ALLOW to block (b)", "bad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestLiveForKeys()
			p.sel = 0
			cmd := p.doAction(tc.act, []streamItem{tc.item}, 1000)
			if (cmd != nil) != tc.wantCmd {
				t.Errorf("cmd non-nil = %v, want %v", cmd != nil, tc.wantCmd)
			}
			if p.action == nil || p.action.text != tc.wantText {
				t.Errorf("action = %+v, want text %q", p.action, tc.wantText)
			}
			if p.action.level != tc.wantLevel {
				t.Errorf("action.level = %q, want %q", p.action.level, tc.wantLevel)
			}
			if p.action.until != 1000+4000 {
				t.Errorf("action.until = %d, want %d", p.action.until, int64(5000))
			}
		})
	}
}

func TestExportWritesJSONLAndSetsSuccessFlash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := newTestLiveForKeys()
	visible := []streamItem{
		{ID: "1", Tool: "Read", Decision: "ALLOW"},
		{ID: "2", Tool: "Write", Decision: "DENY"},
	}
	p.export(visible, 1000)

	if p.action == nil || p.action.level != "ok" {
		t.Fatalf("action = %+v, want a success flash", p.action)
	}
	if !strings.Contains(p.action.text, "exported 2 lines") {
		t.Errorf("action.text = %q, want it to mention 2 exported lines", p.action.text)
	}

	file := filepath.Join(config.Dir(), "live-export.jsonl")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("export file not written: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var first streamItem
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 is not valid JSON: %v", err)
	}
	if first.ID != "1" {
		t.Errorf("first line ID = %q, want %q", first.ID, "1")
	}
}

func TestExportMkdirFailureSetsErrorFlash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// config.Dir() == $HOME/.solongate; pre-creating it as a plain file
	// forces os.MkdirAll to fail.
	if err := os.WriteFile(filepath.Join(home, ".solongate"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := newTestLiveForKeys()
	p.export([]streamItem{{ID: "1"}}, 1000)

	if p.action == nil || p.action.level != "bad" {
		t.Fatalf("action = %+v, want a failure flash", p.action)
	}
	if !strings.HasPrefix(p.action.text, "✗ export failed:") {
		t.Errorf("action.text = %q, want it to start with the export-failed prefix", p.action.text)
	}
}

func liveHelpKeyMsg(token string) (tea.KeyMsg, bool) {
	switch token {
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace}, true
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}, true
	case "←":
		return tea.KeyMsg{Type: tea.KeyLeft}, true
	default:
		if len([]rune(token)) != 1 {
			return tea.KeyMsg{}, false
		}
		return runeKey(token), true
	}
}

func liveSnap(p *Live) string {
	action := ""
	if p.action != nil {
		action = p.action.level + "|" + p.action.text
	}
	inspect := ""
	if p.inspect != nil {
		inspect = p.inspect.ID
	}
	return strings.Join([]string{
		"mode=" + p.mode,
		"signal=" + p.signal,
		"sel=" + strconv.Itoa(p.sel),
		"help=" + strconv.FormatBool(p.help),
		"frozen=" + strconv.FormatBool(p.frozen),
		"searchEdit=" + strconv.FormatBool(p.editingSearch),
		"inspect=" + inspect,
		"layersScroll=" + strconv.Itoa(p.layersScroll),
		"action=" + action,
	}, ";")
}

func preparedLiveForHelpKey(t *testing.T, token string) *Live {
	t.Helper()
	p := newTestLiveForKeys()
	switch token {
	case "w":
		p.merged = []streamItem{{ID: "d1", Decision: "DENY", Tool: "Bash"}}
	case "b":
		p.merged = []streamItem{{ID: "a1", Decision: "ALLOW", Tool: "Read"}}
	case "enter", "e":
		p.merged = []streamItem{{ID: "row", Decision: "ALLOW", Tool: "Read"}}
		if token == "e" {
			t.Setenv("HOME", t.TempDir())
		}
	case "←":
		p.mode = "inspect"
		p.inspect = &streamItem{ID: "row", Decision: "ALLOW", Tool: "Read"}
		p.inspectScroll = 3
	default:
		p.merged = []streamItem{{ID: "row", Decision: "ALLOW", Tool: "Read"}}
	}
	return p
}

func TestLiveHelpAdvertisedKeysHaveHandlers(t *testing.T) {
	// Every discrete help token must change Live state through onKey.
	// Composite navigation labels and the meta "any key" line are covered
	// elsewhere. esc/q are handled by App.onKey, not Live.onKey.
	skipLabel := map[string]struct{}{
		"↑↓ / PgUp PgDn": {},
		"any key":        {},
		"esc":            {},
		"q":              {},
	}
	ctx := tui.PanelContext{Now: time.UnixMilli(1000), Rows: 20, Cols: 80}
	unknown := runeKey("=")

	for _, g := range liveHelp {
		for _, pair := range g.Keys {
			label, desc := pair[0], pair[1]
			if _, ok := skipLabel[label]; ok {
				continue
			}
			tokens := []string{label}
			if strings.Contains(label, " / ") {
				tokens = nil
				for _, part := range strings.Split(label, "/") {
					part = strings.TrimSpace(part)
					if part != "" {
						tokens = append(tokens, part)
					}
				}
			}
			for _, tok := range tokens {
				tok, desc := tok, desc
				t.Run(tok, func(t *testing.T) {
					msg, ok := liveHelpKeyMsg(tok)
					if !ok {
						t.Fatalf("help token %q (%q) has no KeyMsg mapping", tok, desc)
					}

					pKey := preparedLiveForHelpKey(t, tok)
					before := liveSnap(pKey)
					pKey.onKey(msg, ctx)
					afterKey := liveSnap(pKey)

					pUnk := preparedLiveForHelpKey(t, tok)
					pUnk.onKey(unknown, ctx)
					afterUnk := liveSnap(pUnk)

					if afterUnk != before {
						t.Fatalf("baseline unknown key %q changed state: before=%s after=%s", "=", before, afterUnk)
					}
					if afterKey == before {
						t.Errorf("liveHelp advertises %q (%q) but onKey left Live state unchanged (same as unknown key)", tok, desc)
					}
					if afterKey == afterUnk {
						t.Errorf("liveHelp advertises %q (%q) but onKey matched the unknown-key baseline", tok, desc)
					}
				})
			}
		}
	}
}
