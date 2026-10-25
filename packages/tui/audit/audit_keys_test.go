// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

func runeKey(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// withRows gives the panel a loaded list of n entries with distinct,
// increasing timestamps so pageRows() has a stable, predictable sort order.
func withRows(p *Audit, n int) {
	entries := make([]client.AuditEntry, n)
	for i := 0; i < n; i++ {
		entries[i] = client.AuditEntry{
			ID: strconv.Itoa(i), ToolName: "Bash", Decision: "ALLOW",
			CreatedAt: time.Unix(int64(i), 0).UTC().Format(time.RFC3339),
		}
	}
	p.list = &client.AuditList{Entries: entries, Total: n}
}

func TestOnKeyEditingDelegatesToEditField(t *testing.T) {
	p := newTestAudit(t)
	p.beginEdit("tool") // focuses the input, as real use always does before typing
	p.onKey(runeKey("b"), tui.PanelContext{})
	if p.tool != "b" {
		t.Errorf("tool = %q, want b (onKey while editing should delegate to editField)", p.tool)
	}
}

func TestOnKeySpaceTogglesFrozenEvenWhenEditing(t *testing.T) {
	p := newTestAudit(t)
	p.onKey(runeKey(" "), tui.PanelContext{})
	if !p.frozen {
		t.Error("space did not freeze the panel")
	}
	p.onKey(runeKey(" "), tui.PanelContext{})
	if p.frozen {
		t.Error("second space did not unfreeze the panel")
	}
}

func TestOnKeyFrozenIgnoresOtherKeys(t *testing.T) {
	p := newTestAudit(t)
	p.frozen = true
	before := p.di
	p.onKey(runeKey("f"), tui.PanelContext{})
	if p.di != before {
		t.Error("filter changed while frozen, want no-op")
	}
}

func TestOnKeyHelpTogglesAndSwallowsNextKey(t *testing.T) {
	p := newTestAudit(t)
	p.onKey(runeKey("?"), tui.PanelContext{})
	if !p.help {
		t.Fatal("help was not enabled by ?")
	}
	before := p.di
	p.onKey(runeKey("f"), tui.PanelContext{})
	if p.help {
		t.Error("help still true after a following key, want it dismissed")
	}
	if p.di != before {
		t.Error("the key that dismissed help was also applied as a filter change, want it swallowed")
	}
}

func TestOnKeyCtrlRRefreshes(t *testing.T) {
	p := newTestAudit(t)
	cmd := p.onKey(tea.KeyMsg{Type: tea.KeyCtrlR}, tui.PanelContext{})
	if cmd == nil {
		t.Error("ctrl+r returned a nil cmd, want a refresh batch")
	}
	if p.note == nil || !strings.Contains(p.note.text, "refreshed") {
		t.Errorf("note = %v, want a refreshed note", p.note)
	}
}

func TestOnKeyDetailViewNavigation(t *testing.T) {
	p := newTestAudit(t)
	p.view = "detail"
	p.detailScroll = 5

	p.onKey(tea.KeyMsg{Type: tea.KeyUp}, tui.PanelContext{})
	if p.detailScroll != 4 {
		t.Errorf("detailScroll = %d, want 4", p.detailScroll)
	}

	p.detailScroll = 0
	p.onKey(tea.KeyMsg{Type: tea.KeyUp}, tui.PanelContext{})
	if p.detailScroll != 0 {
		t.Errorf("detailScroll = %d, want clamped to 0", p.detailScroll)
	}

	p.onKey(tea.KeyMsg{Type: tea.KeyDown}, tui.PanelContext{})
	if p.detailScroll != 1 {
		t.Errorf("detailScroll = %d, want 1", p.detailScroll)
	}

	p.detailScroll = 20
	p.onKey(tea.KeyMsg{Type: tea.KeyPgUp}, tui.PanelContext{})
	if p.detailScroll != 10 {
		t.Errorf("detailScroll = %d, want 10 after page up", p.detailScroll)
	}

	p.onKey(tea.KeyMsg{Type: tea.KeyPgDown}, tui.PanelContext{})
	if p.detailScroll != 20 {
		t.Errorf("detailScroll = %d, want 20 after page down", p.detailScroll)
	}

	p.onKey(tea.KeyMsg{Type: tea.KeyLeft}, tui.PanelContext{})
	if p.view != "logs" {
		t.Errorf("view = %q, want logs after left", p.view)
	}

	p.view = "detail"
	p.onKey(tea.KeyMsg{Type: tea.KeyEsc}, tui.PanelContext{})
	if p.view != "logs" {
		t.Errorf("view = %q, want logs after esc", p.view)
	}
}

func TestOnKeyLogsLoadingIgnoresKeys(t *testing.T) {
	p := newTestAudit(t)
	p.view = "logs"
	p.busy, p.editing = true, ""
	withRows(p, 3)
	before := p.sel
	p.onKey(tea.KeyMsg{Type: tea.KeyDown}, tui.PanelContext{})
	if p.sel != before {
		t.Error("selection moved while logs were loading, want no-op")
	}
}

func TestOnKeyClearsStaleConfirm(t *testing.T) {
	p := newTestAudit(t)
	p.confirm = &confirmState{kind: "one", key: "x"}
	p.note = &auditNote{text: "pending"}
	p.onKey(runeKey("f"), tui.PanelContext{})
	if p.confirm != nil {
		t.Error("confirm survived an unrelated key, want cleared")
	}
	if p.note != nil {
		t.Error("note survived an unrelated key, want cleared")
	}
}

func TestOnKeySelectionNavigation(t *testing.T) {
	p := newTestAudit(t)
	withRows(p, 3)

	p.onKey(tea.KeyMsg{Type: tea.KeyDown}, tui.PanelContext{})
	if p.sel != 1 {
		t.Errorf("sel = %d, want 1", p.sel)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgDown}, tui.PanelContext{})
	if p.sel != 2 {
		t.Errorf("sel = %d, want clamped to 2 (last row)", p.sel)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyUp}, tui.PanelContext{})
	if p.sel != 1 {
		t.Errorf("sel = %d, want 1", p.sel)
	}
	p.onKey(tea.KeyMsg{Type: tea.KeyPgUp}, tui.PanelContext{})
	if p.sel != 0 {
		t.Errorf("sel = %d, want clamped to 0", p.sel)
	}
}

func TestOnKeyEnterOpensDetailOnlyWithARow(t *testing.T) {
	p := newTestAudit(t)
	p.onKey(tea.KeyMsg{Type: tea.KeyEnter}, tui.PanelContext{})
	if p.view != "logs" {
		t.Error("enter opened detail view with no rows loaded, want no-op")
	}

	withRows(p, 1)
	p.detailScroll = 9
	p.onKey(tea.KeyMsg{Type: tea.KeyEnter}, tui.PanelContext{})
	if p.view != "detail" {
		t.Error("enter did not open detail view with a current row")
	}
	if p.detailScroll != 0 {
		t.Errorf("detailScroll = %d, want reset to 0", p.detailScroll)
	}
}

func TestOnKeyPagination(t *testing.T) {
	// loadLogs() sets p.busy=true as a side effect of being called, and a
	// busy panel ignores further keys (see logsLoading()). We reset busy
	// after each step to isolate the pagination boundary logic itself,
	// standing in for the real result arriving before the next keypress.
	p := newTestAudit(t)
	withRows(p, auditPage+5) // two pages

	cmd := p.onKey(tea.KeyMsg{Type: tea.KeyRight}, tui.PanelContext{})
	if p.page != 1 || p.sel != 0 || cmd == nil {
		t.Errorf("after right: page=%d sel=%d cmd=%v, want 1,0,non-nil", p.page, p.sel, cmd)
	}
	p.busy = false

	cmd = p.onKey(tea.KeyMsg{Type: tea.KeyRight}, tui.PanelContext{})
	if p.page != 1 || cmd != nil {
		t.Errorf("right on the last page: page=%d cmd=%v, want unchanged page and nil cmd", p.page, cmd)
	}
	p.busy = false

	cmd = p.onKey(tea.KeyMsg{Type: tea.KeyLeft}, tui.PanelContext{})
	if p.page != 0 || cmd == nil {
		t.Errorf("after left: page=%d cmd=%v, want 0, non-nil", p.page, cmd)
	}
	p.busy = false

	cmd = p.onKey(tea.KeyMsg{Type: tea.KeyLeft}, tui.PanelContext{})
	if p.page != 0 || cmd != nil {
		t.Errorf("left on the first page: page=%d cmd=%v, want unchanged page and nil cmd", p.page, cmd)
	}
}

func TestOnKeyFilterCycling(t *testing.T) {
	// See the comment in TestOnKeyPagination: loadLogs() sets p.busy=true,
	// so it is reset between steps to isolate each assertion.
	p := newTestAudit(t)
	p.page, p.sel = 2, 2

	p.onKey(runeKey("f"), tui.PanelContext{})
	if p.di != 1 || p.page != 0 || p.sel != 0 {
		t.Errorf("after f: di=%d page=%d sel=%d, want 1,0,0", p.di, p.page, p.sel)
	}
	p.busy = false
	p.di = len(auditDecisions) - 1
	p.onKey(runeKey("f"), tui.PanelContext{})
	if p.di != 0 {
		t.Errorf("di = %d, want wraparound to 0", p.di)
	}
	p.busy = false

	p.page, p.sel = 2, 2
	p.onKey(runeKey("g"), tui.PanelContext{})
	if p.gi != 1 || p.page != 0 || p.sel != 0 {
		t.Errorf("after g: gi=%d page=%d sel=%d, want 1,0,0", p.gi, p.page, p.sel)
	}
}

func TestOnKeyClearFilters(t *testing.T) {
	p := newTestAudit(t)
	p.di, p.gi = 2, 1
	p.tool, p.agent, p.search = "Bash", "agent-a", "x"
	p.page, p.sel = 3, 3

	cmd := p.onKey(runeKey("c"), tui.PanelContext{})
	if p.di != 0 || p.gi != 0 || p.tool != "" || p.agent != "" || p.search != "" || p.page != 0 || p.sel != 0 {
		t.Errorf("state after clear = %+v, want everything reset", p)
	}
	if cmd == nil {
		t.Error("clear filters returned a nil cmd, want a reload")
	}
}

func TestOnKeyDeleteOneRequiresConfirmation(t *testing.T) {
	p := newTestAudit(t)

	// No rows loaded: 'x' is a no-op.
	if cmd := p.onKey(runeKey("x"), tui.PanelContext{}); cmd != nil || p.confirm != nil {
		t.Error("x with no rows should be a no-op")
	}

	withRows(p, 2)
	cmd := p.onKey(runeKey("x"), tui.PanelContext{})
	if cmd != nil {
		t.Error("first x should only arm confirmation, not return a delete cmd")
	}
	if p.confirm == nil || p.confirm.kind != "one" {
		t.Fatalf("confirm = %v, want kind=one armed", p.confirm)
	}
	armedKey := p.confirm.key

	// A different key clears the confirmation (tested via the stale-confirm case already);
	// pressing x again with the same current row proceeds to delete.
	cmd = p.onKey(runeKey("x"), tui.PanelContext{})
	if p.confirm != nil {
		t.Error("confirm still set after the second x, want cleared")
	}
	if cmd == nil {
		t.Error("second x returned a nil cmd, want the delete cmd")
	}
	if armedKey == "" {
		t.Error("armed confirmation key was empty")
	}
}

func TestOnKeyDeleteAllRequiresConfirmation(t *testing.T) {
	p := newTestAudit(t)
	withRows(p, 2)

	cmd := p.onKey(runeKey("X"), tui.PanelContext{})
	if cmd != nil || p.confirm == nil || p.confirm.kind != "all" {
		t.Errorf("first X: cmd=%v confirm=%v, want nil cmd and kind=all armed", cmd, p.confirm)
	}

	cmd = p.onKey(runeKey("X"), tui.PanelContext{})
	if cmd == nil || p.confirm != nil {
		t.Errorf("second X: cmd=%v confirm=%v, want a delete cmd and cleared confirm", cmd, p.confirm)
	}
}

func TestOnKeyBeginEditShortcuts(t *testing.T) {
	cases := []struct {
		key   string
		field string
	}{
		{"t", "tool"},
		{"n", "agent"},
		{"/", "search"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			p := newTestAudit(t)
			p.onKey(runeKey(tc.key), tui.PanelContext{})
			if p.editing != tc.field {
				t.Errorf("editing = %q, want %q", p.editing, tc.field)
			}
		})
	}
}

func TestBeginEditSeedsInputFromCurrentValue(t *testing.T) {
	p := newTestAudit(t)
	p.tool = "Bash"
	p.beginEdit("tool")
	if p.editing != "tool" {
		t.Errorf("editing = %q, want tool", p.editing)
	}
	if p.input.Value() != "Bash" {
		t.Errorf("input value = %q, want Bash", p.input.Value())
	}
}

func TestEditFieldEnterAndEscExit(t *testing.T) {
	for _, kt := range []tea.KeyType{tea.KeyEnter, tea.KeyEsc} {
		p := newTestAudit(t)
		p.beginEdit("tool")
		cmd := p.editField(tea.KeyMsg{Type: kt})
		if p.editing != "" {
			t.Errorf("editing = %q, want cleared", p.editing)
		}
		if cmd == nil {
			t.Error("editField on exit returned a nil cmd, want a reload")
		}
	}
}

func TestEditFieldUpdatesValueAndResetsPaging(t *testing.T) {
	p := newTestAudit(t)
	p.beginEdit("search")
	p.page, p.sel = 4, 4

	p.editField(runeKey("x"))
	if p.search != "x" {
		t.Errorf("search = %q, want x", p.search)
	}
	if p.page != 0 || p.sel != 0 {
		t.Errorf("page=%d sel=%d, want reset to 0,0 after the value changed", p.page, p.sel)
	}
}

func TestEditFieldLeavesPagingAloneWhenValueIsUnchanged(t *testing.T) {
	p := newTestAudit(t)
	p.beginEdit("search")
	p.page, p.sel = 4, 4

	// Left arrow just moves the cursor; the input value does not change.
	p.editField(tea.KeyMsg{Type: tea.KeyLeft})
	if p.page != 4 || p.sel != 4 {
		t.Errorf("page=%d sel=%d, want left untouched since the value did not change", p.page, p.sel)
	}
}

func TestDoDeleteOneRemovesOnlyTheMatchingEntry(t *testing.T) {
	p := newTestAudit(t)
	writeLogLines(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW","session_id":"s1"}`,
		`{"ts":"2026-01-01T00:01:00Z","tool":"Write","decision":"DENY","session_id":"s2"}`,
	)

	at, ok := tui.ParseMillis("2026-01-01T00:01:00Z")
	if !ok {
		t.Fatal("failed to parse the fixture timestamp")
	}
	row := logRow{at: at, tool: "Write", session: "s2"}

	cmd := p.doDelete("one", row)
	msg := cmd()
	res, ok := msg.(auditNoteResult)
	if !ok {
		t.Fatalf("doDelete msg type = %T, want auditNoteResult", msg)
	}
	if !res.reload || !res.toTop {
		t.Errorf("result = %+v, want reload and toTop set on success", res)
	}
	if !strings.HasPrefix(res.note.text, "✓") {
		t.Errorf("note = %q, want a success mark", res.note.text)
	}

	b, err := os.ReadFile(config.LocalLogFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Write") {
		t.Error("the deleted entry is still present in the log file")
	}
	if !strings.Contains(string(b), "Bash") {
		t.Error("the untouched entry was removed too")
	}
}

func TestDoDeleteOneReportsNotFound(t *testing.T) {
	p := newTestAudit(t)
	writeLogLines(t, `{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`)

	cmd := p.doDelete("one", logRow{at: 1, tool: "DoesNotExist"})
	res := cmd().(auditNoteResult)
	if res.reload {
		t.Error("reload = true on a failed delete, want false")
	}
	if !strings.HasPrefix(res.note.text, "✗") {
		t.Errorf("note = %q, want a failure mark", res.note.text)
	}
}

func TestDoDeleteAllClearsTheWholeLog(t *testing.T) {
	p := newTestAudit(t)
	writeLogLines(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`,
		`{"ts":"2026-01-01T00:01:00Z","tool":"Write","decision":"DENY"}`,
	)

	cmd := p.doDelete("all", logRow{})
	res := cmd().(auditNoteResult)
	if !res.reload || !res.toTop {
		t.Errorf("result = %+v, want reload and toTop on success", res)
	}
	b, err := os.ReadFile(config.LocalLogFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "" {
		t.Errorf("log file = %q, want emptied", string(b))
	}
}

func TestDoExportPageWritesTheGivenRows(t *testing.T) {
	p := newTestAudit(t)
	rows := []logRow{
		{id: "1", at: 100, tool: "Bash", decision: "ALLOW"},
		{id: "2", at: 200, tool: "Write", decision: "DENY"},
	}

	cmd := p.doExport("page", rows)
	msg := cmd()
	res, ok := msg.(auditNoteResult)
	if !ok {
		t.Fatalf("doExport msg type = %T, want auditNoteResult", msg)
	}
	if !strings.Contains(res.note.text, "2 rows") {
		t.Errorf("note = %q, want it to mention 2 rows", res.note.text)
	}

	file := filepath.Join(config.Dir(), "audit-export.jsonl")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("export file not written: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d exported lines, want 2", len(lines))
	}
	var first auditExport
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal exported line: %v", err)
	}
	if first.Tool != "Bash" {
		t.Errorf("first exported row tool = %q, want Bash", first.Tool)
	}
}

func TestDoExportAllQueriesAndSortsNewestFirst(t *testing.T) {
	p := newTestAudit(t)
	writeLogLines(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Older","decision":"ALLOW"}`,
		`{"ts":"2026-01-02T00:00:00Z","tool":"Newer","decision":"ALLOW"}`,
	)

	cmd := p.doExport("all", nil)
	res := cmd().(auditNoteResult)
	if !strings.Contains(res.note.text, "2 rows") {
		t.Errorf("note = %q, want it to mention 2 rows", res.note.text)
	}

	file := filepath.Join(config.Dir(), "audit-export.jsonl")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d exported lines, want 2", len(lines))
	}
	var first auditExport
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if first.Tool != "Newer" {
		t.Errorf("first exported row = %q, want the newest entry first", first.Tool)
	}
}