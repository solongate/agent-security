// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package audit

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

// newHome points config.Dir() (and therefore the local audit log) at a fresh
// temp directory so tests never touch a real machine's ~/.solongate.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func writeLogLines(t *testing.T, lines ...string) {
	t.Helper()
	file := config.LocalLogFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestAudit(t *testing.T) *Audit {
	t.Helper()
	newHome(t)
	return newAudit(tui.Deps{Client: client.New()})
}

func TestNextToken(t *testing.T) {
	first := nextToken()
	second := nextToken()
	if second != first+1 {
		t.Errorf("nextToken() sequence = %d, %d; want consecutive integers", first, second)
	}
}

func TestNilIfEmpty(t *testing.T) {
	if got := nilIfEmpty(""); got != nil {
		t.Errorf("nilIfEmpty(\"\") = %v, want nil", got)
	}
	got := nilIfEmpty("x")
	if got == nil || *got != "x" {
		t.Errorf("nilIfEmpty(\"x\") = %v, want pointer to \"x\"", got)
	}
}

func TestLogRowExport(t *testing.T) {
	t.Run("empty optional fields become nil pointers and dlp defaults to empty slice", func(t *testing.T) {
		r := logRow{id: "1", at: 100, tool: "Bash", decision: "ALLOW", permission: "READ"}
		e := r.export()
		if e.Agent != nil || e.Session != nil || e.Reason != nil || e.Rule != nil || e.Args != nil {
			t.Errorf("export() = %+v, want all optional pointer fields nil", e)
		}
		if e.DLP == nil || len(e.DLP) != 0 {
			t.Errorf("export().DLP = %v, want non-nil empty slice", e.DLP)
		}
	})

	t.Run("populated fields are carried through as pointers", func(t *testing.T) {
		ms := 12.5
		r := logRow{
			id: "2", at: 200, tool: "Write", decision: "DENY", permission: "WRITE",
			trust: "TRUSTED", agent: "agent-a", session: "sess-1", reason: "blocked",
			rule: "rule-1", evalMs: &ms, dlp: []string{"AWS key"}, burst: true, args: `{"x":1}`,
		}
		e := r.export()
		if e.Agent == nil || *e.Agent != "agent-a" {
			t.Errorf("Agent = %v, want agent-a", e.Agent)
		}
		if e.Session == nil || *e.Session != "sess-1" {
			t.Errorf("Session = %v, want sess-1", e.Session)
		}
		if e.Reason == nil || *e.Reason != "blocked" {
			t.Errorf("Reason = %v, want blocked", e.Reason)
		}
		if e.Rule == nil || *e.Rule != "rule-1" {
			t.Errorf("Rule = %v, want rule-1", e.Rule)
		}
		if e.Args == nil || *e.Args != `{"x":1}` {
			t.Errorf("Args = %v, want {\"x\":1}", e.Args)
		}
		if e.EvalMs == nil || *e.EvalMs != 12.5 {
			t.Errorf("EvalMs = %v, want 12.5", e.EvalMs)
		}
		if !e.Burst || len(e.DLP) != 1 || e.DLP[0] != "AWS key" {
			t.Errorf("export() = %+v, want burst=true dlp=[AWS key]", e)
		}
	})
}

func TestLogRowStream(t *testing.T) {
	cases := []struct {
		name       string
		row        logRow
		wantDetail string
		wantDLP    bool
	}{
		{
			name:       "detail prefers args over reason",
			row:        logRow{args: "the args", reason: "the reason"},
			wantDetail: "the args",
		},
		{
			name:       "detail falls back to reason when args is empty",
			row:        logRow{reason: "collapse   this   text"},
			wantDetail: "collapse this text",
		},
		{
			name:    "dlp true when matches present",
			row:     logRow{dlp: []string{"AWS key"}},
			wantDLP: true,
		},
		{
			name:    "dlp false when no matches",
			row:     logRow{},
			wantDLP: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.row.stream()
			if s.Detail != tc.wantDetail {
				t.Errorf("Detail = %q, want %q", s.Detail, tc.wantDetail)
			}
			if s.DLP != tc.wantDLP {
				t.Errorf("DLP = %v, want %v", s.DLP, tc.wantDLP)
			}
		})
	}

	t.Run("permission is truncated to 4 runes", func(t *testing.T) {
		s := logRow{permission: "READWRITE"}.stream()
		if s.Permission != "READ" {
			t.Errorf("Permission = %q, want %q", s.Permission, "READ")
		}
	})
}

func TestCloudRow(t *testing.T) {
	t.Run("derives dlp and burst signals from reason when the entry lacks them", func(t *testing.T) {
		reason := "blocked by security layer (dlp): contains an AWS access key."
		e := client.AuditEntry{ID: "1", ToolName: "Bash", Decision: "DENY", Reason: &reason, CreatedAt: "2026-01-01T00:00:00Z"}
		r := cloudRow(e)
		if len(r.dlp) != 1 {
			t.Fatalf("dlp = %v, want one derived entry", r.dlp)
		}
		if r.burst {
			t.Error("burst = true, want false (reason has no rate-limit signal)")
		}
	})

	t.Run("prefers the entry's own dlp matches over reason-derived ones", func(t *testing.T) {
		reason := "blocked by security layer (dlp): contains an AWS access key."
		e := client.AuditEntry{
			ID: "1", ToolName: "Bash", Decision: "DENY", Reason: &reason,
			DLPMatches: []string{"explicit match"}, CreatedAt: "2026-01-01T00:00:00Z",
		}
		r := cloudRow(e)
		if len(r.dlp) != 1 || r.dlp[0] != "explicit match" {
			t.Errorf("dlp = %v, want [explicit match]", r.dlp)
		}
	})

	t.Run("nil optional pointers default to empty strings", func(t *testing.T) {
		e := client.AuditEntry{ID: "1", ToolName: "Bash", Decision: "ALLOW", CreatedAt: "2026-01-01T00:00:00Z"}
		r := cloudRow(e)
		if r.agent != "" || r.session != "" || r.rule != "" {
			t.Errorf("row = %+v, want empty agent/session/rule", r)
		}
	})

	t.Run("populated optional pointers are copied through", func(t *testing.T) {
		agent, session, rule := "agent-a", "sess-1", "rule-1"
		e := client.AuditEntry{
			ID: "1", ToolName: "Bash", Decision: "ALLOW", CreatedAt: "2026-01-01T00:00:00Z",
			AgentName: &agent, SessionID: &session, MatchedRuleID: &rule,
		}
		r := cloudRow(e)
		if r.agent != "agent-a" || r.session != "sess-1" || r.rule != "rule-1" {
			t.Errorf("row = %+v, want agent-a/sess-1/rule-1", r)
		}
	})

	t.Run("arguments summary of literal null is dropped", func(t *testing.T) {
		e := client.AuditEntry{
			ID: "1", ToolName: "Bash", Decision: "ALLOW", CreatedAt: "2026-01-01T00:00:00Z",
			ArgumentsSummary: []byte("null"),
		}
		r := cloudRow(e)
		if r.args != "" {
			t.Errorf("args = %q, want empty for a literal null summary", r.args)
		}
	})

	t.Run("arguments summary with real content is kept", func(t *testing.T) {
		e := client.AuditEntry{
			ID: "1", ToolName: "Bash", Decision: "ALLOW", CreatedAt: "2026-01-01T00:00:00Z",
			ArgumentsSummary: []byte(`{"command":"ls"}`),
		}
		r := cloudRow(e)
		if r.args != `{"command":"ls"}` {
			t.Errorf("args = %q, want the raw JSON", r.args)
		}
	})

	t.Run("CreatedAt is parsed into at", func(t *testing.T) {
		e := client.AuditEntry{ID: "1", ToolName: "Bash", Decision: "ALLOW", CreatedAt: "2026-01-01T00:00:00Z"}
		r := cloudRow(e)
		if r.at == 0 {
			t.Error("at = 0, want a parsed millisecond timestamp")
		}
	})
}

func TestNewAudit(t *testing.T) {
	p := newAudit(tui.Deps{Client: client.New()})
	if p.view != "logs" {
		t.Errorf("view = %q, want logs", p.view)
	}
	if p.tok <= 0 {
		t.Errorf("tok = %d, want a positive token", p.tok)
	}
	if p.input.CharLimit != 200 {
		t.Errorf("input.CharLimit = %d, want 200", p.input.CharLimit)
	}
}

func TestAuditQuery(t *testing.T) {
	p := newTestAudit(t)
	p.di, p.gi = 2, 1
	p.tool, p.agent, p.search = "Bash", "agent-a", "needle"
	p.page = 3

	q := p.query()
	if q.Filter != "ALLOW" {
		t.Errorf("Filter = %q, want ALLOW", q.Filter)
	}
	if q.Signal != "dlp" {
		t.Errorf("Signal = %q, want dlp", q.Signal)
	}
	if q.Tool != "Bash" || q.AgentName != "agent-a" || q.Search != "needle" {
		t.Errorf("query = %+v, want Tool/AgentName/Search set from state", q)
	}
	if q.Limit != auditPage {
		t.Errorf("Limit = %d, want %d", q.Limit, auditPage)
	}
	if q.Offset != 3*auditPage {
		t.Errorf("Offset = %d, want %d", q.Offset, 3*auditPage)
	}
}

func TestAuditPages(t *testing.T) {
	p := newTestAudit(t)
	cases := []struct {
		total int
		want  int
	}{
		{0, 1},
		{1, 1},
		{auditPage, 1},
		{auditPage + 1, 2},
		{2 * auditPage, 2},
		{2*auditPage + 1, 3},
	}
	for _, tc := range cases {
		if got := p.pages(tc.total); got != tc.want {
			t.Errorf("pages(%d) = %d, want %d", tc.total, got, tc.want)
		}
	}
}

func TestAuditCurrent(t *testing.T) {
	p := newTestAudit(t)

	if _, ok := p.current(nil); ok {
		t.Error("current(nil) ok = true, want false")
	}

	rows := []logRow{{id: "a"}, {id: "b"}, {id: "c"}}
	p.sel = 1
	if r, ok := p.current(rows); !ok || r.id != "b" {
		t.Errorf("current() = %+v, %v, want b, true", r, ok)
	}

	p.sel = 99
	if r, ok := p.current(rows); !ok || r.id != "c" {
		t.Errorf("current() with out-of-range sel = %+v, %v, want clamped to last row c", r, ok)
	}
}

func TestAuditLogsLoadingAndError(t *testing.T) {
	p := newTestAudit(t)

	p.busy, p.editing = true, ""
	if !p.logsLoading() {
		t.Error("logsLoading() = false, want true when busy and not editing")
	}

	p.busy, p.editing = true, "tool"
	if p.logsLoading() {
		t.Error("logsLoading() = true, want false while editing a filter field")
	}

	p.busy = false
	if p.logsLoading() {
		t.Error("logsLoading() = true, want false when not busy")
	}

	p.err = nil
	if p.logsError() != nil {
		t.Error("logsError() non-nil with no error set")
	}
	wantErr := os.ErrClosed
	p.err = wantErr
	if p.logsError() != wantErr {
		t.Errorf("logsError() = %v, want %v", p.logsError(), wantErr)
	}
}

func TestAuditUpdateSetsGeneration(t *testing.T) {
	p := newTestAudit(t)
	_, _ = p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")}, tui.PanelContext{Gen: 7})
	if p.gen != 7 {
		t.Errorf("gen = %d, want 7", p.gen)
	}
}

func TestAuditUpdateKeyMsgTogglesFrozen(t *testing.T) {
	p := newTestAudit(t)
	if p.frozen {
		t.Fatal("precondition: frozen should start false")
	}
	_, _ = p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")}, tui.PanelContext{})
	if !p.frozen {
		t.Error("space key via Update did not freeze the panel")
	}
}

func TestAuditUpdateTickWrongTokenIsIgnored(t *testing.T) {
	p := newTestAudit(t)
	_, cmd := p.Update(auditTick{gen: p.gen, tok: p.tok + 999, kind: auditTickStats}, tui.PanelContext{})
	if cmd != nil {
		t.Error("onTick for a stale token returned a non-nil cmd, want nil")
	}
}

func TestAuditUpdateStatsResult(t *testing.T) {
	p := newTestAudit(t)

	p.Update(auditStatsResult{err: os.ErrInvalid}, tui.PanelContext{})
	if p.stats != nil {
		t.Error("stats set after an error result, want nil")
	}

	s := client.Stats{TotalCalls: 5}
	p.Update(auditStatsResult{stats: s}, tui.PanelContext{})
	if p.stats == nil || p.stats.TotalCalls != 5 {
		t.Errorf("stats = %+v, want TotalCalls 5", p.stats)
	}
}

func TestAuditUpdateLogsResult(t *testing.T) {
	p := newTestAudit(t)
	p.busy = true

	_, _ = p.Update(auditLogsResult{err: os.ErrInvalid}, tui.PanelContext{})
	if p.busy {
		t.Error("busy still true after a logs result, want false")
	}
	if p.err == nil {
		t.Error("err not set after a failing logs result")
	}

	p.busy = true
	list := client.AuditList{Total: 3}
	_, _ = p.Update(auditLogsResult{list: list}, tui.PanelContext{})
	if p.busy {
		t.Error("busy still true after a successful logs result")
	}
	if p.err != nil {
		t.Errorf("err = %v, want nil after a successful result", p.err)
	}
	if p.list == nil || p.list.Total != 3 {
		t.Errorf("list = %+v, want Total 3", p.list)
	}
}

func TestAuditUpdateNoteResult(t *testing.T) {
	cases := []struct {
		name       string
		result     auditNoteResult
		wantCmdNil bool
	}{
		{"plain note", auditNoteResult{note: auditNote{text: "hi"}}, true},
		{"reload requests a cmd", auditNoteResult{note: auditNote{text: "hi"}, reload: true}, false},
		{"refresh requests a cmd", auditNoteResult{note: auditNote{text: "hi"}, refresh: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestAudit(t)
			p.sel = 5
			_, cmd := p.Update(tc.result, tui.PanelContext{})
			if p.note == nil || p.note.text != "hi" {
				t.Errorf("note = %v, want set to %q", p.note, "hi")
			}
			if (cmd == nil) != tc.wantCmdNil {
				t.Errorf("cmd nil = %v, want %v", cmd == nil, tc.wantCmdNil)
			}
		})
	}

	t.Run("toTop resets selection", func(t *testing.T) {
		p := newTestAudit(t)
		p.sel = 5
		_, _ = p.Update(auditNoteResult{note: auditNote{text: "hi"}, toTop: true}, tui.PanelContext{})
		if p.sel != 0 {
			t.Errorf("sel = %d, want 0 after toTop", p.sel)
		}
	})
}