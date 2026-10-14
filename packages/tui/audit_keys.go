// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/config"
)

func (p *Audit) onKey(k tea.KeyMsg, ctx PanelContext) tea.Cmd {
	if p.editing != "" {
		return p.editField(k)
	}
	str := k.String()

	// Copy mode first: space toggles, and while frozen ONLY space works.
	if str == " " {
		p.frozen = !p.frozen
		return nil
	}
	if p.frozen {
		return nil
	}
	// ^R refetches on demand, so an entry written since the last poll, or a policy
	// edited in another terminal, shows up without waiting for one.
	if k.Type == tea.KeyCtrlR {
		p.note = &auditNote{text: "⟳ refreshed " + ctx.Now.Format("15:04:05"), level: "ok"}
		return tea.Batch(p.loadLogs(), p.loadStats())
	}
	// `?` works from any view, even mid-load; any key closes it.
	if p.help {
		p.help = false
		return nil
	}
	if str == "?" {
		p.help = true
		return nil
	}

	if p.view == "detail" {
		switch k.Type {
		case tea.KeyLeft, tea.KeyEsc:
			p.view = "logs"
		case tea.KeyUp:
			p.detailScroll = maxInt(0, p.detailScroll-1)
		case tea.KeyDown:
			p.detailScroll++ // clamped at render
		case tea.KeyPgUp:
			p.detailScroll = maxInt(0, p.detailScroll-10)
		case tea.KeyPgDown:
			p.detailScroll += 10
		}
		return nil
	}

	// Keyboard LOCK while data is loading.
	if p.view == "logs" && p.logsLoading() {
		return nil
	}
	// Any key other than the delete keys disarms a pending confirmation.
	if p.confirm != nil && str != "x" && str != "X" {
		p.confirm = nil
		p.note = nil
	}

	// logs view
	rows, total := p.pageRows()
	pages := p.pages(total)
	switch {
	case k.Type == tea.KeyUp:
		p.sel = maxInt(0, p.sel-1)
	case k.Type == tea.KeyDown:
		p.sel = minInt(len(rows)-1, p.sel+1)
	case k.Type == tea.KeyPgUp:
		p.sel = maxInt(0, p.sel-10)
	case k.Type == tea.KeyPgDown:
		p.sel = minInt(len(rows)-1, p.sel+10)
	case k.Type == tea.KeyEnter:
		if _, ok := p.current(rows); ok {
			p.detailScroll = 0
			p.view = "detail"
		}
	case k.Type == tea.KeyRight:
		if p.page < pages-1 {
			p.page++
			p.sel = 0
			return p.loadLogs()
		}
	case k.Type == tea.KeyLeft:
		if p.page > 0 {
			p.page--
			p.sel = 0
			return p.loadLogs()
		}
	case str == "f":
		p.di = (p.di + 1) % len(auditDecisions)
		p.page, p.sel = 0, 0
		return p.loadLogs()
	case str == "g":
		p.gi = (p.gi + 1) % len(auditSignals)
		p.page, p.sel = 0, 0
		return p.loadLogs()
	case str == "x":
		cur, ok := p.current(rows)
		if !ok {
			return nil
		}
		if p.confirm == nil || p.confirm.kind != "one" || p.confirm.key != cur.id {
			p.confirm = &confirmState{kind: "one", key: cur.id}
			p.note = &auditNote{level: "bad", text: "x = delete ONLY the selected entry: " +
				cur.decision + " " + cur.tool + " (" + agoAt(cur.at, ctx.Now) + " ago), press x again"}
			return nil
		}
		p.confirm = nil
		return p.doDelete("one", cur)
	case str == "X":
		if p.confirm == nil || p.confirm.kind != "all" {
			p.confirm = &confirmState{kind: "all", key: "all"}
			p.note = &auditNote{level: "bad", text: "⚠ X = delete ALL matched entries, " +
				"every one of the " + strconv.Itoa(total) + "! press X again"}
			return nil
		}
		p.confirm = nil
		return p.doDelete("all", logRow{})
	case str == "e":
		return p.doExport("page", rows)
	case str == "E":
		return p.doExport("all", rows)
	case str == "t":
		return p.beginEdit("tool")
	case str == "n":
		return p.beginEdit("agent")
	case str == "/":
		return p.beginEdit("search")
	case str == "c":
		p.di, p.gi = 0, 0
		p.tool, p.agent, p.search = "", "", ""
		p.page, p.sel = 0, 0
		return p.loadLogs()
	}
	return nil
}

func (p *Audit) beginEdit(field string) tea.Cmd {
	p.editing = field
	switch field {
	case "tool":
		p.input.SetValue(p.tool)
	case "agent":
		p.input.SetValue(p.agent)
	case "search":
		p.input.SetValue(p.search)
	}
	p.input.CursorEnd()
	return p.input.Focus()
}

// editField runs the one-line filter editor. Enter commits and closes, esc
// closes without discarding what was typed. Ink's text input answered neither
// key, which left esc reaching the shell and unfocusing the panel mid-edit.
func (p *Audit) editField(k tea.KeyMsg) tea.Cmd {
	if k.Type == tea.KeyEnter || k.Type == tea.KeyEsc {
		p.editing = ""
		p.input.Blur()
		return p.loadLogs()
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(k)
	v := p.input.Value()
	switch p.editing {
	case "tool":
		if v != p.tool {
			p.tool, p.page, p.sel = v, 0, 0
		}
	case "agent":
		if v != p.agent {
			p.agent, p.page, p.sel = v, 0, 0
		}
	case "search":
		if v != p.search {
			p.search, p.page, p.sel = v, 0, 0
		}
	}
	return cmd
}

// doDelete removes the selected entry, or every entry of the current source.
func (p *Audit) doDelete(kind string, cur logRow) tea.Cmd {
	p.note = &auditNote{text: "deleting…", level: "ok"}
	gen := p.gen
	return func() tea.Msg {
		fail := func(err error) tea.Msg {
			return auditNoteResult{gen: gen, note: auditNote{text: "✗ " + err.Error(), level: "bad"}}
		}
		// The FILE is the record, and whoever owns the machine owns the file. There
		// is no second copy to delete from: the two DELETE /audit-logs calls that
		// used to be here are gone with the service, and an audit log a remote
		// party could clear on the audited party's behalf was never a record of
		// anything anyway.
		n := 0
		if kind == "one" {
			n = deleteLocalEntry(cur.at, cur.tool, cur.session)
		} else {
			n = clearLocalLog()
		}
		if n == 0 {
			return fail(errors.New("entry not found in the local file"))
		}
		text := "✓ entry deleted"
		if kind != "one" {
			text = "✓ the whole log on this machine was deleted"
		}
		return auditNoteResult{gen: gen, note: auditNote{text: text, level: "ok"},
			reload: true, toTop: true}
	}
}

// doExport writes the current page (e) or everything matching the filters (E).
func (p *Audit) doExport(kind string, pageRows []logRow) tea.Cmd {
	p.note = &auditNote{text: "exporting…", level: "ok"}
	gen, client := p.gen, p.deps.Client
	q := p.query()
	return func() tea.Msg {
		fail := func(err error) tea.Msg {
			return auditNoteResult{gen: gen,
				note: auditNote{text: "✗ export failed: " + err.Error(), level: "bad"}}
		}
		rows := pageRows
		if kind == "all" {
			// Everything matching the filters, not just the page on screen. A branch
			// stood here for the other source, exporting a list filtered in memory.
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			q.Limit, q.Offset = 10_000, 0
			list, err := client.Audit.List(ctx, q)
			if err != nil {
				return fail(err)
			}
			rows = make([]logRow, 0, len(list.Entries))
			for _, e := range list.Entries {
				rows = append(rows, cloudRow(e))
			}
			sort.SliceStable(rows, func(i, j int) bool { return rows[i].at > rows[j].at })
		}
		dir := config.Dir()
		// It was "audit-export-<source>.jsonl", so the two sources could not overwrite
		// each other's export. There is one.
		file := filepath.Join(dir, "audit-export.jsonl")
		var b strings.Builder
		for _, r := range rows {
			line, err := json.Marshal(r.export())
			if err != nil {
				continue
			}
			b.Write(line)
			b.WriteByte('\n')
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fail(err)
		}
		// 0600 AND NOT 0644, and the mode matters more here than on the log it comes
		// from.
		//
		// This file is WIDER than the audit log: the export row carries dlp[] and
		// burst, which the log does not, so a reader who can open this learns which
		// secrets a pattern matched and which calls tripped a limit. The log itself
		// is 0600 inside a 0700 directory. An export of it at 0644 was the one file
		// in the directory any local account could read, holding the most, and
		// nothing chose that: 0644 is what os.WriteFile examples use.
		if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
			return fail(err)
		}
		// CHMOD AS WELL AS THE MODE, because WriteFile only applies a mode when it
		// CREATES the file. An export written once at 0644 keeps 0644 through
		// every rewrite after it, so changing the constant fixes new machines and
		// leaves every machine that already exported one exactly as it was. The
		// chmod is what reaches those.
		_ = os.Chmod(file, 0o600)
		return auditNoteResult{gen: gen, note: auditNote{
			text: "✓ exported " + strconv.Itoa(len(rows)) + " rows → " + file, level: "ok"}}
	}
}