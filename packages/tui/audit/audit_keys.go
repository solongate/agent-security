// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package audit

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

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

func (p *Audit) onKey(k tea.KeyMsg, ctx tui.PanelContext) tea.Cmd {
	if p.editing != "" {
		return p.editField(k)
	}
	str := k.String()

	if str == " " {
		p.frozen = !p.frozen
		return nil
	}
	if p.frozen {
		return nil
	}

	if k.Type == tea.KeyCtrlR {
		p.note = &auditNote{text: "⟳ refreshed " + ctx.Now.Format("15:04:05"), level: "ok"}
		return tea.Batch(p.loadLogs(), p.loadStats())
	}

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
			p.detailScroll = tui.MaxInt(0, p.detailScroll-1)
		case tea.KeyDown:
			p.detailScroll++
		case tea.KeyPgUp:
			p.detailScroll = tui.MaxInt(0, p.detailScroll-10)
		case tea.KeyPgDown:
			p.detailScroll += 10
		}
		return nil
	}

	if p.view == "logs" && p.logsLoading() {
		return nil
	}

	if p.confirm != nil && str != "x" && str != "X" {
		p.confirm = nil
		p.note = nil
	}

	rows, total := p.pageRows()
	pages := p.pages(total)
	switch {
	case k.Type == tea.KeyUp:
		p.sel = tui.MaxInt(0, p.sel-1)
	case k.Type == tea.KeyDown:
		p.sel = tui.MinInt(len(rows)-1, p.sel+1)
	case k.Type == tea.KeyPgUp:
		p.sel = tui.MaxInt(0, p.sel-10)
	case k.Type == tea.KeyPgDown:
		p.sel = tui.MinInt(len(rows)-1, p.sel+10)
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
				cur.decision + " " + cur.tool + " (" + tui.AgoAt(cur.at, ctx.Now) + " ago), press x again"}
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

func (p *Audit) doDelete(kind string, cur logRow) tea.Cmd {
	p.note = &auditNote{text: "deleting…", level: "ok"}
	gen, q, filtered := p.gen, p.query(), p.filterActive()
	return func() tea.Msg {
		fail := func(err error) tea.Msg {
			return auditNoteResult{gen: gen, note: auditNote{text: "✗ " + err.Error(), level: "bad"}}
		}

		n := 0
		switch {
		case kind == "one":
			n = tui.DeleteLocalEntry(cur.at, cur.tool, cur.session)
		case !filtered:
			// No filter is active, so "delete all" still means the whole local
			// file — including lines that no longer parse. Keep that exact
			// behaviour; filtering only narrows what the user asked to delete.
			n = tui.ClearLocalLog()
		default:
			// Delete exactly what the view shows: the same query that produced the
			// rows is the filter, so a user who narrowed the log cannot lose
			// entries that were filtered out of sight.
			n = tui.DeleteLocalLogMatching(func(raw []byte) bool {
				e, ok := client.AuditEntryFromLocalLine(raw)
				return ok && q.Matches(e)
			})
		}
		if n == 0 {
			if kind == "one" {
				return fail(errors.New("entry not found in the local file"))
			}
			return fail(errors.New("no entry in the local file matched the current view"))
		}
		text := "✓ entry deleted"
		if kind != "one" {
			text = "✓ deleted " + strconv.Itoa(n) + " entries matching the active filter"
			if !filtered {
				text = "✓ the whole log on this machine was deleted"
			}
		}
		return auditNoteResult{gen: gen, note: auditNote{text: text, level: "ok"},
			reload: true, toTop: true}
	}
}

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
		truncatedAt := 0
		if kind == "all" {

			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			// client.Audit.List clamps Limit to 1000, so one request per export
			// silently cut every export above 1000 rows. Walk the pages instead
			// and only stop when the matching set is complete.
			rows = rows[:0]
			for offset := 0; ; offset += exportPageSize {
				q.Limit, q.Offset = exportPageSize, offset
				list, err := client.Audit.List(ctx, q)
				if err != nil {
					return fail(err)
				}
				for _, e := range list.Entries {
					rows = append(rows, cloudRow(e))
				}
				if len(rows) >= list.Total {
					break
				}
				if len(list.Entries) < exportPageSize || ctx.Err() != nil {
					truncatedAt = list.Total
					break
				}
			}
			sort.SliceStable(rows, func(i, j int) bool { return rows[i].at > rows[j].at })
		}
		dir := config.Dir()

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

		if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
			return fail(err)
		}

		_ = os.Chmod(file, 0o600)
		text := "✓ exported " + strconv.Itoa(len(rows)) + " rows → " + file
		level := "ok"
		if truncatedAt > len(rows) {
			text = "⚠ exported " + strconv.Itoa(len(rows)) + " of " + strconv.Itoa(truncatedAt) +
				" matching rows (timed out) → " + file
			level = "bad"
		}
		return auditNoteResult{gen: gen, note: auditNote{text: text, level: level}}
	}
}