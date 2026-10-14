// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

// notifyIdleSessions raises a banner when a session stops calling. Banner only:
// an idle transition is routine, not a security event, and a bell plus a
// desktop toast here read as a false DLP or rate-limit alarm.
// ── derived views over the buffer ──────────────────────────────────────────

func (p *Live) matches(e streamItem) bool {
	q := strings.ToLower(strings.TrimSpace(p.search))
	if q == "" {
		return true
	}
	hay := strings.ToLower(e.Tool + " " + e.Agent + " " + e.Decision + " " + e.Permission + " " + e.Rule + " " + e.Detail)
	return strings.Contains(hay, q)
}

func (p *Live) signalOK(e streamItem) bool {
	switch p.signal {
	case "deny":
		return e.Decision != "ALLOW"
	case "dlp":
		return e.DLP
	case "ratelimit":
		return e.Burst
	}
	return true
}

// filtered is the stream after the signal and search filters, oldest first.
func (p *Live) filtered() []streamItem {
	out := make([]streamItem, 0, len(p.merged))
	for _, e := range p.merged {
		// A source filter stood here, all → local → cloud. Everything is from one
		// file, so it filtered that file from itself.
		if !p.matches(e) || !p.signalOK(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// visibleDesc is every buffered entry that passes the filters, newest first, so the
// row count matches the entry total in the status bar.
func (p *Live) visibleDesc() []streamItem {
	f := p.filtered()
	out := make([]streamItem, len(f))
	for i := range f {
		out[i] = f[len(f)-1-i]
	}
	return out
}

// detailEntries is a picked session's timeline: its cloud history plus
// everything in the merged buffer that belongs to it, newest first.
// ── keys ───────────────────────────────────────────────────────────────────

func (p *Live) onKey(k tea.KeyMsg, ctx PanelContext) tea.Cmd {
	now := ctx.Now.UnixMilli()
	if p.editingSearch {
		return p.editSearch(k)
	}
	str := k.String()

	// Copy mode first; while frozen only space resumes.
	if str == " " {
		p.frozen = !p.frozen
		return nil
	}
	if p.frozen {
		return nil
	}
	// `?` opens the full key reference from ANY mode; any key closes it.
	if p.help {
		p.help = false
		return nil
	}
	if str == "?" {
		p.help = true
		return nil
	}
	if str == "/" && p.mode != "pick" {
		p.editingSearch = true
		p.input.SetValue(p.search)
		p.input.CursorEnd()
		return p.input.Focus()
	}

	switch p.mode {
	case "inspect":
		switch k.Type {
		case tea.KeyLeft:
			p.mode = "stream"
			p.inspect = nil
		case tea.KeyUp:
			p.inspectScroll = maxInt(0, p.inspectScroll-1)
		case tea.KeyDown:
			p.inspectScroll++ // clamped at render
		case tea.KeyPgUp:
			p.inspectScroll = maxInt(0, p.inspectScroll-10)
		case tea.KeyPgDown:
			p.inspectScroll += 10
		}
		return nil

	case "layers":
		if k.Type == tea.KeyLeft || str == "l" {
			p.mode = "stream"
			return nil
		}
		switch k.Type {
		case tea.KeyUp:
			p.layersScroll = maxInt(0, p.layersScroll-1)
		case tea.KeyDown:
			p.layersScroll++
		case tea.KeyPgUp:
			p.layersScroll = maxInt(0, p.layersScroll-10)
		case tea.KeyPgDown:
			p.layersScroll += 10
		}
		return nil

	}

	// stream mode
	visible := p.visibleDesc()
	streamBody := maxInt(3, p.streamRows(ctx)-1)
	toggleSignal := func(s string) {
		if p.signal == s {
			p.signal = "none"
		} else {
			p.signal = s
		}
		p.sel = 0
	}
	switch {
	case k.Type == tea.KeyEnter:
		if e, ok := p.selected(visible); ok {
			p.inspect = &e
			p.inspectScroll = 0
			p.mode = "inspect"
		}
	case str == "l":
		p.layersScroll = 0
		p.mode = "layers"
	case str == "w":
		return p.doAction("whitelist", visible, now)
	case str == "b":
		return p.doAction("block", visible, now)
	case str == "d":
		toggleSignal("deny")
	case str == "x":
		toggleSignal("dlp")
	case str == "r":
		toggleSignal("ratelimit")
	case str == "e":
		p.export(visible, now)
	case k.Type == tea.KeyDown:
		p.sel = minInt(len(visible)-1, p.sel+1)
	case k.Type == tea.KeyUp:
		p.sel = maxInt(0, p.sel-1)
	case k.Type == tea.KeyPgDown:
		p.sel = minInt(len(visible)-1, p.sel+streamBody)
	case k.Type == tea.KeyPgUp:
		p.sel = maxInt(0, p.sel-streamBody)
	}
	return nil
}

// editSearch is the live search bar. `/` and enter both finish; esc cancels the
// editing without discarding the query, which is the one key Ink's text input
// did not answer at all.
func (p *Live) editSearch(k tea.KeyMsg) tea.Cmd {
	switch k.Type {
	case tea.KeyEnter, tea.KeyEsc:
		p.editingSearch = false
		p.input.Blur()
		return nil
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(k)
	v := p.input.Value()
	if strings.HasSuffix(v, "/") {
		p.editingSearch = false
		p.input.SetValue(strings.TrimSuffix(v, "/"))
		p.input.Blur()
		return nil
	}
	if v != p.search {
		p.search = v
		p.sel = 0
	}
	return cmd
}

func (p *Live) selected(visible []streamItem) (streamItem, bool) {
	if len(visible) == 0 {
		return streamItem{}, false
	}
	i := minInt(maxInt(0, p.sel), len(visible)-1)
	return visible[i], true
}

// doAction whitelists the selected DENY or blocks the selected ALLOW.
//
// Cloud entries go through the audit endpoints, which resolve the agent to its
// policy; local entries add a rule to this machine's active policy directly.
func (p *Live) doAction(act string, visible []streamItem, now int64) tea.Cmd {
	e, ok := p.selected(visible)
	if !ok {
		return nil
	}
	valid := e.Decision != "ALLOW"
	if act == "block" {
		valid = e.Decision == "ALLOW"
	}
	if !valid {
		text := "select a DENY to whitelist (w)"
		if act == "block" {
			text = "select an ALLOW to block (b)"
		}
		p.action = &flashMsg{text: text, level: "bad", until: now + 4000}
		return nil
	}
	verb := "ALLOW"
	if act == "block" {
		verb = "DENY"
	}
	p.action = &flashMsg{text: map[string]string{"whitelist": "whitelisting…", "block": "blocking…"}[act],
		level: "ok", until: now + 4000}

	gen, c := p.gen, p.deps.Client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		fail := func(err error) tea.Msg {
			return liveActionResult{gen: gen, text: "✗ " + err.Error(), level: "bad"}
		}
		// Active-policy gate for BOTH sources, mirroring the API: with no policy
		// active nothing is granted, not allow, not deny. Resolved fresh on
		// every action so deactivating in the dashboard applies immediately.
		active, err := c.Policies.Active(ctx, "")
		if err != nil {
			return fail(err)
		}
		if active.Policy == nil || active.Policy.ID == "" {
			return liveActionResult{gen: gen, level: "bad",
				text: "✗ no active policy, rule NOT added. Activate a policy first (Policies section)."}
		}
		// THE SAME RULE THE AUDIT BROWSER WOULD MAKE. This had two branches: an entry
		// from the store went through Audit.Whitelist/Block, which builds the rule from
		// the recorded arguments and REFUSES when there is nothing to narrow on; an
		// entry read off the log got a local extractor that looked for no url and took
		// only the BASENAME of a path, and, when it found nothing, left Kind "tool"
		// and silently allowed every call to that tool forever.
		//
		// The store branch went dead when the second read did, so every `w` was taking
		// the widening path. client.RuleSpecFor is now the one implementation of "what rule
		// would have stopped this call", and it refuses rather than widens.
		spec, specErr := client.RuleSpecFor(e.Tool, e.Args, "exact", verb)
		if specErr != nil {
			return liveActionResult{gen: gen, level: "bad", text: "✗ " + specErr.Error()}
		}
		res, err := c.Policies.AddRule(ctx, active.Policy.ID, spec)
		if err != nil {
			return fail(err)
		}
		text := verb + " rule already present"
		if !res.Deduped {
			pid := res.PolicyID
			if pid == "" {
				pid = "?"
			}
			version := ""
			if res.PolicyVersion > 0 {
				version = " v" + strconv.Itoa(res.PolicyVersion)
			}
			text = verb + " rule added → " + pid + version + " · reaches agents in ~30s"
		}
		logText, logLevel := "✓ whitelisted "+e.Tool, "ok"
		if act == "block" {
			logText, logLevel = "⛔ blocked "+e.Tool, "warn"
		}
		return liveActionResult{gen: gen, text: text, level: "ok", logText: logText, logLevel: logLevel}
	}
}

// extractTarget lived here: a second reader of a call's target, over the DISPLAY string
// rather than the recorded arguments. It differed from the store's in two ways that
// decided how wide a policy got, no url, and the basename of a path instead of the path
//, so whitelisting one denial from the stream and from the audit browser produced two
// different rules. client.RuleSpecFor is the one answer now.

func (p *Live) export(visible []streamItem, now int64) {
	dir := config.Dir()
	file := filepath.Join(dir, "live-export.jsonl")
	var b strings.Builder
	for _, e := range visible {
		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		p.action = &flashMsg{text: "✗ export failed: " + err.Error(), level: "bad", until: now + 6000}
		return
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
		p.action = &flashMsg{text: "✗ export failed: " + err.Error(), level: "bad", until: now + 6000}
		return
	}
	// CHMOD AS WELL AS THE MODE, because WriteFile only applies a mode when it
	// CREATES the file. An export written once at 0644 keeps 0644 through
	// every rewrite after it, so changing the constant fixes new machines and
	// leaves every machine that already exported one exactly as it was. The
	// chmod is what reaches those.
	_ = os.Chmod(file, 0o600)
	p.action = &flashMsg{
		text:  "✓ exported " + strconv.Itoa(len(visible)) + " lines → " + file,
		level: "ok", until: now + 6000,
	}
}