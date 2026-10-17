// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

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

func (p *Live) filtered() []streamItem {
	out := make([]streamItem, 0, len(p.merged))
	for _, e := range p.merged {

		if !p.matches(e) || !p.signalOK(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (p *Live) visibleDesc() []streamItem {
	f := p.filtered()
	out := make([]streamItem, len(f))
	for i := range f {
		out[i] = f[len(f)-1-i]
	}
	return out
}

func (p *Live) onKey(k tea.KeyMsg, ctx PanelContext) tea.Cmd {
	now := ctx.Now.UnixMilli()
	if p.editingSearch {
		return p.editSearch(k)
	}
	str := k.String()

	if str == " " {
		p.frozen = !p.frozen
		return nil
	}
	if p.frozen {
		return nil
	}

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
			p.inspectScroll++
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

		active, err := c.Policies.Active(ctx, "")
		if err != nil {
			return fail(err)
		}
		if active.Policy == nil || active.Policy.ID == "" {
			return liveActionResult{gen: gen, level: "bad",
				text: "✗ no active policy, rule NOT added. Activate a policy first (Policies section)."}
		}

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

	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		p.action = &flashMsg{text: "✗ export failed: " + err.Error(), level: "bad", until: now + 6000}
		return
	}

	_ = os.Chmod(file, 0o600)
	p.action = &flashMsg{
		text:  "✓ exported " + strconv.Itoa(len(visible)) + " lines → " + file,
		level: "ok", until: now + 6000,
	}
}