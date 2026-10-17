// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/health"
	"github.com/solongate/agent-security/packages/tui"
)

func onOff(on bool) (string, lipgloss.Style) {
	if on {
		return "on ", stOK
	}
	return "off", stDim
}

func (p *Settings) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	return clip(p.viewList(), p.cols, p.rows)
}

func (p *Settings) firstError() error {
	for _, e := range []error{p.localErr, p.guardErr, p.selfErr} {
		if e != nil {
			return e
		}
	}
	return nil
}

func (p *Settings) viewList() string {
	loading := !p.haveLocal && !p.haveGuard && !p.haveSelf && p.firstError() == nil
	raw := p.firstError()

	err := raw
	if err != nil || loading {
		return dataView(loading, err, false, "", "")
	}

	rows := p.allRows()
	cur := p.current()
	curKey := cur.key()

	type flat struct {
		text string
		key  string
	}
	var lines []flat
	push := func(text, key string) { lines = append(lines, flat{text, key}) }

	lastSec := ""
	for _, r := range rows {
		sec := sectionOf(r)
		if sec != lastSec {
			if lastSec != "" {
				push(" ", "")
			}
			lastSec = sec
			push(stAccentB.Render(sec)+stDim.Render(", "+p.sectionDesc(sec)), "")

		}
		push(p.rowLine(r, r.key() == curKey && p.focused), r.key())

		if r.kind == "repair" && p.repairReport != nil {
			rep := p.repairReport
			if len(rep.Before) > 0 {
				push(stDim.Render("    before:"), "")
				for _, l := range rep.Before {
					st := stOK
					if !l.OK {
						st = stBad
					}
					push(st.Render("      "+pad(l.Label, 20)+" "+l.Detail), "")
				}
			}
			if len(rep.After) > 0 {
				push(stDim.Render("    restored:"), "")
				for _, l := range rep.After {

					st := stOK
					if !l.OK {
						st = stWarn
					}
					push(st.Render("      "+pad(l.Label, 20)+" "+l.Detail), "")
				}
			}
			for _, n := range rep.Notes {
				push(stDim.Render("      "+n), "")
			}
		}

		if r.kind == "doctor" {

			if p.diagBusy {
				for i, label := range doctorSteps {
					mark, st := " ", stDim
					switch {
					case i < p.diagStep:
						mark, st = "✓", stOK
					case i == p.diagStep:
						mark, st = spinFrames[p.spin%len(spinFrames)], stAccent
					}
					push(st.Render("      "+mark+" "+label), "")
				}
			}

			for _, c := range p.diag {
				mark, st := "✗", stBad
				switch c.OK {
				case health.StateOK:
					mark, st = "✓", stOK
				case health.StateWarn:
					mark, st = "!", stWarn
				}
				push(st.Render("    "+mark+" "+pad(c.Name, 16)+" "+c.Detail), "")
			}
		}
	}

	if len(p.protected) > 0 {
		push(" ", "")
		push(stAccentB.Render("PROTECTED PATHS")+
			stDim.Render(", out of the agent's reach, by the OS where it can be"), "")
		for _, r := range p.protected {
			mark, st := "✗", stBad
			switch {
			case r.lock.Immutable:
				mark, st = "✓", stOK
			case r.lock.Held():
				mark, st = "!", stWarn
			}
			push(st.Render("  "+mark+" ")+truncate(r.path, max(20, p.cols-6)), "")
			push(stDim.Render("      "+r.lock.Summary()), "")
		}
		push(stDim.Render("      `solongate protect` adds and removes them"), "")
	}

	push(" ", "")
	push(stDim.Render("solongate v"+Version), "")

	budget := max(4, p.rows-2)
	selLine := 0
	for i, l := range lines {
		if l.key == curKey {
			selLine = i
			break
		}
	}
	texts := make([]string, len(lines))
	for i, l := range lines {
		texts[i] = l.text
	}
	win, above, below := window(texts, selLine, budget)

	var out []string
	hint := "press → to configure"
	if p.focused {
		hint = "↑↓ move · enter act · m toggle · t test · e edit · x remove · d delete · n add" + scrollTag(above, below)
	}
	out = append(out, stDim.Render(hint))

	switch {
	case p.editing != "":
		prompt := "webhook url: "
		switch p.editing {
		case "path":
			prompt = "local log path: "
		}
		out = append(out, stWarn.Render(prompt)+p.input.View())
	case p.msg != nil:
		st := stOK
		if p.msg.bad {
			st = stBad
		}
		out = append(out, st.Render(truncate(p.msg.text, p.cols)))
	default:
		out = append(out, " ")
	}

	out = append(out, win...)
	return joinLines(out)
}

func sectionOf(r setRow) string {
	switch r.kind {
	case "guard", "self", "doctor", "repair":
		return "PROTECTION"
	case "range":
		return "UPDATES"
	}
	return "LOCAL LOGS"
}

func (p *Settings) sectionDesc(sec string) string {
	switch sec {
	case "PROTECTION":
		return "guard hook, self-protection, doctor and repair"
	case "UPDATES":
		return "how far `solongate update` may move this machine"
	}
	return "where the hooks write this machine's audit trail"
}

func (p *Settings) rowLine(r setRow, isCur bool) string {
	l := newLine(false)
	if isCur {
		l.put("▸ ", stAccent)
	} else {
		l.put("  ", stDim)
	}
	spin := spinFrames[p.spin%len(spinFrames)]
	_ = spin

	switch r.kind {
	case "range":
		l.put(pad("range", 11), stDim)
		if config.UpdateRangeOf(p.deps.Cfg) == config.UpdateRangeShort {

			l.put("short", stWarn)
			l.put("  every commit on the branch", stDim)
		} else {
			l.put("long", stOK)
			l.put("   tagged releases only", stDim)
		}

	case "guard":
		l.put(pad("guard", 11), stDim)
		if !p.haveGuard {
			l.put("…", stDim)
			break
		}

		installed := "unknown"
		st := stWarn
		if p.guard.Installed != nil {
			installed = "v" + itoa(*p.guard.Installed)
			if p.guard.UpToDate {
				st = stOK
			}
		}
		l.put(installed, st)
		l.put("  latest v"+itoa(p.guard.Latest)+" · "+itoa(p.guard.DeviceCount)+" device(s), "+
			itoa(p.guard.OutdatedCount)+" outdated (cloud)", stDim)
		l.put(" · enter installs · d removes", stDim)

	case "self":
		l.put(pad("self-prot", 11), stDim)
		if p.haveSelf {
			txt, st := onOff(p.selfProt)
			l.put(txt, st)
		} else {
			l.put("…", stDim)
		}
		l.put("   blocks agents editing SolonGate's own hooks/config · enter toggles", stDim)

	case "doctor":
		l.put(pad("doctor", 11), stDim)
		if p.diagBusy {
			l.put(spinFrames[p.spin%len(spinFrames)]+" running health check…", stAccent)
		} else {
			l.put("health check: policy, guard, hooks, local logs · enter runs it", stDim)
		}

	case "repair":
		l.put(pad("repair", 11), stDim)
		l.put("restore every protection file after tampering or deletion", stDim)
		l.put(" · enter runs it", stDim)

	case "ll-enabled":
		l.put(pad("enabled", 11), stDim)
		txt, st := onOff(p.haveLocal && p.local.Enabled)
		l.put(txt, st)
		l.put("   enter toggles", stDim)

	case "ll-path":
		l.put(pad("path", 11), stDim)
		switch {
		case !p.haveLocal || p.local.Path == "":
			l.put("not set, enter to edit", stDim)
		case p.local.Enabled && !p.llSetting.UsableHere:

			half := max(12, (p.cols-20)/2)
			l.put(truncate(p.local.Path, half), stWarn)
			l.put("  not valid here → "+truncate(p.llSetting.File, half), stDim)
		default:
			l.put(truncate(p.local.Path, max(8, p.cols-14)), stAccent)
		}

	}
	return l.String()
}