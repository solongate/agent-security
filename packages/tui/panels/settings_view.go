// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/health"
	"github.com/solongate/agent-security/packages/tui"
)

// Split from settings.go: the on/off helper and the rendering of the panel.

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

// authErrorShape matched an error worth keeping the panel open for: every loader here
// spoke to a service, and a revoked key 401'd all of them at once. Rendering that
// error INSTEAD of the rows hid the Accounts section, the only way to remove the dead
// account and pair again, so a device revoked from the dashboard was stuck being told
// to use a panel it could not see.
//
// Nothing 401s. The loaders read a file, and the two failures a file has (absent,
// unparseable) are already the ordinary error path below.

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

	// Rows and their section headers are flattened into ONE line list, then
	// windowed around the selected row. Anything that is not selectable, a
	// header, a warning, the version at the bottom, carries an empty key.
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
			// A warning stood here for the WEBHOOKS and ALERTS sections: they fired
			// server-side off the audit POST, which the guard skipped in local-log
			// mode, so they were a silent no-op. sectionOf has produced only
			// PROTECTION and LOCAL LOGS since those sections went, which made the
			// branch unreachable, and its condition (`p.local.Enabled`) is now true
			// on every machine, so it would have shown on all of them.
		}
		push(p.rowLine(r, r.key() == curKey && p.focused), r.key())

		// The repair's two lists, under the row that produced them, in the same
		// shape and order `solongate repair` prints. Not selectable.
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
					// A client the repair could not register is the one line worth
					// colouring: the run succeeded and that client is still
					// unguarded.
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
			// While the check runs, the step list stands in for the result:
			// finished steps tick, the current one spins, the rest sit dim.
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
			// The last run's rows sit under the row that produced them, and are
			// not selectable.
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

	// PROTECTED PATHS, under everything else and not selectable.
	//
	// The mark is the whole point of the section: a tick means the operating
	// system refuses to write or delete it, a warning means the write is
	// refused and a delete is not, a cross means nothing is holding it. All
	// three print the same word in the policy file.
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

	// The version sits at the very bottom of the scrollable list.
	push(" ", "")
	push(stDim.Render("solongate v"+Version), "")

	// hint + status take one line each. The panel must not grow past its box.
	//
	// A third line used to be reserved when the auth banner was showing. There is no
	// banner: nothing here can fail with a credential error.
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
			// Warn rather than OK. It is a supported choice and it is the one
			// that installs code no release has covered, and the colour is the
			// only part of this row somebody reads at a glance.
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
		// The cloud's view: the newest hook, what this project's devices last
		// reported, and how many are behind. The LOCAL truth, which hook files
		// this device actually has, is what `doctor` reads, and enter on this
		// row installs through the same code path `solongate repair` uses.
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
			// The folder is a PROJECT setting shared by every device on it, so
			// it can name a path that only exists on another OS. The hooks then
			// quietly fall back, and this row was the last place still claiming
			// the configured path was in use.
			half := max(12, (p.cols-20)/2)
			l.put(truncate(p.local.Path, half), stWarn)
			l.put("  not valid here → "+truncate(p.llSetting.File, half), stDim)
		default:
			l.put(truncate(p.local.Path, max(8, p.cols-14)), stAccent)
		}

	}
	return l.String()
}