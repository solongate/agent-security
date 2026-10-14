// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"strings"

	"github.com/solongate/agent-security/packages/tui"
)

// Split from sandbox.go: the hint, the panel view, and small render helpers.

func (p *Sandbox) Hint() []string {
	if p.boxErr != nil {
		return []string{"▶ SANDBOX", "", "Not available on this machine.", "", "press → to read why"}
	}
	if len(p.boxes) == 0 {
		return []string{
			"▶ SANDBOX: CLOSED BOXES",
			"",
			"None yet. A box gives an agent one",
			"directory and nothing else.",
			"",
			"press → then n to make one",
		}
	}
	if len(p.boxes) == 1 {
		return []string{"▶ SANDBOX: CLOSED BOXES", "", "box " + p.boxes[0].ID, "",
			truncate(p.boxes[0].Dir, 44), "", "press → to manage"}
	}
	return []string{"▶ SANDBOX: CLOSED BOXES", "", itoa(len(p.boxes)) + " boxes", "", "press → to manage"}
}

func (p *Sandbox) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	return clip(p.view(), p.cols, p.rows)
}

func (p *Sandbox) view() string {
	var out []string

	hint := "press → to configure"
	if p.focused {
		hint = "↑↓ move · n new · enter edit · m network · d d delete"
	}
	out = append(out, stDim.Render(hint))

	switch {
	case p.editing:
		out = append(out, stWarn.Render("directory (absolute path): ")+p.input.View())
	case p.msg != nil:
		st := stOK
		if p.msg.bad {
			st = stBad
		}
		out = append(out, st.Render(truncate(p.msg.text, p.cols)))
	default:
		out = append(out, " ")
	}
	out = append(out, "")

	// A machine that cannot build a box says so rather than listing boxes it
	// could not start.
	if p.boxErr != nil {
		out = append(out, stBad.Render("  No closed box on this machine."))
		out = append(out, "")
		for _, l := range wrapWords(p.boxErr.Error(), sbWidth(p.cols-4)) {
			out = append(out, stDim.Render("  "+l))
		}
		if p.mech != "" {
			out = append(out, "")
			out = append(out, stDim.Render("  `solongate run` is the weaker confinement this machine CAN do:"))
			out = append(out, stDim.Render("  "+p.mech+" over the protected-paths list, rather than a new root."))
		}
		return joinLines(out)
	}

	if !p.loaded {
		out = append(out, stDim.Render("  reading the policy file…"))
		return joinLines(out)
	}

	if len(p.boxes) == 0 {
		out = append(out, stWarn.Render("  No boxes."))
		out = append(out, "")
		out = append(out, stDim.Render("  A box gives an agent one directory and nothing else: no $HOME,"))
		out = append(out, stDim.Render("  no /etc/passwd, no other project. Not refused, absent."))
		out = append(out, "")
		out = append(out, stDim.Render("  press n, then type an absolute path"))
		return joinLines(out)
	}

	for i, b := range p.boxes {
		l := newLine(false)
		if i == p.sel && p.focused {
			l.put("▸ ", stAccent)
		} else {
			l.put("  ", stDim)
		}
		l.put(sbPad(b.ID, 5), stAccent)
		if b.Network {
			l.put(sbPad("net", 5), stDim)
		} else {
			// WARN rather than OK, and not because it is wrong: no network is
			// the STRONGER box and also the one where the agent cannot reach
			// its model. Somebody scanning this column needs to see which of
			// their boxes will not run an agent that needs an API.
			l.put(sbPad(", ", 5), stWarn)
		}
		l.put(truncate(b.Dir, sbWidth(p.cols-16)), stOK)
		out = append(out, l.String())
	}

	if b, ok := p.cur(); ok {
		out = append(out, "")
		out = append(out, stDim.Render("  solongate sandbox "+b.ID+" claude"))
		out = append(out, "")
		if b.Network {
			out = append(out, stDim.Render("  network ON, the agent can reach its model. What leaves over"))
			out = append(out, stDim.Render("  the wire is the DLP and egress layers' job, not the box's."))
		} else {
			out = append(out, stWarn.Render("  network OFF, nothing can leave this box at all, and an agent"))
			out = append(out, stWarn.Render("  that cannot reach its model can only do offline work."))
		}
	}

	return joinLines(out)
}

func sbWidth(n int) int {
	if n < 20 {
		return 20
	}
	return n
}

func sbPad(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

// wrapWords breaks a sentence at spaces, so a long refusal reads as a paragraph
// rather than one clipped line.
func wrapWords(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	out := []string{}
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			out = append(out, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	return append(out, cur)
}