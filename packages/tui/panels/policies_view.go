// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

// Split from policies.go: rendering for every level.

func (p *Policies) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	switch p.view {
	case viewList:
		return clip(p.viewListBody(), p.cols, p.rows)
	case viewPolicy:
		return clip(p.viewPolicyBody(), p.cols, p.rows)
	case viewRules:
		return clip(p.viewRulesBody(), p.cols, p.rows)
	case viewMatch:
		return clip(p.viewMatchBody(), p.cols, p.rows)
	case viewDLP, viewRate:
		return clip(p.viewLayerBody(), p.cols, p.rows)
	default:
		return clip(p.viewRuleBody(), p.cols, p.rows)
	}
}

func (p *Policies) viewListBody() string {
	empty := !p.listLoading && p.listErr == nil && len(p.policies) == 0 && !p.creating && !p.busyCreate
	if p.listLoading && p.policies == nil {
		return dataView(true, nil, false, "", "")
	}
	if p.listErr != nil {
		return dataView(false, p.listErr, false, "", "")
	}
	if empty {
		return dataView(false, nil, true, "No policies yet, press n to create one.", "")
	}

	head := 3
	if p.status != "" {
		head++
	}
	if p.creating {
		head++
	}
	budget := max(3, p.rows-head)

	rows := make([]string, 0, len(p.policies))
	for i, pol := range p.policies {
		l := newLine(false)
		cursor, st := "  ", stPlain
		if i == p.pi {
			cursor, st = "▸ ", stAccentB
		}
		l.put(cursor+pad(truncate(pol.Name, 26), 27), st)
		l.put(pad(string(pol.Mode), 10)+" "+itoa(len(pol.Rules.Items)+pol.Rules.Unreadable)+" rules", stDim)
		if pol.ID == p.activeID && p.activeID != "" {
			l.put("  ● ACTIVE", stOKB)
		}
		rows = append(rows, l.String())
	}
	win, above, below := window(rows, p.pi, budget)

	var out []string
	al := newLine(false)
	al.put("active: ", stDim)
	switch {
	case p.activeLoad && p.activeID == "":
		al.put("…", stDim)
	case p.activeID != "":
		name := p.activeID
		for _, pol := range p.policies {
			if pol.ID == p.activeID {
				name = pol.Name
			}
		}
		al.put("● "+truncate(name, 28), stOKB)
		if p.activeBy != "" {
			al.put(" ("+p.activeBy+")", stDim)
		}
	default:
		al.put("○ NONE, nothing enforced, grants refused", stBadB)
	}
	out = append(out, al.String())

	hint := "press → to browse"
	if p.focused {
		hint = "↑↓ select · enter open · n new · a activate · x deactivate · d delete · ^R refresh" + scrollTag(above, below)
	}
	out = append(out, stDim.Render(hint))

	if p.creating {
		out = append(out, stWarn.Render("new policy name: ")+p.input.View())
	}
	out = append(out, "")
	out = append(out, win...)
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) dirtyTag(l *lineBuf) {
	if p.dirty {
		l.put("  ● unsaved (s save · x discard)", stWarn)
	}
}

// variantTabs is the row the dashboard draws as tabs. The one in force is lit
// and boxed; the rest are dim, and a policy with a single variant draws nothing
// at all, because one tab is not a choice.
func (p *Policies) variantTabs() string {
	if len(p.variants) < 2 {
		return ""
	}
	l := newLine(false)
	for i, v := range p.variants {
		if i == p.vi {
			l.put("[ "+truncate(v.name, 18)+" ]", stAccentB)
		} else {
			l.put("  "+truncate(v.name, 18)+"  ", stDim)
		}
	}
	l.put("   tab switches", stDim)
	return l.String()
}

// layerSummary is the right-hand side of a layer row: what it is set to, in the
// words the dashboard's fold headers use.
func (p *Policies) layerSummary(layer int) (string, lipgloss.Style) {
	switch layer {
	case layerRules:
		n := len(p.rules)
		off := 0
		for _, d := range p.rules {
			if !d.rule.Enabled {
				off++
			}
		}
		text := itoa(n) + " rules"
		if n == 1 {
			text = "1 rule"
		}
		if off > 0 {
			text += " · " + itoa(off) + " off"
		}
		if n == 0 {
			return "no rules yet", stDim
		}
		return text, stPlain
	case layerDLP:
		d := p.sec.DLP
		if d.Mode == client.LayerOff || d.Mode == "" {
			return "off · nothing scanned", stDim
		}
		text := string(d.Mode) + " · " + itoa(len(d.Patterns)+len(d.Custom)) + " detectors"
		return text, modeStyle(string(d.Mode))
	default:
		rl := p.sec.RateLimit
		if rl.Mode == client.LayerOff || rl.Mode == "" {
			return "off · no limit", stDim
		}
		return string(rl.Mode) + " · " + offOr(rl.PerMinute) + "/min · " +
			offOr(rl.PerHour) + "/hr · " + offOr(rl.PerDay) + "/day", modeStyle(string(rl.Mode))
	}
}

var polLayerNames = [layerCount]string{"Rules", "Secret detectors", "Rate limit"}

// A second, dimmer line used to sit under each layer explaining what it was for,
// "what is allowed and what is denied" under Rules, and so on. It doubled the height
// of the card to restate the three names next to it, and it never changed, so after
// the first read it was three lines of furniture between the reader and the numbers
// they came for.

// viewPolicyBody is one policy: its variants along the top, its three layers
// under them. It is the dashboard's policy card, which is always open and whose
// layers are the things that fold.
func (p *Policies) viewPolicyBody() string {
	if p.detailLoading && !p.haveDetail {
		return dataView(true, nil, false, "", "")
	}
	if p.detailErr != nil {
		return dataView(false, p.detailErr, false, "", "")
	}

	var out []string
	name := ""
	if sel, ok := p.selected(); ok {
		name = sel.Name
	}
	h := newLine(false)
	h.put(truncate(name, 30), stAccentB)
	h.put("  mode: ", stDim)
	modeSt := stPlain
	if p.mode == client.ModeWhitelist {
		modeSt = stWarn
	}
	h.put(string(p.mode), modeSt)
	if p.detailID != "" && p.detailID == p.activeID {
		h.put("  ● ACTIVE", stOKB)
	}
	p.dirtyTag(h)
	out = append(out, h.String())

	hint := "press → to open"
	if p.focused {
		hint = "↑↓ layer · enter open · tab variant · v new variant · V remove · m mode · s save · ← back"
	}
	out = append(out, stDim.Render(truncate(hint, p.cols)))

	if tabs := p.variantTabs(); tabs != "" {
		out = append(out, tabs)
	} else {
		out = append(out, stDim.Render("one variant · v adds a second, for a machine that needs different rules"))
	}
	out = append(out, "")

	for i := 0; i < layerCount; i++ {
		sel := p.focused && i == p.li
		l := newLine(sel)
		cursor, cst := "  ", stDim
		if sel {
			cursor, cst = "▸ ", stAccent
		}
		l.put(cursor, cst.Bold(sel))
		l.put(pad(polLayerNames[i], 18), stBold)
		text, st := p.layerSummary(i)
		l.put(pad(truncate(text, max(10, p.cols-42)), max(10, p.cols-42)), st)
		out = append(out, l.String())
	}

	if p.unreadable > 0 {
		// Never silently show fewer rules than the policy has.
		out = append(out, stBad.Render("⚠ "+itoa(p.unreadable)+" rule(s) here cannot be read by this version, edit ~/.solongate/policy.json directly"))
	}
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

// viewLayerBody is a bound editor with this panel's header above it, so the
// policy and the variant being edited are never off screen.
func (p *Policies) viewLayerBody() string {
	child := p.layerPanel()
	if child == nil {
		return ""
	}
	p.syncToLayer()

	var out []string
	name := ""
	if sel, ok := p.selected(); ok {
		name = sel.Name
	}
	h := newLine(false)
	h.put(truncate(name, 24), stAccentB)
	h.put(" · ", stDim)
	which := polLayerNames[layerDLP]
	if p.view == viewRate {
		which = polLayerNames[layerRate]
	}
	h.put(which, stBold)
	if len(p.variants) > 1 && p.vi < len(p.variants) {
		h.put("  ["+truncate(p.variants[p.vi].name, 18)+"]", stAccent)
	}
	// No unsaved tag here: the editor below draws its own, and two of them on
	// one screen reads as two different unsaved things.
	out = append(out, h.String())
	out = append(out, "")
	out = append(out, child.View(p.childCtx()))
	return joinLines(out)
}

func (p *Policies) viewRulesBody() string {
	if p.detailLoading && !p.haveDetail {
		return dataView(true, nil, false, "", "")
	}
	if p.detailErr != nil {
		return dataView(false, p.detailErr, false, "", "")
	}

	statusLines := 0
	if p.status != "" {
		statusLines = len(strings.Split(p.status, "\n"))
	}
	head := 4 + statusLines
	budget := max(3, p.rows-head)

	rows := make([]string, 0, len(p.rules))
	for i, d := range p.rules {
		r := d.rule
		l := newLine(false)
		cur := ""
		if i == p.ri {
			cur = "▸"
		}
		l.put(fit(cur, 2)+"  ", stAccentB)
		on, onStyle := "○", stDim
		if r.Enabled {
			on, onStyle = "●", stOK
		}
		l.put(fit(on, 2)+"  ", onStyle)
		effStyle := stBad
		if r.Effect == "ALLOW" {
			effStyle = stOK
		}
		if !r.Enabled {
			effStyle = stDim
		}
		l.put(fit(r.Effect, 7)+"  ", effStyle)
		l.put(fit(itoa(r.Priority), 4)+"  ", stDim)
		descStyle := stPlain
		if !r.Enabled {
			descStyle = stDim
		}
		l.put(fit(truncate(orDash(r.Description), 38), 38)+"  ", descStyle)
		l.put(fit(orDash(ruleSummary(r)), 14)+"  ", stDim)
		rows = append(rows, l.String())
	}
	win, above, below := window(rows, p.ri, budget)

	var out []string
	name := ""
	if sel, ok := p.selected(); ok {
		name = sel.Name
	}
	t := newLine(false)
	t.put(truncate(name, 28), stAccentB)
	t.put("  mode: ", stDim)
	modeStyleSel := stPlain
	if p.mode == client.ModeWhitelist {
		modeStyleSel = stWarn
	}
	t.put(string(p.mode), modeStyleSel)
	t.put("  "+itoa(len(p.rules))+" rules", stDim)
	if p.unreadable > 0 {
		// Never silently show fewer rules than the policy has.
		t.put("  ⚠ "+itoa(p.unreadable)+" unreadable", stBad)
	}
	p.dirtyTag(t)
	out = append(out, t.String())

	out = append(out, stDim.Render("↑↓ · enter edit · space on/off · e effect · n new · d del · m mode · s save · ← back"+scrollTag(above, below)))
	out = append(out, "")
	out = append(out, stDim.Render(fit("", 2)+"  "+fit("ON", 2)+"  "+fit("EFFECT", 7)+"  "+fit("PRIO", 4)+"  "+fit("DESCRIPTION", 38)+"  "+fit("CONSTRAINTS", 14)+"  "))
	out = append(out, win...)
	if len(p.rules) == 0 {
		out = append(out, stDim.Render("(no rules)"))
	}
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) viewMatchBody() string {
	var items []string
	t := cNone
	effect := ""
	if p.ri < len(p.rules) {
		items = matchItems(p.rules[p.ri].rule)
		t = currentCType(p.rules[p.ri].rule)
		effect = p.rules[p.ri].rule.Effect
	}

	var out []string
	h := newLine(false)
	h.put("Match values ", stAccentB)
	if effect != "" {
		h.put(effect+" · "+string(t), stDim)
	}
	p.dirtyTag(h)
	out = append(out, h.String())
	out = append(out, stDim.Render("↑↓ select · enter/e edit · a add · [ / ] wildcard L/R · d remove · s save · ← back"))
	out = append(out, "")

	rows := make([]string, 0, len(items))
	for i, it := range items {
		sel := i == p.matchSel
		l := newLine(false)
		if sel {
			l.put("▸ ", stAccent)
		} else {
			l.put("  ", stPlain)
		}
		if sel && p.editing {
			v := p.input.Value()
			txt, st := starLeft(strings.HasPrefix(v, "*"))
			l.put(txt, st)
			l.put(p.input.View(), stPlain)
			txt, st = starRight(len(v) > 0 && strings.HasSuffix(v, "*"))
			l.put(txt, st)
			rows = append(rows, l.String())
			continue
		}
		txt, st := starLeft(strings.HasPrefix(it, "*"))
		l.put(txt, st)
		if it == "" {
			l.put("(empty)", stDim)
		} else {
			l.put(it, stPlain)
		}
		txt, st = starRight(len(it) > 0 && strings.HasSuffix(it, "*"))
		l.put(txt, st)
		rows = append(rows, l.String())
	}
	if len(items) == 0 {
		out = append(out, stDim.Render("(no values, press a to add one)"))
	} else {
		// The Ink version drew every value and relied on the outer box to clip.
		// This windows instead, so a long value list scrolls rather than pushing
		// the help line and the status out of the frame.
		statusRows := 0
		if p.status != "" {
			statusRows = 1
		}
		budget := max(1, p.rows-4-statusRows)
		win, _, _ := window(rows, p.matchSel, budget)
		out = append(out, win...)
	}
	out = append(out, stDim.Render("  * = wildcard (any run of chars). Type it directly (rm*) or toggle with [ / ]. Green ✱ = active · left & right shown as you type. Multiple values = OR (any one matches)."))
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) viewRuleBody() string {
	var out []string
	var rule client.PolicyRule
	have := p.ri < len(p.rules)
	if have {
		rule = p.rules[p.ri].rule
	}

	h := newLine(false)
	h.put("Rule ", stAccentB)
	h.put(rule.ID, stDim)
	p.dirtyTag(h)
	out = append(out, h.String())
	out = append(out, stDim.Render("↑↓ field · enter edit/open · space toggle · ←→ move/pick · s save · ← back"))
	out = append(out, "")

	for i, f := range fieldsFor(rule) {
		active := i == p.fi
		l := newLine(false)
		labelStyle := stPlain
		prefix := "  "
		if active {
			labelStyle, prefix = stAccent, "▸ "
		}
		l.put(prefix+pad(f.label, 13), labelStyle)

		switch {
		case f.kind == "perms" && have:
			// Four chips: green on, red off. ←→ moves the cursor, space toggles.
			for pi, perm := range permsAll {
				st := stBad
				if containsString(permListOf(rule), perm) {
					st = stOK
				}
				if active && pi == p.permCursor%len(permsAll) {
					st = st.Reverse(true)
				}
				text := perm
				if pi < len(permsAll)-1 {
					text += "  "
				}
				l.put(text, st)
			}
		case f.kind == "match" && have:
			items := matchItems(rule)
			preview := strings.Join(items, ", ")
			if preview == "" {
				l.put(", ", stDim)
				l.put("   (enter: add values)", stDim)
			} else {
				l.put(preview, stPlain)
				plural := ""
				if len(items) > 1 {
					plural = "s"
				}
				l.put("   ("+itoa(len(items))+" value"+plural+" · enter: edit)", stDim)
			}
		case active && p.editing && f.kind == "text":
			l.put(p.input.View(), stPlain)
		default:
			val := ""
			if have {
				val = p.fieldValue(rule, f.kind)
			}
			switch {
			case val == "":
				l.put(", ", stDim)
			case f.kind == "effect" && val == "ALLOW":
				l.put(val, stOK)
			case f.kind == "effect":
				l.put(val, stBad)
			default:
				l.put(val, stPlain)
			}
		}
		out = append(out, l.String())
	}
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) fieldValue(r client.PolicyRule, kind string) string {
	switch kind {
	case "effect":
		return r.Effect
	case "ctype":
		return string(currentCType(r))
	case "perms":
		return permDisplay(r)
	case "priority":
		return itoa(r.Priority)
	case "text":
		return r.Description
	case "match":
		return cValue(r)
	}
	return ""
}