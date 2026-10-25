// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"encoding/json"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

func (p *Policies) key(k tea.KeyMsg) tea.Cmd {
	s := k.String()
	if s == "ctrl+r" {
		p.status = "⟳ refreshed " + time.Now().Format("15:04:05")
		cmds := []tea.Cmd{p.loadList(), p.loadActive()}
		if p.detailID != "" {
			cmds = append(cmds, p.loadDetail(p.detailID))
		}
		return tea.Batch(cmds...)
	}
	switch p.view {
	case viewList:
		return p.listKey(s)
	case viewPolicy:
		return p.policyKey(s)
	case viewRules:
		return p.rulesKey(s)
	case viewMatch:
		return p.matchKey(s)
	case viewDLP, viewRate:
		return p.layerKey(k, s)
	default:
		return p.ruleKey(k, s)
	}
}

func (p *Policies) policyKey(s string) tea.Cmd {
	switch s {
	case "left":
		p.view = viewList
		p.status = ""
	case "up":
		p.li = max(0, p.li-1)
	case "down":
		p.li = min(layerCount-1, p.li+1)
	case "enter", "right":
		switch p.li {
		case layerRules:
			p.view = viewRules
		case layerDLP:
			p.view = viewDLP
		case layerRate:
			p.view = viewRate

			if !p.rateStarted {
				p.rateStarted = true
				return p.ratePanel.Init(p.childCtx())
			}
		}
	case "tab":
		p.switchVariant(1)
	case "shift+tab":
		p.switchVariant(-1)
	case "m":
		p.flipMode()
	case "v":
		p.addVariant()
	case "V":
		p.dropVariant()
	case "s":
		return p.save()
	case "x":
		p.discard()
	}
	return nil
}

func (p *Policies) flipMode() {
	if p.mode == client.ModeDenylist {
		p.mode = client.ModeWhitelist
	} else {
		p.mode = client.ModeDenylist
	}
	p.mutate()
}

func (p *Policies) listKey(s string) tea.Cmd {
	switch s {
	case "up":
		p.pendingDel = ""
		p.pi = max(0, p.pi-1)
		return p.ensureDetail()
	case "down":
		p.pendingDel = ""
		p.pi = min(len(p.policies)-1, p.pi+1)
		return p.ensureDetail()
	case "enter", "right":
		p.status = ""
		p.view = viewPolicy
		p.li = layerRules
		return nil
	case "a":
		sel, ok := p.selected()
		if !ok {
			return nil
		}
		p.status = "Activating…"
		id, name := sel.ID, sel.Name
		t := p.tag()
		return func() tea.Msg {
			if err := p.deps.Client.Policies.SetActive(bg(), id); err != nil {
				return polActionMsg{genTag: t, status: "✗ " + errText(err)}
			}
			return polActionMsg{
				genTag:        t,
				status:        `✓ "` + name + `" is now the ACTIVE policy (pinned) · reaches agents in ~30s`,
				refreshActive: true,
			}
		}
	case "x":
		p.status = "Deactivating…"
		t := p.tag()
		return func() tea.Msg {
			err := p.deps.Client.Policies.SetActive(bg(), "")
			return polActionMsg{genTag: t, status: "✗ " + errText(err)}
		}
	case "n", "N":
		p.status = ""
		p.creating = true
		p.input.SetValue("")
		p.input.Focus()
		return nil
	case "d":
		sel, ok := p.selected()
		if !ok {
			return nil
		}
		if p.pendingDel != sel.ID {
			p.pendingDel = sel.ID
			p.status = `⚠ d again to DELETE policy "` + sel.Name + `", cannot be undone`
			return nil
		}
		p.pendingDel = ""
		p.status = "Deleting…"
		id, name := sel.ID, sel.Name
		t := p.tag()
		return func() tea.Msg {
			if err := p.deps.Client.Policies.Remove(bg(), id); err != nil {
				return polActionMsg{genTag: t, status: "✗ " + errText(err)}
			}
			return polActionMsg{
				genTag:        t,
				status:        `✓ deleted policy "` + name + `"`,
				refreshList:   true,
				refreshActive: true,
				resetCursor:   true,
			}
		}
	}
	return nil
}

func (p *Policies) rulesKey(s string) tea.Cmd {
	switch s {
	case "left":
		p.view = viewPolicy
		p.status = ""
	case "up":
		p.ri = max(0, p.ri-1)
	case "down":
		p.ri = min(len(p.rules)-1, p.ri+1)
	case "enter", "right":
		if p.ri < len(p.rules) {
			p.fi = 0
			p.view = viewRule
		}
	case " ":
		if p.ri < len(p.rules) {
			p.rules[p.ri].rule.Enabled = !p.rules[p.ri].rule.Enabled
			p.rules[p.ri].edited = true
			p.mutate()
		}
	case "e":
		if p.ri < len(p.rules) {
			p.flipEffect(p.ri)
		}
	case "d":
		if p.ri < len(p.rules) {
			p.rules = append(p.rules[:p.ri:p.ri], p.rules[p.ri+1:]...)
			p.ri = max(0, min(p.ri, len(p.rules)-1))
			p.mutate()
		}
	case "m":
		p.flipMode()
	case "n":

		nr := client.PolicyRule{
			ID:                 "rule-" + itoa(int(time.Now().UnixMilli())),
			Effect:             "DENY",
			Priority:           100,
			ToolPattern:        "*",
			MinimumTrustLevel:  "UNTRUSTED",
			Enabled:            true,
			CommandConstraints: &client.Constraint{Denied: []string{}},
		}
		p.rules = append([]ruleDoc{{rule: nr, edited: true}}, p.rules...)
		p.ri = 0
		p.fi = 0
		p.view = viewRule
		p.mutate()
	case "s":
		return p.save()
	case "x":
		p.discard()
	}
	return nil
}

func (p *Policies) matchKey(s string) tea.Cmd {
	if p.ri >= len(p.rules) {
		p.view = viewRules
		return nil
	}
	items := matchItems(p.rules[p.ri].rule)
	switch s {
	case "left", "esc":
		p.view = viewRule
	case "up":
		p.matchSel = max(0, p.matchSel-1)
	case "down":
		p.matchSel = min(max(0, len(items)-1), p.matchSel+1)
	case "a":
		next := append(append([]string(nil), items...), "")
		p.setItems(next)
		p.matchSel = len(next) - 1
		p.beginEdit("")
	case "enter", "e":
		if len(items) == 0 {
			p.setItems([]string{""})
			p.matchSel = 0
			p.beginEdit("")
			return nil
		}
		p.beginEdit(items[min(p.matchSel, len(items)-1)])
	case "[", "]":
		side := "left"
		if s == "]" {
			side = "right"
		}
		if p.matchSel < len(items) {
			next := append([]string(nil), items...)
			next[p.matchSel] = flipStar(next[p.matchSel], side)
			p.setItems(next)
		}
	case "d":
		if len(items) > 0 && p.matchSel < len(items) {
			next := append(items[:p.matchSel:p.matchSel], items[p.matchSel+1:]...)
			p.setItems(next)
			p.matchSel = max(0, min(p.matchSel, len(next)-1))
		}
	case "s":
		return p.save()
	}
	return nil
}

func (p *Policies) ruleKey(k tea.KeyMsg, s string) tea.Cmd {
	if p.ri >= len(p.rules) {
		p.view = viewRules
		return nil
	}
	fields := fieldsFor(p.rules[p.ri].rule)
	field := fields[min(p.fi, len(fields)-1)]
	switch {

	case s == "esc":
		p.view = viewRules
	case s == "left" && field.kind != "ctype" && field.kind != "perms" && field.kind != "priority":
		p.view = viewRules
	case s == "up":
		p.fi = max(0, p.fi-1)
	case s == "down":
		p.fi = min(len(fields)-1, p.fi+1)
	case field.kind == "effect" && (s == " " || s == "right"):
		p.flipEffect(p.ri)
	case field.kind == "ctype" && (s == " " || s == "right" || s == "left"):
		dir := 1
		if s == "left" {
			dir = -1
		}
		cur := currentCType(p.rules[p.ri].rule)
		idx := 0
		for i, t := range cTypes {
			if t == cur {
				idx = i
			}
		}
		setCType(&p.rules[p.ri].rule, cTypes[(idx+dir+len(cTypes))%len(cTypes)])
		p.rules[p.ri].edited = true
		p.mutate()
	case field.kind == "perms" && s == "left":
		p.permCursor = (p.permCursor + len(permsAll) - 1) % len(permsAll)
	case field.kind == "perms" && s == "right":
		p.permCursor = (p.permCursor + 1) % len(permsAll)
	case field.kind == "perms" && s == " ":
		togglePerm(&p.rules[p.ri].rule, permsAll[p.permCursor%len(permsAll)])
		p.rules[p.ri].edited = true
		p.mutate()
	case field.kind == "match" && (s == "enter" || s == "right"):

		p.matchSel = 0
		p.view = viewMatch
	case field.kind == "priority" && (s == "right" || s == "left"):
		d := 1
		if s == "left" {
			d = -1
		}
		p.rules[p.ri].rule.Priority = max(0, p.rules[p.ri].rule.Priority+d)
		p.rules[p.ri].edited = true
		p.mutate()
	case field.kind == "text" && s == "enter":
		p.beginEdit(p.rules[p.ri].rule.Description)
	case s == "s":
		return p.save()
	}
	_ = k
	return nil
}

func (p *Policies) flipEffect(i int) {
	next := "ALLOW"
	if p.rules[i].rule.Effect == "ALLOW" {
		next = "DENY"
	}
	migrateEffect(&p.rules[i].rule, next)
	p.rules[i].edited = true
	p.mutate()
}

func (p *Policies) setItems(items []string) {
	setMatchItems(&p.rules[p.ri].rule, items)
	p.rules[p.ri].edited = true
	p.mutate()
}

func (p *Policies) beginEdit(value string) {
	p.editing = true
	p.input.SetValue(value)
	p.input.CursorEnd()
	p.input.Focus()
}

func (p *Policies) editingKey(k tea.KeyMsg) tea.Cmd {
	if k.String() == "esc" {
		p.editing = false
		p.input.Blur()
		return nil
	}
	if k.String() != "enter" {
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(k)
		return cmd
	}
	v := p.input.Value()
	p.editing = false
	p.input.Blur()
	if p.ri >= len(p.rules) {
		return nil
	}
	if p.view == viewMatch {
		items := matchItems(p.rules[p.ri].rule)
		val := strings.TrimSpace(v)
		next := append([]string(nil), items...)
		if p.matchSel < len(next) {
			next[p.matchSel] = val
		}

		if val == "" && p.matchSel < len(next) {
			next = append(next[:p.matchSel:p.matchSel], next[p.matchSel+1:]...)
		}
		p.setItems(next)
		p.matchSel = max(0, min(p.matchSel, len(next)-1))
		return nil
	}
	p.rules[p.ri].rule.Description = v
	p.rules[p.ri].edited = true
	p.mutate()
	return nil
}

func (p *Policies) creatingKey(k tea.KeyMsg) tea.Cmd {
	if k.String() == "esc" {
		p.creating = false
		p.input.Blur()
		return nil
	}
	if k.String() != "enter" {
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(k)
		return cmd
	}
	name := strings.TrimSpace(p.input.Value())
	p.creating = false
	p.input.Blur()
	if name == "" {
		return nil
	}
	p.status = "Creating…"

	p.busyCreate = true
	body := client.PolicySet{ID: "policy-" + itoa(int(time.Now().UnixMilli())), Name: name, Mode: client.ModeDenylist}
	t := p.tag()
	return func() tea.Msg {
		if _, err := p.deps.Client.Policies.Create(bg(), body); err != nil {
			return polActionMsg{genTag: t, status: "✗ " + errText(err)}
		}
		return polActionMsg{
			genTag:      t,
			status:      `✓ created "` + name + `" - open it and press n to add rules`,
			refreshList: true,
		}
	}
}

func (p *Policies) save() tea.Cmd {
	body, ok := p.saveBody()
	if !ok {
		return nil
	}
	p.status = "Saving…"
	id := body.ID
	t := p.tag()
	return func() tea.Msg {
		res, err := p.deps.Client.Policies.Update(bg(), id, body)
		return polSavedMsg{genTag: t, rules: res.Rules, err: err}
	}
}

func (p *Policies) saveBody() (client.PolicySet, bool) {
	if !p.haveDetail {
		return client.PolicySet{}, false
	}
	sel, ok := p.selected()
	if !ok {
		return client.PolicySet{}, false
	}
	p.fold()

	vars := make([]client.PolicyVariant, 0, len(p.variants))
	for vi, v := range p.variants {
		where := ""
		if len(p.variants) > 1 {
			where = " in " + v.name
		}

		if v.unreadable > 0 {
			p.status = "✗ " + itoa(v.unreadable) + " rule(s)" + where + " cannot be read by this version, saving would delete them; edit ~/.solongate/policy.json directly"
			return client.PolicySet{}, false
		}
		for i, d := range v.rules {
			if isBlanketRule(d.rule) {
				p.status = "✗ rule " + itoa(i+1) + where + " matches EVERYTHING, pick a Constraint + Match value, or narrow Permissions"
				return client.PolicySet{}, false
			}
		}
		raws := make([]json.RawMessage, 0, len(v.rules))
		for _, d := range v.rules {
			b, err := d.marshal()
			if err != nil {
				p.status = "✗ could not encode rule: " + errText(err)
				return client.PolicySet{}, false
			}
			raws = append(raws, b)
		}
		sec := v.sec
		vars = append(vars, client.PolicyVariant{
			ID:       polOrID(v.id, vi),
			Name:     v.name,
			Rules:    client.Rules{Raw: raws},
			Security: &sec,
		})
	}

	first := vars[0]
	return client.PolicySet{
		ID:          sel.ID,
		Name:        p.detail.Name,
		Description: p.detail.Description,
		Mode:        p.mode,
		Agents:      p.detail.Agents,
		Variants:    vars,

		DefaultVariant: first.ID,
		Rules:          first.Rules,
		Security:       first.Security,
	}, true
}

func polOrID(id string, i int) string {
	if id != "" {
		return id
	}
	return polVariantID(i)
}

func (p *Policies) discard() {
	if p.haveDetail {
		p.adoptPolicy(p.detail.PolicySet)
	}
	p.dirty = false
	p.status = "discarded"
}

func adoptRules(r client.Rules) []ruleDoc {
	out := make([]ruleDoc, 0, len(r.Items))
	for i, item := range r.Items {
		doc := ruleDoc{rule: item}

		if r.Unreadable == 0 && i < len(r.Raw) {
			doc.raw = r.Raw[i]
		}
		out = append(out, doc)
	}
	return out
}

func (p *Policies) adoptPolicy(set client.PolicySet) {
	p.variants = p.variants[:0]
	for _, v := range polDefaultFirst(set.VariantList(), set.DefaultVariant) {
		d := variantDraft{
			id:         v.ID,
			name:       v.Name,
			rules:      adoptRules(v.Rules),
			unreadable: v.Rules.Unreadable,
			sec:        p.layersOf(set, v),
		}
		if d.id == "" {
			d.id = polVariantID(len(p.variants))
		}
		if d.name == "" {
			d.name = polVariantName(p.variants)
		}
		p.variants = append(p.variants, d)
	}
	p.mode = set.Mode
	if p.mode == "" {
		p.mode = client.ModeDenylist
	}
	p.vi = min(p.vi, len(p.variants)-1)
	p.vi = max(0, p.vi)
	p.unfold()
}