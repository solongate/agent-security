// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/health"
	"github.com/solongate/agent-security/packages/core/install"
)

// Split from settings.go: key handling, the one-shot action dispatch, and the
// inline text prompt.

func (p *Settings) key(k tea.KeyMsg) tea.Cmd {
	s := k.String()

	if p.editing != "" {
		// esc abandons the prompt without writing. It is not in the Ink version,
		// and it has to be here: the shell gives a capturing panel every key, so
		// the only other way out of the path prompt would be to submit it, and
		// submitting an empty path CLEARS local logging.
		if s == "esc" {
			p.editing = ""
			p.input.Blur()
			return nil
		}
		if s != "enter" {
			var cmd tea.Cmd
			p.input, cmd = p.input.Update(k)
			return cmd
		}
		return p.submitInput()
	}

	rows := p.allRows()
	cur := p.current()
	p.msg = nil

	switch {
	case s == "up":
		p.sel = max(0, p.sel-1)
		p.confirmDel = ""
	case s == "down":
		p.sel = min(len(rows)-1, p.sel+1)
		p.confirmDel = ""
	case s == "enter" || s == " ":
		return p.activate(cur)
	case s == "m" && (cur.kind == "self" || cur.kind == "ll-enabled"):
		return p.activate(cur)
	case s == "e" && cur.kind == "ll-path":
		return p.activate(cur)
	case s == "d" && cur.kind == "guard":
		if p.installBusy {
			return nil
		}
		p.installBusy = true
		p.msg = &setMessage{text: "removing the guard from this device…"}
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg {
				r := install.Uninstall()
				return setInstallMsg{genTag: t, verb: "remove", ok: r.OK, message: r.Message, notes: r.Notes}
			},
		)
	case s == "r":
		p.readDisk()
		return p.reloadAll()
	}
	return nil
}

func (p *Settings) beginInput(value string) {
	p.input.SetValue(value)
	p.input.CursorEnd()
	p.input.Focus()
}

// activate is what enter does to the row under the cursor.
func (p *Settings) activate(r setRow) tea.Cmd {
	switch r.kind {
	case "range":
		// A toggle rather than a prompt: there are exactly two values and one
		// of them is always the other one. Written through the same setter the
		// CLI uses, and read back into Deps so the row redraws from the file
		// rather than from what this panel believes it just wrote.
		next := config.UpdateRangeLong
		if config.UpdateRangeOf(p.deps.Cfg) == config.UpdateRangeLong {
			next = config.UpdateRangeShort
		}
		if err := config.SetUpdateRange(next); err != nil {
			p.msg = &setMessage{text: "✗ " + errText(err), bad: true}
			return nil
		}
		p.deps.Cfg = config.LoadTUIConfig()
		if next == config.UpdateRangeShort {
			p.msg = &setMessage{text: "✓ short · updates take every commit on the branch"}
		} else {
			p.msg = &setMessage{text: "✓ long · updates take tagged releases only"}
		}
		return nil

	case "guard":
		if p.installBusy {
			return nil
		}
		p.installBusy = true
		p.msg = &setMessage{text: "installing the guard…"}
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg {
				r := install.Install()
				return setInstallMsg{genTag: t, verb: "install", ok: r.OK, message: r.Message, notes: r.Notes}
			},
		)

	case "doctor":
		if p.diagBusy {
			return nil
		}
		p.diagBusy = true
		p.diagStep = 0
		p.diag = nil
		p.msg = nil
		client := p.deps.Client
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg { return setDoctorMsg{genTag: t, checks: health.CollectChecks(bg(), client)} },
		)

	case "repair":
		if p.installBusy {
			return nil
		}
		p.installBusy = true
		p.repairReport = nil
		p.msg = &setMessage{text: "restoring the protection files…"}
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg {
				r := install.Repair()
				return setInstallMsg{genTag: t, verb: "repair", ok: r.OK, message: r.Message, notes: r.Notes, repair: &r}
			},
		)

	case "self":
		if !p.haveSelf {
			return nil
		}
		want := !p.selfProt
		label := "self-protection enabled"
		if !want {
			label = "self-protection disabled"
		}
		return p.run(label, func() error {
			_, err := p.deps.Client.Settings.SetSelfProtection(bg(), want)
			return err
		}, "self")

	case "ll-enabled":
		if !p.haveLocal {
			return nil
		}
		if !p.local.Enabled && strings.TrimSpace(p.local.Path) == "" {
			p.msg = &setMessage{text: "set a path first (↓ then enter)", bad: true}
			return nil
		}
		want := !p.local.Enabled
		label := "local logs enabled"
		if !want {
			label = "local logs disabled"
		}
		path := p.local.Path
		return p.run(label, func() error {
			_, err := p.deps.Client.Settings.SetLocalLogs(bg(), client.LocalLogsConfig{Enabled: want, Path: path})
			return err
		}, "local")

	case "ll-path":
		p.editing = "path"
		p.beginInput(p.local.Path)

	}
	return nil
}

func (p *Settings) submitInput() tea.Cmd {
	v := strings.TrimSpace(p.input.Value())
	which := p.editing
	p.editing = ""
	p.input.Blur()

	switch which {
	case "path":
		enabled := p.haveLocal && p.local.Enabled && v != ""
		label := "path cleared (local logs off)"
		if v != "" {
			label = "path saved"
			if !enabled {
				label += " (press enter on enabled to turn on)"
			}
		}
		return p.run(label, func() error {
			_, err := p.deps.Client.Settings.SetLocalLogs(bg(), client.LocalLogsConfig{Enabled: enabled, Path: v})
			return err
		}, "local")

	}
	return nil
}