// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func Hhmmss(atMs int64) string {
	if atMs <= 0 {
		return "--:--:--"
	}
	return time.UnixMilli(atMs).Format("15:04:05")
}

func ymd(atMs int64) string {
	if atMs <= 0 {
		return "----------"
	}
	return time.UnixMilli(atMs).Format("2006-01-02")
}

func PaneTitle(label, extra string, width int) string {
	tail := " "
	if extra != "" {
		tail = " " + extra + " "
	}
	used := 2 + 1 + len([]rune(label)) + len([]rune(tail))
	fill := 0
	if width > used {
		fill = width - used
	}
	return RenderRow(width,
		Sg("─ ", Theme.Dim),
		Sgb("▎"+label, Theme.AccentBright),
		Sg(tail+strings.Repeat("─", fill), Theme.Dim),
	)
}

type StreamRow struct {
	At         int64
	Tool       string
	Decision   string
	Permission string
	Detail     string
	DLP        bool
	Burst      bool
	Agent      string
	EvalMs     *float64
	Rule       string
}

func StreamLine(e StreamRow, selected, date bool, width int) string {
	cursor, cursorColor := " ", Theme.Dim
	if selected {
		cursor, cursorColor = "▸", Theme.AccentBright
	}
	stamp := "[" + Hhmmss(e.At) + " "
	if date {
		stamp = "[" + ymd(e.At) + " " + Hhmmss(e.At) + " "
	}

	evalText, evalColor := ", ", Theme.Dim
	if e.EvalMs != nil {
		evalText = Num(*e.EvalMs) + "ms"
		if *e.EvalMs > 500 {
			evalColor = Theme.Warn
		}
	}
	agent := e.Agent
	if agent == "" {
		agent = "-"
	}
	dlpColor := Theme.Dim
	dlpText := "dlp:no"
	if e.DLP {
		dlpColor, dlpText = Theme.Bad, "dlp:yes"
	}
	burstColor := Theme.Dim
	burstText := "rl:no"
	if e.Burst {
		burstColor, burstText = Theme.Warn, "rl:yes"
	}

	segs := []Seg{
		Sg(cursor, cursorColor),
		Sg(stamp, Theme.Dim),
		Sg("] ", Theme.Dim),
		Seg{Text: PadEnd(e.Decision, 6), Fg: DecisionColor(e.Decision), Bold: e.Decision != "ALLOW"},
		Sg(PadEnd(Truncate(e.Tool, 12), 13), Theme.Accent),
		Sg(PadEnd(e.Permission, 5), Theme.Dim),
		Sg(PadEnd(evalText, 7), evalColor),
		Sg(PadEnd(Truncate(agent, 11), 12), Theme.Dim),
		Seg{Text: PadEnd(dlpText, 8), Fg: dlpColor, Bold: e.DLP},
		Seg{Text: PadEnd(burstText, 7), Fg: burstColor, Bold: e.Burst},
	}
	if e.Rule != "" && e.Decision != "ALLOW" {
		segs = append(segs, Sg(Truncate(e.Rule, 14)+" ", Theme.Bad))
	}
	segs = append(segs, Sg(e.Detail, Theme.Dim))
	if selected {
		segs = onBG(lipgloss.Color(HexSelectBG), segs)
	}
	return RenderRow(width, segs...)
}

func DataView(loading bool, err error, empty bool, emptyText string, width int, body []string) []string {
	if err != nil {
		return []string{RenderRow(width, Sg("✗ "+err.Error(), Theme.Bad))}
	}
	if loading {
		return []string{RenderRow(width, Sg("⟳ loading…", Theme.Warn))}
	}
	if empty {
		if emptyText == "" {
			emptyText = "No data."
		}
		return []string{RenderRow(width, Sg(emptyText, Theme.Dim))}
	}
	return body
}

func keyHints(hints [][2]string, width int) string {
	segs := make([]Seg, 0, len(hints)*3)
	for i, h := range hints {
		segs = append(segs, Sg(h[0], Theme.Accent), Sg(" "+h[1], Theme.Dim))
		if i < len(hints)-1 {
			segs = append(segs, Sg("   ", Theme.Dim))
		}
	}
	return RenderRow(width, segs...)
}

type HelpGroup struct {
	Title string
	Keys  [][2]string
}

func HelpBlock(groups []HelpGroup, keyWidth, width int) []string {
	var out []string
	for _, g := range groups {
		out = append(out, RenderRow(width, Sgb(g.Title, Theme.Accent)))
		for _, k := range g.Keys {
			out = append(out,
				RenderRow(width,
					Sg(PadEnd("  "+k[0], keyWidth), Theme.AccentBright),
					Sg(k[1], Theme.Dim)))
		}
		out = append(out, "")
	}
	return out
}

func WhyBlock(decision, reason, rule string, dlp []string, burst bool, width int) []string {
	if strings.TrimSpace(reason) == "" && len(dlp) == 0 && !burst && rule == "" {
		return nil
	}

	what := ""
	switch {
	case burst && len(dlp) > 0:
		what = "rate limit · DLP: " + strings.Join(dlp, ", ")
	case burst:
		what = "rate limit"
	case len(dlp) > 0:
		what = "DLP: " + strings.Join(dlp, ", ")
	case rule != "":
		what = "rule " + rule
	}

	key := decision
	if decision == "ALLOW" && (burst || len(dlp) > 0) {
		key = "flagged"
	}

	label := func(k, v string) []string { return WrapLines(PadEnd(k, 10)+v, width) }

	var out []string
	if what != "" {
		out = append(out, label(key, what)...)
	}
	if r := strings.TrimSpace(reason); r != "" {
		out = append(out, label("reason", r)...)
	}
	if len(out) == 0 {
		return nil
	}
	return append(out, "")
}

func WhyColor(decision string, burst bool, dlp []string) lipgloss.TerminalColor {
	if strings.ToUpper(strings.TrimSpace(decision)) == "ALLOW" {
		if burst || len(dlp) > 0 {
			return Theme.Warn
		}
		return Theme.Dim
	}
	return Theme.Bad
}