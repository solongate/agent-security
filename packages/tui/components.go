// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func hhmmss(atMs int64) string {
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

func paneTitle(label, extra string, width int) string {
	tail := " "
	if extra != "" {
		tail = " " + extra + " "
	}
	used := 2 + 1 + len([]rune(label)) + len([]rune(tail))
	fill := 0
	if width > used {
		fill = width - used
	}
	return renderRow(width,
		sg("─ ", theme.Dim),
		sgb("▎"+label, theme.AccentBright),
		sg(tail+strings.Repeat("─", fill), theme.Dim),
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

func streamLine(e StreamRow, selected, date bool, width int) string {
	cursor, cursorColor := " ", theme.Dim
	if selected {
		cursor, cursorColor = "▸", theme.AccentBright
	}
	stamp := "[" + hhmmss(e.At) + " "
	if date {
		stamp = "[" + ymd(e.At) + " " + hhmmss(e.At) + " "
	}

	evalText, evalColor := ", ", theme.Dim
	if e.EvalMs != nil {
		evalText = num(*e.EvalMs) + "ms"
		if *e.EvalMs > 500 {
			evalColor = theme.Warn
		}
	}
	agent := e.Agent
	if agent == "" {
		agent = "-"
	}
	dlpColor := theme.Dim
	dlpText := "dlp:no"
	if e.DLP {
		dlpColor, dlpText = theme.Bad, "dlp:yes"
	}
	burstColor := theme.Dim
	burstText := "rl:no"
	if e.Burst {
		burstColor, burstText = theme.Warn, "rl:yes"
	}

	segs := []seg{
		sg(cursor, cursorColor),
		sg(stamp, theme.Dim),
		sg("] ", theme.Dim),
		seg{text: padEnd(e.Decision, 6), fg: decisionColor(e.Decision), bold: e.Decision != "ALLOW"},
		sg(padEnd(truncate(e.Tool, 12), 13), theme.Accent),
		sg(padEnd(e.Permission, 5), theme.Dim),
		sg(padEnd(evalText, 7), evalColor),
		sg(padEnd(truncate(agent, 11), 12), theme.Dim),
		seg{text: padEnd(dlpText, 8), fg: dlpColor, bold: e.DLP},
		seg{text: padEnd(burstText, 7), fg: burstColor, bold: e.Burst},
	}
	if e.Rule != "" && e.Decision != "ALLOW" {
		segs = append(segs, sg(truncate(e.Rule, 14)+" ", theme.Bad))
	}
	segs = append(segs, sg(e.Detail, theme.Dim))
	if selected {
		segs = onBG(lipgloss.Color(hexSelectBG), segs)
	}
	return renderRow(width, segs...)
}

func dataView(loading bool, err error, empty bool, emptyText string, width int, body []string) []string {
	if err != nil {
		return []string{renderRow(width, sg("✗ "+err.Error(), theme.Bad))}
	}
	if loading {
		return []string{renderRow(width, sg("⟳ loading…", theme.Warn))}
	}
	if empty {
		if emptyText == "" {
			emptyText = "No data."
		}
		return []string{renderRow(width, sg(emptyText, theme.Dim))}
	}
	return body
}

func keyHints(hints [][2]string, width int) string {
	segs := make([]seg, 0, len(hints)*3)
	for i, h := range hints {
		segs = append(segs, sg(h[0], theme.Accent), sg(" "+h[1], theme.Dim))
		if i < len(hints)-1 {
			segs = append(segs, sg("   ", theme.Dim))
		}
	}
	return renderRow(width, segs...)
}

type helpGroup struct {
	title string
	keys  [][2]string
}

func helpBlock(groups []helpGroup, keyWidth, width int) []string {
	var out []string
	for _, g := range groups {
		out = append(out, renderRow(width, sgb(g.title, theme.Accent)))
		for _, k := range g.keys {
			out = append(out,
				renderRow(width,
					sg(padEnd("  "+k[0], keyWidth), theme.AccentBright),
					sg(k[1], theme.Dim)))
		}
		out = append(out, "")
	}
	return out
}

func whyBlock(decision, reason, rule string, dlp []string, burst bool, width int) []string {
	if strings.TrimSpace(reason) == "" && len(dlp) == 0 && !burst {
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

	label := func(k, v string) []string { return wrapLines(padEnd(k, 10)+v, width) }

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

func whyColor(decision string, burst bool, dlp []string) lipgloss.TerminalColor {
	if strings.ToUpper(strings.TrimSpace(decision)) == "ALLOW" {
		if burst || len(dlp) > 0 {
			return theme.Warn
		}
		return theme.Dim
	}
	return theme.Bad
}