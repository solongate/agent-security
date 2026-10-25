// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var SpinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func Truncate4(s string) string {
	r := []rune(s)
	if len(r) > 4 {
		return string(r[:4])
	}
	return s
}

func CollapseSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

func JoinColumns(cols [][]string, widths []int, height int) []string {
	out := make([]string, 0, height)
	for r := 0; r < height; r++ {
		parts := make([]string, 0, len(cols))
		for c, block := range cols {
			line := ""
			if r < len(block) {
				line = block[r]
			}
			w := lipgloss.Width(line)
			if w < widths[c] {
				line += strings.Repeat(" ", widths[c]-w)
			}
			parts = append(parts, line)
		}
		out = append(out, strings.Join(parts, "  "))
	}
	return out
}

func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}