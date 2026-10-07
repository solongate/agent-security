// SPDX-License-Identifier: Apache-2.0

// Package term is the plain-ANSI surface: the palette the non-TUI commands
// print with, and the banner.
//
// It is deliberately separate from lipgloss. The dataroom renders through
// Bubble Tea and can ask the terminal what it supports; a one-shot command
// prints and exits, and dragging a renderer in for six colour codes would make
// `solongate policy list` pay for a TUI it never starts.
package term

import (
	"fmt"
	"os"
)

// The palette, byte for byte the one in packages/proxy/src/cli-utils.ts. The
// blues are a ramp used top to bottom by the banner, so their order is part of
// the artwork rather than a naming convention.
const (
	Reset  = "\x1b[0m"
	Bold   = "\x1b[1m"
	Dim    = "\x1b[2m"
	Italic = "\x1b[3m"
	White  = "\x1b[97m"
	Gray   = "\x1b[90m"
	Blue1  = "\x1b[38;2;20;50;160m"
	Blue2  = "\x1b[38;2;40;80;190m"
	Blue3  = "\x1b[38;2;60;110;215m"
	Blue4  = "\x1b[38;2;90;140;230m"
	Blue5  = "\x1b[38;2;130;170;240m"
	Blue6  = "\x1b[38;2;170;200;250m"
	Green  = "\x1b[38;2;80;200;120m"
	Red    = "\x1b[38;2;220;80;80m"
	Cyan   = "\x1b[38;2;100;200;220m"
	Yellow = "\x1b[38;2;220;200;80m"
	BgBlue = "\x1b[48;2;20;50;160m"
)

// Log writes a line to stderr.
//
// Stderr, not stdout, and that is load-bearing: the same binary is the MCP
// proxy, and MCP speaks JSON-RPC over stdout. A banner on stdout is a protocol
// error to whatever is on the other end.
func Log(msg string) { fmt.Fprintln(os.Stderr, msg) }

// Out writes to stdout, for command OUTPUT — the thing a user pipes into jq.
func Out(msg string) { fmt.Fprintln(os.Stdout, msg) }

var BannerFull = []string{
	" ███████╗ ██████╗ ██╗      ██████╗ ███╗   ██╗ ██████╗  █████╗ ████████╗███████╗",
	" ██╔════╝██╔═══██╗██║     ██╔═══██╗████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝",
	" ███████╗██║   ██║██║     ██║   ██║██╔██╗ ██║██║  ███╗███████║   ██║   █████╗  ",
	" ╚════██║██║   ██║██║     ██║   ██║██║╚██╗██║██║   ██║██╔══██║   ██║   ██╔══╝  ",
	" ███████║╚██████╔╝███████╗╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║   ██║   ███████╗",
	" ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝",
}

var BannerColors = []string{Blue1, Blue2, Blue3, Blue4, Blue5, Blue6}

func PrintBanner(subtitle string) {
	Log("")
	for i, line := range BannerFull {
		Log(Bold + BannerColors[i%len(BannerColors)] + line + Reset)
	}
	Log("")
	Log("  " + Dim + Italic + subtitle + Reset)
	Log("")
}
