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
//
// VARIABLES RATHER THAN CONSTANTS, so they can be emptied when nothing is going
// to interpret them. Every command that printed these used to be gated to a
// real terminal, which made the question moot; `solongate run` is the first one
// that is not, because the shell shim launches an agent through it and a script
// or an IDE has no tty. Without this, a confined launch writes `\x1b[2m` into
// somebody's build log.
var (
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

// STDERR, NOT STDOUT, is what decides. Everything in this package writes there:
// stdout belongs to `--json` and to anything being piped into another program,
// and a command whose JSON goes down a pipe still has a person reading its
// banner on the terminal beside it.
//
// NO_COLOR is honoured whatever the answer. It is a one-line courtesy and the
// convention is widely enough followed that ignoring it reads as an oversight.
func init() {
	if os.Getenv("NO_COLOR") != "" || !isatty(os.Stderr) {
		Reset, Bold, Dim, Italic, White, Gray = "", "", "", "", "", ""
		Blue1, Blue2, Blue3, Blue4, Blue5, Blue6 = "", "", "", "", "", ""
		Green, Red, Cyan, Yellow, BgBlue = "", "", "", "", ""
	}
}

// isatty asks the file itself rather than taking a dependency. A character
// device is what a terminal is; a pipe, a file and /dev/null are not.
func isatty(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

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
