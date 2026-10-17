// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package term

import (
	"fmt"
	"os"
)

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

func init() {
	if os.Getenv("NO_COLOR") != "" || !isatty(os.Stderr) {
		Reset, Bold, Dim, Italic, White, Gray = "", "", "", "", "", ""
		Blue1, Blue2, Blue3, Blue4, Blue5, Blue6 = "", "", "", "", "", ""
		Green, Red, Cyan, Yellow, BgBlue = "", "", "", "", ""
	}
}

func isatty(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func Log(msg string) { fmt.Fprintln(os.Stderr, msg) }

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