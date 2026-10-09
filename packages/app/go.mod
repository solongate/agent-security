module github.com/solongate/agent-security/packages/app

go 1.25.0

// DO NOT `go mod tidy` yet. Bubble Tea, bubbles and lipgloss are required here
// for the TUI slice and nothing imports them until it lands, so tidy would
// helpfully delete the three dependencies the port is planned around.
require github.com/mattn/go-isatty v0.0.24

require (
	github.com/charmbracelet/bubbles v1.0.0 // indirect
	github.com/charmbracelet/bubbletea v1.3.10 // indirect
	github.com/charmbracelet/lipgloss v1.1.0 // indirect
)

require (
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/colorprofile v0.4.1 // indirect
	github.com/charmbracelet/x/ansi v0.11.6 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.10.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.6.0 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/landlock-lsm/go-landlock v0.10.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/solongate/agent-security/packages/shared v0.0.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
)

replace github.com/solongate/agent-security/packages/policy => ../policy

// The extension endpoint's address, so that whether the running agent can
// answer a browser is asked of the one derivation rather than copied here. A
// second copy of that rule is precisely the divergence that put the agent and
// the native host on different pipes on Windows.

replace github.com/solongate/agent-security/packages/shared => ../shared

require (
	github.com/solongate/agent-security/packages/cli v0.0.0
	github.com/solongate/agent-security/packages/core v0.0.0
	github.com/solongate/agent-security/packages/tui v0.0.0
)

replace github.com/solongate/agent-security/packages/core => ../core

replace github.com/solongate/agent-security/packages/cli => ../cli

replace github.com/solongate/agent-security/packages/tui => ../tui
