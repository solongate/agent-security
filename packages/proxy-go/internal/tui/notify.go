package tui

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Best-effort desktop toast for the Live console's security alerts (DENY, DLP,
// rate limit). It only SHOWS a notification — clicking it does nothing. Every
// platform uses a tool it already ships with and every failure is swallowed,
// because a missing notifier must never disturb the dataroom.
//
//	Linux   — notify-send (libnotify, present on GNOME and KDE desktops)
//	Windows — a NotifyIcon balloon through the built-in PowerShell
//	macOS   — the built-in osascript notification
func desktopNotify(title, msg string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("notify-send", "-a", "SolonGate", title, msg)
	case "windows":
		q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
		ps := "Add-Type -AssemblyName System.Windows.Forms;" +
			"Add-Type -AssemblyName System.Drawing;" +
			"$n=New-Object System.Windows.Forms.NotifyIcon;" +
			"$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;" +
			"$n.ShowBalloonTip(6000,'" + q(title) + "','" + q(msg) + "',[System.Windows.Forms.ToolTipIcon]::Warning);" +
			"Start-Sleep -Milliseconds 6500;$n.Dispose()"
		cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	case "darwin":
		esc := func(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
		cmd = exec.Command("osascript", "-e",
			`display notification "`+esc(msg)+`" with title "`+esc(title)+`"`)
	default:
		return
	}
	// The child must not inherit this process's stdout: the dataroom owns the
	// alternate screen, and one line from a notifier writing to it paints over
	// the frame until the next full render.
	cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	if cmd.Start() != nil {
		return
	}
	// Reaped in the background so a notifier that lingers (the PowerShell one
	// sleeps 6.5s by design) does not leave a zombie behind for the rest of the
	// session.
	go func() { _ = cmd.Wait() }()
}

// bell rings the terminal.
//
// Writing to stdout under the alternate screen is normally how a TUI corrupts
// itself, and this is the one exception: BEL prints nothing and moves no
// cursor, so it cannot disturb the frame Bubble Tea drew.
func bell() { _, _ = os.Stdout.WriteString("\a") }
