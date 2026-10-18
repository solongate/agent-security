// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func desktopNotify(title, msg string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command(unixBinary("notify-send"), "-a", "SolonGate", title, msg)
	case "windows":
		q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
		ps := "Add-Type -AssemblyName System.Windows.Forms;" +
			"Add-Type -AssemblyName System.Drawing;" +
			"$n=New-Object System.Windows.Forms.NotifyIcon;" +
			"$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;" +
			"$n.ShowBalloonTip(6000,'" + q(title) + "','" + q(msg) + "',[System.Windows.Forms.ToolTipIcon]::Warning);" +
			"Start-Sleep -Milliseconds 6500;$n.Dispose()"
		cmd = exec.Command(windowsPowerShell(), "-NoProfile", "-NonInteractive", "-Command", ps)
	case "darwin":
		esc := func(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
		cmd = exec.Command(unixBinary("osascript"), "-e",
			`display notification "`+esc(msg)+`" with title "`+esc(title)+`"`)
	default:
		return
	}

	cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	if cmd.Start() != nil {
		return
	}

	go func() { _ = cmd.Wait() }()
}

func bell() { _, _ = os.Stdout.WriteString("\a") }

// windowsPowerShell resolves the fixed, unwriteable System32 location of
// powershell.exe instead of trusting a PATH lookup, falling back to the bare
// name only if that location doesn't exist on this machine.
func windowsPowerShell() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return "powershell"
}

// unixBinary resolves a Unix system utility to its fixed /usr/bin location
// instead of trusting a PATH lookup, falling back to the bare name if absent.
func unixBinary(name string) string {
	p := "/usr/bin/" + name
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return name
}