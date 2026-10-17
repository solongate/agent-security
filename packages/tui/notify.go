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

	cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	if cmd.Start() != nil {
		return
	}

	go func() { _ = cmd.Wait() }()
}

func bell() { _, _ = os.Stdout.WriteString("\a") }