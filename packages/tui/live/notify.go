// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

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
		cmd = exec.Command(unixBinary("osascript"), "-e",
			`display notification `+appleScriptString(msg)+` with title `+appleScriptString(title))
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

func appleScriptString(s string) string {
	// Notification text can contain agent-controlled paths or commands; an
	// unescaped backslash can end the literal and run injected AppleScript.
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

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

func unixBinary(name string) string {
	p := "/usr/bin/" + name
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return name
}