// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

var appleScriptStringTests = []struct {
	name string
	in   string
	want string
}{
	{name: "plain text", in: "plain text", want: `"plain text"`},
	{name: "double quote", in: `"`, want: `"\""`},
	{name: "backslash", in: `\`, want: `"\\"`},
	{name: "backslash followed by quote", in: `\"`, want: `"\\\""`},
	{name: "trailing backslash", in: `trailing\`, want: `"trailing\\"`},
	// With quote-only escaping this ends the literal and AppleScript evaluates 2 + 2.
	{name: "breakout payload", in: `\" & (2 + 2) --`, want: `"\\\" & (2 + 2) --"`},
	{name: "empty", in: "", want: `""`},
	{name: "newline", in: "\n", want: "\"\n\""},
	{name: "carriage return", in: "\r", want: "\"\r\""},
	{name: "CRLF", in: "a\r\nb", want: "\"a\r\nb\""},
	{name: "curly quotes", in: "“’”", want: `"“’”"`},
	{name: "non-ASCII", in: "café 世界", want: `"café 世界"`},
}

func TestAppleScriptString(t *testing.T) {
	for _, tt := range appleScriptStringTests {
		t.Run(tt.name, func(t *testing.T) {
			if got := appleScriptString(tt.in); got != tt.want {
				t.Errorf("appleScriptString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestAppleScriptStringRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("osascript round-trip requires macOS")
	}
	if _, err := os.Stat("/usr/bin/osascript"); err != nil {
		t.Skip("/usr/bin/osascript is not available")
	}

	for _, tt := range appleScriptStringTests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := exec.Command("/usr/bin/osascript", "-e", "return "+appleScriptString(tt.in)).Output()
			if err != nil {
				t.Errorf("osascript round-trip for %q failed: %v", tt.in, err)
				return
			}
			got := strings.TrimSuffix(string(out), "\n")
			if got != tt.in {
				t.Errorf("osascript round-trip = %q, want %q", got, tt.in)
			}
		})
	}
}

func TestWindowsPowerShellFallsBackWhenNotFound(t *testing.T) {
	// On a non-Windows test runner (or any machine without that exact
	// install layout) the computed path never exists, so windowsPowerShell
	// must fall back to the bare "powershell" command name regardless of
	// SystemRoot. This exercises that not-found branch; the found/Stat-ok
	// branch is not reachable here without writing outside the sandbox.
	t.Setenv("SystemRoot", "")
	if got := windowsPowerShell(); got != "powershell" {
		t.Errorf("windowsPowerShell() = %q, want %q with no SystemRoot set", got, "powershell")
	}

	t.Setenv("SystemRoot", `C:\DoesNotExist`)
	if got := windowsPowerShell(); got != "powershell" {
		t.Errorf("windowsPowerShell() = %q, want %q with an unresolvable SystemRoot", got, "powershell")
	}
}

func TestUnixBinaryFallsBackWhenNotFound(t *testing.T) {
	const name = "sg-definitely-not-a-real-binary-xyz"
	if got := unixBinary(name); got != name {
		t.Errorf("unixBinary(%q) = %q, want the bare name when /usr/bin/%s does not exist", name, got, name)
	}
}