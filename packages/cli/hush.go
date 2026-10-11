// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
)

// hushTTY turns off terminal echo for the length of a run, and gives it back.
//
// KEYS PRESSED DURING AN INSTALL MUST NOT LAND ON THE SCREEN. A repair or an
// update writes for twenty seconds, redrawing one line in place while it works,
// and anything typed over it is echoed by the kernel straight into the middle
// of that line. It is not even only the person's own typing: the terminal
// answers escape-sequence queries on the same channel, and those replies echo
// too, which is where a stray ":" or "," on a line comes from.
//
// Echo off stops all of it, and on the way out the restore also DISCARDS
// whatever arrived while the screen was busy, so a key pressed during an
// install does not run as a command the moment the prompt comes back.
//
// THROUGH stty RATHER THAN A TERMIOS BINDING. It is one short-lived process at
// the top of a command that is about to run a package manager and a compiler,
// and it keeps a C-level dependency out of a security tool's build for the sake
// of two ioctls. If stty is not there, nothing happens and nothing breaks.
func hushTTY() func() {
	if !isTerminal(os.Stdin) {
		return func() {}
	}
	read := exec.Command("stty", "-g")
	read.Stdin = os.Stdin // stty asks the terminal on ITS stdin, not ours by default
	saved, err := read.Output()
	if err != nil {
		return func() {}
	}
	state := trimLine(string(saved))
	if state == "" || stty("-echo") != nil {
		return func() {}
	}
	return func() {
		// min 0 time 0 makes a read return immediately with whatever is
		// waiting, so one pass empties the buffer rather than blocking on it.
		if stty("-icanon", "min", "0", "time", "0") == nil {
			drainStdin()
		}
		_ = stty(state)
	}
}

func stty(args ...string) error {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func drainStdin() {
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if n == 0 || err != nil {
			return
		}
	}
}

func trimLine(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
