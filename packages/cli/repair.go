// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"runtime"

	"github.com/solongate/agent-security/packages/core/install"
)

// RunRepair is `solongate repair`: restore the guard after tampering or
// deletion. It needs no API client and no login round trip — the account already
// on the device is reused — so it does not go through the command router above.
func RunRepair([]string) int {
	if code, refused := refuseUnderSudo(); refused {
		return code
	}

	rep := install.Repair()

	// ONE LINE PER THING, AND EVERY ONE OF THEM A MARK.
	//
	// This used to print a "before" list, a blank line, a "restored" list, and
	// a tick. Almost all of it was the same six rows twice over, and the only
	// reader who benefited was somebody comparing them column by column. It
	// runs in the middle of `solongate update` and of install.sh, both of which
	// report a step as one [  OK  ] line, so three paragraphs of its own went
	// past too fast to read and in a different voice from everything around it.
	//
	// So: the state the repair LEFT, one row at a time, in the same two marks
	// the rest of the run uses. A client it could not register is the row worth
	// seeing, and it is the one that says [FAILED] while the run carries on.
	if !rep.OK {
		markNo(rep.Message)
		return 1
	}
	for _, l := range rep.After {
		line := padRight(l.Label, 20) + " " + l.Detail
		if !l.OK {
			markNo(line)
			continue
		}
		markOK(line)
	}
	// Notes are conditions the repair cannot fix on the user's behalf, such as
	// Codex needing `/hooks` run inside it once. They are not steps, so they do
	// not get a mark; they are indented under the last one.
	for _, n := range rep.Notes {
		errln("         " + n)
	}
	markOK(rep.Message)
	// SAID HERE AND NOWHERE ELSE. A client reads its hooks when it starts, so a
	// session that is already open is running under whatever was registered
	// when it launched, and a repair it cannot see looks like a repair that did
	// not work. install.sh and `solongate update` both reach this through the
	// same binary, so putting it here says it once rather than in three voices.
	errln("         open a new AI session for it to take effect")
	return 0
}

// refuseUnderSudo stops a repair that would arm the wrong home directory.
//
// Repair installs the guard hooks into the INVOKING user's home. Under sudo that
// is root's home, so it would report success while the user's agents stayed
// exactly as broken as before. This is easy to hit by momentum: the fix for a
// root-owned npm folder is `sudo npm i -g …` followed by this command — which
// must NOT be sudo.
func refuseUnderSudo() (int, bool) {
	if runtime.GOOS == "windows" || os.Getuid() != 0 || os.Getenv("SOLONGATE_INTERNAL") == "1" {
		return 0, false
	}
	whose := ""
	if u := os.Getenv("SUDO_USER"); u != "" {
		whose = " of " + u + "’s"
	}
	errln("")
	errln("  Do not run `solongate repair` with sudo.")
	errln("  It installs the guard into your home directory, and as root it would")
	errln("  arm root’s home instead" + whose + " — reporting success while nothing changed for you.")
	errln("")
	errln("  Run it as yourself:  solongate repair")
	errln("")
	return 1, true
}
