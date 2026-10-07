// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"os"
	"runtime"

	"github.com/codeyevsky/solongate/proxy/internal/install"
)

// RunRepair is `solongate repair`: restore the guard after tampering or
// deletion. It needs no API client and no login round trip — the account already
// on the device is reused — so it does not go through the command router above.
func RunRepair([]string) int {
	if code, refused := refuseUnderSudo(); refused {
		return code
	}

	rep := install.Repair()

	errln("")
	errln("  " + bold("SolonGate repair"))
	errln("")
	errln("  before:")
	for _, l := range rep.Before {
		errln("    " + padRight(l.Label, 20) + " " + l.Detail)
	}
	errln("")

	if !rep.OK {
		errln("  " + red("✗ ") + rep.Message)
		return 1
	}

	errln("  restored:")
	for _, l := range rep.After {
		detail := l.Detail
		// A client the repair could not register is the one line worth colouring:
		// the run "succeeded" and that client is still unguarded.
		if !l.OK {
			detail = yellow(detail)
		}
		errln("    " + padRight(l.Label, 20) + " " + detail)
	}
	errln("")
	for _, n := range rep.Notes {
		errln("  " + n)
		errln("")
	}

	errln("  " + green("✓ ") + rep.Message)
	errln("")
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
