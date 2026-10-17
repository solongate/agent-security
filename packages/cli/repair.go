// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"os"
	"runtime"

	"github.com/solongate/agent-security/packages/core/install"
)

func RunRepair([]string) int {
	if code, refused := refuseUnderSudo(); refused {
		return code
	}

	stop := spin("Registering the guard with your agents")
	rep := install.Repair()
	stop()

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

	for _, n := range rep.Notes {
		noteln(n)
	}
	markOK(rep.Message)

	typeOut("         open a new AI session for it to take effect")
	return 0
}

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
	errln("  arm root’s home instead" + whose + ", reporting success while nothing changed for you.")
	errln("")
	errln("  Run it as yourself:  solongate repair")
	errln("")
	return 1, true
}