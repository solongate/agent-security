// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package maintenance

import (
	"os"
	"runtime"

	"github.com/solongate/agent-security/packages/cli/cliutil"
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
		line := cliutil.PadRight(l.Label, 20) + " " + l.Detail
		if !l.OK {
			markNo(line)
			continue
		}
		markOK(line)
	}

	for _, n := range rep.Notes {
		cliutil.Noteln(n)
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
	cliutil.Errln("")
	cliutil.Errln("  Do not run `solongate repair` with sudo.")
	cliutil.Errln("  It installs the guard into your home directory, and as root it would")
	cliutil.Errln("  arm root’s home instead" + whose + ", reporting success while nothing changed for you.")
	cliutil.Errln("")
	cliutil.Errln("  Run it as yourself:  solongate repair")
	cliutil.Errln("")
	return 1, true
}
