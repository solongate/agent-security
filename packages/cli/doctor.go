// SPDX-License-Identifier: Apache-2.0

// What `solongate doctor` PRINTS. What it checks is core/health, which the
// TUI reads too: a verdict a person acts on should not depend on which
// surface they happened to open.

package cli

import (
	"context"
	"strconv"
	"strings"

	"github.com/solongate/agent-security/packages/core/api"
	"github.com/solongate/agent-security/packages/core/health"
)

func runDoctor(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	checks := health.CollectChecks(ctx, c)

	failed := 0
	warned := 0
	for _, ch := range checks {
		switch ch.OK {
		case health.StateFail:
			failed++
		case health.StateWarn:
			warned++
		}
	}

	if p.flagBool("json") {
		printJSON(checks)
		if failed > 0 {
			return 1, nil
		}
		return 0, nil
	}

	errln("")
	errln("  " + bold("SolonGate doctor"))
	errln("")
	for _, ch := range checks {
		mark := red("✗")
		switch ch.OK {
		case health.StateOK:
			mark = green("✓")
		case health.StateWarn:
			mark = yellow("!")
		}
		errln("  " + mark + " " + padRight(ch.Name, 16) + " " + dim(ch.Detail))
	}
	errln("")
	switch {
	case failed > 0:
		tail := ""
		if warned > 0 {
			tail = dim(" · " + strconv.Itoa(warned) + " warning(s)")
		}
		errln("  " + red(strconv.Itoa(failed)+" problem(s)") + tail)
	case warned > 0:
		errln("  " + yellow(strconv.Itoa(warned)+" warning(s)") + " " + dim("- guard is working"))
	default:
		errln("  " + green("all good"))
	}
	if failed > 0 {
		return 1, nil
	}
	return 0, nil
}

// padRight pads to n columns and never truncates, matching String.padEnd. A
// check name longer than the column pushes its detail right rather than being
// cut: the name is the thing you look up.
func padRight(s string, n int) string {
	if displayWidth(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-displayWidth(s))
}
