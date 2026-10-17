// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"
	"strconv"
	"strings"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/health"
)

func runDoctor(ctx context.Context, c *client.Client, p parsedArgs) (int, error) {
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

func padRight(s string, n int) string {
	if displayWidth(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-displayWidth(s))
}