// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/health"
)

func doctorUsage() string {
	return usage("solongate doctor", "health check: policy, guard, hooks, local logs", []usageRow{
		row("doctor", "run all health checks"),
		line("doctor --json"),
	})
}

func runDoctor(ctx context.Context, c *client.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "help" || sub == "-h" || p.flagBool("help") {
		errln(doctorUsage())
		return 0, nil
	}
	if sub != "" {
		return unknownSub("doctor", sub, doctorUsage())
	}

	checks := health.CollectChecks(ctx, c)

	failed := 0
	warned := 0
	nameWidth := 18
	for _, ch := range checks {
		switch ch.OK {
		case health.StateFail:
			failed++
		case health.StateWarn:
			warned++
		}
		if w := displayWidth(ch.Name); w > nameWidth {
			nameWidth = w
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
		errln("  " + mark + " " + padRight(ch.Name, nameWidth) + " " + dim(ch.Detail))
	}
	errln("")
	switch {
	case len(checks) == 0:
		errln("  " + yellow("no checks recorded"))
	case failed > 0:
		tail := ""
		if warned > 0 {
			tail = dim(" · " + plural(warned, "warning", "warnings"))
		}
		errln("  " + red(plural(failed, "problem", "problems")) + tail)
	case warned > 0:
		errln("  " + yellow(plural(warned, "warning", "warnings")) + " " + dim("- guard is working"))
	default:
		errln("  " + green("all good"))
	}
	if failed > 0 {
		return 1, nil
	}
	return 0, nil
}