// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package maintenance

import (
	"context"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/health"
)

func doctorUsage() string {
	return cliutil.Usage("solongate doctor", "health check: policy, guard, hooks, local logs", []cliutil.UsageRow{
		cliutil.Row("doctor", "run all health checks"),
		cliutil.Line("doctor --json"),
	})
}

func RunDoctor(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	sub := p.Positional(0)
	if sub == "help" || sub == "-h" || p.FlagBool("help") {
		cliutil.Errln(doctorUsage())
		return 0, nil
	}
	if sub != "" {
		return cliutil.UnknownSub("doctor", sub, doctorUsage())
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
		if w := cliutil.DisplayWidth(ch.Name); w > nameWidth {
			nameWidth = w
		}
	}

	if p.FlagBool("json") {
		cliutil.PrintJSON(checks)
		if failed > 0 {
			return 1, nil
		}
		return 0, nil
	}

	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Bold("SolonGate doctor"))
	cliutil.Errln("")
	for _, ch := range checks {
		mark := cliutil.Red("✗")
		switch ch.OK {
		case health.StateOK:
			mark = cliutil.Green("✓")
		case health.StateWarn:
			mark = cliutil.Yellow("!")
		}
		cliutil.Errln("  " + mark + " " + cliutil.PadRight(ch.Name, nameWidth) + " " + cliutil.Dim(ch.Detail))
	}
	cliutil.Errln("")
	switch {
	case len(checks) == 0:
		cliutil.Errln("  " + cliutil.Yellow("no checks recorded"))
	case failed > 0:
		tail := ""
		if warned > 0 {
			tail = cliutil.Dim(" · " + cliutil.Plural(warned, "warning", "warnings"))
		}
		cliutil.Errln("  " + cliutil.Red(cliutil.Plural(failed, "problem", "problems")) + tail)
	case warned > 0:
		cliutil.Errln("  " + cliutil.Yellow(cliutil.Plural(warned, "warning", "warnings")) + " " + cliutil.Dim("- guard is working"))
	default:
		cliutil.Errln("  " + cliutil.Green("all good"))
	}
	if failed > 0 {
		return 1, nil
	}
	return 0, nil
}
