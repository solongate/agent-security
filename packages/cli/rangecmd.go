// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

func rangeUsage() string {
	return usage("solongate range", "how far an update may move", []usageRow{
		row("range", "which range this machine is on"),
		row("range long", "tagged releases only  (the default)"),
		row("range short", "every commit on the branch"),
	})
}

func runRange(ctx context.Context, c *client.Client, p parsedArgs) (int, error) {
	switch arg := p.positional(0); arg {
	case "":
		return rangeShow()
	case "help":
		errln(rangeUsage())
		return 0, nil
	case config.UpdateRangeLong, config.UpdateRangeShort:
		if err := config.SetUpdateRange(arg); err != nil {
			return 1, err
		}
		return rangeShow()
	default:
		errln(rangeUsage())
		return 1, nil
	}
}

func rangeShow() (int, error) {
	cur := config.UpdateRangeOf(config.LoadTUIConfig())
	other := config.UpdateRangeShort
	if cur == config.UpdateRangeShort {
		other = config.UpdateRangeLong
	}

	errln("")
	if cur == config.UpdateRangeShort {
		errln("  " + yellow(cur) + dim("   every commit on the branch"))
	} else {
		errln("  " + green(cur) + dim("    tagged releases only"))
	}
	errln("  " + dim("`solongate range "+other+"` to change it"))
	errln("")
	return 0, nil
}