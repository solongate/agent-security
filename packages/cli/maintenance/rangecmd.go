// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package maintenance

import (
	"context"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

func rangeUsage() string {
	return cliutil.Usage("solongate range", "how far an update may move", []cliutil.UsageRow{
		cliutil.Row("range", "which range this machine is on"),
		cliutil.Row("range long", "tagged releases only  (the default)"),
		cliutil.Row("range short", "every commit on the branch"),
	})
}

func RunRange(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	switch arg := p.Positional(0); arg {
	case "":
		return rangeShow()
	case "help":
		cliutil.Errln(rangeUsage())
		return 0, nil
	case config.UpdateRangeLong, config.UpdateRangeShort:
		if err := config.SetUpdateRange(arg); err != nil {
			return 1, err
		}
		return rangeShow()
	default:
		cliutil.Errln(rangeUsage())
		return 1, nil
	}
}

func rangeShow() (int, error) {
	cur := config.UpdateRangeOf(config.LoadTUIConfig())
	other := config.UpdateRangeShort
	if cur == config.UpdateRangeShort {
		other = config.UpdateRangeLong
	}

	cliutil.Errln("")
	if cur == config.UpdateRangeShort {
		cliutil.Errln("  " + cliutil.Yellow(cur) + cliutil.Dim("   every commit on the branch"))
	} else {
		cliutil.Errln("  " + cliutil.Green(cur) + cliutil.Dim("    tagged releases only"))
	}
	cliutil.Errln("  " + cliutil.Dim("`solongate range "+other+"` to change it"))
	cliutil.Errln("")
	return 0, nil
}
