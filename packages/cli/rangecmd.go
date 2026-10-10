// SPDX-License-Identifier: Apache-2.0

// `solongate range` is how far an update is allowed to move.
//
// THERE ARE TWO HONEST ANSWERS AND THIS PRODUCT CANNOT PICK FOR YOU. A tag is
// a deliberate act: somebody decided a state was worth naming and a release
// job agreed. The tip of a branch is whatever was merged a few minutes ago,
// which is how a fix reaches you the same day and also how you inherit the
// thing the next commit fixes. Both are reasonable; they are reasonable for
// different people.
//
// So the default is the cautious one and the other is one command away.
package cli

import (
	"context"

	"github.com/solongate/agent-security/packages/core/api"
	"github.com/solongate/agent-security/packages/core/config"
)

func rangeUsage() string {
	return usage("solongate range", "how far an update may move", []usageRow{
		row("range", "which range this machine is on"),
		row("range long", "tagged releases only  (the default)"),
		row("range short", "every commit on the branch"),
	})
}

func runRange(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
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

	errln("")
	for _, r := range []struct {
		name, line string
		warn       bool
	}{
		{config.UpdateRangeLong, "tagged releases only. A maintainer named the state and the release job agreed.", false},
		{config.UpdateRangeShort, "every commit on the branch. Fixes arrive the day they land, and so does whatever the next commit fixes.", true},
	} {
		mark, label := "  ", dim(r.name)
		if r.name == cur {
			mark = green("▸ ")
			label = bold(r.name)
			if r.warn {
				label = yellow(r.name)
			}
		}
		errln("  " + mark + label)
		errln("      " + dim(r.line))
	}
	errln("")
	errln("  " + dim("`solongate update` moves this checkout and reinstalls from it."))
	errln("")
	return 0, nil
}
