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

// rangeShow prints the current range and nothing else.
//
// THE EXPLANATION IS IN THE TUI. A one-shot command answers the question it
// was asked: which range is this machine on. Two paragraphs weighing the two
// choices is the right thing to read ONCE, while deciding, which is the
// Settings panel; printing it on every `solongate range` makes it the thing
// somebody scrolls past to find the one word they came for.
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
