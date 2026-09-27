package commands

import (
	"context"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

// `solongate ghost …` — the hidden-path layer.
//
// Ghost was the one security layer with no CLI at all: it lived only in the
// dataroom's DLP panel, which meant it could not be scripted, could not be put
// in a runbook, and could not be diffed in CI like the other four. This file
// closes that.
//
// It sits beside dlp.go rather than inside it because the two are different
// layers that happen to share a panel. `dlp show` listing ghost routes would be
// a lie about what DLP is, and `dlp ghost-add` would be a worse name than this.
//
// Mode here is "on"/"off", not the off/detect/block of the other layers. There
// is no detect for ghost and there cannot be: the whole point is that the path
// looks absent, and a mode that recorded an attempt while still serving the file
// would defeat it.

func ghostUsage() string {
	return usage("solongate ghost", "hidden paths", []usageRow{
		row("ghost show", "current mode + routes"),
		row("ghost on", "start hiding the routes"),
		row("ghost off", "stop hiding them (the routes are kept)"),
		row("ghost add <glob>", "hide one more path"),
		row("ghost remove <glob>", "stop hiding one path"),
	})
}

func ghostModeColor(m string) string {
	if m == "on" {
		return green(m)
	}
	return dim("off")
}

// isBlanketGlob reports a route that would hide EVERYTHING.
//
// `*` on its own expands to `\S*`, which matches every path the guard is ever
// handed, so saving it turns the whole filesystem invisible to the agent and the
// next thing that happens is a support ticket that reads "the agent says none of
// my files exist". The policy editor refuses catch-all rules on save for exactly
// this reason; this is the same refusal for the same reason.
func isBlanketGlob(glob string) bool {
	return strings.TrimSpace(strings.ReplaceAll(glob, "*", "")) == ""
}

func hasRoute(routes []string, glob string) bool {
	for _, r := range routes {
		if r == glob {
			return true
		}
	}
	return false
}

func withoutRoute(routes []string, glob string) []string {
	next := make([]string, 0, len(routes))
	for _, r := range routes {
		if r != glob {
			next = append(next, r)
		}
	}
	return next
}

func runGhost(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "" {
		sub = "show"
	}
	jsonOut := p.flagBool("json")

	if sub == "help" {
		errln(ghostUsage())
		return 0, nil
	}

	// Same shape as dlp.go: every subcommand except help needs the current
	// layers, and a write has to send back the layers it is not changing or the
	// save would clear them.
	cur, err := c.Settings.GetSecurityLayers(ctx)
	if err != nil {
		return 1, err
	}
	layers := cur.Layers

	save := func(next api.SecurityLayers) (api.SecurityLayers, error) {
		return c.Settings.SetSecurityLayers(ctx, next)
	}

	switch sub {
	case "show":
		if jsonOut {
			printJSON(layers.Ghost)
			return 0, nil
		}
		errln("")
		errln("  Ghost   mode: " + ghostModeColor(layers.Ghost.Mode))
		if len(layers.Ghost.Patterns) == 0 {
			errln(dim("\n  No routes. `solongate ghost add <glob>` to hide a path."))
			return 0, nil
		}
		rows := make([][]string, 0, len(layers.Ghost.Patterns))
		for _, r := range layers.Ghost.Patterns {
			rows = append(rows, []string{cyan("•"), r})
		}
		table([]string{"", "ROUTE"}, rows)
		// Routes are kept when the layer is switched off, so a list on its own
		// does not tell you whether anything is being hidden. Saying so here is
		// cheaper than the alternative, which is finding out from a test that
		// passed when it should not have.
		if layers.Ghost.Mode != "on" {
			errln(dim("\n  Ghost is off: these routes are stored but nothing is hidden."))
		}
		return 0, nil

	case "on", "off":
		next := layers
		next.Ghost.Mode = sub
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.Ghost)
			return 0, nil
		}
		okf("Ghost → %s", saved.Ghost.Mode)
		if sub == "on" && len(saved.Ghost.Patterns) == 0 {
			errln(dim("  No routes yet, so nothing is hidden. `solongate ghost add <glob>`."))
		}
		return 0, nil

	case "add":
		glob := p.rest(1)
		if glob == "" {
			return usageErr("Usage: ghost add <glob>")
		}
		if isBlanketGlob(glob) {
			errln(red("  ✗ ") + `"` + glob + `" would hide every path.`)
			errln(dim("    Ghost routes are globs: `*` is any run of non-whitespace."))
			errln(dim("    Anchor it on something, e.g. *payroll.csv or *internal/*.pem"))
			return 1, nil
		}
		if hasRoute(layers.Ghost.Patterns, glob) {
			// Idempotent rather than an error: a runbook that adds its routes on
			// every run should not fail its second run.
			if jsonOut {
				printJSON(layers.Ghost)
				return 0, nil
			}
			okf(`Route "%s" is already hidden`, glob)
			return 0, nil
		}
		next := layers
		next.Ghost.Patterns = append(append([]string(nil), layers.Ghost.Patterns...), glob)
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.Ghost)
			return 0, nil
		}
		errln(green(`  ✓ Hiding "`+glob+`"`) +
			dim(" ("+strconv.Itoa(len(saved.Ghost.Patterns))+" route(s))"))
		// Adding a route to a layer that is off is the one mistake this command
		// makes easy, and it fails silently: the route is saved, the file is
		// still readable, and nothing says why.
		if saved.Ghost.Mode != "on" {
			errln(dim("    Ghost is off. `solongate ghost on` to start hiding."))
		}
		return 0, nil

	case "remove":
		glob := p.rest(1)
		if glob == "" {
			return usageErr("Usage: ghost remove <glob>")
		}
		if !hasRoute(layers.Ghost.Patterns, glob) {
			errln(`  No such route: "` + glob + `"`)
			if len(layers.Ghost.Patterns) > 0 {
				errln(dim("  Current:"))
				for _, r := range layers.Ghost.Patterns {
					errln("    " + dim("•") + " " + r)
				}
			}
			return 1, nil
		}
		next := layers
		next.Ghost.Patterns = withoutRoute(layers.Ghost.Patterns, glob)
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.Ghost)
			return 0, nil
		}
		errln(green(`  ✓ Stopped hiding "`+glob+`"`) +
			dim(" ("+strconv.Itoa(len(saved.Ghost.Patterns))+" route(s) left)"))
		return 0, nil
	}

	return unknownSub("ghost", sub, ghostUsage())
}
