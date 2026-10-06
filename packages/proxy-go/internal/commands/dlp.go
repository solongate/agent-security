package commands

import (
	"context"
	"strconv"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func dlpUsage() string {
	return usage("solongate dlp", "data-loss prevention", []usageRow{
		row("dlp show", "current mode + enabled patterns"),
		row("dlp mode <off|detect|redact|block>", "detect records · redact masks · block refuses"),
		row("dlp enable <pattern>", "enable a built-in pattern"),
		row("dlp disable <pattern>", "disable a built-in pattern"),
		row("dlp add-custom --name X --re <regex>", "add a custom pattern"),
		row("dlp remove-custom <name>", "remove a custom pattern"),
	})
}

func runDLP(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "" {
		sub = "show"
	}
	jsonOut := p.flagBool("json")

	if sub == "help" {
		errln(dlpUsage())
		return 0, nil
	}

	// Fetched before the switch, as in the TypeScript: every subcommand except
	// help needs the current layers, and the write path needs them to send back
	// the layers it is not changing.
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
			printJSON(map[string]any{"dlp": layers.DLP, "availablePatterns": cur.AvailablePatterns})
			return 0, nil
		}
		errln("")
		errln("  DLP   mode: " + modeColor(layers.DLP.Mode))
		enabled := make(map[string]bool, len(layers.DLP.Patterns))
		for _, n := range layers.DLP.Patterns {
			enabled[n] = true
		}
		rows := make([][]string, 0, len(cur.AvailablePatterns))
		for _, name := range cur.AvailablePatterns {
			if enabled[name] {
				rows = append(rows, []string{green("●"), name})
			} else {
				rows = append(rows, []string{dim("○"), dim(name)})
			}
		}
		table([]string{"", "PATTERN"}, rows)
		if len(layers.DLP.Custom) > 0 {
			errln(dim("\n  Custom:"))
			for _, cp := range layers.DLP.Custom {
				errln("    " + cyan(cp.Name) + "  " + dim(cp.Re))
			}
		}
		return 0, nil

	case "mode":
		mode := p.positional(1)
		if mode != "off" && mode != "detect" && mode != "redact" && mode != "block" {
			return usageErr("Usage: dlp mode <off|detect|redact|block>")
		}
		next := layers
		next.DLP.Mode = api.LayerMode(mode)
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.DLP)
			return 0, nil
		}
		okf("DLP mode → %s", string(saved.DLP.Mode))
		return 0, nil

	case "enable", "disable":
		pattern := p.rest(1)
		if pattern == "" {
			return usageErr("Usage: dlp " + sub + " <pattern>")
		}
		// A pattern name that is not one the cloud offers would be saved and
		// then silently never matched, because the guard looks the names up in
		// its own table. Refusing here, with the list, is the only place that is
		// visible.
		known := false
		for _, a := range cur.AvailablePatterns {
			if a == pattern {
				known = true
				break
			}
		}
		if !known {
			errln(`  Unknown pattern: "` + pattern + `". Available:`)
			for _, a := range cur.AvailablePatterns {
				errln("    " + dim("•") + " " + a)
			}
			return 1, nil
		}
		next := layers
		next.DLP.Patterns = togglePattern(layers.DLP.Patterns, pattern, sub == "enable")
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.DLP)
			return 0, nil
		}
		errln(green(`  ✓ `+sub+`d "`+pattern+`"`) +
			dim(" ("+strconv.Itoa(len(saved.DLP.Patterns))+" active)"))
		return 0, nil

	case "add-custom":
		name, re := p.flagStr("name"), p.flagStr("re")
		if name == "" || re == "" {
			return usageErr("Usage: dlp add-custom --name <name> --re <regex>")
		}
		next := layers
		next.DLP.Custom = append(withoutCustom(layers.DLP.Custom, name), api.CustomPattern{Name: name, Re: re})
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.DLP)
			return 0, nil
		}
		okf(`Custom pattern "%s" added`, name)
		return 0, nil

	case "remove-custom":
		name := p.rest(1)
		if name == "" {
			return usageErr("Usage: dlp remove-custom <name>")
		}
		next := layers
		next.DLP.Custom = withoutCustom(layers.DLP.Custom, name)
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.DLP)
			return 0, nil
		}
		okf(`Removed custom pattern "%s"`, name)
		return 0, nil
	}

	return unknownSub("dlp", sub, dlpUsage())
}

// togglePattern adds or removes one name, keeping the order the rest arrived in.
// A Set round trip in JavaScript preserves insertion order; sorting here would
// rewrite the stored list on every edit and make the dashboard's diff view show
// changes nobody made.
func togglePattern(patterns []string, name string, on bool) []string {
	next := make([]string, 0, len(patterns)+1)
	found := false
	for _, p := range patterns {
		if p == name {
			found = true
			if !on {
				continue
			}
		}
		next = append(next, p)
	}
	if on && !found {
		next = append(next, name)
	}
	return next
}

func withoutCustom(custom []api.CustomPattern, name string) []api.CustomPattern {
	next := make([]api.CustomPattern, 0, len(custom))
	for _, c := range custom {
		if c.Name != name {
			next = append(next, c)
		}
	}
	return next
}
