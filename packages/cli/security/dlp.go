// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package security

import (
	"context"
	"strconv"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

func dlpUsage() string {
	return cliutil.Usage("solongate dlp", "data-loss prevention", []cliutil.UsageRow{
		cliutil.Row("dlp show", "current mode + enabled patterns"),
		cliutil.Row("dlp mode <off|detect|redact|block>", "detect records · redact masks · block refuses"),
		cliutil.Row("dlp enable <pattern>", "enable a built-in pattern"),
		cliutil.Row("dlp disable <pattern>", "disable a built-in pattern"),
		cliutil.Row("dlp add-custom --name X --re <regex>", "add a custom pattern"),
		cliutil.Row("dlp remove-custom <name>", "remove a custom pattern"),
	})
}

func RunDLP(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	sub := p.Positional(0)
	if sub == "" {
		sub = "show"
	}
	jsonOut := p.FlagBool("json")

	if sub == "help" {
		cliutil.Errln(dlpUsage())
		return 0, nil
	}

	cur, err := c.Settings.GetSecurityLayers(ctx)
	if err != nil {
		return 1, err
	}
	layers := cur.Layers

	save := func(next client.SecurityLayers) (client.SecurityLayers, error) {
		return c.Settings.SetSecurityLayers(ctx, next)
	}

	switch sub {
	case "show":
		if jsonOut {
			cliutil.PrintJSON(map[string]any{"dlp": layers.DLP, "availablePatterns": cur.AvailablePatterns})
			return 0, nil
		}
		cliutil.Errln("")
		cliutil.Errln("  DLP   mode: " + modeColor(layers.DLP.Mode))
		enabled := make(map[string]bool, len(layers.DLP.Patterns))
		for _, n := range layers.DLP.Patterns {
			enabled[n] = true
		}
		rows := make([][]string, 0, len(cur.AvailablePatterns))
		for _, name := range cur.AvailablePatterns {
			if enabled[name] {
				rows = append(rows, []string{cliutil.Green("●"), name})
			} else {
				rows = append(rows, []string{cliutil.Dim("○"), cliutil.Dim(name)})
			}
		}
		cliutil.Table([]string{"", "PATTERN"}, rows)
		if len(layers.DLP.Custom) > 0 {
			cliutil.Errln(cliutil.Dim("\n  Custom:"))
			for _, cp := range layers.DLP.Custom {
				cliutil.Errln("    " + cliutil.Cyan(cp.Name) + "  " + cliutil.Dim(cp.Re))
			}
		}
		return 0, nil

	case "mode":
		mode := p.Positional(1)
		if mode != "off" && mode != "detect" && mode != "redact" && mode != "block" {
			return cliutil.UsageErr("Usage: dlp mode <off|detect|redact|block>")
		}
		next := layers
		next.DLP.Mode = client.LayerMode(mode)
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(saved.DLP)
			return 0, nil
		}
		cliutil.Okf("DLP mode → %s", string(saved.DLP.Mode))
		return 0, nil

	case "enable", "disable":
		pattern := p.Rest(1)
		if pattern == "" {
			return cliutil.UsageErr("Usage: dlp " + sub + " <pattern>")
		}

		known := false
		for _, a := range cur.AvailablePatterns {
			if a == pattern {
				known = true
				break
			}
		}
		if !known {
			cliutil.Errln(`  Unknown pattern: "` + pattern + `". Available:`)
			for _, a := range cur.AvailablePatterns {
				cliutil.Errln("    " + cliutil.Dim("•") + " " + a)
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
			cliutil.PrintJSON(saved.DLP)
			return 0, nil
		}
		cliutil.Errln(cliutil.Green(`  ✓ `+sub+`d "`+pattern+`"`) +
			cliutil.Dim(" ("+strconv.Itoa(len(saved.DLP.Patterns))+" active)"))
		return 0, nil

	case "add-custom":
		name, re := p.FlagStr("name"), p.FlagStr("re")
		if name == "" || re == "" {
			return cliutil.UsageErr("Usage: dlp add-custom --name <name> --re <regex>")
		}
		next := layers
		next.DLP.Custom = append(withoutCustom(layers.DLP.Custom, name), client.CustomPattern{Name: name, Re: re})
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(saved.DLP)
			return 0, nil
		}
		cliutil.Okf(`Custom pattern "%s" added`, name)
		return 0, nil

	case "remove-custom":
		name := p.Rest(1)
		if name == "" {
			return cliutil.UsageErr("Usage: dlp remove-custom <name>")
		}
		next := layers
		next.DLP.Custom = withoutCustom(layers.DLP.Custom, name)
		saved, err := save(next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(saved.DLP)
			return 0, nil
		}
		cliutil.Okf(`Removed custom pattern "%s"`, name)
		return 0, nil
	}

	return cliutil.UnknownSub("dlp", sub, dlpUsage())
}

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

func withoutCustom(custom []client.CustomPattern, name string) []client.CustomPattern {
	next := make([]client.CustomPattern, 0, len(custom))
	for _, c := range custom {
		if c.Name != name {
			next = append(next, c)
		}
	}
	return next
}
