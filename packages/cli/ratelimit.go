// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"
	"strconv"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
)

func ratelimitUsage() string {
	return usage("solongate ratelimit", "request throttling", []usageRow{
		row("ratelimit show", "current limits + change history"),
		line("ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]"),
		row("ratelimit history", "recent limit changes"),
	})
}

func modeColor(m client.LayerMode) string {
	switch m {
	case client.LayerBlock:
		return green(string(m))
	case client.LayerDetect:
		return yellow(string(m))
	}
	return dim(string(m))
}

func runRateLimit(ctx context.Context, c *client.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "" {
		sub = "show"
	}
	jsonOut := p.flagBool("json")

	switch sub {
	case "help":
		errln(ratelimitUsage())
		return 0, nil

	case "show":

		type histResult struct {
			history []client.RateLimitChange
			err     error
		}
		histCh := make(chan histResult, 1)
		go func() {
			h, err := c.Settings.GetRateLimitHistory(ctx)
			histCh <- histResult{h, err}
		}()
		layers, lerr := c.Settings.GetSecurityLayers(ctx)
		hist := <-histCh
		if lerr != nil {
			return 1, lerr
		}
		if hist.err != nil {
			return 1, hist.err
		}
		rl := layers.Layers.RateLimit
		if jsonOut {
			printJSON(map[string]any{"rateLimit": rl, "history": hist.history})
			return 0, nil
		}
		errln("")
		errln("  Rate limit   mode: " + modeColor(rl.Mode))
		errln("  " + bold(strconv.Itoa(rl.PerMinute)) + " " + dim("/min") +
			"   " + bold(strconv.Itoa(rl.PerHour)) + " " + dim("/hour") +
			"   " + bold(strconv.Itoa(rl.PerDay)) + " " + dim("/day"))
		if len(hist.history) > 0 {
			minutes := make([]int, 0, len(hist.history))
			for _, h := range hist.history {
				minutes = append(minutes, h.Minute)
			}
			errln("  history      " + cyan(sparkline(minutes)) +
				" " + dim("("+strconv.Itoa(len(hist.history))+" changes, per-min)"))
		}
		return 0, nil

	case "history":
		history, err := c.Settings.GetRateLimitHistory(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(history)
			return 0, nil
		}
		if len(history) == 0 {
			errln(dim("  No rate-limit changes recorded."))
			return 0, nil
		}
		rows := make([][]string, 0, len(history))
		for _, h := range history {
			rows = append(rows, []string{
				dim(isoMillis(h.TS)),
				strconv.Itoa(h.Minute),
				strconv.Itoa(h.Hour),
				strconv.Itoa(h.Day),
			})
		}
		table([]string{"WHEN", "MINUTE", "HOUR", "DAY"}, rows)
		return 0, nil

	case "set":
		minute, hasMinute := p.flagNumOK("minute")
		hour, hasHour := p.flagNumOK("hour")
		day, hasDay := p.flagNumOK("day")
		mode := p.flagStr("mode")
		if !hasMinute && !hasHour && !hasDay && mode == "" {
			return usageErr("Usage: ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]")
		}

		cur, err := c.Settings.GetSecurityLayers(ctx)
		if err != nil {
			return 1, err
		}
		next := cur.Layers
		if mode != "" {
			next.RateLimit.Mode = client.LayerMode(mode)
		}
		if hasMinute {
			next.RateLimit.PerMinute = minute
		}
		if hasHour {
			next.RateLimit.PerHour = hour
		}
		if hasDay {
			next.RateLimit.PerDay = day
		}
		saved, err := c.Settings.SetSecurityLayers(ctx, next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved.RateLimit)
			return 0, nil
		}
		r := saved.RateLimit
		errln(green("  ✓ Rate limit updated") + dim("  "+
			strconv.Itoa(r.PerMinute)+"/min "+strconv.Itoa(r.PerHour)+"/h "+
			strconv.Itoa(r.PerDay)+"/day  ("+string(r.Mode)+")"))
		return 0, nil
	}

	return unknownSub("ratelimit", sub, ratelimitUsage())
}

func isoMillis(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}