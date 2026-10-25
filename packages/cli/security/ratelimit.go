// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package security

import (
	"context"
	"strconv"
	"time"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

func ratelimitUsage() string {
	return cliutil.Usage("solongate ratelimit", "request throttling", []cliutil.UsageRow{
		cliutil.Row("ratelimit show", "current limits + change history"),
		cliutil.Line("ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]"),
		cliutil.Row("ratelimit history", "recent limit changes"),
	})
}

func modeColor(m client.LayerMode) string {
	switch m {
	case client.LayerBlock:
		return cliutil.Green(string(m))
	case client.LayerDetect:
		return cliutil.Yellow(string(m))
	}
	return cliutil.Dim(string(m))
}

func RunRateLimit(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	sub := p.Positional(0)
	if sub == "" {
		sub = "show"
	}
	jsonOut := p.FlagBool("json")

	switch sub {
	case "help":
		cliutil.Errln(ratelimitUsage())
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
			cliutil.PrintJSON(map[string]any{"rateLimit": rl, "history": hist.history})
			return 0, nil
		}
		cliutil.Errln("")
		cliutil.Errln("  Rate limit   mode: " + modeColor(rl.Mode))
		cliutil.Errln("  " + cliutil.Bold(strconv.Itoa(rl.PerMinute)) + " " + cliutil.Dim("/min") +
			"   " + cliutil.Bold(strconv.Itoa(rl.PerHour)) + " " + cliutil.Dim("/hour") +
			"   " + cliutil.Bold(strconv.Itoa(rl.PerDay)) + " " + cliutil.Dim("/day"))
		if len(hist.history) > 0 {
			minutes := make([]int, 0, len(hist.history))
			for _, h := range hist.history {
				minutes = append(minutes, h.Minute)
			}
			cliutil.Errln("  history      " + cliutil.Cyan(cliutil.Sparkline(minutes)) +
				" " + cliutil.Dim("("+strconv.Itoa(len(hist.history))+" changes, per-min)"))
		}
		return 0, nil

	case "history":
		history, err := c.Settings.GetRateLimitHistory(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(history)
			return 0, nil
		}
		if len(history) == 0 {
			cliutil.Errln(cliutil.Dim("  No rate-limit changes recorded."))
			return 0, nil
		}
		rows := make([][]string, 0, len(history))
		for _, h := range history {
			rows = append(rows, []string{
				cliutil.Dim(isoMillis(h.TS)),
				strconv.Itoa(h.Minute),
				strconv.Itoa(h.Hour),
				strconv.Itoa(h.Day),
			})
		}
		cliutil.Table([]string{"WHEN", "MINUTE", "HOUR", "DAY"}, rows)
		return 0, nil

	case "set":
		minute, hasMinute := p.FlagNumOK("minute")
		hour, hasHour := p.FlagNumOK("hour")
		day, hasDay := p.FlagNumOK("day")
		mode := p.FlagStr("mode")
		if !hasMinute && !hasHour && !hasDay && mode == "" {
			return cliutil.UsageErr("Usage: ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]")
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
			cliutil.PrintJSON(saved.RateLimit)
			return 0, nil
		}
		r := saved.RateLimit
		cliutil.Errln(cliutil.Green("  ✓ Rate limit updated") + cliutil.Dim("  "+
			strconv.Itoa(r.PerMinute)+"/min "+strconv.Itoa(r.PerHour)+"/h "+
			strconv.Itoa(r.PerDay)+"/day  ("+string(r.Mode)+")"))
		return 0, nil
	}

	return cliutil.UnknownSub("ratelimit", sub, ratelimitUsage())
}

func isoMillis(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}
